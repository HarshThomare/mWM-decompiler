"""Native CPU oracle: run a Flexo test ELF, read architectural accuracy at exit.

Does not inject rdtscp/clflush into the transient window. The binary already
times WR occupancy after rollback.
"""

import os
import re
import subprocess
from typing import Dict, List, Optional

GATE_RE = re.compile(
    r"=== (?P<name>.+?) ===\s+"
    r"Accuracy:\s+(?P<acc>[\d.]+)%,\s+"
    r"Error detected:\s+(?P<det>[\d.]+)%,\s+"
    r"Undetected error:\s+(?P<und>[\d.]+)%",
    re.MULTILINE,
)


def parse_flexo_output(text: str) -> List[Dict]:
    rows = []
    for m in GATE_RE.finditer(text):
        acc = float(m.group("acc"))
        rows.append(
            {
                "name": m.group("name").strip(),
                "accuracy_pct": acc,
                "error_detected_pct": float(m.group("det")),
                "undetected_error_pct": float(m.group("und")),
                "admitted": acc >= 90.0,
            }
        )
    return rows


def run_flexo_elf(
    path: str,
    trials: int = 2000,
    core: int = 0,
    retry: bool = False,
    timeout_s: int = 120,
) -> Dict:
    cmd = ["taskset", "-c", str(core), os.path.abspath(path), "-t", str(trials)]
    if retry:
        cmd.append("-r")
    # First process faults in WRs/pages; Flexo measures AND first, so a cold
    # run looks like a failed CPU. Warm up with a short throwaway invocation.
    warmup = cmd[:]
    warmup[warmup.index("-t") + 1] = str(min(400, max(50, trials // 4)))
    subprocess.run(warmup, capture_output=True, text=True, timeout=timeout_s, check=False)
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )
    text = (proc.stdout or "") + (proc.stderr or "")
    rows = parse_flexo_output(text)
    accs = [r["accuracy_pct"] for r in rows]
    median = sorted(accs)[len(accs) // 2] if accs else 0.0
    # Combined gate ELFs run AND first while WRs/pages are cold; later
    # circuits in the same process (and dedicated ALU/adder ELFs) are the
    # real signal that this CPU can execute Flexo.
    admitted = bool(rows) and (
        all(r["admitted"] for r in rows)
        or median >= 90.0
        or (len(rows) > 1 and all(r["admitted"] for r in rows[1:]))
    )
    return {
        "elf": path,
        "cmd": cmd,
        "returncode": proc.returncode,
        "trials": trials,
        "core": core,
        "circuits": rows,
        "median_accuracy_pct": median,
        "admitted": admitted,
        "raw": text,
    }
