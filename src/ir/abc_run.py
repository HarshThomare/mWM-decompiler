"""Run Berkeley ABC on recovered BLIF (canonicalize + optional CEC)."""

import os
import re
import subprocess
from pathlib import Path
from typing import Dict, Optional

REPO = Path(__file__).resolve().parents[2]
ABC_CANDIDATES = [
    REPO / ".deps" / "abc-master" / "abc",
    REPO / ".deps" / "abc",
    Path("/usr/bin/abc"),
]


def find_abc() -> Optional[Path]:
    for p in ABC_CANDIDATES:
        if p.is_file() and os.access(p, os.X_OK):
            return p
    which = subprocess.run(["which", "abc"], capture_output=True, text=True)
    if which.returncode == 0:
        return Path(which.stdout.strip())
    return None


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_STATS_RE = re.compile(
    r"i/o\s*=\s*(?P<ni>\d+)\s*/\s*(?P<no>\d+).*?lat\s*=\s*(?P<lat>\d+).*?nd\s*=\s*(?P<nd>\d+).*?edge\s*=\s*(?P<edge>\d+)",
    re.IGNORECASE | re.DOTALL,
)


def _run_abc(script: str, timeout_s: int = 120) -> str:
    abc = find_abc()
    if abc is None:
        raise FileNotFoundError("abc binary not found; build .deps/abc-master")
    proc = subprocess.run(
        [str(abc), "-c", script],
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=str(REPO),
    )
    return _ANSI_RE.sub("", (proc.stdout or "") + (proc.stderr or ""))


def synthesize(blif_path: str, verilog_path: str, timeout_s: int = 180) -> Dict:
    blif_path = os.path.abspath(blif_path)
    verilog_path = os.path.abspath(verilog_path)
    cmd = (
        f"read_blif {blif_path}; print_stats; strash; print_stats; "
        f"dc2; dc2; print_stats; write_verilog {verilog_path}; quit"
    )
    log = _run_abc(cmd, timeout_s=timeout_s)
    stats = []
    for m in _STATS_RE.finditer(log):
        stats.append({k: int(v) for k, v in m.groupdict().items()})
    return {
        "log": log,
        "stats": stats,
        "verilog": verilog_path if os.path.isfile(verilog_path) else None,
        "ok": "Error" not in log.split("read_blif")[-1][:200] if "read_blif" in log else True,
    }


def cec(gold_blif: str, impl_blif: str, timeout_s: int = 180) -> Dict:
    gold_blif = os.path.abspath(gold_blif)
    impl_blif = os.path.abspath(impl_blif)
    log = _run_abc(f"cec {gold_blif} {impl_blif}; quit", timeout_s=timeout_s)
    equiv = bool(re.search(r"Networks are equivalent", log, re.I))
    neq = bool(re.search(r"Networks are NOT equivalent", log, re.I))
    return {"log": log, "equivalent": equiv, "not_equivalent": neq}
