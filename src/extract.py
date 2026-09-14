#!/usr/bin/env python3
"""Recover typed µWM IR from any ELF: locate → lift → compose → BLIF/C."""

import argparse
import itertools
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
sys.path.insert(0, str(ROOT))

from ir.abc_run import cec, find_abc, synthesize
from ir.blif import net_ports, net_to_blif, rename_ports
from ir.flexo_tables import DUAL_RAIL_AND, DUAL_RAIL_XOR, check_decode
from ir.gold_blif import gold_for
from ir.net import Kind, MixedCompositionError, Net, Place, TransKind, gate_transition
from lift.flexo import has_dual_gate
from lift.harvest import HarvestResult, harvest_elf
from lift.recover import LiftContext, lift_from_elf
from oracle.btb import BtbAdapter
from oracle.cache import CacheAdapter
from oracle.native import run_flexo_elf
from oracle.tlb import TlbAdapter


def _glob_elfs(root: Path, prefix: str):
    if not root.is_dir():
        return []
    paths = sorted({p.resolve() for p in root.rglob("*.elf") if p.is_file()})
    return [(f"{prefix}_{p.stem}", p, 0, False, 60) for p in paths]


def flexo_elfs():
    return _glob_elfs(REPO / "third_party/flexo", "flexo")


def gitm_elfs():
    return _glob_elfs(REPO / "third_party/gitm", "gitm")


def tae_elfs():
    d = REPO / "third_party/tae/build/bin"
    if d.is_dir():
        paths = sorted(d.glob("*.elf"), key=lambda p: (p.name != "gates.elf", p.name))
        if paths:
            return [("tae_" + p.stem, p, 0, False, 60) for p in paths]
    return _glob_elfs(REPO / "third_party/tae", "tae")


def all_jobs():
    return flexo_elfs() + gitm_elfs() + tae_elfs()


def _gate_net(name: str, n_in: int, table_id: int) -> Net:
    net = Net(name=name)
    ins = [f"i{i}" for i in range(n_in)]
    outs = ["o0"]
    for n in ins + outs:
        net.add_place(Place(n, Kind.VOLATILE, "bit"))
    net.add_transition(gate_transition(f"{name}_g", n_in, table_id, ins, outs))
    net.native["dual_gate_instances"] = 1
    net.native["wired_instances"] = 1
    return net


def _blif_ports(text: str, kind: str):
    prefix = ".inputs " if kind == "inputs" else ".outputs "
    for line in text.splitlines():
        if line.startswith(prefix):
            return line.split()[1:]
    return []


def self_test() -> None:
    check_decode()
    assert DUAL_RAIL_AND[((1, 0), (1, 0))] == (1, 0)
    assert DUAL_RAIL_XOR[((0, 1), (1, 0))] == (0, 1)

    g8 = gold_for("adder8")
    assert g8 and _blif_ports(g8, "outputs")[-1] == "cout"
    g8s = gold_for("adder8", n_out=8)
    assert g8s and "cout" not in _blif_ports(g8s, "outputs")
    assert len(_blif_ports(g8s, "outputs")) == 8
    g8c = gold_for("adder8", n_out=9)
    assert g8c and _blif_ports(g8c, "outputs")[-1] == "cout"

    if not find_abc():
        raise FileNotFoundError("abc binary not found; CEC self-test needs .deps/abc-master")
    with tempfile.TemporaryDirectory() as td:
        outdir = Path(td)
        for name, n_in, tid in (("and", 2, 8), ("xor", 2, 6), ("mux", 3, 172)):
            decomp = decompile_net(_gate_net(name, n_in, tid), outdir / name)
            cec_info = decomp.get("cec") or {}
            assert cec_info.get("equivalent"), (name, cec_info)
    print("self-test: DualGate AND/XOR/MUX, adder gold ports, CEC ok")


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _match_native(op: str, cpu: dict):
    nop = _norm(op)
    for row in cpu.get("circuits") or []:
        if nop in _norm(row["name"]) or _norm(row["name"]) in nop:
            return row
        compact = _norm(row["name"].replace("ADDER", "adder").replace("bit", ""))
        if compact == nop or compact.replace("adder", "adder") == nop:
            return row
    return None


def _try_cec(gold: str, impl: str, gold_path: Path, impl_path: Path) -> dict:
    gold_path.write_text(gold)
    impl_path.write_text(impl)
    try:
        return cec(str(gold_path), str(impl_path))
    except Exception as e:
        return {"equivalent": False, "not_equivalent": False, "log": str(e)}


def has_lut(net: Net) -> bool:
    return any(t.kind == TransKind.GATE and t.gate_table for t in net.transitions.values())


def decompile_net(net, outdir: Path) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    blif = net_to_blif(net)
    blif_path = outdir / f"{net.name}.blif"
    blif_path.write_text(blif)
    verilog_path = outdir / f"{net.name}.v"
    abc_info = {"ok": False, "stats": [], "log": "abc missing"}
    if find_abc():
        try:
            n_gates = net.native.get("dual_gate_instances") or 1
            abc_info = synthesize(str(blif_path), str(verilog_path), timeout_s=min(600, 60 + n_gates * 2))
            abc_info.pop("log", None)
        except Exception as e:
            abc_info = {"ok": False, "stats": [], "error": str(e)}
    pis, pos = net_ports(net)
    gold = gold_for(net.name, n_out=len(pos))
    cec_info = None
    if gold and find_abc():
        gins, gouts = None, None
        g_blif = gold
        for line in gold.splitlines():
            if line.startswith(".inputs "):
                gins = line.split()[1:]
            if line.startswith(".outputs "):
                gouts = line.split()[1:]
        impl = blif
        if gins and gouts and len(pis) == len(gins) and len(pos) == len(gouts):
            impl = rename_ports(blif, gins, gouts)
        cec_info = _try_cec(g_blif, impl, outdir / f"{net.name}.gold.blif", outdir / f"{net.name}.cec.blif")
        if not cec_info.get("equivalent") and gins and len(pis) <= 4 and len(pis) == len(gins):
            for perm in itertools.permutations(gins):
                impl_p = rename_ports(blif, perm, gouts)
                trial = _try_cec(
                    g_blif, impl_p, outdir / f"{net.name}.gold.blif", outdir / f"{net.name}.cec.blif"
                )
                if trial.get("equivalent"):
                    cec_info = trial
                    cec_info["pi_perm"] = list(perm)
                    break
        if cec_info:
            cec_info.pop("log", None)
    c_path = outdir / f"{net.name}.c"
    c_src = net_to_c(net)
    if c_src:
        c_path.write_text(c_src)
    return {
        "blif": str(blif_path),
        "verilog": str(verilog_path) if verilog_path.exists() else None,
        "c": str(c_path) if c_src else None,
        "abc": abc_info,
        "cec": cec_info,
        "places": len(net.places),
        "gates": net.native.get("dual_gate_instances"),
        "wired": net.native.get("wired_instances"),
        "class": net.classify(),
        "pis_pos": net_ports(net),
    }


def net_to_c(net: Net) -> str:
    """Deterministic C for LUT regions. ISA/unlabeled nets stay commented stubs."""
    gates = [t for t in net.transitions.values() if t.kind == TransKind.GATE]
    if not gates or not any(t.gate_table for t in gates):
        unc = net.native.get("uncertainty") or "no_lut"
        return (
            f"/* {net.name}: no Boolean LUT (uncertainty={unc}). "
            f"BTB/TLB native adapters may be unemulated. */\n"
        )
    lines = [f"/* recovered {net.name} compose={_compose_label(net)} */", "#include <stdint.h>", ""]
    for t in gates:
        if not t.gate_table:
            continue
        args = ", ".join(f"uint32_t {n}" for n in t.inputs) or "void"
        ident = re.sub(r"[^A-Za-z0-9_]", "_", t.name)
        lines.append(f"uint32_t {ident}({args}) {{")
        n_in = len(t.inputs)
        for bits in range(1 << n_in):
            key = tuple((bits >> k) & 1 for k in range(n_in))
            bit = int(t.gate_table.get(key, 0))
            cond = " && ".join(
                f"{t.inputs[k]} == { (bits >> k) & 1 }" for k in range(n_in)
            ) or "1"
            lines.append(f"  if ({cond}) return {bit};")
        lines.append("  return 0;")
        lines.append("}")
        lines.append("")
    return "\n".join(lines)


def strip_copy(src: Path, dst: Path) -> Path:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    subprocess.check_call(["strip", "--strip-all", str(dst)])
    return dst


def harvest_stats(h: HarvestResult) -> dict:
    resolved = [c for c in h.candidates if not c.unresolved]
    by = {}
    for c in resolved:
        key = f"{c.resource}+{c.trigger}"
        by[key] = by.get(key, 0) + 1
    return {
        "n_primitives": len(h.primitives),
        "n_candidates": len(h.candidates),
        "n_resolved": len(resolved),
        "n_unresolved": len(h.candidates) - len(resolved),
        "resolved": by,
        "entries": [(c.resource, c.trigger, c.entry) for c in resolved],
    }


def _compose_label(net: Net) -> str:
    try:
        return net.compose()
    except MixedCompositionError as e:
        return f"rejected:{e}"


def _llm_overlay(net: Net, no_llm: bool):
    from llm.aid import cluster, propose_names, render_c
    from llm.client import should_run

    if no_llm or not should_run(False):
        return None
    try:
        return {
            "names": propose_names(net, no_llm=False),
            "cluster": cluster(net, no_llm=False),
            "c": render_c(net, no_llm=False),
        }
    except Exception as e:
        return {"error": str(e)}


def extract_elf(
    path,
    *,
    stripped: bool = False,
    run_native: bool = False,
    no_llm: bool = False,
    blif: bool = False,
    outdir=None,
    trials: int = 2000,
    core: int = 0,
    retry: bool = False,
    timeout_s: int = 180,
    max_windows: int = 8,
    keep_stripped=None,
) -> dict:
    """Locate → hypothesize → native adapters → family lift → typed compose → BLIF/C."""
    src = Path(path)
    work = src
    tmp = None
    if stripped:
        tmp = Path(keep_stripped) if keep_stripped else Path(tempfile.mkdtemp(prefix="uwm-strip-")) / (src.stem + ".stripped")
        work = strip_copy(src, tmp)
    harvest = harvest_elf(str(work))
    ctx = LiftContext(
        path=str(work),
        harvest=harvest,
        cache=CacheAdapter(),
        btb=BtbAdapter(),
        tlb=TlbAdapter(),
        native=True,
        run_native=run_native,
        max_windows=max_windows,
    )
    cpu = None
    dual = has_dual_gate(str(work))
    if run_native and has_dual_gate(str(src)):
        cpu = run_flexo_elf(
            str(src),
            trials=trials,
            core=core,
            retry=retry,
            timeout_s=timeout_s,
        )
        cpu.pop("raw", None)
    elif run_native:
        tae = ctx.btb.run_tae_elf(str(src), trials=trials)
        cpu = {"adapter": "btb", "result": tae.to_dict(), "admitted": bool(tae.causal)}
    result = lift_from_elf(str(work), ctx=ctx)
    nets = []
    compose_errors = []
    for net in result.nets:
        try:
            net.compose()
            nets.append(net)
        except MixedCompositionError as e:
            compose_errors.append({"name": net.name, "error": str(e)})
            result.rejected.append(
                {
                    "name": net.name,
                    "resource": None,
                    "trigger": None,
                    "entry": None,
                    "reason": f"mixed:{e}",
                }
            )
    if cpu:
        for net in nets:
            row = _match_native(net.name, cpu)
            net.native["cpu_circuit"] = row
            net.native["cpu_admitted"] = cpu.get("admitted")
    decompiles = {}
    llm = {}
    if outdir is None:
        outdir = ROOT / "output" / "ir"
    outdir = Path(outdir)
    for net in nets:
        tag = net.name
        decomp = None
        if blif and has_lut(net):
            decomp = decompile_net(net, outdir / tag)
        elif blif:
            c_src = net_to_c(net)
            dest = outdir / tag
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f"{net.name}.c").write_text(c_src)
            decomp = {"c": str(dest / f"{net.name}.c"), "blif": None, "cec": None}
        overlay = _llm_overlay(net, no_llm)
        if overlay:
            llm[net.name] = overlay
        if decomp:
            decompiles[net.name] = decomp
    stats = harvest_stats(harvest)
    abstain = []
    if not nets:
        abstain.append("no_recovered_net")
    if stats["n_resolved"] == 0:
        abstain.append("no_resolved_region")
    for net in nets:
        if net.native.get("uncertainty"):
            abstain.append(f"{net.name}:{net.native['uncertainty']}")
        for t in net.transitions.values():
            expr = t.expr if isinstance(t.expr, dict) else {}
            unc = expr.get("uncertainty") if expr else None
            if unc:
                abstain.append(f"{net.name}:{unc}")
    return {
        "elf": str(src),
        "work_elf": str(work),
        "stripped": bool(stripped),
        "dual_gate": dual,
        "harvest": stats,
        "nets": nets,
        "rejected": list(result.rejected),
        "compose_errors": compose_errors,
        "decompiles": decompiles,
        "llm": llm or None,
        "native": cpu,
        "abstain": abstain,
    }


def print_net(net, decomp=None):
    unc = net.native.get("uncertainty")
    extra_u = f"  uncertainty={unc}" if unc else ""
    print(
        f"net {net.name}  class={net.classify()}  compose={_compose_label(net)}  "
        f"places={len(net.places)}  trans={len(net.transitions)}  "
        f"wired={net.native.get('wired_instances')}/{net.native.get('dual_gate_instances')}"
        f"{extra_u}"
    )
    shown = 0
    for t in net.transitions.values():
        extra = ""
        if t.table_id is not None:
            extra = f" n_in={t.n_in} n_out={t.n_out} table={t.table_id}"
            extra += f" {t.inputs}->{t.outputs}"
        elif t.expr is not None:
            extra = f" trigger={t.trigger} resource={t.resource}"
        print(f"  T {t.kind.value:8} {t.name}{extra}")
        shown += 1
        if shown >= 12 and len(net.transitions) > 14:
            rest = len(net.transitions) - shown
            print(f"  ... {rest} more transitions")
            break
    if decomp:
        abc = decomp.get("abc") or {}
        stats = abc.get("stats") or []
        last = stats[-1] if stats else {}
        if decomp.get("blif"):
            print(f"  BLIF {decomp.get('blif')}  ABC nd={last.get('nd')} i/o={last.get('ni')}/{last.get('no')}")
        if decomp.get("c"):
            print(f"  C {decomp.get('c')}")
        cec_info = decomp.get("cec")
        if cec_info:
            print(f"  CEC equivalent={cec_info.get('equivalent')} perm={cec_info.get('pi_perm')}")


def _net_payload(net: Net, decomp, overlay) -> dict:
    payload = net.to_dict()
    payload["compose"] = _compose_label(net)
    if decomp:
        payload["decompile"] = decomp
    if overlay:
        payload["llm"] = overlay
    return payload


def main():
    p = argparse.ArgumentParser(description="Recover typed µWM IR from an ELF")
    p.add_argument("elf", nargs="?", help="ELF to decompile (any family; symbols optional)")
    p.add_argument(
        "--run-native",
        action="store_true",
        help="execute the ELF on this CPU (Flexo accuracy / TAE banners). Off by default.",
    )
    p.add_argument("-t", "--trials", type=int, default=2000)
    p.add_argument("--core", type=int, default=0)
    p.add_argument("--retry", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--blif", action="store_true", help="export BLIF/C and run ABC on LUT regions")
    p.add_argument("--all", action="store_true", help="Flexo + GITM + TAE ELFs under third_party/")
    p.add_argument("--stripped", action="store_true", help="strip a copy before locate/lift")
    p.add_argument("--no-llm", action="store_true", help="skip optional LLM overlay; IR/CEC unchanged")
    p.add_argument("--max-windows", type=int, default=8)
    p.add_argument("--outdir", default=str(ROOT / "output" / "ir"))
    args = p.parse_args()

    if args.self_test:
        self_test()
        return 0

    jobs = []
    if args.all:
        jobs = all_jobs()
    elif args.elf:
        jobs = [("one", Path(args.elf), args.trials, args.retry, 180)]
    else:
        p.error("elf is required unless --self-test / --all")

    outdir = Path(args.outdir)
    summary = []
    rc = 0
    for tag, elf, trials, retry, timeout in jobs:
        if not Path(elf).exists():
            print(f"missing {elf}")
            rc = 1
            continue
        if not args.json:
            print(f"\n=== {tag} {elf} ===")
        report = extract_elf(
            elf,
            stripped=args.stripped,
            run_native=args.run_native,
            no_llm=args.no_llm,
            blif=args.blif,
            outdir=outdir / tag,
            trials=trials if not args.elf else args.trials,
            core=args.core,
            retry=retry if not args.elf else args.retry,
            timeout_s=timeout,
            max_windows=args.max_windows,
        )
        hs = report["harvest"]
        if args.json:
            payload = {
                "elf": report["elf"],
                "stripped": report["stripped"],
                "dual_gate": report["dual_gate"],
                "harvest": hs,
                "rejected": report["rejected"],
                "compose_errors": report["compose_errors"],
                "abstain": report["abstain"],
                "native": report["native"],
                "nets": [
                    _net_payload(
                        net,
                        report["decompiles"].get(net.name),
                        (report["llm"] or {}).get(net.name),
                    )
                    for net in report["nets"]
                ],
            }
            print(json.dumps(payload, indent=2))
        else:
            resolved = hs["resolved"] or {}
            keys = " ".join(f"{k}={v}" for k, v in resolved.items()) or "none"
            print(
                f"harvest primitives={hs['n_primitives']} candidates={hs['n_candidates']} "
                f"resolved={hs['n_resolved']} {keys}"
            )
            if report["abstain"]:
                print("abstain " + ",".join(report["abstain"]))
            if report["rejected"]:
                print(f"rejected {len(report['rejected'])}")
            if not report["nets"]:
                print("no recovered net (abstain)")
            for net in report["nets"]:
                print_net(net, report["decompiles"].get(net.name))
        for net in report["nets"]:
            decomp = report["decompiles"].get(net.name) or {}
            summary.append(
                {
                    "elf": str(elf),
                    "tag": tag,
                    "circuit": net.name,
                    "class": net.classify(),
                    "compose": _compose_label(net),
                    "places": len(net.places),
                    "gates": net.native.get("dual_gate_instances"),
                    "wired": net.native.get("wired_instances"),
                    "native": (net.native.get("cpu_circuit") or {}).get("accuracy_pct"),
                    "cec": decomp.get("cec") if decomp else None,
                    "abc": (decomp.get("abc") or {}).get("stats") if decomp else None,
                    "resolved": hs["n_resolved"],
                    "abstain": report["abstain"],
                }
            )
        if not report["nets"]:
            summary.append(
                {
                    "elf": str(elf),
                    "tag": tag,
                    "circuit": None,
                    "class": None,
                    "compose": None,
                    "resolved": hs["n_resolved"],
                    "abstain": report["abstain"],
                    "rejected": len(report["rejected"]),
                }
            )
        cpu = report["native"]
        if args.run_native and cpu and not args.json:
            print(f"native admitted={cpu.get('admitted')} median={cpu.get('median_accuracy_pct')} return={cpu.get('returncode')}")
            for row in cpu.get("circuits") or []:
                flag = "ok" if row["admitted"] else "FAIL"
                print(f"  [{flag}] {row['name']}: {row['accuracy_pct']:.2f}%")
            if not cpu.get("admitted"):
                rc = 1

    if args.all:
        (outdir / "summary.json").write_text(json.dumps(summary, indent=2))
        print(f"\nWrote {outdir / 'summary.json'} ({len(summary)} circuits)")
    return rc


if __name__ == "__main__":
    sys.exit(main())
