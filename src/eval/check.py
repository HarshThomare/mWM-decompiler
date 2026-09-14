"""Cross-family extract/eval checks. Run: python src/eval/check.py"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from extract import decompile_net, extract_elf, harvest_stats, strip_copy
from ir.net import ConversionEdge, MixedCompositionError, TransKind, isa_region, wr_place
from lift.flexo import has_dual_gate
from lift.harvest import harvest_elf
from lift.recover import lift_circuits

REPO = Path(__file__).resolve().parents[2]
FLEXO_AND = REPO / "src/gates/flexo/gates/gate_and.elf"
GITM_AND = REPO / "src/gates/gitm/main_and.elf"
TAE_GATES = REPO / "third_party/tae/build/bin/gates.elf"


def _resolved(h):
    return [c for c in h.candidates if not c.unresolved]


def _gcc_negative(tmpdir: Path) -> Path:
    src = tmpdir / "neg.c"
    elf = tmpdir / "neg.elf"
    src.write_text("int main(void) { return 0; }\n")
    subprocess.check_call(["gcc", "-O2", "-o", str(elf), str(src)])
    return strip_copy(elf, tmpdir / "neg.stripped")


def check_flexo_and_symbols() -> dict:
    assert FLEXO_AND.is_file()
    a = harvest_elf(str(FLEXO_AND))
    b = harvest_elf(str(FLEXO_AND))
    ra, rb = harvest_stats(a)["entries"], harvest_stats(b)["entries"]
    assert ra == rb and len(ra) >= 8, (ra, rb)
    dcache = [c for c in _resolved(a) if c.resource == "dcache" and c.trigger == "rsb"]
    assert len(dcache) >= 8
    report = extract_elf(FLEXO_AND, no_llm=True)
    names = [n.name for n in report["nets"]]
    assert "and" in names, names
    assert report["dual_gate"] is True
    and_net = next(n for n in report["nets"] if n.name == "and")
    assert and_net.compose() == "lut"
    assert and_net.classify() == "flexo"
    g = next(t for t in and_net.transitions.values() if t.kind == TransKind.GATE)
    assert g.table_id == 8 and g.gate_table[(1, 1)] == 1
    cec_ok = None
    with tempfile.TemporaryDirectory() as td:
        decomp = decompile_net(and_net, Path(td) / "and")
        cec_ok = (decomp.get("cec") or {}).get("equivalent")
        assert cec_ok, decomp.get("cec")
        assert decomp.get("c")
    return {"detect": len(dcache), "cec": cec_ok, "stable": ra == rb}


def check_flexo_and_stripped() -> dict:
    with tempfile.TemporaryDirectory() as td:
        stripped = strip_copy(FLEXO_AND, Path(td) / "gate_and.stripped")
        assert not has_dual_gate(str(stripped))
        h = harvest_elf(str(stripped))
        dcache = [c for c in _resolved(h) if c.resource == "dcache" and c.trigger == "rsb"]
        assert len(dcache) >= 8, [c.to_dict() for c in h.candidates[:4]]
        report = extract_elf(FLEXO_AND, stripped=True, no_llm=True, keep_stripped=stripped)
        assert report["dual_gate"] is False
        assert report["nets"], report["abstain"]
        for net in report["nets"]:
            assert net.compose() == "lut"
            payload = net.to_dict()
            json.dumps(payload)
            assert payload["places"] and payload["transitions"]
        assert any(n.native.get("uncertainty") == "no_native_samples" for n in report["nets"])
        return {"detect": len(dcache), "nets": len(report["nets"]), "unlabeled": True}


def check_gitm_and() -> dict:
    h = harvest_elf(str(GITM_AND))
    hit = [c for c in _resolved(h) if c.resource == "dcache" and c.trigger == "exception"]
    assert hit, [c.to_dict() for c in h.candidates[:4]]
    report = extract_elf(GITM_AND, no_llm=True, max_windows=1)
    assert report["nets"], report["rejected"]
    net = report["nets"][0]
    assert net.compose() == "lut"
    g = next(t for t in net.transitions.values() if t.kind == TransKind.GATE)
    assert g.trigger == "exception"
    return {"detect": len(hit), "table_id": g.table_id, "uncertainty": net.native.get("uncertainty")}


def check_tae_gates() -> dict:
    h = harvest_elf(str(TAE_GATES))
    btb = [c for c in _resolved(h) if c.resource == "btb" and c.trigger == "indirect_jmp"]
    assert btb, [c.to_dict() for c in h.candidates[:6]]
    report = extract_elf(TAE_GATES, no_llm=True, max_windows=2)
    assert report["nets"], report["rejected"]
    net = report["nets"][0]
    assert net.compose() == "isa"
    assert net.classify() == "tae"
    expr = [t for t in net.transitions.values() if t.kind == TransKind.EXPR]
    assert expr and (expr[0].expr or {}).get("uncertainty") in ("unemulated", "btb_unemulated")
    assert any("unemulated" in a or "btb_unemulated" in a for a in report["abstain"])
    return {"detect": len(btb), "uncertainty": (expr[0].expr or {}).get("uncertainty")}


def check_mixed_conversion() -> None:
    net = lift_circuits(str(FLEXO_AND))
    and_net = next(n for n in net if n.name == "and")
    and_net.add_place(wr_place("s", "btb"))
    from ir.net import Transition

    and_net.add_transition(Transition(name="body", kind=TransKind.EXPR, expr="x", inputs=["s"], outputs=["s"]))
    and_net.add_region(isa_region("w", places=["s"], transitions=["body"]))
    try:
        and_net.compose()
    except MixedCompositionError:
        pass
    else:
        raise AssertionError("expected MixedCompositionError without conversion")
    and_net.add_conversion(ConversionEdge("c0", src="w4", dst="s", src_resource="dcache", dst_resource="btb"))
    assert and_net.compose() == "converted"


def check_no_llm_emits() -> None:
    labeled = extract_elf(FLEXO_AND, no_llm=True)
    also = extract_elf(FLEXO_AND, no_llm=False)
    a = [n.to_dict() for n in labeled["nets"]]
    b = [n.to_dict() for n in also["nets"]]
    assert a == b
    assert labeled["llm"] is None
    and_net = next(n for n in labeled["nets"] if n.name == "and")
    assert and_net.to_dict()["places"]
    with tempfile.TemporaryDirectory() as td:
        stripped = extract_elf(FLEXO_AND, stripped=True, no_llm=True, keep_stripped=Path(td) / "s.elf")
        assert stripped["nets"]
        raw = json.dumps([n.to_dict() for n in stripped["nets"]])
        assert "places" in raw and "transitions" in raw
        assert stripped["llm"] is None


def check_negative() -> dict:
    with tempfile.TemporaryDirectory() as td:
        neg = _gcc_negative(Path(td))
        h = harvest_elf(str(neg))
        resolved = _resolved(h)
        report = extract_elf(neg, no_llm=True)
        assert resolved == [], [c.to_dict() for c in resolved]
        assert report["nets"] == []
        assert "no_resolved_region" in report["abstain"]
        assert "no_recovered_net" in report["abstain"]
        return {"resolved": 0, "nets": 0, "fp": 0, "abstain": True}


def check_cli_json() -> None:
    proc = subprocess.run(
        [sys.executable, str(REPO / "src/extract.py"), str(FLEXO_AND), "--no-llm", "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload.get("dual_gate") is True
    names = [n["name"] for n in payload.get("nets") or []]
    assert "and" in names
    assert payload.get("llm") is None or all(n.get("llm") is None for n in payload["nets"])


def main() -> None:
    flexo = check_flexo_and_symbols() if FLEXO_AND.is_file() else {"detect": 0, "cec": None, "stable": None, "skip": True}
    stripped = check_flexo_and_stripped() if FLEXO_AND.is_file() else {"detect": 0, "unlabeled": None, "skip": True}
    gitm = check_gitm_and() if GITM_AND.is_file() else {"detect": 0, "table_id": None, "skip": True}
    tae = check_tae_gates() if TAE_GATES.is_file() else {"detect": 0, "uncertainty": None, "skip": True}
    if FLEXO_AND.is_file():
        check_mixed_conversion()
        check_no_llm_emits()
        check_cli_json()
    neg = check_negative()
    tp = sum(bool(x.get("detect")) for x in (flexo, gitm, tae) if not x.get("skip"))
    fp = neg["fp"]
    print(
        "eval-check:"
        f" flexo_and detect={flexo['detect']} cec={flexo['cec']} stable={flexo['stable']}"
        f" stripped_detect={stripped['detect']} unlabeled={stripped['unlabeled']}"
        f" gitm_and detect={gitm['detect']} table={gitm['table_id']} unc={gitm.get('uncertainty')}"
        f" tae_gates detect={tae['detect']} {tae['uncertainty']}"
        f" negative resolved={neg['resolved']} abstain={neg['abstain']}"
        f" P/R binaries tp={tp}/3 fp={fp}"
    )


if __name__ == "__main__":
    main()
