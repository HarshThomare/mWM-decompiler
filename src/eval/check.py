"""Cross-family extract/eval checks. Run: python src/eval/check.py"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from extract import decompile_net, extract_elf, harvest_stats, strip_copy
from ir.abc_run import find_abc
from ir.net import ConversionEdge, MixedCompositionError
from ir.events import EventKind
from ir.relation import DerivedForm, Relation, sequential_machine_interp
from ir.state import BTB_ENTRY, state_var
from lift.flexo import has_dual_gate
from lift.harvest import _flexo_style, _gitm_style, harvest_elf
from lift.recover import lift_circuits

REPO = Path(__file__).resolve().parents[2]
FLEXO_AND = REPO / "src/gates/flexo/gates/gate_and.elf"
GITM_AND = REPO / "src/gates/gitm/main_and.elf"
TAE_GATES = REPO / "third_party/tae/build/bin/gates.elf"


def _skip(label: str, path: Path) -> dict:
    print(f"eval-check: skip {label} (missing {path})")
    return {"detect": 0, "skip": True, "path": str(path)}


def _derived(h):
    return [f for f in h.fragments if not f.unresolved()]


def _entries(h):
    return sorted((f.entry, len(f.events)) for f in h.fragments)


def _branch_style(frag: Relation) -> bool:
    kinds = {e.kind for e in frag.events}
    btb = BTB_ENTRY in frag.specs() or any(e.subject == BTB_ENTRY for e in frag.events)
    return EventKind.ARCH_BRANCH in kinds and btb


def _lut_payload(net):
    for r in net.relations.values():
        if r.derived_form() is DerivedForm.BOOLEAN_LUT and r.interpretation is not None:
            return r.interpretation.payload
    raise AssertionError(f"{net.name}: no boolean_lut")


def _gcc_negative(tmpdir: Path) -> Path:
    src = tmpdir / "neg.c"
    elf = tmpdir / "neg.elf"
    src.write_text("int main(void) { return 0; }\n")
    subprocess.check_call(["gcc", "-O2", "-o", str(elf), str(src)])
    return strip_copy(elf, tmpdir / "neg.stripped")


def _assert_relation_schema(payload: dict) -> None:
    for banned in ("class", "resource", "trigger", "lut", "isa", "places", "transitions", "regions"):
        assert banned not in payload, banned
    for rel in payload.get("relations") or []:
        for banned in ("resource", "trigger", "class"):
            assert banned not in rel, banned
        assert "events" in rel and "derived" in rel


def check_flexo_and_symbols() -> dict:
    assert FLEXO_AND.is_file()
    a = harvest_elf(str(FLEXO_AND))
    b = harvest_elf(str(FLEXO_AND))
    sa, sb = harvest_stats(a), harvest_stats(b)
    assert sa["n_events"] == sb["n_events"] and sa["n_fragments"] == sb["n_fragments"]
    assert _entries(a) == _entries(b) and sa["n_fragments"] >= 1
    flexo = [f for f in a.fragments if _flexo_style(f)]
    assert flexo
    assert _derived(a) == []
    report = extract_elf(FLEXO_AND, no_llm=True)
    names = [n.name for n in report["nets"]]
    assert "and" in names, names
    assert report["dual_gate"] is True
    and_net = next(n for n in report["nets"] if n.name == "and")
    assert and_net.compose() == "boolean_lut"
    payload = _lut_payload(and_net)
    assert payload["table_id"] == 8 and payload["gate_table"][(1, 1)] == 1
    _assert_relation_schema(and_net.to_dict())
    cec_ok = None
    if find_abc():
        with tempfile.TemporaryDirectory() as td:
            decomp = decompile_net(and_net, Path(td) / "and")
            cec_ok = (decomp.get("cec") or {}).get("equivalent")
            assert cec_ok, decomp.get("cec")
            assert decomp.get("c")
    else:
        print("eval-check: skip Flexo CEC (abc binary missing)")
    return {"detect": len(flexo), "cec": cec_ok, "stable": True}


def check_flexo_and_stripped() -> dict:
    with tempfile.TemporaryDirectory() as td:
        stripped = strip_copy(FLEXO_AND, Path(td) / "gate_and.stripped")
        blob = stripped.read_bytes()
        assert b"__DualGate__" not in blob
        assert b"__weird__" not in blob
        assert not has_dual_gate(str(stripped))
        h = harvest_elf(str(stripped))
        flexo = [f for f in h.fragments if _flexo_style(f)]
        assert flexo, [f.to_dict() for f in h.fragments[:4]]
        assert all(f.unresolved() for f in h.fragments)
        report = extract_elf(FLEXO_AND, stripped=True, no_llm=True, keep_stripped=stripped)
        assert report["dual_gate"] is False
        for net in report["nets"]:
            payload = net.to_dict()
            json.dumps(payload)
            _assert_relation_schema(payload)
            assert payload["derived"] != "lut"
        if not report["nets"]:
            assert "no_recovered_net" in report["abstain"] or "no_derived_relation" in report["abstain"]
        return {"detect": len(flexo), "nets": len(report["nets"]), "unlabeled": True}


def check_gitm_and() -> dict:
    h = harvest_elf(str(GITM_AND))
    hits = [f for f in h.fragments if _gitm_style(f)]
    assert hits, [f.to_dict() for f in h.fragments[:4]]
    assert all(f.unresolved() for f in hits)
    report = extract_elf(GITM_AND, no_llm=True, max_windows=1)
    for net in report["nets"]:
        assert net.compose() != "lut"
        _assert_relation_schema(net.to_dict())
    unc = None
    table_id = None
    if report["nets"]:
        net = report["nets"][0]
        unc = net.native.get("uncertainty")
        if net.compose() == "boolean_lut":
            table_id = _lut_payload(net).get("table_id")
    else:
        assert "no_recovered_net" in report["abstain"] or "no_derived_relation" in report["abstain"]
    return {"detect": len(hits), "table_id": table_id, "uncertainty": unc}


def check_tae_gates() -> dict:
    h = harvest_elf(str(TAE_GATES))
    hits = [f for f in h.fragments if _branch_style(f)]
    assert hits, [f.to_dict() for f in h.fragments[:6]]
    report = extract_elf(TAE_GATES, no_llm=True, max_windows=2)
    assert report["nets"], report["rejected"]
    net = report["nets"][0]
    assert net.compose() == "branch_dependent"
    rel = next(iter(net.relations.values()))
    assert rel.derived_form() is DerivedForm.BRANCH_DEPENDENT
    payload = rel.interpretation.payload if rel.interpretation else {}
    unc = payload.get("uncertainty")
    assert unc in ("unemulated", "btb_unemulated") or rel.validation.value == "unresolved"
    assert any("unemulated" in a for a in report["abstain"]) or rel.validation.value == "unresolved"
    _assert_relation_schema(net.to_dict())
    return {"detect": len(hits), "uncertainty": unc}


def check_mixed_conversion() -> None:
    nets = lift_circuits(str(FLEXO_AND))
    and_net = next(n for n in nets if n.name == "and")
    seq = Relation("seq")
    seq.add_m_out(state_var("s", BTB_ENTRY))
    seq.set_interpretation(sequential_machine_interp(registers=["s"], step="tick"))
    and_net.add_relation(seq)
    try:
        and_net.compose()
    except MixedCompositionError:
        pass
    else:
        raise AssertionError("expected MixedCompositionError without conversion")
    lut_name = next(n for n in and_net.relations if n != "seq")
    and_net.add_conversion(
        ConversionEdge(
            "c0",
            src=lut_name,
            dst="seq",
            src_form=DerivedForm.BOOLEAN_LUT.value,
            dst_form=DerivedForm.SEQUENTIAL_MACHINE.value,
        )
    )
    assert and_net.compose() == "converted"


def check_no_llm_emits() -> None:
    labeled = extract_elf(FLEXO_AND, no_llm=True)
    assert labeled["llm"] is None
    and_net = next(n for n in labeled["nets"] if n.name == "and")
    payload = and_net.to_dict()
    _assert_relation_schema(payload)
    with tempfile.TemporaryDirectory() as td:
        stripped = extract_elf(FLEXO_AND, stripped=True, no_llm=True, keep_stripped=Path(td) / "s.elf")
        raw = json.dumps([n.to_dict() for n in stripped["nets"]])
        assert "relations" in raw or stripped["nets"] == []
        assert "places" not in raw and "transitions" not in raw
        assert stripped["llm"] is None


def check_negative() -> dict:
    with tempfile.TemporaryDirectory() as td:
        neg = _gcc_negative(Path(td))
        h = harvest_elf(str(neg))
        derived = _derived(h)
        report = extract_elf(neg, no_llm=True)
        assert derived == [], [f.to_dict() for f in derived]
        assert report["nets"] == []
        assert "no_recovered_net" in report["abstain"] or "no_derived_relation" in report["abstain"]
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
    assert payload.get("llm") is None
    for net in payload["nets"]:
        _assert_relation_schema(net)
        if net["name"] == "and":
            assert net.get("derived") == "boolean_lut"


def main() -> None:
    skipped = []
    if FLEXO_AND.is_file():
        flexo = check_flexo_and_symbols()
        stripped = check_flexo_and_stripped()
        check_mixed_conversion()
        check_no_llm_emits()
        check_cli_json()
    else:
        flexo = _skip("Flexo DualGate", FLEXO_AND)
        stripped = {"detect": 0, "unlabeled": None, "skip": True}
        skipped.append(str(FLEXO_AND))
    gitm = check_gitm_and() if GITM_AND.is_file() else _skip("GITM", GITM_AND)
    if gitm.get("skip"):
        skipped.append(str(GITM_AND))
    tae = check_tae_gates() if TAE_GATES.is_file() else _skip("TAE", TAE_GATES)
    if tae.get("skip"):
        skipped.append(str(TAE_GATES))
    neg = check_negative()
    tp = sum(bool(x.get("detect")) for x in (flexo, gitm, tae) if not x.get("skip"))
    n_fix = sum(1 for x in (flexo, gitm, tae) if not x.get("skip"))
    print(
        "eval-check:"
        f" flexo_and detect={flexo.get('detect')} cec={flexo.get('cec')} stable={flexo.get('stable')}"
        f" stripped_detect={stripped.get('detect')} unlabeled={stripped.get('unlabeled')}"
        f" gitm_and detect={gitm.get('detect')} table={gitm.get('table_id')} unc={gitm.get('uncertainty')}"
        f" tae_gates detect={tae.get('detect')} {tae.get('uncertainty')}"
        f" negative resolved={neg['resolved']} abstain={neg['abstain']}"
        f" P/R binaries tp={tp}/{n_fix} fp={neg['fp']}"
        + (f" skipped={','.join(skipped)}" if skipped else "")
    )


if __name__ == "__main__":
    main()
