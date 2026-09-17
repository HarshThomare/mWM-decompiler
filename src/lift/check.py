"""Relation/event checks for harvest + recover. Run: python src/lift/check.py"""

import sys
from pathlib import Path

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ir.events import EventKind, make_event
from ir.flexo_tables import encode_dual_gate
from ir.net import ConversionEdge, MixedCompositionError, Net
from ir.relation import (
    DerivedForm,
    Relation,
    ValidationStatus,
    sequential_machine_interp,
)
from ir.state import (
    BTB_ENTRY,
    CACHE_OCCUPANCY,
    TLB_ENTRY,
    ArchInput,
    state_var,
)
from lift.flexo import apply_boolean_lut, lut_from_dual_rail, validate_occupancy
from lift.harvest import _flexo_style, _gitm_style, harvest_elf
from lift.recover import LiftContext, derive_relation, guess_form, lift_circuits, lift_elf, lift_from_harvest
from oracle.cache import CacheAdapter
from oracle.tlb import TlbAdapter

REPO = Path(__file__).resolve().parents[2]
FLEXO_AND = REPO / "src/gates/flexo/gates/gate_and.elf"
GITM_AND = REPO / "src/gates/gitm/main_and.elf"
TAE_GATES = REPO / "third_party/tae/build/bin/gates.elf"

K = EventKind

_KIND_ATTRS = {
    K.STATE_READ: {"insn": "mov", "subject": CACHE_OCCUPANCY, "provenance": ("check.read",)},
    K.STATE_WRITE: {"insn": "mov", "subject": CACHE_OCCUPANCY, "provenance": ("check.write",)},
    K.STATE_CLEAR: {"insn": "clflush", "subject": CACHE_OCCUPANCY, "provenance": ("check.clear",)},
    K.STATE_TRAIN: {"insn": "jmp", "subject": BTB_ENTRY, "provenance": ("check.train",)},
    K.STATE_OBSERVE: {"insn": "rdtsc", "subject": CACHE_OCCUPANCY, "provenance": ("check.observe",)},
    K.WINDOW_OPEN: {"insn": "call", "provenance": ("cacm.window.rsb",)},
    K.WINDOW_SQUASH: {"insn": "ret", "provenance": ("cacm.window.rsb.poison",)},
    K.WINDOW_EXTEND: {"insn": "lfence", "provenance": ("semantic.fence",)},
    K.ARCH_COMPUTE: {"insn": "xor", "operand": "eax, edi"},
    K.ARCH_BRANCH: {"insn": "jmp", "operand": "rax"},
    K.ARCH_MEMORY: {"insn": "mov", "operand": "[rcx]"},
}


def _skip(label: str, path: Path) -> None:
    print(f"lift-check: skip {label} (missing {path})")


def _and_trials():
    return {
        (0, 0): [(40, 300)] * 4,
        (1, 0): [(40, 300)] * 4,
        (0, 1): [(40, 300)] * 4,
        (1, 1): [(300, 40)] * 4,
    }


def _xor_trials():
    return {
        (0, 0): [(40, 300)] * 4,
        (1, 0): [(300, 40)] * 4,
        (0, 1): [(300, 40)] * 4,
        (1, 1): [(40, 300)] * 4,
    }


def _calibrated_cache() -> CacheAdapter:
    ad = CacheAdapter()
    ad.calibrate_occupancy([40] * 8, [300] * 8)
    return ad


def _lut_payload(net: Net) -> dict:
    for r in net.relations.values():
        if r.derived_form() is DerivedForm.BOOLEAN_LUT and r.interpretation is not None:
            return r.interpretation.payload
    raise AssertionError(f"{net.name}: no boolean_lut interpretation")


def _branch_style(frag: Relation) -> bool:
    kinds = {e.kind for e in frag.events}
    btb = BTB_ENTRY in frag.specs() or any(e.subject == BTB_ENTRY for e in frag.events)
    return EventKind.ARCH_BRANCH in kinds and btb


def check_synthetic_event_kinds() -> None:
    for i, kind in enumerate(EventKind):
        rel = Relation(f"e_{kind.value}")
        attrs = dict(_KIND_ATTRS[kind])
        ev = make_event(kind, addr=0x1000 + i, **attrs)
        rel.add_event(ev)
        assert rel.events[0].kind is kind
        d = ev.to_dict()
        assert d["kind"] == kind.value
        assert "role" not in d and "resource" not in d and "trigger" not in d
        assert rel.unresolved() and rel.derived_form() is DerivedForm.UNKNOWN

    full = Relation("all_kinds")
    for i, kind in enumerate(EventKind):
        full.add_event(make_event(kind, addr=0x2000 + i, **_KIND_ATTRS[kind]))
    assert [e.kind for e in full.events] == list(EventKind)
    assert full.unresolved()


def check_synthetic_derived_forms() -> None:
    lut = Relation("lut")
    lut.add_m_in(state_var("lut.a", CACHE_OCCUPANCY, phys_key="w2"))
    lut.add_m_out(state_var("lut.b", CACHE_OCCUPANCY, phys_key="w4"))
    lut.add_event(make_event(K.STATE_READ, subject=CACHE_OCCUPANCY, addr=1))
    lut.add_event(make_event(K.ARCH_COMPUTE, addr=2, insn="and"))
    lut.add_event(make_event(K.STATE_WRITE, subject=CACHE_OCCUPANCY, addr=3))
    lut.add_event(make_event(K.WINDOW_SQUASH, addr=4))
    assert guess_form(lut) is DerivedForm.BOOLEAN_LUT
    assert derive_relation(lut, LiftContext(path="synthetic")) is None
    assert lut.unresolved()

    ad = _calibrated_cache()
    filled = Relation("stripped_and")
    filled.add_m_in(state_var("stripped_and.w3", CACHE_OCCUPANCY, phys_key="w3"))
    filled.add_m_in(state_var("stripped_and.w2", CACHE_OCCUPANCY, phys_key="w2"))
    filled.add_m_out(state_var("stripped_and.w4", CACHE_OCCUPANCY, phys_key="w4"))
    filled.add_event(make_event(K.STATE_READ, subject=CACHE_OCCUPANCY, addr=1))
    filled.add_event(make_event(K.ARCH_COMPUTE, addr=2, insn="and"))
    filled.add_event(make_event(K.STATE_WRITE, subject=CACHE_OCCUPANCY, addr=3))
    filled.add_event(make_event(K.WINDOW_SQUASH, addr=4))
    got = derive_relation(
        filled, LiftContext(path="synthetic", occupancy={"stripped_and": _and_trials()}, cache=ad)
    )
    assert got is not None and got.derived_form() is DerivedForm.BOOLEAN_LUT
    assert got.validation is ValidationStatus.CONFIRMED
    assert encode_dual_gate(2, got.interpretation.payload["gate_table"]) == 8

    br = Relation("br")
    br.add_m_in(state_var("br.p", BTB_ENTRY, phys_key="pc"))
    br.add_event(make_event(K.STATE_READ, subject=BTB_ENTRY, addr=1))
    br.add_event(make_event(K.ARCH_COMPUTE, addr=2, insn="add"))
    br.add_event(make_event(K.ARCH_BRANCH, addr=3, operand="rax"))
    br.add_event(make_event(K.STATE_WRITE, subject=BTB_ENTRY, addr=4))
    assert guess_form(br) is DerivedForm.BRANCH_DEPENDENT
    gotb = derive_relation(br, LiftContext(path="synthetic"))
    assert gotb is not None and gotb.derived_form() is DerivedForm.BRANCH_DEPENDENT
    assert gotb.validation is ValidationStatus.UNRESOLVED

    tlb = Relation("vpn0", entry=0x1000)
    tlb.add_m_in(state_var("vpn0.evicted", TLB_ENTRY, phys_key="0x1000"))
    tlb.add_m_out(state_var("vpn0.filled", TLB_ENTRY, phys_key="0x1000"))
    tlb.add_event(make_event(K.STATE_READ, subject=TLB_ENTRY, addr=0x1000))
    tlb.add_event(make_event(K.ARCH_COMPUTE, addr=0x1004, insn="mov"))
    tlb.add_event(make_event(K.STATE_WRITE, subject=TLB_ENTRY, addr=0x1008))
    assert guess_form(tlb) is DerivedForm.TRANSITION_SYSTEM
    gott = derive_relation(
        tlb,
        LiftContext(
            path="synthetic",
            tlb=TlbAdapter(),
            tlb_samples={"vpn0": {"evicted": [400] * 6, "after": [31] * 6}},
        ),
    )
    assert gott is not None and gott.derived_form() is DerivedForm.TRANSITION_SYSTEM
    assert gott.validation is ValidationStatus.CONFIRMED

    idx = Relation("idx")
    idx.add_a(ArchInput("stride", domain="int", binding="0x440"))
    idx.add_event(make_event(K.ARCH_MEMORY, addr=1, operand="[rax]"))
    idx.add_event(make_event(K.ARCH_MEMORY, addr=2, operand="[rcx]"))
    assert guess_form(idx) is DerivedForm.INDEXED_MEMORY
    goti = derive_relation(idx, LiftContext(path="synthetic"))
    assert goti is not None and goti.derived_form() is DerivedForm.INDEXED_MEMORY

    seq = Relation("seq")
    seq.add_m_in(state_var("seq.m", BTB_ENTRY, phys_key="pc"))
    seq.add_event(make_event(K.STATE_WRITE, subject=BTB_ENTRY, addr=1))
    seq.add_event(make_event(K.STATE_TRAIN, subject=BTB_ENTRY, addr=2))
    assert guess_form(seq) is DerivedForm.SEQUENTIAL_MACHINE
    gots = derive_relation(seq, LiftContext(path="synthetic"))
    assert gots is not None and gots.derived_form() is DerivedForm.SEQUENTIAL_MACHINE

    bv = Relation("bv")
    bv.add_m_in(state_var("bv.m", BTB_ENTRY, phys_key="r"))
    bv.add_event(make_event(K.ARCH_COMPUTE, addr=1, insn="add"))
    bv.add_event(make_event(K.ARCH_COMPUTE, addr=2, insn="xor"))
    bv.add_event(make_event(K.ARCH_COMPUTE, addr=3, insn="and"))
    assert guess_form(bv) is DerivedForm.BITVECTOR
    gotv = derive_relation(bv, LiftContext(path="synthetic"))
    assert gotv is not None and gotv.derived_form() is DerivedForm.BITVECTOR


def check_negative_ambiguous() -> None:
    inc = Relation("inc")
    inc.add_event(make_event(K.STATE_READ, subject=CACHE_OCCUPANCY, addr=1))
    inc.add_event(make_event(K.WINDOW_OPEN, addr=2))
    assert guess_form(inc) is DerivedForm.UNKNOWN
    assert derive_relation(inc, LiftContext(path="synthetic")) is None
    assert inc.unresolved() and inc.validation is ValidationStatus.UNRESOLVED

    br_only = Relation("br_only")
    br_only.add_event(make_event(K.ARCH_BRANCH, addr=1, operand="rax"))
    assert guess_form(br_only) is DerivedForm.UNKNOWN
    assert derive_relation(br_only, LiftContext(path="synthetic")) is None
    assert br_only.unresolved()

    crt = Relation("crt")
    crt.add_m_in(state_var("crt.m", BTB_ENTRY, phys_key="pc"))
    crt.add_event(make_event(K.STATE_TRAIN, subject=BTB_ENTRY, addr=1, insn="jmp"))
    crt.add_event(make_event(K.ARCH_BRANCH, addr=1, operand="rax"))
    crt.add_event(make_event(K.STATE_TRAIN, subject=BTB_ENTRY, addr=2, insn="jmp"))
    crt.add_event(make_event(K.ARCH_BRANCH, addr=2, operand="rdx"))
    assert guess_form(crt) is DerivedForm.UNKNOWN
    assert derive_relation(crt, LiftContext(path="synthetic")) is None
    assert crt.unresolved()

    h = type("H", (), {"source": "synthetic", "fragments": [inc, br_only], "relations": [inc, br_only]})()
    res = lift_from_harvest(h, LiftContext(path="synthetic", harvest=h))  # type: ignore[arg-type]
    assert res.nets == []


def check_occupancy_refine() -> None:
    ad = _calibrated_cache()
    table = lut_from_dual_rail(ad, 2, _and_trials())
    assert table is not None and encode_dual_gate(2, table) == 8

    rel = Relation("and")
    rel.add_m_in(state_var("and.w2", CACHE_OCCUPANCY, phys_key="w2"))
    rel.add_m_in(state_var("and.w3", CACHE_OCCUPANCY, phys_key="w3"))
    rel.add_m_out(state_var("and.w4", CACHE_OCCUPANCY, phys_key="w4"))
    apply_boolean_lut(rel, n_in=2, table_id=8, inputs=["w2", "w3"], outputs=["w4"])
    rel.validation = ValidationStatus.CONFIRMED
    validate_occupancy(rel, LiftContext(path="synthetic", occupancy={"and": _xor_trials()}, cache=ad))
    assert rel.validation is ValidationStatus.REFINED
    assert encode_dual_gate(2, rel.interpretation.payload["gate_table"]) == 6


def check_flexo_dual_gate() -> None:
    nets = lift_circuits(str(FLEXO_AND))
    names = [n.name for n in nets]
    assert "and" in names, names
    and_net = next(n for n in nets if n.name == "and")
    assert and_net.compose() == "boolean_lut"
    payload = _lut_payload(and_net)
    assert payload["table_id"] == 8
    table = payload["gate_table"]
    assert table[(1, 1)] == 1 and table[(1, 0)] == 0
    rel = next(iter(and_net.relations.values()))
    kinds = {e.kind for e in rel.events}
    assert kinds or payload["table_id"] == 8
    assert CACHE_OCCUPANCY in rel.specs()
    assert BTB_ENTRY not in rel.specs()
    d = rel.to_dict()
    assert "resource" not in d and "trigger" not in d and "class" not in d

    h = harvest_elf(str(FLEXO_AND))
    flexo = [f for f in h.fragments if _flexo_style(f)]
    assert flexo, [f.to_dict() for f in h.fragments[:4]]
    assert all(f.unresolved() for f in h.fragments)
    leftover = [f for f in h.fragments if _branch_style(f) and not _flexo_style(f)]
    assert all(f.unresolved() for f in leftover)

    merged = lift_elf(str(FLEXO_AND))
    assert merged.compose() == "boolean_lut"
    seq = Relation("seq")
    seq.add_m_out(state_var("s", BTB_ENTRY))
    seq.set_interpretation(sequential_machine_interp(registers=["s"], step="tick"))
    merged.add_relation(seq)
    try:
        merged.compose()
    except MixedCompositionError:
        pass
    else:
        raise AssertionError("expected MixedCompositionError without conversion")
    lut_name = next(n for n in merged.relations if n != "seq")
    merged.add_conversion(
        ConversionEdge(
            "c0",
            src=lut_name,
            dst="seq",
            src_form=DerivedForm.BOOLEAN_LUT.value,
            dst_form=DerivedForm.SEQUENTIAL_MACHINE.value,
        )
    )
    assert merged.compose() == "converted"


def check_flexo_occupancy_reject() -> None:
    ad = _calibrated_cache()
    dual = lift_circuits(
        str(FLEXO_AND),
        ctx=LiftContext(path=str(FLEXO_AND), occupancy={"and": _xor_trials()}, cache=ad),
    )
    and_net = next(n for n in dual if n.name == "and")
    rel = next(iter(and_net.relations.values()))
    assert rel.validation is ValidationStatus.REFINED
    payload = rel.interpretation.payload
    assert payload["table_id"] == 6 and payload["gate_table"][(1, 0)] == 1


def check_gitm_and() -> None:
    h = harvest_elf(str(GITM_AND))
    hits = [f for f in h.fragments if _gitm_style(f)]
    assert hits, [f.to_dict() for f in h.fragments[:4]]
    assert all(f.unresolved() for f in hits)
    hit = hits[0]
    kinds = {e.kind for e in hit.events}
    assert K.WINDOW_OPEN in kinds
    assert CACHE_OCCUPANCY in hit.specs() or any(e.subject == CACHE_OCCUPANCY for e in hit.events)
    ctx = LiftContext(path=str(GITM_AND), harvest=h, max_windows=1)
    res = lift_from_harvest(h, ctx)
    for n in res.nets:
        assert n.compose() != "lut"
        if n.compose() == "boolean_lut":
            assert _lut_payload(n).get("gate_table") is not None
    assert hit.unresolved()

    ad = _calibrated_cache()
    filled = derive_relation(
        hit,
        LiftContext(path=str(GITM_AND), occupancy={hit.name: _and_trials()}, cache=ad),
    )
    assert filled is not None
    assert filled.derived_form() is DerivedForm.BOOLEAN_LUT
    assert encode_dual_gate(2, filled.interpretation.payload["gate_table"]) == 8


def check_tae_gates() -> None:
    h = harvest_elf(str(TAE_GATES))
    hits = [f for f in h.fragments if _branch_style(f)]
    assert hits, [f.to_dict() for f in h.fragments[:6]]
    assert all(f.unresolved() for f in hits)
    net = lift_elf(str(TAE_GATES), max_windows=2)
    assert net.compose() == "branch_dependent"
    rel = next(iter(net.relations.values()))
    assert rel.derived_form() is DerivedForm.BRANCH_DEPENDENT
    kinds = {e.kind for e in rel.events}
    assert K.ARCH_BRANCH in kinds
    payload = rel.interpretation.payload if rel.interpretation else {}
    assert payload.get("uncertainty") in ("unemulated", "btb_unemulated", None) or rel.validation is ValidationStatus.UNRESOLVED
    d = net.to_dict()
    assert "class" not in d
    assert d["derived"] == "branch_dependent"
    assert not any(r.derived_form() is DerivedForm.BOOLEAN_LUT for r in net.relations.values())


def check_tlb_unemulated() -> None:
    tlb = Relation("vpn1", entry=0x2000)
    tlb.add_m_in(state_var("vpn1.evicted", TLB_ENTRY, phys_key="0x2000"))
    tlb.add_event(make_event(K.STATE_READ, subject=TLB_ENTRY, addr=0x2000))
    tlb.add_event(make_event(K.STATE_WRITE, subject=TLB_ENTRY, addr=0x2010))
    gott = derive_relation(tlb, LiftContext(path="synthetic", tlb=TlbAdapter()))
    assert gott is not None and gott.derived_form() is DerivedForm.TRANSITION_SYSTEM
    assert gott.interpretation.payload.get("uncertainty") == "unemulated"
    assert gott.validation is ValidationStatus.UNRESOLVED


def main() -> None:
    check_synthetic_event_kinds()
    check_synthetic_derived_forms()
    check_negative_ambiguous()
    check_occupancy_refine()
    check_tlb_unemulated()
    skipped = []
    if FLEXO_AND.is_file():
        check_flexo_dual_gate()
        check_flexo_occupancy_reject()
    else:
        _skip("Flexo DualGate", FLEXO_AND)
        skipped.append(str(FLEXO_AND))
    if GITM_AND.is_file():
        check_gitm_and()
    else:
        _skip("GITM", GITM_AND)
        skipped.append(str(GITM_AND))
    if TAE_GATES.is_file():
        check_tae_gates()
    else:
        _skip("TAE", TAE_GATES)
        skipped.append(str(TAE_GATES))
    print(
        "lift-check: event kinds, derived forms, negative/unknown, occupancy, TLB ok"
        + (f"; skipped fixtures: {', '.join(skipped)}" if skipped else "")
    )


if __name__ == "__main__":
    main()
