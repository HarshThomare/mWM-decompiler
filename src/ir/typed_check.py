"""Self-checks for the relation-first IR. Run: python src/ir/typed_check.py

Synthetic traces for each EventKind and DerivedForm. Harvest/lift/extract/llm
are covered by their own checks.
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from ir.events import CANONICAL_EVENT_KINDS, EventKind, Evidence, make_event
    from ir.net import ConversionEdge, MixedCompositionError, Net
    from ir.relation import (
        DerivedForm,
        Fragment,
        Interpretation,
        Relation,
        ValidationStatus,
        bitvector_interp,
        boolean_lut_interp,
        branch_dependent_interp,
        eval_boolean_lut,
        indexed_memory_interp,
        sequential_machine_interp,
        transition_system_interp,
    )
    from ir.state import (
        BTB_ENTRY,
        CACHE_OCCUPANCY,
        TLB_ENTRY,
        ArchInput,
        Persistence,
        TimingConstraint,
        register_state_spec,
        state_var,
        state_var_spec,
        StateVarSpec,
    )
else:
    from .events import CANONICAL_EVENT_KINDS, EventKind, Evidence, make_event
    from .net import ConversionEdge, MixedCompositionError, Net
    from .relation import (
        DerivedForm,
        Fragment,
        Interpretation,
        Relation,
        ValidationStatus,
        bitvector_interp,
        boolean_lut_interp,
        branch_dependent_interp,
        eval_boolean_lut,
        indexed_memory_interp,
        sequential_machine_interp,
        transition_system_interp,
    )
    from .state import (
        BTB_ENTRY,
        CACHE_OCCUPANCY,
        TLB_ENTRY,
        ArchInput,
        Persistence,
        TimingConstraint,
        register_state_spec,
        state_var,
        state_var_spec,
        StateVarSpec,
    )


_KIND_ATTRS = {
    EventKind.STATE_READ: {"insn": "mov", "subject": CACHE_OCCUPANCY, "operand": "[rax]"},
    EventKind.STATE_WRITE: {"insn": "mov", "subject": CACHE_OCCUPANCY, "operand": "[rbx]"},
    EventKind.STATE_CLEAR: {"insn": "clflush", "subject": CACHE_OCCUPANCY},
    EventKind.STATE_TRAIN: {"insn": "jmp", "subject": BTB_ENTRY, "operand": "rax"},
    EventKind.STATE_OBSERVE: {"insn": "rdtsc", "subject": CACHE_OCCUPANCY},
    EventKind.WINDOW_OPEN: {"insn": "call"},
    EventKind.WINDOW_SQUASH: {"insn": "ret"},
    EventKind.WINDOW_EXTEND: {"insn": "lfence"},
    EventKind.ARCH_COMPUTE: {"insn": "xor", "operand": "eax, edi"},
    EventKind.ARCH_BRANCH: {"insn": "jmp", "operand": "rax"},
    EventKind.ARCH_MEMORY: {"insn": "mov", "operand": "[rcx]"},
}


def _trace(rel: Relation, kinds) -> None:
    for i, kind in enumerate(kinds):
        attrs = dict(_KIND_ATTRS.get(kind, {}))
        rel.add_event(make_event(kind, insn=attrs.pop("insn", "placeholder"), addr=0x100 + i, provenance=("check",), **attrs))


def check_canonical_event_kinds() -> None:
    expected = {
        "STATE_READ",
        "STATE_WRITE",
        "STATE_CLEAR",
        "STATE_TRAIN",
        "STATE_OBSERVE",
        "WINDOW_OPEN",
        "WINDOW_SQUASH",
        "WINDOW_EXTEND",
        "ARCH_COMPUTE",
        "ARCH_BRANCH",
        "ARCH_MEMORY",
    }
    assert {k.value for k in EventKind} == expected
    assert CANONICAL_EVENT_KINDS == frozenset(EventKind)
    rel = Relation("all_events")
    _trace(rel, EventKind)
    assert [e.kind for e in rel.events] == list(EventKind)
    ev = rel.events[0]
    assert ev.kind is EventKind.STATE_READ and ev.insn == "mov" and ev.addr == 0x100
    assert ev.subject == CACHE_OCCUPANCY and ev.provenance == ["check"]
    d = ev.to_dict()
    assert d["kind"] == "STATE_READ" and "role" not in d and "resource" not in d
    for e in rel.events:
        assert e.insn and e.addr is not None
        assert "role" not in e.to_dict() and "trigger" not in e.to_dict()
    try:
        make_event("NOT_A_KIND")
    except ValueError:
        pass
    else:
        raise AssertionError("expected invalid event kind to fail")


def check_evidence_has_no_trigger() -> None:
    sig = inspect.signature(Evidence)
    assert "trigger" not in sig.parameters
    ev = Evidence(observations=[{"hit": 1}], confidence=0.7)
    d = ev.to_dict()
    assert d == {"observations": [{"hit": 1}], "confidence": 0.7}
    assert "trigger" not in d


def check_state_var_specs() -> None:
    cache = state_var_spec(CACHE_OCCUPANCY)
    assert cache.encoding == "dual_rail" and cache.destructive_read and not cache.persistent
    assert cache.adapter == "occupancy" and cache.phys_key_role == "line"
    btb = state_var_spec(BTB_ENTRY)
    assert btb.encoding == "btb_target" and btb.persistent and btb.width == 16
    assert btb.adapter == "train_observe"
    tlb = state_var_spec(TLB_ENTRY)
    assert tlb.encoding == "hit_miss" and tlb.destructive_read and tlb.adapter == "evict_walk"
    register_state_spec(
        StateVarSpec(
            name="pht_entry",
            encoding="taken",
            destructive_read=False,
            persistent=True,
            width=1,
            phys_key_role="index",
            adapter="train_observe",
        )
    )
    p = state_var("p0", "pht_entry", phys_key="17")
    assert p.persistence == Persistence.PERSISTENT and p.encoding == "taken"
    line = state_var("c0", CACHE_OCCUPANCY, phys_key="0x4000")
    assert line.persistence == Persistence.VOLATILE and line.destructive_read is True
    assert "dcache" not in line.to_dict().values()


def check_unresolved_relation() -> None:
    r = Relation("frag")
    r.add_m_in(state_var("m", CACHE_OCCUPANCY, phys_key="0"))
    r.add_a(ArchInput("a0", domain="bit", binding="rdi"))
    r.add_t(TimingConstraint("w", kind="open", window_len=32))
    r.add_event(make_event(EventKind.WINDOW_OPEN, insn="call", addr=0x10, subject="m"))
    assert r.unresolved() and r.derived_form() is DerivedForm.UNKNOWN
    assert r.validation is ValidationStatus.UNRESOLVED
    d = r.to_dict()
    assert d["derived"] == "unknown"
    assert "interpretation" not in d
    assert "resource" not in d and "trigger" not in d and "class" not in d
    net = Net("n")
    net.add_relation(r)
    assert net.compose() == "unknown"
    assert "class" not in net.to_dict()
    assert Fragment is Relation


def check_boolean_lut() -> None:
    r = Relation("and")
    r.add_m_in(state_var("x", CACHE_OCCUPANCY))
    r.add_m_in(state_var("y", CACHE_OCCUPANCY))
    r.add_m_out(state_var("z", CACHE_OCCUPANCY))
    r.add_a(ArchInput("i0"))
    r.add_a(ArchInput("i1"))
    r.add_t(TimingConstraint("rho", kind="squash"))
    for kind in (
        EventKind.WINDOW_OPEN,
        EventKind.STATE_WRITE,
        EventKind.ARCH_COMPUTE,
        EventKind.STATE_READ,
        EventKind.WINDOW_SQUASH,
    ):
        r.add_event(make_event(kind, subject="z" if "STATE" in kind.value else None))
    r.set_interpretation(boolean_lut_interp(2, table_id=8, inputs=["x", "y"], outputs=["z"]))
    r.validation = ValidationStatus.CONFIRMED
    r.confidence = 0.9
    assert r.derived_form() is DerivedForm.BOOLEAN_LUT
    assert eval_boolean_lut(r.interpretation, (1, 1)) == 1
    assert eval_boolean_lut(r.interpretation, (1, 0)) == 0
    net = Net("and")
    net.add_relation(r)
    assert net.compose() == "boolean_lut"
    assert net.compose_relation("and") == "boolean_lut"
    d = net.to_dict()
    assert d["derived"] == "boolean_lut"
    assert "lut" not in d and "class" not in d
    assert d["relations"][0]["interpretation"]["form"] == "boolean_lut"


def check_each_derived_form() -> None:
    traces = {
        DerivedForm.BITVECTOR: [EventKind.ARCH_COMPUTE, EventKind.ARCH_COMPUTE, EventKind.ARCH_COMPUTE],
        DerivedForm.TRANSITION_SYSTEM: [EventKind.STATE_READ, EventKind.ARCH_COMPUTE, EventKind.STATE_WRITE],
        DerivedForm.INDEXED_MEMORY: [EventKind.ARCH_MEMORY, EventKind.ARCH_MEMORY],
        DerivedForm.BRANCH_DEPENDENT: [
            EventKind.STATE_READ,
            EventKind.ARCH_COMPUTE,
            EventKind.ARCH_BRANCH,
            EventKind.STATE_WRITE,
        ],
        DerivedForm.SEQUENTIAL_MACHINE: [EventKind.STATE_WRITE, EventKind.STATE_TRAIN],
    }
    builders = [
        (DerivedForm.BITVECTOR, bitvector_interp("x^y", width=8)),
        (DerivedForm.TRANSITION_SYSTEM, transition_system_interp(["s0", "s1"], step="delta")),
        (DerivedForm.INDEXED_MEMORY, indexed_memory_interp(index="vpn", cells={"0": 1})),
        (DerivedForm.BRANCH_DEPENDENT, branch_dependent_interp("zf", then="t", otherwise="e")),
        (DerivedForm.SEQUENTIAL_MACHINE, sequential_machine_interp(registers=["m"], step="tick")),
    ]
    for form, interp in builders:
        r = Relation(form.value)
        spec = TLB_ENTRY if form == DerivedForm.INDEXED_MEMORY else (
            CACHE_OCCUPANCY if form == DerivedForm.BITVECTOR else BTB_ENTRY
        )
        r.add_m_in(state_var("m", spec))
        _trace(r, traces[form])
        r.set_interpretation(interp)
        assert r.derived_form() is form
        assert [e.kind for e in r.events] == traces[form]
        net = Net(form.value)
        net.add_relation(r)
        assert net.compose() == form.value
        d = r.to_dict()
        assert d["derived"] == form.value
        assert "resource" not in d and "class" not in d


def check_at_most_one_interpretation() -> None:
    r = Relation("one")
    r.set_interpretation(bitvector_interp("x", width=1))
    r.set_interpretation(boolean_lut_interp(1, table_id=1))
    assert r.derived_form() is DerivedForm.BOOLEAN_LUT
    r.set_interpretation(None)
    assert r.unresolved()
    try:
        r.set_interpretation(Interpretation(form=DerivedForm.BOOLEAN_LUT, payload={}))
    except ValueError as e:
        assert "boolean_lut" in str(e)
    else:
        raise AssertionError("expected payload check to fail")


def check_mixed_forms_rejected() -> None:
    net = Net("mix")
    a = Relation("lut")
    a.add_m_out(state_var("z", CACHE_OCCUPANCY))
    a.set_interpretation(boolean_lut_interp(2, table_id=8))
    b = Relation("seq")
    b.add_m_out(state_var("s", BTB_ENTRY))
    b.set_interpretation(sequential_machine_interp(registers=["s"], step="tick"))
    net.add_relation(a)
    net.add_relation(b)
    try:
        net.compose()
    except MixedCompositionError as e:
        assert "without conversion edges" in str(e)
    else:
        raise AssertionError("expected MixedCompositionError")
    assert net.derived() == "mixed"


def check_conversion_allows_mix() -> None:
    net = Net("mix")
    a = Relation("lut")
    a.add_m_out(state_var("z", CACHE_OCCUPANCY))
    a.set_interpretation(boolean_lut_interp(2, table_id=8))
    b = Relation("seq")
    b.add_m_out(state_var("s", BTB_ENTRY))
    b.set_interpretation(sequential_machine_interp(registers=["s"], step="tick"))
    net.add_relation(a)
    net.add_relation(b)
    net.add_conversion(
        ConversionEdge(
            "c0",
            src="lut",
            dst="seq",
            src_form=DerivedForm.BOOLEAN_LUT.value,
            dst_form=DerivedForm.SEQUENTIAL_MACHINE.value,
            encoding="copy",
        )
    )
    assert net.compose() == "converted"
    assert net.to_dict()["derived"] == "converted"


def check_mixed_specs_rejected() -> None:
    net = Net("specs")
    a = Relation("cache")
    a.add_m_out(state_var("z", CACHE_OCCUPANCY))
    a.set_interpretation(boolean_lut_interp(1, table_id=1))
    b = Relation("tlb")
    b.add_m_out(state_var("t", TLB_ENTRY))
    b.set_interpretation(boolean_lut_interp(1, table_id=1))
    net.add_relation(a)
    net.add_relation(b)
    try:
        net.compose()
    except MixedCompositionError as e:
        assert "without conversion edges" in str(e)
    else:
        raise AssertionError("expected MixedCompositionError")


def check_same_form_same_spec_composes() -> None:
    net = Net("two")
    for name in ("g0", "g1"):
        r = Relation(name)
        r.add_m_out(state_var(f"{name}.z", CACHE_OCCUPANCY))
        r.set_interpretation(boolean_lut_interp(2, table_id=8))
        net.add_relation(r)
    assert net.compose() == "boolean_lut"


def check_rejected_cannot_fuse() -> None:
    net = Net("bad")
    ok = Relation("ok")
    ok.add_m_out(state_var("z", CACHE_OCCUPANCY))
    ok.set_interpretation(boolean_lut_interp(1, table_id=1))
    bad = Relation("no", validation=ValidationStatus.REJECTED)
    net.add_relation(ok)
    net.add_relation(bad)
    try:
        net.compose()
    except MixedCompositionError as e:
        assert "rejected" in str(e)
    else:
        raise AssertionError("expected MixedCompositionError")
    solo = Net("solo")
    solo.add_relation(Relation("no", validation=ValidationStatus.REJECTED))
    assert solo.compose() == "rejected"


def check_unknown_plus_resolved_rejected() -> None:
    net = Net("partial")
    a = Relation("lut")
    a.add_m_out(state_var("z", CACHE_OCCUPANCY))
    a.set_interpretation(boolean_lut_interp(1, table_id=1))
    b = Relation("mystery")
    b.add_m_out(state_var("s", BTB_ENTRY))
    net.add_relation(a)
    net.add_relation(b)
    try:
        net.compose()
    except MixedCompositionError:
        pass
    else:
        raise AssertionError("expected MixedCompositionError")


def check_ambiguous_stays_unknown() -> None:
    r = Relation("amb")
    r.add_m_in(state_var("m", CACHE_OCCUPANCY, phys_key="0"))
    _trace(r, (EventKind.STATE_READ, EventKind.WINDOW_OPEN, EventKind.ARCH_BRANCH))
    assert r.unresolved() and r.derived_form() is DerivedForm.UNKNOWN
    assert r.validation is ValidationStatus.UNRESOLVED
    assert "interpretation" not in r.to_dict()
    net = Net("amb")
    net.add_relation(r)
    assert net.compose() == "unknown"


def check_schema_keys() -> None:
    r = Relation("k")
    r.set_interpretation(boolean_lut_interp(1, table_id=1))
    net = Net("k", source="check")
    net.add_relation(r)
    d = net.to_dict()
    for banned in ("class", "resource", "trigger", "lut", "isa", "places", "transitions", "regions"):
        assert banned not in d, banned
    rd = d["relations"][0]
    for banned in ("resource", "trigger", "class"):
        assert banned not in rd, banned


def main() -> None:
    check_canonical_event_kinds()
    check_evidence_has_no_trigger()
    check_state_var_specs()
    check_unresolved_relation()
    check_boolean_lut()
    check_each_derived_form()
    check_at_most_one_interpretation()
    check_mixed_forms_rejected()
    check_conversion_allows_mix()
    check_mixed_specs_rejected()
    check_same_form_same_spec_composes()
    check_rejected_cannot_fuse()
    check_unknown_plus_resolved_rejected()
    check_ambiguous_stays_unknown()
    check_schema_keys()
    print("typed-check: event ontology, relations, derived forms, mixed rejection ok")


if __name__ == "__main__":
    main()
