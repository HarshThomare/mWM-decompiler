"""Checks for optional LLM overlay. Run: python src/llm/check.py"""

import copy
import json
import sys
from pathlib import Path

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ir.events import EventKind, make_event  # noqa: E402
from ir.net import ConversionEdge, MixedCompositionError, Net  # noqa: E402
from ir.relation import (  # noqa: E402
    DerivedForm,
    Relation,
    ValidationStatus,
    boolean_lut_interp,
    sequential_machine_interp,
)
from ir.state import ArchInput, BTB_ENTRY, CACHE_OCCUPANCY, TimingConstraint, state_var  # noqa: E402
from llm.aid import (  # noqa: E402
    ALLOWED,
    FORBIDDEN,
    check_cluster,
    check_names,
    check_rank,
    check_relation_hypothesis,
    check_render_c,
    cluster,
    compact_fragment_evidence,
    fragment_evidence,
    propose_names,
    propose_relation,
    rank,
    render_c,
    snapshot,
    verified_class,
)
from llm.client import JSON_OBJECT, ask_json, parse_json, should_run  # noqa: E402


def _lut_relation() -> Relation:
    r = Relation("and")
    r.add_m_in(state_var("w2", CACHE_OCCUPANCY))
    r.add_m_in(state_var("w3", CACHE_OCCUPANCY))
    r.add_m_out(state_var("w4", CACHE_OCCUPANCY))
    r.add_a(ArchInput("i0"))
    r.add_event(make_event(EventKind.WINDOW_OPEN, id="e_open"))
    r.add_event(make_event(EventKind.STATE_WRITE, id="e_wr", subject="w4"))
    r.add_event(make_event(EventKind.ARCH_COMPUTE, id="e_op"))
    r.add_event(make_event(EventKind.STATE_READ, id="e_rd", subject="w4"))
    r.add_event(make_event(EventKind.WINDOW_SQUASH, id="e_sq"))
    r.set_interpretation(boolean_lut_interp(2, table_id=8, inputs=["w2", "w3"], outputs=["w4"]))
    r.validation = ValidationStatus.CONFIRMED
    return r


def _and_net() -> Net:
    net = Net(name="and", source="check")
    net.add_relation(_lut_relation())
    return net


def _odd_fragment() -> Relation:
    r = Relation("odd")
    r.add_m_in(state_var("m", CACHE_OCCUPANCY, phys_key="0"))
    r.add_a(ArchInput("a0", domain="bit", binding="rdi"))
    r.add_t(TimingConstraint("w", kind="open", window_len=32))
    r.add_event(make_event(EventKind.WINDOW_OPEN, id="e0", insn="call", addr=0x10, subject="m"))
    r.add_event(make_event(EventKind.STATE_WRITE, id="e1", insn="mov", subject="m"))
    r.add_event(make_event(EventKind.ARCH_COMPUTE, id="e2", insn="and"))
    r.add_event(make_event(EventKind.STATE_READ, id="e3", insn="mov", subject="m"))
    r.add_event(make_event(EventKind.WINDOW_SQUASH, id="e4", insn="ret"))
    return r


def _ok_hyp(**kw: object) -> dict:
    d = {
        "form": "boolean_lut",
        "confidence": 0.6,
        "cited_events": ["e0", "e1", "e3"],
        "facts": ["WINDOW_OPEN then STATE_WRITE on m", "STATE_READ observes m"],
        "inferences": ["occupancy bits combine as a LUT"],
        "note": "maybe",
    }
    d.update(kw)
    return d


def check_parse_json() -> None:
    assert parse_json('{"a": 1}') == {"a": 1}
    assert parse_json('sure\n```json\n{"ranking": ["x"]}\n```')["ranking"] == ["x"]
    nested = parse_json('note {"names": {"w2": "a"}, "extra": {"k": 1}} trailing')
    assert nested["names"]["w2"] == "a" and nested["extra"]["k"] == 1
    try:
        parse_json("no object here")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def check_json_retry() -> None:
    calls = []

    def fake(p: str) -> str:
        calls.append(p)
        if p.rstrip().endswith("JSON only"):
            return '{"ok": true}'
        return "not json"

    assert ask_json("hi", complete_fn=fake) == {"ok": True}
    assert len(calls) == 2 and JSON_OBJECT in calls[0] and calls[1].endswith("JSON only")


def check_json_retry_fails() -> None:
    def fake(_p: str) -> str:
        return "not json"

    try:
        ask_json("hi", complete_fn=fake)
    except ValueError as e:
        assert "not parseable JSON after retry" in str(e)
    else:
        raise AssertionError("expected ValueError")


def check_verified_only() -> None:
    net = _and_net()
    assert verified_class(net) == "boolean_lut"
    snap = snapshot(net, relations=["and"])
    assert snap["derived"] == "boolean_lut" and "native" not in snap and "class" not in snap
    empty = Net("empty")
    try:
        verified_class(empty)
    except ValueError as e:
        assert "empty" in str(e)
    else:
        raise AssertionError("expected empty reject")
    bad = Net("mix")
    a = Relation("lut")
    a.add_m_out(state_var("z", CACHE_OCCUPANCY))
    a.set_interpretation(boolean_lut_interp(2, table_id=8))
    b = Relation("seq")
    b.add_m_out(state_var("s", BTB_ENTRY))
    b.set_interpretation(sequential_machine_interp(registers=["s"], step="tick"))
    bad.add_relation(a)
    bad.add_relation(b)
    try:
        snapshot(bad)
    except ValueError as e:
        assert "unverified" in str(e)
    else:
        raise AssertionError("expected mixed reject")
    try:
        bad.compose()
    except MixedCompositionError:
        pass
    else:
        raise AssertionError("expected MixedCompositionError")


def check_gates() -> None:
    net = _and_net()
    assert check_rank({"ranking": ["b", "a"], "note": "maybe"}, ["a", "b"])["ranking"] == ["b", "a"]
    try:
        check_rank({"ranking": ["nope"]}, ["a"])
    except ValueError:
        pass
    else:
        raise AssertionError("expected bad ranking reject")
    names = check_names({"names": {"w2": "a", "w3": "b", "e_op": "unknown"}}, net)
    assert names["names"] == {"w2": "a", "w3": "b"}
    try:
        check_names({"names": {"ghost": "x"}}, net)
    except ValueError:
        pass
    else:
        raise AssertionError("expected unknown node reject")
    try:
        check_names({"names": {"w2": "a", "w3": "a"}}, net)
    except ValueError:
        pass
    else:
        raise AssertionError("expected colliding names reject")
    cl = check_cluster({"clusters": [{"name": "and2", "members": ["e_op"]}]}, net)
    assert cl["clusters"][0]["members"] == ["e_op"]
    try:
        check_cluster({"clusters": [{"name": "x", "members": ["missing"]}]}, net)
    except ValueError:
        pass
    else:
        raise AssertionError("expected bad member reject")
    try:
        check_cluster({"clusters": [{"name": "x", "members": ["and"]}]}, net)
    except ValueError:
        pass
    else:
        raise AssertionError("expected relation-name cluster reject")
    c = check_render_c(
        {"c": "uint32_t f(uint32_t w2, uint32_t w3) { return w2 & w3; }"},
        net,
    )
    assert "return w2 & w3" in c["c"]
    try:
        check_render_c({"c": "uint32_t f(uint32_t w2) { for(;;) return w2; }"}, net)
    except ValueError:
        pass
    else:
        raise AssertionError("expected loop reject")
    try:
        check_render_c({"c": "uint32_t f(uint32_t z) { return z; }"}, net)
    except ValueError:
        pass
    else:
        raise AssertionError("expected invented ident reject")


def check_no_llm_equivalence() -> None:
    net = _and_net()
    before = copy.deepcopy(net.to_dict())
    assert should_run(True) is False
    assert rank(net, [{"id": "and"}], no_llm=True) is None
    assert propose_names(net, no_llm=True) is None
    assert cluster(net, no_llm=True) is None
    assert render_c(net, no_llm=True) is None
    mixed = Net("mixed")
    a = Relation("lut")
    a.add_m_out(state_var("z", CACHE_OCCUPANCY))
    a.set_interpretation(boolean_lut_interp(2, table_id=8))
    b = Relation("seq")
    b.add_m_out(state_var("s", BTB_ENTRY))
    b.set_interpretation(sequential_machine_interp(registers=["s"], step="tick"))
    mixed.add_relation(a)
    mixed.add_relation(b)
    assert rank(mixed, ["x"], no_llm=True) is None
    check_names({"names": {"w2": "a"}}, net)
    check_cluster({"clusters": [{"name": "and2", "members": ["e_op"]}]}, net)
    check_render_c({"c": "uint32_t f(uint32_t w2, uint32_t w3) { return w2 & w3; }"}, net)
    assert net.to_dict() == before
    assert json.dumps(before, sort_keys=True) == json.dumps(net.to_dict(), sort_keys=True)
    for name in FORBIDDEN:
        assert name not in ALLOWED
    assert "relation" in ALLOWED


def check_bridged_ok() -> None:
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
        )
    )
    snap = snapshot(net)
    assert snap["derived"] == "converted" and "native" not in snap


def _assert_unchanged(frag: Relation, before: dict) -> None:
    assert frag.to_dict() == before
    assert frag.interpretation is None
    assert frag.derived_form() is DerivedForm.UNKNOWN
    assert frag.validation is ValidationStatus.UNRESOLVED


def check_relation_hypothesis_ok() -> None:
    frag = _odd_fragment()
    before = copy.deepcopy(frag.to_dict())
    hyp = check_relation_hypothesis(_ok_hyp(), frag)
    assert hyp.form == DerivedForm.BOOLEAN_LUT.value
    assert hyp.confidence == 0.6
    assert hyp.cited_events == ("e0", "e1", "e3")
    assert hyp.facts and hyp.inferences
    d = hyp.to_dict()
    assert d["status"] == ValidationStatus.HYPOTHESIS.value
    assert d["confirmed"] is False
    _assert_unchanged(frag, before)

    abstain = check_relation_hypothesis(
        {
            "form": "unknown",
            "confidence": 0.1,
            "cited_events": ["e2"],
            "facts": ["ARCH_COMPUTE and"],
            "inferences": [],
        },
        frag,
    )
    assert abstain.form == DerivedForm.UNKNOWN.value
    assert abstain.to_dict()["status"] == ValidationStatus.ABSTAINED.value
    _assert_unchanged(frag, before)

    blob = fragment_evidence(frag)
    dumped = json.dumps(blob)
    for banned in ("native", "resource", "trigger", "class", "family", "dcache", "btb"):
        assert banned not in dumped
    assert [e["id"] for e in blob["events"]] == ["e0", "e1", "e2", "e3", "e4"]


def check_relation_hypothesis_rejects() -> None:
    frag = _odd_fragment()
    before = copy.deepcopy(frag.to_dict())

    def reject(payload: dict, *needles: str) -> None:
        try:
            check_relation_hypothesis(payload, frag)
        except ValueError as e:
            msg = str(e)
            assert any(n in msg for n in needles), msg
        else:
            raise AssertionError(f"expected reject for {payload}")
        _assert_unchanged(frag, before)

    reject(_ok_hyp(form="lut"), "unsupported")
    reject(_ok_hyp(form="dcache"), "unsupported")
    reject(_ok_hyp(form="bitvector_function"), "unsupported")
    reject(_ok_hyp(cited_events=["e0", "ghost"]), "cited")
    reject(_ok_hyp(cited_events=[]), "cite")
    reject(_ok_hyp(cited_events=["e0", "e0"]), "duplicate")
    reject(_ok_hyp(confidence=1.5), "confidence")
    reject(_ok_hyp(confidence=True), "confidence")
    reject(_ok_hyp(facts="WINDOW_OPEN"), "facts")
    reject(_ok_hyp(inferences={"x": 1}), "inferences")
    reject(
        _ok_hyp(
            facts=["same claim"],
            inferences=["same claim"],
        ),
        "distinct",
    )
    reject(_ok_hyp(facts=[]), "facts")
    reject({"form": "boolean_lut"}, "confidence")


def check_propose_relation_injected() -> None:
    frag = _odd_fragment()
    before = copy.deepcopy(frag.to_dict())
    payload = _ok_hyp()

    def fake(_p: str) -> str:
        return json.dumps(payload)

    hyp = propose_relation(frag, complete_fn=fake)
    assert hyp is not None
    assert hyp.form == "boolean_lut" and hyp.to_dict()["confirmed"] is False
    _assert_unchanged(frag, before)

    def bad(_p: str) -> str:
        return json.dumps(_ok_hyp(form="wr_kind", cited_events=["nope"]))

    try:
        propose_relation(frag, complete_fn=bad)
    except ValueError:
        pass
    else:
        raise AssertionError("expected malformed/unsupported reject")
    _assert_unchanged(frag, before)

    assert propose_relation(frag, no_llm=True) is None
    assert propose_relation(frag, no_llm=True, complete_fn=fake) is None
    _assert_unchanged(frag, before)


def check_dict_event_trace() -> None:
    trace = {
        "name": "odd",
        "resource": "dcache",
        "trigger": "rsb",
        "native": {"log": "secret"},
        "class": "lut",
        "events": [
            {"id": "e0", "kind": "WINDOW_OPEN", "resource": "dcache", "insn": "call"},
            {"id": "e1", "kind": "STATE_WRITE", "subject": "m", "trigger": "rsb"},
            {"kind": "STATE_OBSERVE", "subject": "m"},
        ],
    }
    blob = fragment_evidence(trace)
    dumped = json.dumps(blob)
    for banned in ("resource", "trigger", "native", "class", "dcache"):
        assert banned not in dumped
    assert [e["id"] for e in blob["events"]] == ["e0", "e1", "e2"]
    hyp = check_relation_hypothesis(
        {
            "form": "unknown",
            "confidence": 0.0,
            "cited_events": ["e2"],
            "facts": ["STATE_OBSERVE m"],
            "inferences": [],
        },
        trace,
    )
    assert hyp.form == "unknown"
    assert "native" not in trace or trace["native"] == {"log": "secret"}

    def fake(_p: str) -> str:
        return json.dumps(
            {
                "form": "indexed_memory",
                "confidence": 0.4,
                "cited_events": ["e0", "e1"],
                "facts": ["write after window open"],
                "inferences": ["index from subject m"],
            }
        )

    hyp2 = propose_relation(trace, complete_fn=fake)
    assert hyp2 is not None and hyp2.form == "indexed_memory"
    assert trace["resource"] == "dcache"
    assert trace.get("interpretation") is None


def check_hypothesis_not_derived() -> None:
    frag = _odd_fragment()
    net = Net("odd")
    net.add_relation(frag)
    assert net.compose() == "unknown"
    hyp = check_relation_hypothesis(_ok_hyp(), frag)
    assert hyp.form == "boolean_lut"
    assert frag.unresolved()
    assert net.compose() == "unknown"
    assert "interpretation" not in frag.to_dict()


def check_compact_evidence() -> None:
    frag = Relation("big")
    for i in range(200):
        frag.add_event(make_event(EventKind.STATE_CLEAR, id=f"c{i}", insn="clflush", addr=i))
    frag.add_event(make_event(EventKind.WINDOW_OPEN, id="open", insn="call", addr=1000))
    blob = compact_fragment_evidence(frag, max_events=32)
    assert blob["summary"]["truncated"] is True
    assert blob["summary"]["n_events"] == 201
    assert len(blob["events"]) <= 32
    assert "open" in {e["id"] for e in blob["events"]}
    dumped = json.dumps(blob)
    assert "resource" not in dumped and "trigger" not in dumped

    small = compact_fragment_evidence(_odd_fragment(), max_events=32)
    assert small["summary"]["truncated"] is False
    assert [e["id"] for e in small["events"]] == ["e0", "e1", "e2", "e3", "e4"]


def main() -> None:
    check_parse_json()
    check_json_retry()
    check_json_retry_fails()
    check_verified_only()
    check_gates()
    check_no_llm_equivalence()
    check_bridged_ok()
    check_relation_hypothesis_ok()
    check_relation_hypothesis_rejects()
    check_propose_relation_injected()
    check_dict_event_trace()
    check_hypothesis_not_derived()
    check_compact_evidence()
    print("llm-check: parse, verified IR, structural gates, relation hypothesis, --no-llm overlay ok")


if __name__ == "__main__":
    main()
