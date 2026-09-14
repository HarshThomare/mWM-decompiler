"""Checks for optional LLM overlay. Run: python src/llm/check.py"""

import copy
import json
import sys
from pathlib import Path

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ir.net import (  # noqa: E402
    ConversionEdge,
    Kind,
    MixedCompositionError,
    Net,
    Place,
    TransKind,
    Transition,
    gate_transition,
    isa_region,
    lut_region,
    wr_place,
)
from llm.aid import (  # noqa: E402
    FORBIDDEN,
    check_cluster,
    check_names,
    check_rank,
    check_render_c,
    cluster,
    propose_names,
    rank,
    render_c,
    snapshot,
    verified_class,
)
from llm.client import ask_json, parse_json, should_run  # noqa: E402


def _and_net() -> Net:
    net = Net(name="and", source="check")
    net.add_place(Place("w3", Kind.VOLATILE, "bit"))
    net.add_place(Place("w2", Kind.VOLATILE, "bit"))
    net.add_place(Place("w4", Kind.VOLATILE, "bit"))
    net.add_transition(gate_transition("g", 2, 8, ["w3", "w2"], ["w4"]))
    net.add_transition(Transition(name="rho", kind=TransKind.ROLLBACK, expr=None))
    for p in net.places.values():
        p.resource = "dcache"
        p.encoding = "dual_rail"
        p.destructive_read = True
    net.add_region(lut_region("and_lut", "dcache", places=net.places, transitions=["g"]))
    return net


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
    assert len(calls) == 2 and calls[1].endswith("JSON only")


def check_verified_only() -> None:
    net = _and_net()
    assert verified_class(net) == "lut"
    snap = snapshot(net, transitions=["g"], places=["w2", "w3", "w4"])
    assert snap["class"] == "lut" and "native" not in snap
    empty = Net("empty")
    try:
        verified_class(empty)
    except ValueError as e:
        assert "empty" in str(e)
    else:
        raise AssertionError("expected empty reject")
    bad = _and_net()
    bad.add_place(wr_place("s", "btb"))
    bad.add_transition(Transition(name="body", kind=TransKind.EXPR, expr="x", inputs=["s"], outputs=["s"]))
    bad.add_region(isa_region("w", places=["s"], transitions=["body"]))
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
    names = check_names({"names": {"w2": "a", "w3": "b", "g": "unknown"}}, net)
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
    cl = check_cluster({"clusters": [{"name": "and2", "members": ["g"]}]}, net)
    assert cl["clusters"][0]["members"] == ["g"]
    try:
        check_cluster({"clusters": [{"name": "x", "members": ["missing"]}]}, net)
    except ValueError:
        pass
    else:
        raise AssertionError("expected bad member reject")
    try:
        check_cluster({"clusters": [{"name": "x", "members": ["rho"]}]}, net)
    except ValueError:
        pass
    else:
        raise AssertionError("expected rollback cluster reject")
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
    mixed.add_place(wr_place("a", "dcache"))
    mixed.add_place(wr_place("b", "btb"))
    mixed.add_transition(gate_transition("g", 2, 8, ["a", "b"], ["a"]))
    assert rank(mixed, ["x"], no_llm=True) is None
    check_names({"names": {"w2": "a"}}, net)
    check_cluster({"clusters": [{"name": "and2", "members": ["g"]}]}, net)
    check_render_c({"c": "uint32_t f(uint32_t w2, uint32_t w3) { return w2 & w3; }"}, net)
    assert net.to_dict() == before
    assert json.dumps(before, sort_keys=True) == json.dumps(net.to_dict(), sort_keys=True)
    for name in FORBIDDEN:
        assert name not in ("rank", "names", "cluster", "render_c")


def check_bridged_ok() -> None:
    net = _and_net()
    net.add_place(wr_place("s", "btb", phys_key="0"))
    net.add_transition(Transition(name="body", kind=TransKind.EXPR, expr="x", inputs=["s"], outputs=["s"]))
    net.add_region(isa_region("w", places=["s"], transitions=["body"]))
    net.add_conversion(
        ConversionEdge("c0", src="w4", dst="s", src_resource="dcache", dst_resource="btb")
    )
    assert snapshot(net)["class"] == "converted"


def main() -> None:
    check_parse_json()
    check_json_retry()
    check_verified_only()
    check_gates()
    check_no_llm_equivalence()
    check_bridged_ok()
    print("llm-check: parse, verified IR, structural gates, --no-llm overlay ok")


if __name__ == "__main__":
    main()
