"""Small checks for typed evidence IR. Run: python src/ir/typed_check.py"""

import sys
from pathlib import Path

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from ir.net import (
        ConversionEdge,
        Evidence,
        Kind,
        MixedCompositionError,
        Net,
        Place,
        RegionKind,
        ResourceKind,
        ResourceSpec,
        TransKind,
        Transition,
        gate_transition,
        isa_region,
        lut_region,
        register_resource,
        resource_spec,
        wr_place,
    )
else:
    from .net import (
        ConversionEdge,
        Evidence,
        Kind,
        MixedCompositionError,
        Net,
        Place,
        RegionKind,
        ResourceKind,
        ResourceSpec,
        TransKind,
        Transition,
        gate_transition,
        isa_region,
        lut_region,
        register_resource,
        resource_spec,
        wr_place,
    )


def _legacy_and() -> Net:
    net = Net(name="and", source="check")
    net.add_place(Place("w3", Kind.VOLATILE, "bit"))
    net.add_place(Place("w2", Kind.VOLATILE, "bit"))
    net.add_place(Place("w4", Kind.VOLATILE, "bit"))
    net.add_transition(
        gate_transition("__DualGate__2_1_8@139a", 2, 8, ["w3", "w2"], ["w4"])
    )
    net.add_transition(Transition(name="rho", kind=TransKind.ROLLBACK, expr=None))
    return net


def check_legacy_apis() -> None:
    net = _legacy_and()
    assert net.classify() == "flexo"
    assert net.compose() == "flexo"
    assert net.flexo_classifiable() and not net.tae_classifiable()
    t = net.transitions["__DualGate__2_1_8@139a"]
    assert net.fire_gate(t, (1, 1)) == 1
    d = net.to_dict()
    assert d["class"] == "flexo"
    assert d["places"][0] == {"name": "w3", "kind": "volatile", "col": "bit"}
    assert "regions" not in d
    # lift_flexo_elf-style copy
    p = next(iter(net.places.values()))
    Place(p.name, p.kind, p.col)
    Transition(
        name=t.name,
        kind=t.kind,
        n_in=t.n_in,
        n_out=t.n_out,
        table_id=t.table_id,
        gate_table=t.gate_table,
        gate_tables=t.gate_tables,
        expr=t.expr,
        inputs=t.inputs,
        outputs=t.outputs,
        addr=t.addr,
    )


def check_resource_specs() -> None:
    dc = resource_spec("dcache")
    assert dc.encoding == "dual_rail" and dc.destructive_read and not dc.persistent
    assert dc.trigger == "rsb" and dc.phys_key_role == "line"
    btb = resource_spec(ResourceKind.BTB.value)
    assert btb.encoding == "btb_target" and btb.persistent and btb.width == 16
    tlb = resource_spec("tlb")
    assert tlb.encoding == "hit_miss" and tlb.destructive_read
    register_resource(
        ResourceSpec(
            kind="pht",
            encoding="taken",
            destructive_read=False,
            persistent=True,
            width=1,
            trigger="indirect_jmp",
            phys_key_role="index",
        )
    )
    p = wr_place("p0", "pht", phys_key="17")
    assert p.kind == Kind.PERSISTENT and p.encoding == "taken"


def check_wr_place() -> None:
    line = wr_place("c0", ResourceKind.DCACHE, phys_key="0x4000")
    assert line.kind == Kind.VOLATILE and line.destructive_read is True
    assert line.encoding == "dual_rail" and line.resource == "dcache"
    br = wr_place("b0", "btb", phys_key="pc:0x10")
    assert br.kind == Kind.PERSISTENT and br.destructive_read is False
    pg = wr_place("t0", "tlb", phys_key="0x1000")
    assert pg.encoding == "hit_miss"


def check_lut_region() -> None:
    net = _legacy_and()
    for p in net.places.values():
        p.resource = "dcache"
        p.encoding = "dual_rail"
        p.destructive_read = True
    net.add_region(
        lut_region(
            "and_lut",
            ResourceKind.DCACHE,
            places=net.places,
            transitions=["__DualGate__2_1_8@139a"],
            evidence=Evidence(trigger="rsb", observations=[{"wired": 1}], confidence=0.9),
        )
    )
    assert net.compose() == "lut"
    assert net.compose_region("and_lut") == "lut"
    assert net.classify() == "flexo"
    assert net.regions["and_lut"].trigger == "rsb"
    assert net.to_dict()["regions"][0]["kind"] == "lut"


def check_isa_region() -> None:
    net = Net("search")
    net.add_place(wr_place("s", "btb", phys_key="0"))
    net.add_transition(
        Transition(
            name="body",
            kind=TransKind.EXPR,
            expr="cmp/jmp",
            inputs=["s"],
            outputs=["s"],
            trigger="indirect_jmp",
            resource="btb",
            evidence=Evidence(trigger="indirect_jmp", confidence=0.6),
            window_len=32,
        )
    )
    net.add_region(
        isa_region("wf", places=["s"], transitions=["body"], entry=0x100, exit=0x140)
    )
    assert net.compose() == "isa"
    assert net.classify() == "tae"
    assert net.regions["wf"].kind == RegionKind.ISA


def check_mixed_lut_isa_rejected() -> None:
    net = _legacy_and()
    net.add_place(wr_place("s", "btb"))
    net.add_transition(Transition(name="body", kind=TransKind.EXPR, expr="x", inputs=["s"], outputs=["s"]))
    net.add_region(lut_region("g", "dcache", places=["w3", "w2", "w4"], transitions=["__DualGate__2_1_8@139a"]))
    net.add_region(isa_region("w", places=["s"], transitions=["body"]))
    try:
        net.compose()
    except MixedCompositionError as e:
        assert "without conversion edges" in str(e)
    else:
        raise AssertionError("expected MixedCompositionError")
    # derived view may still pick tae; compose() is what refuses fusion
    assert net.classify() == "tae"


def check_conversion_allows_mix() -> None:
    net = _legacy_and()
    for nm in ("w3", "w2", "w4"):
        net.places[nm].resource = "dcache"
    net.add_place(wr_place("s", "btb", phys_key="0"))
    net.add_transition(Transition(name="body", kind=TransKind.EXPR, expr="x", inputs=["s"], outputs=["s"]))
    net.add_region(lut_region("g", "dcache", places=["w3", "w2", "w4"], transitions=["__DualGate__2_1_8@139a"]))
    net.add_region(isa_region("w", places=["s"], transitions=["body"]))
    net.add_conversion(
        ConversionEdge("c0", src="w4", dst="s", src_resource="dcache", dst_resource="btb", encoding="copy")
    )
    assert net.compose() == "converted"


def check_gate_mixes_resources_rejected() -> None:
    net = Net("bad")
    net.add_place(wr_place("a", "dcache"))
    net.add_place(wr_place("b", "btb"))
    net.add_transition(gate_transition("g", 2, 8, ["a", "b"], ["a"]))
    try:
        net.compose()
    except MixedCompositionError as e:
        assert "mixes resources" in str(e)
    else:
        raise AssertionError("expected MixedCompositionError")


def check_lut_cannot_hold_expr() -> None:
    net = Net("bad")
    net.add_place(wr_place("a", "dcache"))
    net.add_transition(Transition(name="e", kind=TransKind.EXPR, expr="x", inputs=["a"], outputs=["a"]))
    net.add_region(lut_region("g", "dcache", places=["a"], transitions=["e"]))
    try:
        net.compose()
    except MixedCompositionError as e:
        assert "lut region cannot contain expr" in str(e)
    else:
        raise AssertionError("expected MixedCompositionError")


def main() -> None:
    check_legacy_apis()
    check_resource_specs()
    check_wr_place()
    check_lut_region()
    check_isa_region()
    check_mixed_lut_isa_rejected()
    check_conversion_allows_mix()
    check_gate_mixes_resources_rejected()
    check_lut_cannot_hold_expr()
    print("typed-check: resource specs, regions, conversions, mixed rejection ok")


if __name__ == "__main__":
    main()
