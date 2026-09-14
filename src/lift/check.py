"""Small checks for family semantic recovery. Run: python src/lift/check.py"""

import sys
from pathlib import Path

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ir.flexo_tables import decode_dual_gate, encode_dual_gate
from ir.net import ConversionEdge, MixedCompositionError, TransKind, wr_place
from lift.flexo import FlexoRecovery, lut_from_dual_rail
from lift.gitm import GitmRecovery
from lift.harvest import Candidate, harvest_elf
from lift.recover import LiftContext, lift_circuits, lift_elf, lift_from_harvest
from oracle.cache import CacheAdapter
from oracle.tlb import TlbAdapter

REPO = Path(__file__).resolve().parents[2]
FLEXO_AND = REPO / "src/gates/flexo/gates/gate_and.elf"
GITM_AND = REPO / "src/gates/gitm/main_and.elf"
TAE_GATES = REPO / "third_party/tae/build/bin/gates.elf"


def check_flexo_dual_gate() -> None:
    nets = lift_circuits(str(FLEXO_AND))
    names = [n.name for n in nets]
    assert "and" in names, names
    and_net = next(n for n in nets if n.name == "and")
    assert and_net.compose() == "lut"
    assert and_net.classify() == "flexo"
    gates = [t for t in and_net.transitions.values() if t.kind == TransKind.GATE]
    assert len(gates) == 1
    g = gates[0]
    assert g.table_id == 8 and g.gate_table[(1, 1)] == 1 and g.gate_table[(1, 0)] == 0
    assert g.resource == "dcache" and and_net.regions
    h = harvest_elf(str(FLEXO_AND))
    dcache = [c for c in h.candidates if c.resource == "dcache" and c.entry == and_net.native.get("func_addr")]
    assert dcache and dcache[0].trigger == "rsb"
    # leftover BTB harvest is a hypothesis: DualGate evidence wins, do not fuse
    btb = [c for c in h.candidates if c.resource == "btb"]
    assert btb and all(c.unresolved for c in btb)
    merged = lift_elf(str(FLEXO_AND))
    assert merged.compose() == "lut"
    try:
        merged.add_place(wr_place("s", "btb"))
        from ir.net import Transition

        merged.add_transition(Transition(name="body", kind=TransKind.EXPR, expr="x", inputs=["s"], outputs=["s"]))
        from ir.net import isa_region

        merged.add_region(isa_region("w", places=["s"], transitions=["body"]))
        merged.compose()
    except MixedCompositionError:
        pass
    else:
        raise AssertionError("expected MixedCompositionError without conversion")
    merged.add_conversion(ConversionEdge("c0", src="w4", dst="s", src_resource="dcache", dst_resource="btb"))
    assert merged.compose() == "converted"


def check_stripped_occupancy_and_reject() -> None:
    ad = CacheAdapter()
    ad.calibrate_occupancy([40] * 8, [300] * 8)
    and_trials = {
        (0, 0): [(40, 300)] * 4,
        (1, 0): [(40, 300)] * 4,
        (0, 1): [(40, 300)] * 4,
        (1, 1): [(300, 40)] * 4,
    }
    table = lut_from_dual_rail(ad, 2, and_trials)
    assert table is not None and encode_dual_gate(2, table) == 8
    cand = Candidate(
        name="stripped_and",
        resource="dcache",
        trigger="rsb",
        entry=0x11e0,
        exit=0x13fb,
        phys_keys=["w3", "w2", "w4"],
        unresolved=False,
        confidence=0.9,
    )
    ctx = LiftContext(path=str(FLEXO_AND), occupancy={"stripped_and": and_trials}, cache=ad)
    net = FlexoRecovery().recover(cand, ctx)
    assert net is not None and net.compose() == "lut"
    g = next(t for t in net.transitions.values() if t.kind == TransKind.GATE)
    assert g.gate_table[(1, 1)] == 1 and g.table_id == 8

    xor_trials = {
        (0, 0): [(40, 300)] * 4,
        (1, 0): [(300, 40)] * 4,
        (0, 1): [(300, 40)] * 4,
        (1, 1): [(40, 300)] * 4,
    }
    dual = lift_circuits(str(FLEXO_AND), ctx=LiftContext(path=str(FLEXO_AND), occupancy={"and": xor_trials}, cache=ad))
    and_net = next(n for n in dual if n.name == "and")
    assert and_net.native.get("static_rejected")
    g = next(t for t in and_net.transitions.values() if t.kind == TransKind.GATE)
    assert g.table_id == 6 and g.gate_table[(1, 0)] == 1


def check_gitm_and() -> None:
    h = harvest_elf(str(GITM_AND))
    hit = [c for c in h.candidates if c.resource == "dcache" and c.trigger == "exception" and not c.unresolved]
    assert hit, [c.to_dict() for c in h.candidates[:4]]
    ctx = LiftContext(path=str(GITM_AND), harvest=h, max_windows=1)
    res = lift_from_harvest(h, ctx)
    assert res.nets, ctx.rejected
    net = res.nets[0]
    assert net.compose() == "lut"
    g = next(t for t in net.transitions.values() if t.kind == TransKind.GATE)
    assert g.trigger == "exception" and g.resource == "dcache"
    assert g.n_in == 2
    assert net.native.get("uncertainty") == "no_native_samples"
    assert g.gate_table is None
    ad = CacheAdapter()
    ad.calibrate_occupancy([40] * 8, [300] * 8)
    and_trials = {
        (0, 0): [(40, 300)] * 4,
        (1, 0): [(40, 300)] * 4,
        (0, 1): [(40, 300)] * 4,
        (1, 1): [(300, 40)] * 4,
    }
    filled = GitmRecovery().recover(
        hit[0],
        LiftContext(path=str(GITM_AND), occupancy={hit[0].name: and_trials}, cache=ad),
    )
    assert filled is not None
    fg = next(t for t in filled.transitions.values() if t.kind == TransKind.GATE)
    assert encode_dual_gate(2, fg.gate_table) == 8


def check_tae_gates() -> None:
    h = harvest_elf(str(TAE_GATES))
    btb = [c for c in h.candidates if c.resource == "btb" and not c.unresolved]
    assert btb, [c.to_dict() for c in h.candidates[:6]]
    net = lift_elf(str(TAE_GATES), max_windows=2)
    assert net.compose() == "isa"
    assert net.classify() == "tae"
    expr = [t for t in net.transitions.values() if t.kind == TransKind.EXPR]
    assert expr and expr[0].gate_table is None
    assert expr[0].expr and expr[0].expr.get("uncertainty") in ("unemulated", "btb_unemulated")
    persist = [p for p in net.places.values() if p.resource == "btb"]
    assert persist and all(p.kind.value == "persistent" for p in persist)
    assert any(r.kind.value == "isa" for r in net.regions.values())
    # harvest may also see dcache; without a conversion edge it must not be fused
    assert not any(p.resource == "dcache" for p in net.places.values())


def check_tlb_transitions() -> None:
    cand = Candidate(
        name="vpn0",
        resource="tlb",
        trigger="rsb",
        entry=0x1000,
        exit=0x1100,
        phys_keys=["0x1000"],
        unresolved=False,
        confidence=0.7,
    )
    h = type("H", (), {"source": "synthetic", "candidates": [cand]})()
    ad = TlbAdapter()
    ctx = LiftContext(
        path="synthetic",
        tlb=ad,
        tlb_samples={"vpn0": {"evicted": [400] * 6, "after": [31] * 6}},
    )
    res = lift_from_harvest(h, ctx)  # type: ignore[arg-type]
    assert res.nets
    net = res.nets[0]
    assert net.compose() in ("lut", "isa")
    t = next(x for x in net.transitions.values() if x.kind != TransKind.ROLLBACK)
    assert t.resource == "tlb"
    assert net.native.get("tlb", {}).get("causal") is True
    ctx2 = LiftContext(path="synthetic", tlb=TlbAdapter())
    res2 = lift_from_harvest(h, ctx2)  # type: ignore[arg-type]
    t2 = next(x for x in res2.nets[0].transitions.values() if x.kind != TransKind.ROLLBACK)
    assert t2.kind == TransKind.EXPR
    assert t2.gate_table is None
    assert "unemulated" in str(t2.expr)


def main() -> None:
    if FLEXO_AND.is_file():
        check_flexo_dual_gate()
        check_stripped_occupancy_and_reject()
    else:
        print("lift-check: skip DualGate (no Flexo ELF)")
    if GITM_AND.is_file():
        check_gitm_and()
    else:
        print("lift-check: skip GITM (no ELF)")
    if TAE_GATES.is_file():
        check_tae_gates()
    else:
        print("lift-check: skip TAE (no ELF)")
    check_tlb_transitions()
    print("lift-check: DualGate, occupancy, GITM AND, TAE ISA, TLB transitions ok")


if __name__ == "__main__":
    main()
