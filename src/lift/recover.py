"""Deterministic relation derivation: event evidence → at most one derived form.

Harvest emits unresolved Relations. This module recognizes boolean_lut,
bitvector, transition_system, indexed_memory, branch_dependent, or
sequential_machine only when the trace supports it. Incomplete stays unknown.
Native adapters confirm / refine / reject claims about M; they do not assign
Flexo/TAE/TLB family labels.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

_SRC = Path(__file__).resolve().parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ir.events import EventKind, Evidence
from ir.net import MixedCompositionError, Net
from ir.relation import (
    DerivedForm,
    Relation,
    ValidationStatus,
    bitvector_interp,
    indexed_memory_interp,
    sequential_machine_interp,
)
from ir.state import BTB_ENTRY, CACHE_OCCUPANCY, TLB_ENTRY, Persistence
from lift.flexo import (
    dual_gate_facts,
    has_dual_gate,
    relation_from_dual_gate,
    validate_occupancy,
)
from lift.gitm import is_exception_window, refine_exception_occupancy
from lift.harvest import HarvestResult, harvest_elf
from lift.tae import branch_predicate, enrich_branch_dependent
from lift.tlb import enrich_transition
from oracle.btb import BtbAdapter
from oracle.cache import CacheAdapter
from oracle.tlb import TlbAdapter

K = EventKind


@dataclass
class LiftContext:
    path: str
    harvest: Optional[HarvestResult] = None
    cache: Optional[CacheAdapter] = None
    btb: Optional[BtbAdapter] = None
    tlb: Optional[TlbAdapter] = None
    occupancy: Optional[Dict[str, Dict[tuple, Sequence[tuple]]]] = None
    btb_samples: Optional[Dict[str, Dict[str, Any]]] = None
    tlb_samples: Optional[Dict[str, Dict[str, Any]]] = None
    native: bool = True
    run_native: bool = False
    max_windows: int = 64
    llm: bool = False  # opt-in propose_relation; still hypothesis-only
    rejected: List[Dict[str, Any]] = field(default_factory=list)
    _native_log: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def adapters(self) -> tuple:
        if self.cache is None:
            self.cache = CacheAdapter()
        if self.btb is None:
            self.btb = BtbAdapter()
        if self.tlb is None:
            self.tlb = TlbAdapter()
        return self.cache, self.btb, self.tlb

    def reject(self, rel: Relation, reason: str) -> None:
        self.rejected.append(
            {
                "name": rel.name,
                "entry": rel.entry,
                "reason": reason,
                "derived": rel.derived_form().value,
                "validation": rel.validation.value,
            }
        )


@dataclass
class LiftResult:
    source: str
    nets: List[Net]
    harvest: Optional[HarvestResult] = None
    rejected: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def relations(self) -> List[Relation]:
        out: List[Relation] = []
        for n in self.nets:
            out.extend(n.relations.values())
        return out

    def primary(self) -> Net:
        if not self.nets:
            raise MixedCompositionError(f"{self.source}: no recovered relation")
        if len(self.nets) == 1:
            self.nets[0].compose()
            return self.nets[0]
        return merge_homogeneous(self.nets, name=Path(self.source).stem, source=self.source)


def merge_homogeneous(nets: Sequence[Net], name: str = "merged", source: str = "") -> Net:
    out = Net(name=name, source=source or (nets[0].source if nets else ""))
    for n in nets:
        for r in n.relations.values():
            nm = r.name if r.name not in out.relations else f"{n.name}.{r.name}"
            if nm != r.name:
                r.name = nm
            if r.name not in out.relations:
                out.add_relation(r)
        for e in n.conversions.values():
            if e.name not in out.conversions:
                out.add_conversion(e)
        for k, v in n.native.items():
            if k == "circuits":
                out.native.setdefault("circuits", []).extend(v if isinstance(v, list) else [v])
            elif k == "adapters":
                bucket = out.native.setdefault("adapters", {})
                if isinstance(v, dict):
                    for rk, rows in v.items():
                        bucket.setdefault(rk, []).extend(rows if isinstance(rows, list) else [rows])
            elif k not in out.native:
                out.native[k] = v
        out.native.setdefault("circuits", []).append(
            {"op": n.name, "relations": len(n.relations), "derived": n.derived()}
        )
    out.compose()
    return out


def _subseq(rel: Relation, kinds: Sequence[EventKind], aliases: Optional[Dict[EventKind, Set[EventKind]]] = None) -> bool:
    aliases = aliases or {}
    i = 0
    for e in rel.events:
        want = kinds[i]
        if e.kind == want or e.kind in aliases.get(want, ()):
            i += 1
            if i == len(kinds):
                return True
    return False


def _specs(rel: Relation) -> Set[str]:
    names = set(rel.specs())
    for e in rel.events:
        if e.subject:
            names.add(e.subject)
    return names


def _kinds(rel: Relation) -> Set[EventKind]:
    return {e.kind for e in rel.events}


def _has_window(rel: Relation) -> bool:
    return bool(_kinds(rel) & {K.WINDOW_OPEN, K.WINDOW_SQUASH, K.WINDOW_EXTEND})


def guess_form(rel: Relation) -> DerivedForm:
    """Event-pattern guess. Does not attach an interpretation or family label."""
    kinds = _kinds(rel)
    specs = _specs(rel)
    has_read = bool(kinds & {K.STATE_READ, K.STATE_CLEAR, K.STATE_OBSERVE})
    has_write = bool(kinds & {K.STATE_WRITE, K.STATE_TRAIN})
    has_compute = K.ARCH_COMPUTE in kinds
    has_mem = K.ARCH_MEMORY in kinds
    has_branch = K.ARCH_BRANCH in kinds
    read_al = {K.STATE_READ: {K.STATE_CLEAR, K.STATE_OBSERVE}}
    write_al = {K.STATE_WRITE: {K.STATE_TRAIN}}

    occupancy = CACHE_OCCUPANCY in specs
    lut_window = K.WINDOW_SQUASH in kinds or is_exception_window(rel)
    if (
        occupancy
        and has_write
        and (has_compute or has_mem)
        and lut_window
        and (has_read or is_exception_window(rel))
    ):
        return DerivedForm.BOOLEAN_LUT

    if has_branch and (BTB_ENTRY in specs or has_read or has_write) and (
        _subseq(rel, (K.STATE_READ, K.ARCH_COMPUTE, K.ARCH_BRANCH, K.STATE_WRITE), {**read_al, **write_al})
        or _subseq(rel, (K.STATE_READ, K.ARCH_BRANCH, K.STATE_WRITE), {**read_al, **write_al})
        or (BTB_ENTRY in specs and has_branch and has_compute)
    ):
        return DerivedForm.BRANCH_DEPENDENT

    if TLB_ENTRY in specs and has_write and (
        _subseq(rel, (K.STATE_READ, K.ARCH_COMPUTE, K.STATE_WRITE), read_al)
        or _subseq(rel, (K.STATE_READ, K.STATE_WRITE), read_al)
        or has_read
    ):
        return DerivedForm.TRANSITION_SYSTEM

    if has_mem and not occupancy and (
        any("stride" in a.name or (a.binding or "").startswith("0x") for a in rel.a_inputs.values())
        or len({e.operand for e in rel.events if e.kind == K.ARCH_MEMORY and e.operand}) >= 2
    ):
        return DerivedForm.INDEXED_MEMORY

    writes = [e for e in rel.events if e.kind in (K.STATE_WRITE, K.STATE_TRAIN)]
    persistent = any(
        v.persistence is Persistence.PERSISTENT for v in list(rel.m_in.values()) + list(rel.m_out.values())
    )
    if len(writes) >= 2 and persistent and not has_branch:
        return DerivedForm.SEQUENTIAL_MACHINE

    widths = [
        v.width
        for v in list(rel.m_in.values()) + list(rel.m_out.values())
        if v.width and v.width > 1
    ]
    if has_compute and not _has_window(rel) and not occupancy and (widths or sum(1 for e in rel.events if e.kind == K.ARCH_COMPUTE) >= 3):
        return DerivedForm.BITVECTOR

    return DerivedForm.UNKNOWN


def _bind_non_lut(rel: Relation, form: DerivedForm) -> None:
    if form == DerivedForm.BRANCH_DEPENDENT:
        pred = branch_predicate(rel)
        if pred:
            from ir.relation import branch_dependent_interp

            rel.set_interpretation(branch_dependent_interp(pred))
        return
    if form == DerivedForm.TRANSITION_SYSTEM:
        from ir.relation import transition_system_interp

        rel.set_interpretation(transition_system_interp(states=["evicted", "filled"], step="walk"))
        return
    if form == DerivedForm.INDEXED_MEMORY:
        mems = [e.operand or e.insn for e in rel.events if e.kind == K.ARCH_MEMORY]
        idx = next(iter(rel.a_inputs.values()), None)
        rel.set_interpretation(
            indexed_memory_interp(
                index=idx.binding if idx is not None else (mems[0] if mems else rel.name),
                cells=mems or None,
            )
        )
        return
    if form == DerivedForm.SEQUENTIAL_MACHINE:
        regs = [v.name for v in list(rel.m_in.values()) + list(rel.m_out.values())]
        rel.set_interpretation(sequential_machine_interp(registers=regs or [rel.name], step="trace"))
        return
    if form == DerivedForm.BITVECTOR:
        ops = [e.insn or e.operand for e in rel.events if e.kind == K.ARCH_COMPUTE]
        width = next(
            (v.width for v in list(rel.m_in.values()) + list(rel.m_out.values()) if v.width and v.width > 1),
            None,
        )
        rel.set_interpretation(bitvector_interp(";".join(x for x in ops if x) or rel.name, width=width))


def _maybe_llm(rel: Relation, ctx: LiftContext) -> None:
    """Hypothesis only. Must still pass guess_form / native before set_interpretation."""
    if not rel.unresolved():
        return
    try:
        from llm.aid import propose_relation
        from llm.client import should_run
    except Exception:
        return
    if not should_run(False):
        return
    try:
        hyp = propose_relation(rel)
    except Exception:
        return
    if hyp is None or hyp.form == DerivedForm.UNKNOWN.value:
        return
    obs = list(rel.evidence.observations) if rel.evidence else []
    obs.append({"llm_hypothesis": hyp.to_dict(), "confirmed": False})
    rel.evidence = Evidence(observations=obs, confidence=rel.confidence)
    guessed = guess_form(rel)
    if guessed.value != hyp.form and guessed is DerivedForm.UNKNOWN:
        # LLM named a form events do not support — leave unknown
        return
    if hyp.form == DerivedForm.BOOLEAN_LUT.value:
        validate_occupancy(rel, ctx)
        return
    form = guessed if guessed is not DerivedForm.UNKNOWN else DerivedForm(hyp.form)
    if rel.unresolved() and form is not DerivedForm.UNKNOWN and form is not DerivedForm.BOOLEAN_LUT:
        _bind_non_lut(rel, form)
        _validate(rel, form, ctx)


def _validate(rel: Relation, form: DerivedForm, ctx: LiftContext) -> None:
    has_occ = bool((ctx.occupancy or {}).get(rel.name))
    has_btb = bool((ctx.btb_samples or {}).get(rel.name))
    has_tlb = bool((ctx.tlb_samples or {}).get(rel.name))
    if form == DerivedForm.BOOLEAN_LUT or (form is DerivedForm.UNKNOWN and has_occ):
        if is_exception_window(rel):
            refine_exception_occupancy(rel, ctx)
        else:
            validate_occupancy(rel, ctx)
        return
    if form == DerivedForm.BRANCH_DEPENDENT or (form is DerivedForm.UNKNOWN and has_btb):
        enrich_branch_dependent(rel, ctx)
        return
    if form == DerivedForm.TRANSITION_SYSTEM or (form is DerivedForm.UNKNOWN and has_tlb):
        enrich_transition(rel, ctx)


def derive_relation(rel: Relation, ctx: LiftContext) -> Optional[Relation]:
    """Mutate `rel` in place. None if rejected or still unknown."""
    form = guess_form(rel)
    if form is not DerivedForm.UNKNOWN and form is not DerivedForm.BOOLEAN_LUT:
        _bind_non_lut(rel, form)
    _validate(rel, form, ctx)
    if rel.validation == ValidationStatus.REJECTED:
        return None
    if rel.unresolved() and ctx.llm:
        _maybe_llm(rel, ctx)
    if rel.validation == ValidationStatus.REJECTED:
        return None
    if rel.unresolved():
        return None
    return rel


def _net_of(rel: Relation, ctx: LiftContext) -> Net:
    net = Net(name=rel.name, source=rel.source or ctx.path)
    net.add_relation(rel)
    log = ctx._native_log.get(rel.name)
    if log:
        net.native.update(log)
        bucket = net.native.setdefault("adapters", {})
        for rk, payload in log.items():
            bucket.setdefault(rk, []).append(payload)
    if rel.derived_form() == DerivedForm.BOOLEAN_LUT:
        p = rel.interpretation.payload if rel.interpretation else {}
        net.native["dual_gate_instances"] = 1 if p.get("table_id") is not None or p.get("gate_table") else 0
        net.native["wired_instances"] = net.native["dual_gate_instances"]
    if rel.validation == ValidationStatus.UNRESOLVED and rel.evidence:
        for o in rel.evidence.observations:
            if isinstance(o, dict) and o.get("uncertainty"):
                net.native["uncertainty"] = o["uncertainty"]
                break
    try:
        net.compose()
    except MixedCompositionError:
        pass
    return net


def _match_frag(harvest: Optional[HarvestResult], addr: Optional[int]) -> Optional[Relation]:
    if harvest is None or addr is None:
        return None
    for f in harvest.fragments:
        if f.entry == addr:
            return f
    return None


def _dual_gate_nets(path: str, ctx: LiftContext) -> List[Net]:
    facts = dual_gate_facts(path)
    if not facts:
        return []
    h = ctx.harvest or harvest_elf(path)
    ctx.harvest = h
    nets: List[Net] = []
    for fact in facts:
        frag = _match_frag(h, fact["func_addr"])
        gates = fact["gates"]
        if len(gates) == 1:
            rel = relation_from_dual_gate(fact, frag)
            validate_occupancy(rel, ctx)
            if rel.validation == ValidationStatus.REJECTED:
                continue
            net = _net_of(rel, ctx)
            net.native["func_addr"] = fact["func_addr"]
            net.native["symbol"] = fact.get("symbol")
            net.native["op"] = fact["op"]
            net.native["dual_gate_instances"] = 1
            net.native["wired_instances"] = 1
            nets.append(net)
            continue
        net = Net(name=fact["op"], source=path)
        net.native["func_addr"] = fact["func_addr"]
        net.native["symbol"] = fact.get("symbol")
        net.native["dual_gate_instances"] = len(gates)
        net.native["wired_instances"] = len(gates)
        for i, g in enumerate(gates):
            sub = dict(fact, op=f"{fact['op']}.g{i}", gates=[g])
            rel = relation_from_dual_gate(sub, frag if i == 0 else None)
            validate_occupancy(rel, ctx)
            if rel.validation == ValidationStatus.REJECTED:
                continue
            net.add_relation(rel)
        if net.relations:
            try:
                net.compose()
            except MixedCompositionError:
                pass
            nets.append(net)
    return nets


def lift_from_harvest(harvest: HarvestResult, ctx: Optional[LiftContext] = None) -> LiftResult:
    ctx = ctx or LiftContext(path=harvest.source, harvest=harvest)
    ctx.harvest = harvest
    ctx.path = ctx.path or harvest.source
    ctx.adapters()
    nets: List[Net] = []
    n_ok = 0
    for frag in harvest.relations:
        if n_ok >= ctx.max_windows:
            ctx.reject(frag, "max_windows")
            continue
        got = derive_relation(frag, ctx)
        if got is None:
            continue
        nets.append(_net_of(got, ctx))
        n_ok += 1
    return LiftResult(source=harvest.source, nets=nets, harvest=harvest, rejected=list(ctx.rejected))


def lift_circuits(
    path: str,
    harvest: Optional[HarvestResult] = None,
    ctx: Optional[LiftContext] = None,
) -> List[Net]:
    path = str(path)
    ctx = ctx or LiftContext(path=path, harvest=harvest)
    ctx.path = path
    if harvest is not None:
        ctx.harvest = harvest
    dual = _dual_gate_nets(path, ctx)
    if dual:
        return dual
    h = ctx.harvest or harvest_elf(path)
    ctx.harvest = h
    return lift_from_harvest(h, ctx).nets


def lift_from_elf(path: str, **kw: Any) -> LiftResult:
    path = str(path)
    harvest = kw.pop("harvest", None)
    ctx = kw.pop("ctx", None) or LiftContext(path=path, harvest=harvest, **kw)
    ctx.path = path
    nets = lift_circuits(path, harvest=ctx.harvest, ctx=ctx)
    h = ctx.harvest
    if h is None and not nets:
        h = harvest_elf(path)
        ctx.harvest = h
        return lift_from_harvest(h, ctx)
    return LiftResult(source=path, nets=nets, harvest=h, rejected=list(ctx.rejected))


def lift_elf(path: str, **kw: Any) -> Net:
    """Harvest + derive + typed compose. Homogeneous merge, else MixedCompositionError."""
    return lift_from_elf(path, **kw).primary()


__all__ = [
    "LiftContext",
    "LiftResult",
    "derive_relation",
    "guess_form",
    "has_dual_gate",
    "lift_circuits",
    "lift_elf",
    "lift_from_elf",
    "lift_from_harvest",
    "merge_homogeneous",
]


def _self_check() -> None:
    from ir.events import make_event
    from ir.state import state_var
    from oracle.cache import CacheAdapter
    from oracle.tlb import TlbAdapter

    # incomplete occupancy window → unknown, no fake LUT
    r = Relation("inc")
    r.add_event(make_event(K.STATE_READ, subject=CACHE_OCCUPANCY, addr=1))
    r.add_event(make_event(K.WINDOW_OPEN, addr=2))
    assert guess_form(r) is DerivedForm.UNKNOWN

    lut = Relation("lut")
    lut.add_m_in(state_var("lut.a", CACHE_OCCUPANCY, phys_key="w2"))
    lut.add_m_out(state_var("lut.b", CACHE_OCCUPANCY, phys_key="w4"))
    lut.add_event(make_event(K.STATE_READ, subject=CACHE_OCCUPANCY, addr=1))
    lut.add_event(make_event(K.ARCH_COMPUTE, addr=2, insn="xor"))
    lut.add_event(make_event(K.STATE_WRITE, subject=CACHE_OCCUPANCY, addr=3))
    lut.add_event(make_event(K.WINDOW_SQUASH, addr=4))
    assert guess_form(lut) is DerivedForm.BOOLEAN_LUT
    ctx = LiftContext(path="synthetic")
    assert derive_relation(lut, ctx) is None  # no table, do not fake

    ad = CacheAdapter()
    ad.calibrate_occupancy([40] * 8, [300] * 8)
    trials = {
        (0, 0): [(40, 300)] * 4,
        (1, 0): [(40, 300)] * 4,
        (0, 1): [(40, 300)] * 4,
        (1, 1): [(300, 40)] * 4,
    }
    lut2 = Relation("stripped_and")
    lut2.add_m_in(state_var("stripped_and.w3", CACHE_OCCUPANCY, phys_key="w3"))
    lut2.add_m_in(state_var("stripped_and.w2", CACHE_OCCUPANCY, phys_key="w2"))
    lut2.add_m_out(state_var("stripped_and.w4", CACHE_OCCUPANCY, phys_key="w4"))
    lut2.add_event(make_event(K.STATE_READ, subject=CACHE_OCCUPANCY, addr=1))
    lut2.add_event(make_event(K.ARCH_COMPUTE, addr=2, insn="and"))
    lut2.add_event(make_event(K.STATE_WRITE, subject=CACHE_OCCUPANCY, addr=3))
    lut2.add_event(make_event(K.WINDOW_SQUASH, addr=4))
    ctx2 = LiftContext(path="synthetic", occupancy={"stripped_and": trials}, cache=ad)
    got = derive_relation(lut2, ctx2)
    assert got is not None and got.derived_form() is DerivedForm.BOOLEAN_LUT
    assert got.validation is ValidationStatus.CONFIRMED
    assert got.interpretation.payload["gate_table"][(1, 1)] == 1

    br = Relation("br")
    br.add_m_in(state_var("br.p", BTB_ENTRY, phys_key="pc"))
    br.add_event(make_event(K.STATE_READ, subject=BTB_ENTRY, addr=1))
    br.add_event(make_event(K.ARCH_COMPUTE, addr=2, insn="add"))
    br.add_event(make_event(K.ARCH_BRANCH, addr=3, operand="rax"))
    br.add_event(make_event(K.STATE_WRITE, subject=BTB_ENTRY, addr=4))
    assert guess_form(br) is DerivedForm.BRANCH_DEPENDENT
    ctx3 = LiftContext(path="synthetic")
    gotb = derive_relation(br, ctx3)
    assert gotb is not None and gotb.derived_form() is DerivedForm.BRANCH_DEPENDENT
    assert gotb.validation is ValidationStatus.UNRESOLVED  # unemulated BTB

    tlb = Relation("vpn0", entry=0x1000)
    tlb.add_m_in(state_var("vpn0.evicted", TLB_ENTRY, phys_key="0x1000"))
    tlb.add_m_out(state_var("vpn0.filled", TLB_ENTRY, phys_key="0x1000"))
    tlb.add_event(make_event(K.STATE_READ, subject=TLB_ENTRY, addr=0x1000))
    tlb.add_event(make_event(K.ARCH_COMPUTE, addr=0x1004, insn="mov"))
    tlb.add_event(make_event(K.STATE_WRITE, subject=TLB_ENTRY, addr=0x1008))
    assert guess_form(tlb) is DerivedForm.TRANSITION_SYSTEM
    ctx4 = LiftContext(
        path="synthetic",
        tlb=TlbAdapter(),
        tlb_samples={"vpn0": {"evicted": [400] * 6, "after": [31] * 6}},
    )
    gott = derive_relation(tlb, ctx4)
    assert gott is not None and gott.derived_form() is DerivedForm.TRANSITION_SYSTEM
    assert gott.validation is ValidationStatus.CONFIRMED

    ctx5 = LiftContext(path="synthetic", tlb=TlbAdapter())
    tlb2 = Relation("vpn1", entry=0x2000)
    tlb2.add_m_in(state_var("vpn1.evicted", TLB_ENTRY, phys_key="0x2000"))
    tlb2.add_event(make_event(K.STATE_READ, subject=TLB_ENTRY, addr=0x2000))
    tlb2.add_event(make_event(K.STATE_WRITE, subject=TLB_ENTRY, addr=0x2010))
    gott2 = derive_relation(tlb2, ctx5)
    assert gott2 is not None and gott2.derived_form() is DerivedForm.TRANSITION_SYSTEM
    assert gott2.interpretation.payload.get("uncertainty") == "unemulated"

    print("recover self-check: forms + occupancy + unemulated BTB/TLB ok")


if __name__ == "__main__":
    _self_check()

