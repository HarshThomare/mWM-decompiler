"""Family-specific semantic recovery behind a common interface.

Harvest locates candidates; this module recovers typed Nets: DualGate LUTs,
stripped Flexo occupancy, GITM exception gates, TAE ISA regions, TLB walks.
Unsupported LUT+ISA / multi-resource fusion raises MixedCompositionError.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

_SRC = Path(__file__).resolve().parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ir.net import MixedCompositionError, Net, Place, TransKind, Transition
from lift.flexo import FlexoRecovery, annotate_flexo, has_dual_gate, lift_dual_gate, lut_from_dual_rail, reconcile_gate
from lift.gitm import GitmRecovery
from lift.harvest import Candidate, HarvestResult, harvest_elf
from lift.tae import TaeRecovery
from lift.tlb import TlbRecovery
from oracle.btb import BtbAdapter
from oracle.cache import CacheAdapter
from oracle.tlb import TlbAdapter

FAMILIES = (FlexoRecovery(), GitmRecovery(), TaeRecovery(), TlbRecovery())


@dataclass
class LiftContext:
    path: str
    harvest: Optional[HarvestResult] = None
    cache: Optional[CacheAdapter] = None
    btb: Optional[BtbAdapter] = None
    tlb: Optional[TlbAdapter] = None
    occupancy: Optional[Dict[str, Dict[Tuple[int, ...], Sequence[tuple]]]] = None
    btb_samples: Optional[Dict[str, Dict[str, Any]]] = None
    tlb_samples: Optional[Dict[str, Dict[str, Any]]] = None
    native: bool = True
    run_native: bool = False
    max_windows: int = 2
    rejected: List[Dict[str, Any]] = field(default_factory=list)

    def adapters(self) -> Tuple[CacheAdapter, BtbAdapter, TlbAdapter]:
        if self.cache is None:
            self.cache = CacheAdapter()
        if self.btb is None:
            self.btb = BtbAdapter()
        if self.tlb is None:
            self.tlb = TlbAdapter()
        return self.cache, self.btb, self.tlb

    def reject(self, cand: Candidate, reason: str) -> None:
        self.rejected.append(
            {
                "name": cand.name,
                "resource": cand.resource,
                "trigger": cand.trigger,
                "entry": cand.entry,
                "reason": reason,
            }
        )


@dataclass
class LiftResult:
    source: str
    nets: List[Net]
    harvest: Optional[HarvestResult] = None
    rejected: List[Dict[str, Any]] = field(default_factory=list)

    def primary(self) -> Net:
        if not self.nets:
            raise MixedCompositionError(f"{self.source}: no recovered family")
        if len(self.nets) == 1:
            self.nets[0].compose()
            return self.nets[0]
        return merge_homogeneous(self.nets, name=Path(self.source).stem, source=self.source)


def merge_homogeneous(nets: Sequence[Net], name: str = "merged", source: str = "") -> Net:
    """Union same-resource recovered nets. Mixed resources need conversion edges."""
    out = Net(name=name, source=source or (nets[0].source if nets else ""))
    for n in nets:
        prefix = n.name
        for p in n.places.values():
            nm = p.name if p.name not in out.places else f"{prefix}.{p.name}"
            if nm not in out.places:
                out.add_place(
                    Place(
                        nm,
                        p.kind,
                        p.col,
                        resource=p.resource,
                        phys_key=p.phys_key,
                        encoding=p.encoding,
                        destructive_read=p.destructive_read,
                        evidence=p.evidence,
                    )
                )
        rename = {}
        for t in n.transitions.values():
            if t.kind == TransKind.ROLLBACK:
                continue
            tn = t.name if t.name not in out.transitions else f"{prefix}.{t.name}"
            rename[t.name] = tn
            out.add_transition(
                Transition(
                    name=tn,
                    kind=t.kind,
                    window_len=t.window_len,
                    n_in=t.n_in,
                    n_out=t.n_out,
                    table_id=t.table_id,
                    gate_table=t.gate_table,
                    gate_tables=t.gate_tables,
                    expr=t.expr,
                    inputs=list(t.inputs),
                    outputs=list(t.outputs),
                    addr=t.addr,
                    trigger=t.trigger,
                    resource=t.resource,
                    evidence=t.evidence,
                )
            )
        for r in n.regions.values():
            rn = r.name if r.name not in out.regions else f"{prefix}.{r.name}"
            region = type(r)(
                name=rn,
                kind=r.kind,
                resource=r.resource,
                places=list(r.places),
                transitions=[rename.get(t, t) for t in r.transitions],
                window_len=r.window_len,
                trigger=r.trigger,
                evidence=r.evidence,
                entry=r.entry,
                exit=r.exit,
            )
            out.add_region(region)
        for e in n.conversions.values():
            if e.name not in out.conversions:
                out.add_conversion(e)
        for k, v in n.native.items():
            if k == "circuits":
                out.native.setdefault("circuits", []).extend(v if isinstance(v, list) else [v])
            elif k not in out.native:
                out.native[k] = v
        out.native.setdefault("circuits", []).append(
            {"op": n.name, "places": len(n.places), "gates": n.native.get("dual_gate_instances")}
        )
    if "rho" not in out.transitions and any(
        t.kind == TransKind.GATE for n in nets for t in n.transitions.values()
    ):
        out.add_transition(Transition(name="rho", kind=TransKind.ROLLBACK, expr=None))
    out.compose()
    return out


def lift_from_harvest(harvest: HarvestResult, ctx: Optional[LiftContext] = None) -> LiftResult:
    """Recover one net per matching candidate; reject unconfirmed hypotheses."""
    ctx = ctx or LiftContext(path=harvest.source, harvest=harvest)
    ctx.harvest = harvest
    ctx.path = ctx.path or harvest.source
    ctx.adapters()
    nets: List[Net] = []
    per_family: Dict[str, int] = {}
    for rec in FAMILIES:
        for cand in harvest.candidates:
            if not rec.match(cand, ctx):
                continue
            if per_family.get(rec.name, 0) >= ctx.max_windows:
                ctx.reject(cand, "max_windows")
                continue
            net = rec.recover(cand, ctx)
            if net is None:
                continue
            nets.append(net)
            per_family[rec.name] = per_family.get(rec.name, 0) + 1
    return LiftResult(source=harvest.source, nets=nets, harvest=harvest, rejected=list(ctx.rejected))


def lift_circuits(
    path: str,
    harvest: Optional[HarvestResult] = None,
    ctx: Optional[LiftContext] = None,
) -> List[Net]:
    """Per-function nets. DualGate-symbol Flexo stays the extract.py path."""
    path = str(path)
    ctx = ctx or LiftContext(path=path, harvest=harvest)
    ctx.path = path
    dual = lift_dual_gate(path, cands=(harvest.candidates if harvest else None))
    if dual:
        if ctx.occupancy:
            adapter = ctx.cache or CacheAdapter()
            if not adapter.cal.ok:
                adapter.calibrate_occupancy([40.0] * 8, [300.0] * 8)
            for net in dual:
                trials = ctx.occupancy.get(net.name)
                if not trials:
                    continue
                table = lut_from_dual_rail(adapter, next(t.n_in for t in net.transitions.values() if t.kind == TransKind.GATE), trials)
                if table:
                    reconcile_gate(net, table, "cache_occupancy")
        return dual
    h = harvest or harvest_elf(path)
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
    """Harvest + family recover + typed compose. Homogeneous merge, else MixedCompositionError."""
    return lift_from_elf(path, **kw).primary()


# re-export DualGate helper for callers that already type nets
__all__ = [
    "FAMILIES",
    "LiftContext",
    "LiftResult",
    "annotate_flexo",
    "has_dual_gate",
    "lift_circuits",
    "lift_elf",
    "lift_from_elf",
    "lift_from_harvest",
    "merge_homogeneous",
]
