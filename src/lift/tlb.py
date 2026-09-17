"""Transition-system enrichment for tlb_entry M. TlbAdapter validates the walk.

STATE_READ → ARCH_COMPUTE → STATE_WRITE on tlb_entry is a transition system,
not a LUT. Unemulated walks keep the form and record uncertainty.
"""

from __future__ import annotations

from ir.relation import Relation, ValidationStatus, transition_system_interp
from ir.state import TLB_ENTRY, state_var
from oracle.tlb import TlbAdapter

from .flexo import evidence_from_native


def _vpn(rel: Relation) -> str:
    for v in list(rel.m_in.values()) + list(rel.m_out.values()):
        if v.phys_key:
            return str(v.phys_key)
    if rel.entry is not None:
        return f"{rel.entry:#x}"
    return rel.name


def enrich_transition(rel: Relation, ctx) -> None:
    adapter: TlbAdapter = ctx.tlb or TlbAdapter()
    samples = (ctx.tlb_samples or {}).get(rel.name)
    key = _vpn(rel)
    if samples:
        evicted = samples.get("evicted") or []
        after = samples.get("after") or []
        if evicted or after:
            result = adapter.test_vpn_causality(str(key), evicted, after)
        elif samples.get("latencies"):
            result = adapter.recover_hit_miss(samples["latencies"], phys_key=str(key))
        else:
            result = adapter.unavailable("unemulated", phys_key=str(key))
        if result.causal is False and result.uncertainty == "no_effect":
            rel.set_interpretation(None)
            rel.validation = ValidationStatus.REJECTED
            ctx.reject(rel, "tlb_no_effect")
            return
    else:
        result = adapter.unavailable("unemulated", phys_key=str(key))

    step = "filled" if result.causal else ("unknown" if result.uncertainty else "walk")
    if result.uncertainty == "unemulated":
        step = "walk"
    rel.set_interpretation(
        transition_system_interp(
            states=["evicted", "filled"],
            step=step,
            vpn=key,
            uncertainty=result.uncertainty,
        )
    )
    if TLB_ENTRY not in rel.specs():
        rel.add_m_in(state_var(f"{rel.name}.evicted", TLB_ENTRY, phys_key=str(key)))
        rel.add_m_out(state_var(f"{rel.name}.filled", TLB_ENTRY, phys_key=str(key)))

    ev = evidence_from_native(result)
    ev.observations = list(ev.observations) + [{"harvest": rel.name}]
    if rel.evidence is not None:
        ev.observations = list(rel.evidence.observations) + list(ev.observations)
    rel.evidence = ev
    if result.confidence is not None:
        rel.confidence = result.confidence
    if result.uncertainty == "unemulated" or result.invalid:
        rel.validation = ValidationStatus.UNRESOLVED
    else:
        rel.validation = ValidationStatus.CONFIRMED
    ctx._native_log = getattr(ctx, "_native_log", {})
    ctx._native_log[rel.name] = {"tlb": result.to_dict()}
