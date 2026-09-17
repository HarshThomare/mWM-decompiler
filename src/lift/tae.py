"""Branch-dependent enrichment. BtbAdapter validates claims about M, not the form.

TAE-like traces (STATE_READ → ARCH_COMPUTE → ARCH_BRANCH → STATE_WRITE) stay
branch_dependent. Unemulated BTB does not invent a LUT or a taken target.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Optional

from capstone.x86 import X86_OP_IMM

from ir.events import EventKind
from ir.relation import Relation, ValidationStatus, branch_dependent_interp
from ir.state import BTB_ENTRY, state_var
from oracle.btb import BtbAdapter

from .flexo import evidence_from_native
from .harvest import _disasm, _text


def _slice_insns(ctx, entry: Optional[int], exit: Optional[int], limit: int = 4096):
    from elftools.elf.elffile import ELFFile
    from pathlib import Path

    if not ctx.path or not Path(ctx.path).is_file():
        return []
    with open(ctx.path, "rb") as f:
        elf = ELFFile(f)
        lo, _hi, code = _text(elf)
    insns = _disasm(code, lo)
    out = []
    for insn in insns:
        if entry is not None and insn.address < entry:
            continue
        if exit is not None and insn.address >= exit:
            break
        out.append(insn)
        if len(out) >= limit:
            break
        if insn.mnemonic == "ret" and len(out) > 4 and entry is not None:
            if insn.address - entry > 0x40:
                break
    return out


def _isa_summary(insns) -> Dict[str, Any]:
    mnems = Counter(i.mnemonic for i in insns)
    indirect = []
    for insn in insns:
        if insn.mnemonic not in ("jmp", "call") or not insn.operands:
            continue
        if insn.operands[0].type == X86_OP_IMM:
            continue
        indirect.append(insn.address)
    return {
        "n_insns": len(insns),
        "mnems": dict(mnems.most_common(16)),
        "indirect": [f"{a:#x}" for a in indirect[:24]],
    }


def branch_predicate(rel: Relation) -> Optional[str]:
    branches = [e for e in rel.events if e.kind == EventKind.ARCH_BRANCH]
    if not branches:
        return None
    last = branches[-1]
    return last.operand or last.insn or (f"{last.addr:#x}" if last.addr is not None else rel.name)


def enrich_branch_dependent(rel: Relation, ctx) -> None:
    """Fill predicate / then-else from events + optional BTB samples. Never fake a LUT."""
    pred = branch_predicate(rel)
    if pred is None:
        return
    adapter: BtbAdapter = ctx.btb or BtbAdapter()
    samples = (ctx.btb_samples or {}).get(rel.name)
    result = None
    then = otherwise = None
    if samples:
        trained = samples.get("trained") or samples.get("targets") or []
        untrained = samples.get("untrained") or []
        key = next((v.phys_key for v in rel.m_in.values() if v.phys_key), rel.name)
        if untrained and trained:
            result = adapter.test_index_causality(
                str(key),
                untrained,
                trained,
                expected_target=samples.get("expected"),
            )
        else:
            result = adapter.observe_target(trained or samples.get("targets") or [])
        if result.causal is False and result.uncertainty == "no_effect":
            rel.set_interpretation(None)
            rel.validation = ValidationStatus.REJECTED
            ctx.reject(rel, "btb_no_effect")
            return
        then = result.value
        otherwise = None
        if untrained:
            from oracle.runner import majority

            otherwise, _, _ = majority(untrained)
    else:
        result = adapter.unavailable("unemulated")

    insns = _slice_insns(ctx, rel.entry, rel.exit)
    summary = _isa_summary(insns) if insns else {}
    rel.set_interpretation(
        branch_dependent_interp(
            pred,
            then=then,
            otherwise=otherwise,
            isa=summary or None,
            uncertainty=result.uncertainty if result is not None else None,
        )
    )
    if BTB_ENTRY not in rel.specs():
        key = f"{rel.entry:#x}" if rel.entry is not None else rel.name
        rel.add_m_in(state_var(f"{rel.name}.{key}", BTB_ENTRY, phys_key=str(key)))
        rel.add_m_out(state_var(f"{rel.name}.{key}.out", BTB_ENTRY, phys_key=str(key)))

    ev = evidence_from_native(result) if result is not None else rel.evidence
    if result is not None:
        extra = {"harvest": rel.name, "predicate": pred}
        if summary:
            extra["isa"] = summary
        ev.observations = list(ev.observations) + [extra]
        if rel.evidence is not None:
            ev.observations = list(rel.evidence.observations) + list(ev.observations)
        rel.evidence = ev
        if result.confidence is not None:
            rel.confidence = result.confidence
        if result.uncertainty == "unemulated":
            rel.validation = ValidationStatus.UNRESOLVED
        elif result.invalid:
            rel.validation = ValidationStatus.UNRESOLVED
        else:
            rel.validation = ValidationStatus.CONFIRMED
    ctx._native_log = getattr(ctx, "_native_log", {})
    ctx._native_log[rel.name] = {"btb": result.to_dict() if result is not None else None}
