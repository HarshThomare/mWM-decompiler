"""Occupancy / DualGate validators for boolean_lut claims about M.

Native CacheAdapter confirms, refines, or rejects. Never invents a LUT
when unemulated.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict, List, Optional, Sequence, Tuple

from capstone.x86 import X86_OP_IMM
from elftools.elf.elffile import ELFFile

from ir.events import Evidence
from ir.flexo_tables import encode_dual_gate
from ir.relation import Relation, ValidationStatus, boolean_lut_interp
from ir.state import CACHE_OCCUPANCY, ArchInput, state_var
from oracle.cache import CacheAdapter

from .flexo_static import DUAL_RE, _disasm, _symbols, _text_bytes, _weird_op

HIT = 40.0
MISS = 300.0


def evidence_from_native(result) -> Evidence:
    obs = list(result.observations)
    meta = {
        "protocol": result.protocol,
        "invalid": result.invalid,
        "wemu_supported": result.wemu_supported,
    }
    if result.causal is not None:
        meta["causal"] = result.causal
    if result.uncertainty is not None:
        meta["uncertainty"] = result.uncertainty
    if result.value is not None:
        meta["value"] = result.value
    if result.phys_key is not None:
        meta["phys_key"] = result.phys_key
    obs.append(meta)
    return Evidence(observations=obs, confidence=result.confidence)


def has_dual_gate(path: str) -> bool:
    return bool(dual_gate_facts(path))


def dual_gate_facts(path: str) -> List[Dict[str, Any]]:
    """Symbol-table DualGate instances. No Net / Place construction."""
    path = str(path)
    with open(path, "rb") as f:
        elf = ELFFile(f)
        syms = _symbols(elf)
        text_addr, text = _text_bytes(elf)
    dual_by_addr: Dict[int, Tuple[str, int, int, int]] = {}
    for addr, (name, _size) in syms.items():
        m = DUAL_RE.match(name)
        if not m:
            continue
        n_in, n_out, table_id = map(int, m.groups())
        dual_by_addr[addr] = (name, n_in, n_out, table_id)
    if not dual_by_addr:
        return []
    out: List[Dict[str, Any]] = []
    for addr, (name, size) in sorted(syms.items()):
        op = _weird_op(name)
        if not op:
            continue
        gates = []
        for insn in _disasm(text, addr, size, text_addr):
            if insn.mnemonic != "call" or not insn.operands:
                continue
            if insn.operands[0].type != X86_OP_IMM:
                continue
            tgt = int(insn.operands[0].imm)
            if tgt not in dual_by_addr:
                continue
            gname, n_in, n_out, table_id = dual_by_addr[tgt]
            gates.append(
                {
                    "symbol": gname,
                    "n_in": n_in,
                    "n_out": n_out,
                    "table_id": table_id,
                    "addr": insn.address,
                }
            )
        if gates:
            out.append({"op": op, "func_addr": addr, "symbol": name, "gates": gates, "source": path})
    return out


def occupancy_io(rel: Relation) -> Tuple[List[str], List[str]]:
    keys: List[str] = []
    seen = set()
    for v in list(rel.m_in.values()) + list(rel.m_out.values()):
        k = v.phys_key or v.name
        if k in seen:
            continue
        seen.add(k)
        keys.append(str(k))
    if len(keys) >= 2:
        return keys[:-1], keys[-1:]
    if keys:
        return keys, [f"{rel.name}.out"]
    return [f"{rel.name}.in0"], [f"{rel.name}.out"]


def lut_from_dual_rail(
    adapter: CacheAdapter,
    n_in: int,
    trials_by_input: Dict[Tuple[int, ...], Sequence[tuple]],
) -> Optional[Dict[Tuple[int, ...], int]]:
    """Fill a LUT from dual-rail occupancy trials. None if any minterm is invalid."""
    table: Dict[Tuple[int, ...], int] = {}
    for bits in range(1 << n_in):
        key = tuple((bits >> k) & 1 for k in range(n_in))
        trials = trials_by_input.get(key)
        if trials is None:
            key_msb = tuple((bits >> (n_in - 1 - k)) & 1 for k in range(n_in))
            trials = trials_by_input.get(key_msb)
            if trials is not None:
                key = key_msb
        if not trials:
            return None
        rec = adapter.recover_dual_rail(trials)
        if rec.invalid or rec.value is None:
            return None
        table[key] = int(rec.value)
    if len(table) != 1 << n_in:
        return None
    return table


def apply_boolean_lut(
    rel: Relation,
    *,
    n_in: int,
    table_id: Optional[int] = None,
    table: Optional[Dict[Tuple[int, ...], int]] = None,
    inputs: Optional[List[str]] = None,
    outputs: Optional[List[str]] = None,
    n_out: int = 1,
) -> None:
    if table is None and table_id is None:
        return
    ins, outs = inputs, outputs
    if ins is None or outs is None:
        d_in, d_out = occupancy_io(rel)
        ins = ins or d_in
        outs = outs or d_out
    rel.set_interpretation(
        boolean_lut_interp(
            n_in,
            table_id=table_id,
            n_out=n_out,
            gate_table=table,
            inputs=ins,
            outputs=outs,
        )
    )


def _ensure_occupancy_vars(rel: Relation, inputs: Sequence[str], outputs: Sequence[str]) -> None:
    for nm in list(inputs) + list(outputs):
        if not any(v.phys_key == nm or v.name.endswith(nm) for v in rel.m_in.values()):
            rel.add_m_in(state_var(f"{rel.name}.{nm}", CACHE_OCCUPANCY, phys_key=nm))
        if not any(v.phys_key == nm or v.name.endswith(nm) for v in rel.m_out.values()):
            rel.add_m_out(state_var(f"{rel.name}.{nm}.out", CACHE_OCCUPANCY, phys_key=nm))
        if nm not in rel.a_inputs and nm in inputs:
            rel.add_a(ArchInput(name=nm, domain="bit", width=1, binding=nm))


def relation_from_dual_gate(fact: Dict[str, Any], harvest_frag: Optional[Relation] = None) -> Relation:
    """Static DualGate → confirmed boolean_lut. Harvest events are evidence, not the table."""
    op = fact["op"]
    gates = fact["gates"]
    g0 = gates[0]
    rel = Relation(name=op, source=fact.get("source") or "", entry=fact["func_addr"])
    ins = [f"i{i}" for i in range(g0["n_in"])]
    outs = [f"o{i}" for i in range(g0["n_out"])]
    if harvest_frag is not None:
        h_in, h_out = occupancy_io(harvest_frag)
        if len(h_in) == g0["n_in"]:
            ins = h_in
        if len(h_out) == g0["n_out"]:
            outs = h_out
        for e in harvest_frag.events:
            rel.add_event(replace(e, id=""))
        for a in harvest_frag.a_inputs.values():
            if a.name not in rel.a_inputs:
                rel.add_a(a)
        for t in harvest_frag.t_constraints.values():
            if t.name not in rel.t_constraints:
                rel.add_t(t)
        rel.exit = harvest_frag.exit
    _ensure_occupancy_vars(rel, ins, outs)
    apply_boolean_lut(
        rel,
        n_in=g0["n_in"],
        table_id=g0["table_id"],
        n_out=g0["n_out"],
        inputs=ins,
        outputs=outs,
    )
    rel.validation = ValidationStatus.CONFIRMED
    rel.evidence = Evidence(
        observations=[
            {
                "static": "dual_gate",
                "n_gates": len(gates),
                "table_id": g0["table_id"],
                "func_addr": fact["func_addr"],
            }
        ],
        confidence=1.0,
    )
    rel.confidence = 1.0
    return rel


def reconcile_lut(
    rel: Relation,
    table: Dict[Tuple[int, ...], int],
    src: str,
    inputs: Optional[List[str]] = None,
    outputs: Optional[List[str]] = None,
) -> None:
    """Dynamic occupancy wins when it contradicts DualGate static."""
    n_in = len(next(iter(table)))
    interp = rel.interpretation
    static = interp.payload.get("gate_table") if interp is not None else None
    ins = inputs
    outs = outputs
    if interp is not None:
        ins = ins or list(interp.payload.get("inputs") or [])
        outs = outs or list(interp.payload.get("outputs") or [])
    tid = encode_dual_gate(n_in, table)
    apply_boolean_lut(rel, n_in=n_in, table_id=tid, table=table, inputs=ins, outputs=outs)
    if static is not None and dict(static) != dict(table):
        rel.validation = ValidationStatus.REFINED
        obs = list(rel.evidence.observations) if rel.evidence else []
        obs.append(
            {
                "rejected_static": True,
                "src": src,
                "static": {"".join(map(str, k)): v for k, v in static.items()},
                "dynamic": {"".join(map(str, k)): v for k, v in table.items()},
            }
        )
        rel.evidence = Evidence(observations=obs, confidence=0.8)
        rel.confidence = 0.8
    else:
        rel.validation = ValidationStatus.CONFIRMED


def _occupancy_trials(rel: Relation, ctx) -> Optional[Dict[Tuple[int, ...], Sequence[tuple]]]:
    bag = ctx.occupancy or {}
    trials = bag.get(rel.name)
    if trials:
        return trials
    harvest = getattr(ctx, "harvest", None)
    if harvest is not None and rel.entry is not None:
        for f in harvest.fragments:
            if f.entry == rel.entry and f.name in bag:
                return bag[f.name]
    if rel.entry is not None:
        for k, v in bag.items():
            if k == f"{rel.entry:#x}":
                return v
    return None


def validate_occupancy(rel: Relation, ctx) -> None:
    """Confirm / refine / reject a boolean_lut claim. No table → leave unknown."""
    trials = _occupancy_trials(rel, ctx)
    if not trials:
        return
    adapter: CacheAdapter = ctx.cache or CacheAdapter()
    if not adapter.cal.ok:
        adapter.calibrate_occupancy([HIT] * 8, [MISS] * 8)
    n_in = len(next(iter(trials)))
    table = lut_from_dual_rail(adapter, n_in, trials)
    if table is None:
        if rel.interpretation is not None:
            return
        rel.set_interpretation(None)
        rel.validation = ValidationStatus.REJECTED
        ctx.reject(rel, "occupancy_invalid")
        return
    rec = adapter.recover_dual_rail(next(iter(trials.values())))
    ins, outs = occupancy_io(rel)
    if rel.interpretation is not None and rel.interpretation.payload.get("gate_table") is not None:
        reconcile_lut(rel, table, "cache_occupancy", inputs=ins, outputs=outs)
    else:
        apply_boolean_lut(rel, n_in=n_in, table=table, table_id=encode_dual_gate(n_in, table), inputs=ins, outputs=outs)
        rel.validation = ValidationStatus.CONFIRMED
    ev = evidence_from_native(rec)
    if rel.evidence is not None:
        ev.observations = list(rel.evidence.observations) + list(ev.observations)
    rel.evidence = ev
    if rec.confidence is not None:
        rel.confidence = rec.confidence
    ctx._native_log = getattr(ctx, "_native_log", {})
    ctx._native_log[rel.name] = {"cache": rec.to_dict()}
