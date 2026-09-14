"""Flexo LUT recovery: DualGate symbols, or CacheAdapter occupancy on harvested windows."""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

from ir.flexo_tables import encode_dual_gate
from ir.net import (
    Evidence,
    Net,
    ResourceKind,
    TransKind,
    Transition,
    lut_region,
    resource_spec,
    wr_place,
)
from lift.flexo_static import lift_flexo_circuits
from lift.harvest import Candidate
from oracle.cache import CacheAdapter
from oracle.runner import NativeResult

HIT = 40.0
MISS = 300.0


def has_dual_gate(path: str) -> bool:
    nets = lift_flexo_circuits(path)
    return any(n.native.get("dual_gate_instances") for n in nets)


def annotate_flexo(
    net: Net,
    cand: Optional[Candidate] = None,
    native: Optional[NativeResult] = None,
) -> Net:
    """Attach dcache LUT typing. DualGate tables stay as recovered."""
    spec = resource_spec(ResourceKind.DCACHE.value)
    ev = cand.as_evidence() if cand is not None else Evidence(trigger=spec.trigger)
    if native is not None:
        ev = native.to_evidence()
        if cand is not None:
            ev.observations = list(ev.observations) + [{"harvest": cand.name}]
    for p in net.places.values():
        if not p.resource:
            p.resource = spec.kind
            p.encoding = spec.encoding
            p.destructive_read = spec.destructive_read
        if p.evidence is None:
            p.evidence = ev
    gates: List[str] = []
    for t in net.transitions.values():
        if t.kind != TransKind.GATE:
            continue
        t.resource = spec.kind
        t.trigger = spec.trigger
        if t.evidence is None:
            t.evidence = ev
        gates.append(t.name)
    if gates and f"{net.name}_lut" not in net.regions:
        net.add_region(
            lut_region(
                f"{net.name}_lut",
                spec.kind,
                places=list(net.places),
                transitions=gates,
                trigger=spec.trigger,
                evidence=ev,
                entry=net.native.get("func_addr") if isinstance(net.native.get("func_addr"), int) else (cand.entry if cand else None),
                exit=cand.exit if cand else None,
            )
        )
    net.compose()
    return net


def _match_harvest(net: Net, cands: Sequence[Candidate]) -> Optional[Candidate]:
    addr = net.native.get("func_addr")
    if addr is None:
        return None
    for c in cands:
        if c.entry == addr and c.resource == ResourceKind.DCACHE.value:
            return c
    return None


def lift_dual_gate(
    path: str,
    cands: Optional[Sequence[Candidate]] = None,
    native: Optional[NativeResult] = None,
) -> List[Net]:
    out = []
    for net in lift_flexo_circuits(path):
        if not net.native.get("dual_gate_instances"):
            continue
        cand = _match_harvest(net, cands or ())
        out.append(annotate_flexo(net, cand=cand, native=native))
    return out


def lut_from_dual_rail(
    adapter: CacheAdapter,
    n_in: int,
    trials_by_input: Dict[Tuple[int, ...], Sequence[tuple]],
) -> Optional[Dict[Tuple[int, ...], int]]:
    """Fill a GATE table from dual-rail occupancy trials. None if any minterm is invalid."""
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


def reconcile_gate(net: Net, table: Dict[Tuple[int, ...], int], src: str) -> Net:
    """Dynamic LUT wins when it contradicts DualGate static. Else attach evidence."""
    gates = [t for t in net.transitions.values() if t.kind == TransKind.GATE]
    if not gates:
        return net
    t = gates[0]
    static = t.gate_table
    if static is not None and dict(static) != dict(table):
        net.native["static_rejected"] = {
            "reason": "occupancy_mismatch",
            "static": {"".join(map(str, k)): v for k, v in static.items()},
            "dynamic": {"".join(map(str, k)): v for k, v in table.items()},
            "src": src,
        }
        t.gate_table = table
        t.gate_tables = [table]
        t.table_id = encode_dual_gate(t.n_in or len(next(iter(table))), table)
        t.evidence = Evidence(
            trigger=t.trigger,
            observations=[{"rejected_static": True, "src": src}],
            confidence=0.8,
        )
    elif static is None:
        t.gate_table = table
        t.gate_tables = [table]
        t.table_id = encode_dual_gate(len(next(iter(table))), table)
    return net


def _gate_net(
    name: str,
    inputs: List[str],
    outputs: List[str],
    table: Optional[Dict[Tuple[int, ...], int]],
    cand: Candidate,
    evidence: Evidence,
) -> Net:
    spec = resource_spec(ResourceKind.DCACHE.value)
    net = Net(name=name, source=cand.name)
    for nm in inputs + outputs:
        if nm not in net.places:
            net.add_place(wr_place(nm, spec.kind, phys_key=nm, evidence=evidence))
    n_in = len(inputs)
    tid = encode_dual_gate(n_in, table) if table else None
    net.add_transition(
        Transition(
            name=f"{name}.g",
            kind=TransKind.GATE,
            n_in=n_in,
            n_out=len(outputs),
            table_id=tid,
            gate_table=table,
            gate_tables=[table] if table else None,
            inputs=inputs,
            outputs=outputs,
            addr=cand.entry,
            trigger=cand.trigger or spec.trigger,
            resource=spec.kind,
            evidence=evidence,
        )
    )
    net.add_transition(Transition(name="rho", kind=TransKind.ROLLBACK, expr=None))
    net.add_region(
        lut_region(
            f"{name}_lut",
            spec.kind,
            places=list(net.places),
            transitions=[f"{name}.g"],
            trigger=cand.trigger or spec.trigger,
            evidence=evidence,
            entry=cand.entry,
            exit=cand.exit,
        )
    )
    net.native["dual_gate_instances"] = 1 if table else 0
    net.native["wired_instances"] = 1 if table else 0
    net.native["op"] = name
    if table is None:
        net.native["uncertainty"] = "no_native_samples"
    net.compose()
    return net


class FlexoRecovery:
    name = "flexo"
    resource = ResourceKind.DCACHE.value

    def match(self, cand: Candidate, ctx) -> bool:
        if cand.resource != self.resource:
            return False
        return cand.trigger == "rsb"

    def recover(self, cand: Candidate, ctx) -> Optional[Net]:
        keys = list(cand.phys_keys) or [cand.name]
        inputs, outputs = (keys[:-1], keys[-1:]) if len(keys) >= 2 else (keys, [f"{cand.name}.out"])
        n_in = len(inputs)
        if n_in < 1 or n_in > 4:
            return None
        adapter: CacheAdapter = ctx.cache or CacheAdapter()
        table = None
        ev = cand.as_evidence()
        trials = (ctx.occupancy or {}).get(cand.name)
        if trials:
            adapter.calibrate_occupancy([HIT] * 8, [MISS] * 8)
            table = lut_from_dual_rail(adapter, n_in, trials)
            if table is None:
                ctx.reject(cand, "occupancy_invalid")
                return None
            rec = adapter.recover_dual_rail(next(iter(trials.values())))
            ev = rec.to_evidence()
        else:
            ev = Evidence(
                trigger=cand.trigger,
                observations=[{"uncertainty": "no_native_samples"}],
                confidence=cand.confidence,
            )
        net = _gate_net(cand.name, inputs, outputs, table, cand, ev)
    if table is None:
        net.native["uncertainty"] = "no_native_samples"
        return net
