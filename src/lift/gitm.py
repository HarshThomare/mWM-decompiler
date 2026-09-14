"""GITM exception+dcache gate recovery via native occupancy samples."""

from __future__ import annotations

from typing import List, Optional, Tuple

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
from lift.harvest import Candidate
from oracle.cache import CacheAdapter

HIT = 40.0
MISS = 300.0


def _hex_keys(cand: Candidate) -> List[str]:
    keys = []
    for k in cand.phys_keys:
        s = str(k)
        if s.startswith("0x"):
            try:
                int(s, 16)
                keys.append(s)
            except ValueError:
                continue
    keys.sort(key=lambda s: int(s, 16), reverse=True)
    return keys


def _window(cand: Candidate) -> Tuple[int, int]:
    """Stop at the first timer after the exception; later flushes are the next trial."""
    prims = cand.primitives
    start = cand.entry if cand.entry is not None else (min(p.addr for p in prims) if prims else 0)
    if not prims:
        return start, cand.exit or (start + 0x200)
    trigs = sorted(p.addr for p in prims if p.note == "cacm.window.exception")
    timers = sorted(p.addr for p in prims if p.role == "timer")
    t0 = trigs[0] if trigs else min(p.addr for p in prims)
    t1 = trigs[1] if len(trigs) > 1 else None
    after = [a for a in timers if a > t0 and (t1 is None or a < t1)]
    if after:
        end = after[0]
    elif t1 is not None:
        end = t1
    else:
        end = t0 + 0x120
    return start, end


def _gitm_net(cand: Candidate, ctx, ins_k, out_k, n_in, table, ev: Evidence, adapter: CacheAdapter) -> Net:
    spec = resource_spec(ResourceKind.DCACHE.value)
    net = Net(name=cand.name, source=ctx.path)
    for nm in ins_k + [out_k]:
        net.add_place(wr_place(nm, spec.kind, phys_key=nm, evidence=ev))
    tid = encode_dual_gate(n_in, table) if table else None
    tname = f"{cand.name}.g"
    net.add_transition(
        Transition(
            name=tname,
            kind=TransKind.GATE,
            n_in=n_in,
            n_out=1,
            table_id=tid,
            gate_table=table,
            gate_tables=[table] if table else None,
            inputs=ins_k,
            outputs=[out_k],
            addr=cand.entry,
            trigger="exception",
            resource=spec.kind,
            evidence=ev,
        )
    )
    net.add_transition(Transition(name="rho", kind=TransKind.ROLLBACK, expr=None))
    net.add_region(
        lut_region(
            f"{cand.name}_lut",
            spec.kind,
            places=list(net.places),
            transitions=[tname],
            trigger="exception",
            evidence=ev,
            entry=cand.entry,
            exit=cand.exit,
        )
    )
    net.native["dual_gate_instances"] = 1 if table else 0
    net.native["wired_instances"] = 1 if table else 0
    net.native["family"] = "gitm"
    net.native["window"] = list(_window(cand))
    adapter.runner.attach(net, adapter.decode_occupancy(HIT, phys_key=out_k))
    if table is None:
        net.native["uncertainty"] = "no_native_samples"
    net.compose()
    return net


class GitmRecovery:
    name = "gitm"
    resource = ResourceKind.DCACHE.value

    def match(self, cand: Candidate, ctx) -> bool:
        if cand.resource != self.resource:
            return False
        return cand.trigger == "exception" and not cand.unresolved

    def recover(self, cand: Candidate, ctx) -> Optional[Net]:
        keys = _hex_keys(cand)
        if len(keys) < 2 or len(keys) > 4:
            return None
        ins_k, out_k = keys[:-1], keys[-1]
        n_in = len(ins_k)
        adapter: CacheAdapter = ctx.cache or CacheAdapter()
        adapter.calibrate_occupancy([HIT] * 8, [MISS] * 8)
        table = None
        if ctx.occupancy and cand.name in ctx.occupancy:
            from lift.flexo import lut_from_dual_rail

            table = lut_from_dual_rail(adapter, n_in, ctx.occupancy[cand.name])
        if table is None:
            ev = Evidence(
                trigger="exception",
                observations=[{"uncertainty": "no_native_samples"}],
                confidence=cand.confidence,
            )
            return _gitm_net(cand, ctx, ins_k, out_k, n_in, None, ev, adapter)
        ones = sum(table.values())
        ev = Evidence(
            trigger="exception",
            observations=[{"table": {"".join(map(str, k)): v for k, v in table.items()}}],
            confidence=0.85 if 0 < ones < (1 << n_in) else 0.4,
        )
        return _gitm_net(cand, ctx, ins_k, out_k, n_in, table, ev, adapter)
