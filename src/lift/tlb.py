"""TLB hit/miss state-transition recovery via TlbAdapter."""

from __future__ import annotations

from typing import Optional

from ir.net import (
    Net,
    ResourceKind,
    TransKind,
    Transition,
    isa_region,
    lut_region,
    wr_place,
)
from lift.harvest import Candidate
from oracle.tlb import TlbAdapter
from oracle.runner import NativeResult


class TlbRecovery:
    name = "tlb"
    resource = ResourceKind.TLB.value

    def match(self, cand: Candidate, ctx) -> bool:
        return cand.resource == self.resource

    def recover(self, cand: Candidate, ctx) -> Optional[Net]:
        adapter: TlbAdapter = ctx.tlb or TlbAdapter()
        samples = (ctx.tlb_samples or {}).get(cand.name)
        key = cand.phys_keys[0] if cand.phys_keys else cand.name
        result: NativeResult
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
                ctx.reject(cand, "tlb_no_effect")
                return None
        else:
            result = adapter.unavailable("unemulated", phys_key=str(key))
        ev = result.to_evidence()
        ev.observations = list(ev.observations) + [{"harvest": cand.name}]
        net = Net(name=cand.name, source=ctx.path)
        evicted_p = wr_place(f"{cand.name}.evicted", self.resource, phys_key=str(key), evidence=ev)
        filled_p = wr_place(f"{cand.name}.filled", self.resource, phys_key=str(key), evidence=ev)
        net.add_place(evicted_p)
        net.add_place(filled_p)
        tname = f"{cand.name}.walk"
        table = None
        kind = TransKind.EXPR
        expr: object = {
            "kind": "tlb_transition",
            "from": "evicted",
            "to": "filled" if result.causal else "unknown",
            "uncertainty": result.uncertainty,
        }
        if result.value in (0, 1) and result.causal:
            # occupancy bit as a 0-input constant after the walk
            kind = TransKind.GATE
            table = {(): int(result.value)}
            expr = None
        net.add_transition(
            Transition(
                name=tname,
                kind=kind,
                n_in=0 if table is not None else 1,
                n_out=1,
                gate_table=table,
                gate_tables=[table] if table else None,
                expr=expr,
                inputs=[evicted_p.name] if kind == TransKind.EXPR else [],
                outputs=[filled_p.name],
                addr=cand.entry,
                trigger=cand.trigger or adapter.trigger,
                resource=self.resource,
                evidence=ev,
            )
        )
        # LUT region only when we recovered a Boolean occupancy bit
        if kind == TransKind.GATE:
            net.add_region(
                lut_region(
                    f"{cand.name}_lut",
                    self.resource,
                    places=list(net.places),
                    transitions=[tname],
                    trigger=cand.trigger or adapter.trigger,
                    evidence=ev,
                    entry=cand.entry,
                    exit=cand.exit,
                )
            )
        else:
            net.add_region(
                isa_region(
                    f"{cand.name}_tlb",
                    self.resource,
                    places=list(net.places),
                    transitions=[tname],
                    trigger=cand.trigger or adapter.trigger,
                    evidence=ev,
                    entry=cand.entry,
                    exit=cand.exit,
                )
            )
        adapter.record(net, filled_p.name, phys_key=str(key), result=result)
        net.native["family"] = self.name
        net.native["tlb"] = result.to_dict()
        net.compose()
        return net
