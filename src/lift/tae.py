"""TAE ISA-region recovery. Fill from native BTB samples; never fake LUTs."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional

from capstone.x86 import X86_OP_IMM

from ir.net import (
    Evidence,
    Kind,
    Net,
    ResourceKind,
    TransKind,
    Transition,
    isa_region,
    wr_place,
)
from lift.harvest import Candidate, _disasm, _text
from oracle.btb import BtbAdapter
from oracle.runner import NativeResult


def _slice_insns(ctx, entry: Optional[int], exit: Optional[int], limit: int = 4096):
    from elftools.elf.elffile import ELFFile

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
            # keep going through small epilogues; stop after a far ret
            if insn.address - entry > 0x40:
                break
    return out


def _isa_expr(insns) -> Dict[str, Any]:
    mnems = Counter(i.mnemonic for i in insns)
    indirect = []
    for insn in insns:
        if insn.mnemonic not in ("jmp", "call") or not insn.operands:
            continue
        if insn.operands[0].type == X86_OP_IMM:
            continue
        indirect.append(insn.address)
    return {
        "kind": "isa",
        "n_insns": len(insns),
        "mnems": dict(mnems.most_common(16)),
        "indirect": [f"{a:#x}" for a in indirect[:24]],
        "uncertainty": "btb_unemulated",
    }


class TaeRecovery:
    name = "tae"
    resource = ResourceKind.BTB.value

    def match(self, cand: Candidate, ctx) -> bool:
        return cand.resource == self.resource and cand.trigger == "indirect_jmp"

    def recover(self, cand: Candidate, ctx) -> Optional[Net]:
        if cand.unresolved and cand.confidence < 0.45:
            ctx.reject(cand, "unresolved_btb")
            return None
        adapter: BtbAdapter = ctx.btb or BtbAdapter()
        samples = (ctx.btb_samples or {}).get(cand.name)
        result: NativeResult
        if samples:
            trained = samples.get("trained") or samples.get("targets") or []
            untrained = samples.get("untrained") or []
            if untrained and trained:
                result = adapter.test_index_causality(
                    cand.phys_keys[0] if cand.phys_keys else cand.name,
                    untrained,
                    trained,
                    expected_target=samples.get("expected"),
                )
            else:
                result = adapter.observe_target(trained or samples.get("targets") or [])
            if result.causal is False and result.uncertainty == "no_effect":
                ctx.reject(cand, "btb_no_effect")
                return None
        else:
            result = adapter.unavailable("unemulated")
        insns = _slice_insns(ctx, cand.entry, cand.exit)
        expr = _isa_expr(insns)
        if result.uncertainty:
            expr["uncertainty"] = result.uncertainty
        ev = result.to_evidence()
        ev.observations = list(ev.observations) + [{"harvest": cand.to_dict(), "isa": expr}]
        net = Net(name=cand.name, source=ctx.path)
        places = []
        for k in cand.phys_keys[:16] or [f"{cand.entry:#x}" if cand.entry else cand.name]:
            p = wr_place(f"{cand.name}.{k}", self.resource, phys_key=str(k), evidence=ev)
            assert p.kind == Kind.PERSISTENT
            net.add_place(p)
            places.append(p.name)
        tname = f"{cand.name}.body"
        net.add_transition(
            Transition(
                name=tname,
                kind=TransKind.EXPR,
                expr=expr,
                inputs=places,
                outputs=places,
                addr=cand.entry,
                trigger=cand.trigger,
                resource=self.resource,
                evidence=ev,
                window_len=expr.get("n_insns"),
            )
        )
        net.add_region(
            isa_region(
                f"{cand.name}_isa",
                self.resource,
                places=places,
                transitions=[tname],
                trigger=cand.trigger,
                evidence=ev,
                entry=cand.entry,
                exit=cand.exit,
                window_len=expr.get("n_insns"),
            )
        )
        adapter.record(net, places[0], phys_key=cand.phys_keys[0] if cand.phys_keys else None, result=result)
        net.native["family"] = self.name
        net.native["btb"] = result.to_dict()
        net.compose()
        return net
