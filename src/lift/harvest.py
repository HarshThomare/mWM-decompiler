"""Whole-ELF µWM locator. CFG + semantic evidence; no DualGate / __weird__ symbols.

CACM Table 1 (Evtyushkin et al., Computing with Time) is seed evidence for
WR kinds and window triggers, not a closed opcode language. Extra patterns
(address-formation imul, dual-rail pairs, timed-load sandwiches, invlpg) are
recorded with provenance. Unresolved sites are kept, not dropped.
"""

from __future__ import annotations

import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from elftools.elf.elffile import ELFFile

_SRC = Path(__file__).resolve().parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ir.net import (
    Evidence,
    Region,
    ResourceKind,
    isa_region,
    lut_region,
    resource_spec,
    wr_place,
)
from lift.flexo_static import (
    _canon,
    _find_perm,
    _find_wr_offset,
    _logical_wire,
    _perm_id,
    _reg,
    _tag_wire,
)

# CACM Table 1 WR kinds → typed IR resource when one exists.
_CACM_WR = {
    "dcache": ResourceKind.DCACHE.value,
    "icache": None,
    "rob": None,
    "mul": None,
    "bp": None,
    "btb": ResourceKind.BTB.value,
    "vmx": None,
}
_TYPED = {ResourceKind.DCACHE.value, ResourceKind.BTB.value, ResourceKind.TLB.value}

_PREFETCH = {
    "prefetch",
    "prefetcht0",
    "prefetcht1",
    "prefetcht2",
    "prefetchnta",
    "prefetchw",
    "prefetchwt1",
}
_VMX = {
    "vmxon",
    "vmxoff",
    "vmlaunch",
    "vmresume",
    "vmread",
    "vmwrite",
    "vmptrld",
    "vmptrst",
    "vmclear",
    "vmcall",
}
_TIMER = {"rdtsc", "rdtscp"}
_FLUSH = {"clflush", "clflushopt"}


@dataclass
class Primitive:
    addr: int
    mnem: str
    role: str  # trigger | timer | probe | addr_form | seed
    kind_guess: Optional[str] = None
    target: Optional[str] = None
    note: str = ""
    func: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "addr": self.addr,
            "mnem": self.mnem,
            "role": self.role,
        }
        if self.kind_guess:
            d["kind_guess"] = self.kind_guess
        if self.target is not None:
            d["target"] = self.target
        if self.note:
            d["note"] = self.note
        return d


@dataclass
class Candidate:
    """Located µWM region. Compatible with Evidence / wr_place / Region."""

    name: str
    resource: Optional[str]
    trigger: Optional[str]
    entry: Optional[int]
    exit: Optional[int]
    phys_keys: List[str] = field(default_factory=list)
    encoding: Optional[str] = None
    primitives: List[Primitive] = field(default_factory=list)
    provenance: List[str] = field(default_factory=list)
    confidence: float = 0.0
    unresolved: bool = True

    def as_evidence(self) -> Evidence:
        roles = Counter(p.role for p in self.primitives)
        kinds = Counter(p.kind_guess for p in self.primitives if p.kind_guess)
        obs: List[Dict[str, Any]] = [p.to_dict() for p in self.primitives[:24]]
        obs.append(
            {
                "provenance": list(self.provenance),
                "n_primitives": len(self.primitives),
                "roles": dict(roles),
                "kind_guesses": dict(kinds),
                "unresolved": self.unresolved,
                "entry": self.entry,
                "exit": self.exit,
            }
        )
        return Evidence(trigger=self.trigger, observations=obs, confidence=self.confidence)

    def as_places(self):
        if self.resource not in _TYPED:
            return []
        ev = self.as_evidence()
        keys = self.phys_keys or (
            [f"{self.entry:#x}"] if self.entry is not None else [self.name]
        )
        places = []
        for k in keys[:16]:
            places.append(wr_place(f"{self.name}.{k}", self.resource, phys_key=str(k), evidence=ev))
        return places

    def as_region(self) -> Optional[Region]:
        if self.resource not in _TYPED:
            return None
        ev = self.as_evidence()
        places = [p.name for p in self.as_places()]
        kw = dict(
            name=self.name,
            resource=self.resource,
            places=places,
            trigger=self.trigger,
            evidence=ev,
            entry=self.entry,
            exit=self.exit,
        )
        if self.resource == ResourceKind.BTB.value:
            return isa_region(**kw)
        return lut_region(**kw)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "resource": self.resource,
            "trigger": self.trigger,
            "entry": self.entry,
            "exit": self.exit,
            "phys_keys": list(self.phys_keys),
            "encoding": self.encoding,
            "confidence": self.confidence,
            "unresolved": self.unresolved,
            "provenance": list(self.provenance),
            "primitives": [p.to_dict() for p in self.primitives[:24]],
            "n_primitives": len(self.primitives),
        }
        d["evidence"] = self.as_evidence().to_dict()
        return d


@dataclass
class HarvestResult:
    source: str
    candidates: List[Candidate]
    primitives: List[Primitive]
    funcs: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "n_primitives": len(self.primitives),
            "n_candidates": len(self.candidates),
            "funcs": self.funcs,
            "candidates": [c.to_dict() for c in self.candidates],
        }


def _text(elf: ELFFile) -> Tuple[int, int, bytes]:
    text = elf.get_section_by_name(".text")
    if text is None:
        raise ValueError("ELF has no .text")
    addr = int(text["sh_addr"])
    data = text.data()
    return addr, addr + len(data), data


def _disasm(code: bytes, addr: int) -> List:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.skipdata = True
    return [i for i in md.disasm(code, addr) if i.id != 0]


def _imm_target(insn) -> Optional[int]:
    if not insn.operands:
        return None
    op = insn.operands[0]
    if op.type == X86_OP_IMM:
        return int(op.imm)
    return None


def _mem_target(insn, op) -> str:
    mem = op.mem
    base = insn.reg_name(mem.base) if mem.base else None
    index = insn.reg_name(mem.index) if mem.index else None
    if base == "rip":
        return f"{insn.address + insn.size + mem.disp:#x}"
    parts = []
    if base:
        parts.append(_canon(base) or base)
    if index:
        idx = _canon(index) or index
        parts.append(f"{idx}*{mem.scale}" if mem.scale not in (0, 1) else idx)
    if mem.disp:
        parts.append(f"{mem.disp:#x}")
    return "+".join(parts) if parts else "unknown"


def _is_rip_mem(insn) -> bool:
    if not insn.operands:
        return False
    op = insn.operands[0]
    if op.type != X86_OP_MEM or not op.mem.base:
        return False
    return insn.reg_name(op.mem.base) == "rip"


def _is_load(insn) -> bool:
    if insn.mnemonic not in ("mov", "movzx", "movsx", "movsxd", "movabs") or len(insn.operands) < 2:
        return False
    return insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_MEM


def _zeroed_before(insns: Sequence, i: int, reg: str) -> bool:
    for j in range(i - 1, max(-1, i - 10), -1):
        prev = insns[j]
        ops = prev.operands
        if prev.mnemonic in ("xor", "sub") and len(ops) >= 2:
            a, b = _reg(prev, ops[0]), _reg(prev, ops[1])
            if a and a == b == reg:
                return True
        if prev.mnemonic in ("mov", "xor") and ops and ops[0].type == X86_OP_REG:
            dest = _reg(prev, ops[0])
            if dest == reg:
                if prev.mnemonic == "xor" and len(ops) >= 2 and _reg(prev, ops[1]) == dest:
                    return True
                if ops[1].type == X86_OP_IMM and ops[1].imm == 0:
                    return True
                return False
    return False


def _rsp_mem(insn) -> bool:
    if not insn.operands or insn.operands[0].type != X86_OP_MEM:
        return False
    mem = insn.operands[0].mem
    if mem.index:
        return False
    base = insn.reg_name(mem.base) if mem.base else None
    return _canon(base) == "rsp" and mem.disp == 0


def _func_entries(insns: Sequence, text_lo: int, text_hi: int) -> List[int]:
    entries: Set[int] = set()
    if insns:
        entries.add(insns[0].address)
    by_addr = {i.address for i in insns}
    for insn in insns:
        if insn.mnemonic == "endbr64":
            entries.add(insn.address)
        if insn.mnemonic != "call":
            continue
        tgt = _imm_target(insn)
        if tgt is not None and text_lo <= tgt < text_hi and tgt in by_addr:
            entries.add(tgt)
    return sorted(entries)


def _assign_funcs(insns: Sequence, entries: Sequence[int]) -> Dict[int, int]:
    """Map insn address → function entry (interval to next call-target)."""
    if not entries:
        return {}
    bounds = list(entries) + [insns[-1].address + insns[-1].size]
    out: Dict[int, int] = {}
    ei = 0
    for insn in insns:
        while ei + 1 < len(bounds) and insn.address >= bounds[ei + 1]:
            ei += 1
        out[insn.address] = bounds[ei]
    return out


def _call_graph(insns: Sequence, func_of: Dict[int, int], text_lo: int, text_hi: int) -> Dict[int, Set[int]]:
    g: Dict[int, Set[int]] = defaultdict(set)
    for insn in insns:
        if insn.mnemonic != "call":
            continue
        tgt = _imm_target(insn)
        if tgt is None or not (text_lo <= tgt < text_hi):
            continue
        src = func_of.get(insn.address)
        dst = func_of.get(tgt, tgt)
        if src is not None:
            g[src].add(dst)
    return g


def _scan_primitives(insns: Sequence, text_lo: int, text_hi: int) -> List[Primitive]:
    prims: List[Primitive] = []
    n = len(insns)

    def add(i, role, kind=None, target=None, note=""):
        insn = insns[i]
        prims.append(
            Primitive(
                addr=insn.address,
                mnem=insn.mnemonic,
                role=role,
                kind_guess=kind,
                target=target,
                note=note,
            )
        )

    for i, insn in enumerate(insns):
        mnem = insn.mnemonic
        ops = insn.operands

        if mnem in _FLUSH and ops:
            tgt = _mem_target(insn, ops[0]) if ops[0].type == X86_OP_MEM else "unknown"
            kind = "icache" if tgt.startswith("0x") and text_lo <= int(tgt, 16) < text_hi else "dcache"
            add(i, "probe", kind, tgt, "cacm.flush")
            continue
        if mnem in _PREFETCH and ops:
            tgt = _mem_target(insn, ops[0]) if ops[0].type == X86_OP_MEM else "unknown"
            add(i, "probe", "dcache", tgt, "semantic.prefetch")
            continue
        if mnem == "invlpg" and ops:
            tgt = _mem_target(insn, ops[0]) if ops[0].type == X86_OP_MEM else "unknown"
            add(i, "probe", "tlb", tgt, "semantic.invlpg")
            continue
        if mnem in _TIMER:
            add(i, "timer", None, None, "cacm.timer")
            continue
        if mnem in ("lfence", "mfence", "sfence"):
            add(i, "seed", None, None, "semantic.fence")
            continue
        if mnem in ("xbegin", "xabort", "xend"):
            add(i, "trigger", None, None, "cacm.window.tsx")
            continue
        if mnem in ("ud2", "int3"):
            add(i, "trigger", None, None, "cacm.window.exception")
            continue
        if mnem in _VMX:
            add(i, "seed", "vmx", None, "cacm.vmx")
            continue
        if mnem in ("div", "idiv") and ops:
            op = ops[0]
            if op.type == X86_OP_REG:
                reg = _canon(insn.reg_name(op.reg))
                if reg and _zeroed_before(insns, i, reg):
                    add(i, "trigger", None, reg, "cacm.window.exception")
            continue
        if mnem == "imul" and len(ops) == 3 and ops[2].type == X86_OP_IMM:
            imm = ops[2].imm
            if 0x100 <= imm <= 0x2000 and imm % 16 == 0:
                kind = "tlb" if imm % 0x1000 == 0 else "dcache"
                add(i, "addr_form", kind, hex(imm), "semantic.wr_stride")
            continue
        if mnem in ("jmp", "call") and ops and ops[0].type != X86_OP_IMM and not _is_rip_mem(insn):
            tgt = insn.op_str
            add(i, "trigger", "btb", tgt, "cacm.btb.indirect")
            continue
        if mnem in ("add", "or", "xor") and _rsp_mem(insn):
            # poison return address: add/xor [rsp], *
            add(i, "trigger", None, "[rsp]", "cacm.window.rsb")

    # Timed load between nearby rdtsc/rdtscp is a dcache (or tlb) read, not a closed opcode.
    timer_idx = [i for i, ins in enumerate(insns) if ins.mnemonic in _TIMER]
    for a, b in zip(timer_idx, timer_idx[1:]):
        if insns[b].address - insns[a].address > 0x40:
            continue
        for k in range(a + 1, b):
            if _is_load(insns[k]):
                op = insns[k].operands[1]
                tgt = _mem_target(insns[k], op) if op.type == X86_OP_MEM else "unknown"
                add(k, "probe", "dcache", tgt, "semantic.timed_load")

    # rsb: [rsp] write then ret in the next few insns
    by_addr = {p.addr: p for p in prims}
    for i, insn in enumerate(insns):
        p = by_addr.get(insn.address)
        if p is None or p.note != "cacm.window.rsb":
            continue
        for j in range(i + 1, min(n, i + 6)):
            if insns[j].mnemonic in ("ret", "retf"):
                p.note = "cacm.window.rsb.poison"
                break

    return prims


def _alias_wr_targets(insns: Sequence) -> Tuple[Optional[int], List[str]]:
    """Copy-prop helper: imul WR stride + dual-rail pointer pairs → phys_keys.

    Not the discovery entry point; only runs after harvest already saw a stride.
    """
    wr_off = _find_wr_offset(insns)
    if not wr_off or wr_off == 0x440:
        # 0x440 is flexo_static's default when no stride exists; trust counts.
        counts = Counter()
        for insn in insns:
            if insn.mnemonic != "imul" or len(insn.operands) != 3:
                continue
            if insn.operands[2].type == X86_OP_IMM:
                imm = insn.operands[2].imm
                if 0x100 <= imm <= 0x2000 and imm % 16 == 0:
                    counts[imm] += 1
        if not counts:
            return None, []
        wr_off = counts.most_common(1)[0][0]
    array_disp, nslots = _find_perm(insns)
    regs: Dict[str, Any] = {}
    rbp_slots: Dict[int, Any] = {}
    rails: List[int] = []

    def set_reg(r, tag):
        if r:
            regs[r] = tag

    def get_reg(r):
        return regs.get(r) if r else None

    def kill(r):
        if r:
            regs.pop(r, None)

    for insn in insns:
        ops = insn.operands
        mnem = insn.mnemonic
        if mnem == "movsxd" and len(ops) >= 2:
            set_reg(_reg(insn, ops[0]), get_reg(_reg(insn, ops[1])))
            continue
        if mnem in ("movzx", "movsx") and len(ops) >= 2:
            if ops[1].type == X86_OP_REG:
                set_reg(_reg(insn, ops[0]), get_reg(_reg(insn, ops[1])))
            else:
                kill(_reg(insn, ops[0]))
            continue
        if mnem == "lea" and len(ops) >= 2 and ops[1].type == X86_OP_MEM:
            dst = _reg(insn, ops[0])
            mem = ops[1].mem
            tags = []
            if mem.base:
                tags.append(get_reg(_canon(insn.reg_name(mem.base))))
            if mem.index:
                tags.append(get_reg(_canon(insn.reg_name(mem.index))))
            off_tag = next((t for t in tags if t and t[0] in ("off", "ptr", "idx")), None)
            if off_tag:
                set_reg(dst, ("ptr", off_tag[1]))
            else:
                kill(dst)
            continue
        if mnem == "imul" and len(ops) == 3 and ops[2].type == X86_OP_IMM and ops[2].imm == wr_off:
            dest, src = _reg(insn, ops[0]), _reg(insn, ops[1])
            wid = _tag_wire(get_reg(src))
            if wid is not None:
                set_reg(dest, ("off", wid))
            else:
                kill(dest)
            continue
        if mnem in ("add", "sub") and len(ops) >= 2:
            dest = _reg(insn, ops[0])
            if dest is None:
                continue
            if ops[1].type == X86_OP_IMM and ops[1].imm == 1 and mnem == "add":
                wid = _tag_wire(get_reg(dest))
                if wid is not None:
                    set_reg(dest, ("idx", wid))
                    continue
            if ops[1].type == X86_OP_REG:
                src = _reg(insn, ops[1])
                dt, st = get_reg(dest), get_reg(src)
                pick = None
                for t in (st, dt):
                    if t and t[0] in ("off", "ptr"):
                        pick = t
                        break
                    if t and t[0] == "idx":
                        pick = ("off", t[1])
                if pick:
                    set_reg(dest, ("ptr", pick[1]) if pick[0] != "ptr" else pick)
                    continue
            kill(dest)
            continue
        if mnem == "mov" and len(ops) >= 2:
            dst, src = ops[0], ops[1]
            if dst.type == X86_OP_REG and src.type == X86_OP_REG:
                set_reg(_reg(insn, dst), get_reg(_reg(insn, src)))
                continue
            if dst.type == X86_OP_REG and src.type == X86_OP_MEM:
                mem = src.mem
                base = _canon(insn.reg_name(mem.base) if mem.base else None)
                dest = _reg(insn, dst)
                if base == "rbp" and not mem.index:
                    tag = rbp_slots.get(mem.disp)
                    if tag:
                        set_reg(dest, tag)
                    else:
                        pid = _perm_id(mem.disp, array_disp, nslots)
                        set_reg(dest, ("perm", pid) if pid is not None else None)
                    continue
                if mem.index and base == "rbp":
                    pid = _perm_id(mem.disp, array_disp, nslots)
                    if pid is not None:
                        set_reg(dest, ("perm", pid))
                    else:
                        kill(dest)
                    continue
                kill(dest)
                continue
            if dst.type == X86_OP_MEM and src.type == X86_OP_REG:
                mem = dst.mem
                base = _canon(insn.reg_name(mem.base) if mem.base else None)
                if base == "rbp" and not mem.index:
                    rbp_slots[mem.disp] = get_reg(_reg(insn, src))
                continue
            if dst.type == X86_OP_REG:
                kill(_reg(insn, dst))
            continue
        if mnem == "clflush" and ops and ops[0].type == X86_OP_MEM:
            mem = ops[0].mem
            for rname in (
                _canon(insn.reg_name(mem.base)) if mem.base else None,
                _canon(insn.reg_name(mem.index)) if mem.index else None,
            ):
                wid = _tag_wire(get_reg(rname))
                if wid is not None:
                    rails.append(wid)
        if ops and ops[0].type == X86_OP_REG and mnem not in (
            "cmp",
            "test",
            "clflush",
            "mfence",
            "nop",
            "and",
            "or",
            "shr",
            "shl",
        ):
            kill(_reg(insn, ops[0]))

    keys: List[str] = []
    seen = set()
    for w in rails:
        name = _logical_wire(w)
        if name not in seen:
            seen.add(name)
            keys.append(name)
    # dual-rail pairs: consecutive rail ids collapse via _logical_wire already
    return wr_off, keys


def _score(
    resource: Optional[str],
    trigger: Optional[str],
    n_probe: int,
    n_timer: int,
    n_addr: int,
    inherited: bool,
    n_alias: int,
    n_btb: int = 0,
) -> Tuple[float, bool]:
    conf = 0.0
    if n_probe:
        conf += 0.22
    if n_timer:
        conf += 0.18
    if trigger:
        conf += 0.22
    if n_addr:
        conf += 0.15
    if inherited:
        conf += 0.12
    if n_alias:
        conf += 0.08
    if n_btb >= 3:
        conf += 0.25
    if n_btb >= 32:
        conf += 0.15
    if resource in _TYPED and trigger:
        conf += 0.08
    conf = min(1.0, conf)
    unresolved = conf < 0.45 or resource not in _TYPED or not trigger
    return conf, unresolved


def _uses_helpers(prims: Sequence[Primitive]) -> bool:
    """Inherited RSB/timer helpers attach only to gadgets, not CRT/jmp-rax stubs."""
    for p in prims:
        if p.role in ("probe", "addr_form"):
            return True
        if p.note in ("cacm.window.exception", "cacm.window.tsx") or p.note.startswith("cacm.window.rsb"):
            return True
    return False


def _trigger_of(
    prims: Sequence[Primitive],
    inherited: Sequence[str],
    resource: Optional[str] = None,
    n_ret: int = 0,
    n_probe: int = 0,
) -> Tuple[Optional[str], List[str]]:
    notes = [p.note for p in prims]
    prov: List[str] = []
    trig = None
    n_btb = sum(1 for p in prims if p.kind_guess == "btb")
    if resource == ResourceKind.BTB.value and n_btb:
        trig = "indirect_jmp"
        prov.append("cacm.btb.indirect")
        return trig, prov
    if any(n.startswith("cacm.window.rsb") for n in notes) or "helper.rsb" in inherited:
        trig = "rsb"
        prov.append("cacm.window.rsb" if any(n.startswith("cacm.window.rsb") for n in notes) else "cfg.call_rsb")
    if any(p.note == "cacm.window.exception" for p in prims) or "helper.exception" in inherited:
        trig = "exception"
        prov.append("cacm.window.exception")
    if any(p.note == "cacm.window.tsx" for p in prims):
        trig = "tsx"
        prov.append("cacm.window.tsx")
    if trig is None and n_ret >= 8 and n_probe:
        trig = "rsb"
        prov.append("semantic.ret_window")
    if "helper.timer" in inherited:
        prov.append("cfg.call_timer")
    return trig, prov


def _resource_of(prims: Sequence[Primitive]) -> Tuple[Optional[str], List[str]]:
    kinds = Counter(p.kind_guess for p in prims if p.kind_guess)
    prov = []
    if kinds.get("tlb") and kinds["tlb"] >= kinds.get("dcache", 0) and kinds["tlb"] >= kinds.get("btb", 0):
        prov.append("semantic.tlb" if any(p.note == "semantic.invlpg" for p in prims) else "semantic.wr_stride")
        return ResourceKind.TLB.value, prov
    if kinds.get("dcache"):
        prov.append("cacm.dcache")
        return ResourceKind.DCACHE.value, prov
    if kinds.get("btb"):
        prov.append("cacm.btb")
        return ResourceKind.BTB.value, prov
    if kinds.get("icache"):
        return "icache", ["cacm.icache"]
    if kinds.get("vmx"):
        return "vmx", ["cacm.vmx"]
    extra = [k for k, _ in kinds.most_common() if k]
    return (extra[0] if extra else None), ([f"cacm.{extra[0]}"] if extra else [])


def _phys_keys(prims: Sequence[Primitive], aliases: Sequence[str]) -> List[str]:
    keys: List[str] = []
    seen = set()
    for a in aliases:
        if a not in seen:
            seen.add(a)
            keys.append(a)
    for p in prims:
        if p.kind_guess == "btb":
            t = f"{p.addr:#x}"
        elif p.role == "probe" and p.target and p.target.startswith("0x"):
            t = p.target
        else:
            continue
        if t in seen:
            continue
        seen.add(t)
        keys.append(t)
        if len(keys) >= 16:
            break
    return keys


def _classify_func(prims: Sequence[Primitive], n_insns: int, inherited: Sequence[str]) -> str:
    n_probe = sum(1 for p in prims if p.role == "probe")
    n_timer = sum(1 for p in prims if p.role == "timer")
    n_addr = sum(1 for p in prims if p.role == "addr_form")
    n_btb = sum(1 for p in prims if p.kind_guess == "btb")
    rsb = any(p.note.startswith("cacm.window.rsb") for p in prims)
    exc = any(p.note == "cacm.window.exception" for p in prims)
    if n_timer and n_insns <= 24 and n_addr == 0 and n_btb == 0 and not rsb and not exc:
        return "helper_timer"
    if rsb and n_probe == 0 and n_addr == 0 and n_btb == 0:
        return "helper_rsb"
    if exc and n_probe == 0 and n_addr == 0 and n_insns <= 32:
        return "helper_exception"
    if (rsb or "helper.rsb" in inherited or "helper.exception" in inherited) and n_probe == 0 and n_addr == 0 and n_btb == 0:
        return "helper_window"
    if n_probe or n_addr or n_btb >= 2 or (exc and n_timer) or (exc and n_probe):
        return "candidate"
    if prims:
        return "weak"
    return "empty"


def _inherit(entry: int, graph: Dict[int, Set[int]], cls: Dict[int, str], depth: int = 3) -> List[str]:
    out: List[str] = []
    seen = {entry}
    stack = [(c, 1) for c in graph.get(entry, ())]
    while stack:
        node, d = stack.pop()
        if node in seen or d > depth:
            continue
        seen.add(node)
        kind = cls.get(node)
        if kind == "helper_timer":
            out.append("helper.timer")
        elif kind == "helper_rsb":
            out.append("helper.rsb")
        elif kind == "helper_exception":
            out.append("helper.exception")
        elif kind == "helper_window":
            out.append("helper.rsb")
            stack.extend((c, d + 1) for c in graph.get(node, ()))
        else:
            stack.extend((c, d + 1) for c in graph.get(node, ()))
    return out


def _split_exception_windows(prims: Sequence[Primitive]) -> Optional[List[List[Primitive]]]:
    trigs = sorted(p.addr for p in prims if p.note == "cacm.window.exception")
    if len(trigs) < 2:
        return None
    if min(b - a for a, b in zip(trigs, trigs[1:])) < 0x100:
        return None
    groups: List[List[Primitive]] = [[] for _ in trigs]
    for p in prims:
        nearest = min(range(len(trigs)), key=lambda i: abs(p.addr - trigs[i]))
        if abs(p.addr - trigs[nearest]) <= 0x280:
            groups[nearest].append(p)
    groups = [g for g in groups if g]
    return groups if len(groups) >= 2 else None


def _split_resources(prims: Sequence[Primitive]) -> List[List[Primitive]]:
    """If dcache and btb evidence coexist, keep them as separate candidates."""
    cache = [p for p in prims if p.kind_guess in ("dcache", "tlb", "icache") or p.role in ("probe", "addr_form", "timer")]
    btb = [p for p in prims if p.kind_guess == "btb"]
    other = [p for p in prims if p not in cache and p not in btb]
    if cache and len(btb) >= 3:
        return [cache + other, btb + other]
    return [list(prims)]


def _candidate_from(
    name: str,
    prims: List[Primitive],
    entry: int,
    exit: int,
    inherited: Sequence[str],
    insns: Sequence,
) -> Candidate:
    n_probe = sum(1 for p in prims if p.role == "probe")
    n_timer = sum(1 for p in prims if p.role == "timer") + (1 if "helper.timer" in inherited else 0)
    n_addr = sum(1 for p in prims if p.role == "addr_form")
    n_btb = sum(1 for p in prims if p.kind_guess == "btb")
    n_ret = sum(1 for insn in insns if insn.mnemonic == "ret")
    resource, rprov = _resource_of(prims)
    trigger, tprov = _trigger_of(
        prims, inherited, resource=resource, n_ret=n_ret, n_probe=n_probe
    )
    aliases: List[str] = []
    wr_off = None
    if any(p.role == "addr_form" for p in prims) and len(insns) <= 8000:
        wr_off, aliases = _alias_wr_targets(insns)
        if wr_off:
            tprov = list(tprov) + [f"semantic.wr_stride={wr_off:#x}"]
        if aliases:
            tprov = list(tprov) + ["flexo.copy_prop.dual_rail"]
    provenance = []
    for x in list(rprov) + list(tprov) + [p.note for p in prims if p.note]:
        if x and x not in provenance:
            provenance.append(x)
    for h in inherited:
        if h not in provenance:
            provenance.append(h)
    conf, unresolved = _score(
        resource,
        trigger,
        n_probe,
        n_timer,
        n_addr,
        bool(inherited),
        len(aliases),
        n_btb=n_btb,
    )
    encoding = resource_spec(resource).encoding if resource in _TYPED else None
    keys = _phys_keys(prims, aliases)
    if not keys and entry is not None:
        keys = [f"{entry:#x}"]
    return Candidate(
        name=name,
        resource=resource,
        trigger=trigger,
        entry=entry,
        exit=exit,
        phys_keys=keys,
        encoding=encoding,
        primitives=prims,
        provenance=provenance,
        confidence=round(conf, 3),
        unresolved=unresolved,
    )


def harvest_elf(path: str) -> HarvestResult:
    """Locate µWM candidate regions in a (possibly stripped) ELF."""
    path = str(path)
    with open(path, "rb") as f:
        elf = ELFFile(f)
        text_lo, text_hi, code = _text(elf)
    insns = _disasm(code, text_lo)
    if not insns:
        return HarvestResult(source=path, candidates=[], primitives=[])

    entries = _func_entries(insns, text_lo, text_hi)
    func_of = _assign_funcs(insns, entries)
    graph = _call_graph(insns, func_of, text_lo, text_hi)
    insns_by_func: Dict[int, List] = defaultdict(list)
    for insn in insns:
        e = func_of.get(insn.address)
        if e is not None:
            insns_by_func[e].append(insn)
    prims = _scan_primitives(insns, text_lo, text_hi)
    for p in prims:
        p.func = func_of.get(p.addr)

    by_func: Dict[int, List[Primitive]] = defaultdict(list)
    for p in prims:
        if p.func is not None:
            by_func[p.func].append(p)

    n_insns = Counter(func_of[i.address] for i in insns if i.address in func_of)
    cls: Dict[int, str] = {}
    for e in entries:
        cls[e] = _classify_func(by_func.get(e, []), n_insns.get(e, 0), [])

    # second pass with one-level helper tags so DualGate→mod_ret is a window helper
    for e in entries:
        inh = _inherit(e, graph, cls)
        cls[e] = _classify_func(by_func.get(e, []), n_insns.get(e, 0), inh)

    candidates: List[Candidate] = []
    used: Set[int] = set()
    idx = 0
    for e in entries:
        local = by_func.get(e, [])
        if not local:
            continue
        inh = _inherit(e, graph, cls)
        if not _uses_helpers(local):
            inh = []
        kind = _classify_func(local, n_insns.get(e, 0), inh)
        if kind.startswith("helper") or kind == "empty":
            continue
        fins = insns_by_func.get(e, [])
        exit_addr = (fins[-1].address + fins[-1].size) if fins else e
        groups = _split_exception_windows(local)
        if groups is None:
            groups = _split_resources(local)
        for g in groups:
            name = f"c{idx}"
            idx += 1
            cand = _candidate_from(name, g, e, exit_addr, inh, fins)
            candidates.append(cand)
            used.update(id(p) for p in g)

    # leftover primitives (should be rare) — retain as unresolved
    for p in prims:
        if id(p) in used:
            continue
        if p.func is not None and cls.get(p.func, "").startswith("helper"):
            continue
        if p.role in ("seed",) and p.note == "semantic.fence":
            continue
        cand = Candidate(
            name=f"c{idx}",
            resource=_CACM_WR.get(p.kind_guess or "", p.kind_guess),
            trigger=None,
            entry=p.addr,
            exit=p.addr,
            phys_keys=[p.target] if p.target else [f"{p.addr:#x}"],
            primitives=[p],
            provenance=[p.note or p.role],
            confidence=0.15,
            unresolved=True,
        )
        idx += 1
        candidates.append(cand)

    candidates.sort(key=lambda c: (c.unresolved, -c.confidence, c.entry or 0))
    return HarvestResult(source=path, candidates=candidates, primitives=prims, funcs=entries)


def self_check() -> None:
    repo = Path(__file__).resolve().parents[2]
    flexo = repo / "src/gates/flexo/gates/gate_and.elf"
    gitm = repo / "src/gates/gitm/main_and.elf"
    h = harvest_elf(str(flexo))
    dcache_rsb = [
        c
        for c in h.candidates
        if c.resource == "dcache" and c.trigger == "rsb" and not c.unresolved
    ]
    assert len(dcache_rsb) >= 8, (len(dcache_rsb), [c.to_dict() for c in h.candidates[:4]])
    assert all(c.unresolved for c in h.candidates if c.resource == "btb")
    assert any("semantic.wr_stride" in " ".join(c.provenance) for c in dcache_rsb)
    assert any(k.startswith("w") for k in dcache_rsb[0].phys_keys)
    # copy-prop is a helper, not required to resolve every rail
    ev = dcache_rsb[0].as_evidence()
    assert ev.trigger == "rsb" and ev.confidence is not None and ev.confidence >= 0.45
    place = dcache_rsb[0].as_places()[0]
    assert place.resource == "dcache" and place.encoding == "dual_rail" and place.phys_key
    region = dcache_rsb[0].as_region()
    assert region is not None and region.kind.value == "lut" and region.resource == "dcache"

    g = harvest_elf(str(gitm))
    gitm_hit = [
        c
        for c in g.candidates
        if c.resource == "dcache" and c.trigger == "exception" and not c.unresolved
    ]
    assert gitm_hit, [c.to_dict() for c in g.candidates[:6]]
    gev = gitm_hit[0].as_evidence()
    assert gev.trigger == "exception" and gev.observations
    # harvest must not need symbols: strip-equivalent is "we never read .symtab"
    print(
        "harvest self-check:"
        f" flexo dcache+rsb={len(dcache_rsb)}/{len(h.candidates)}"
        f" gitm dcache+exception={len(gitm_hit)}/{len(g.candidates)}"
    )


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "--self-check":
        res = harvest_elf(sys.argv[1])
        import json

        print(json.dumps(res.to_dict(), indent=2)[:8000])
        print(
            f"# {res.source}: {len(res.primitives)} primitives, "
            f"{len(res.candidates)} candidates, "
            f"{sum(1 for c in res.candidates if not c.unresolved)} resolved"
        )
    else:
        self_check()
