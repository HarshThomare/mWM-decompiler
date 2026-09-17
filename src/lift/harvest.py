"""Whole-ELF µWM locator. CFG + semantic evidence; no DualGate / __weird__ symbols.

Harvest emits ordered ontology events and relation fragments
``M_out = F(M_in, A, T)``. CACM Table 1 is seed evidence, not a closed opcode
language. Incomplete fragments stay unresolved; Flexo/TAE/TLB are not assigned.
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

from ir.events import Event, EventKind, Evidence, make_event
from ir.relation import Fragment, Relation, ValidationStatus
from ir.state import (
    ArchInput,
    BTB_ENTRY,
    CACHE_OCCUPANCY,
    TLB_ENTRY,
    TimingConstraint,
    state_var,
)

# Avoid `from lift.flexo_static` — that executes lift/__init__.py (family lifters).
import importlib.util as _ilu

_fs_spec = _ilu.spec_from_file_location(
    "_harvest_flexo_static", Path(__file__).resolve().parent / "flexo_static.py"
)
_fs = _ilu.module_from_spec(_fs_spec)
assert _fs_spec.loader is not None
_fs_spec.loader.exec_module(_fs)
_canon = _fs._canon
_find_perm = _fs._find_perm
_find_wr_offset = _fs._find_wr_offset
_logical_wire = _fs._logical_wire
_perm_id = _fs._perm_id
_reg = _fs._reg
_tag_wire = _fs._tag_wire

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
_ALU = {
    "add",
    "sub",
    "and",
    "or",
    "xor",
    "shl",
    "shr",
    "sar",
    "lea",
    "imul",
    "mul",
    "neg",
    "not",
    "inc",
    "dec",
}
_LOAD_MOV = {"mov", "movzx", "movsx", "movsxd", "movabs"}
_STATE_M = frozenset(
    {
        EventKind.STATE_READ,
        EventKind.STATE_WRITE,
        EventKind.STATE_CLEAR,
        EventKind.STATE_TRAIN,
    }
)
# Flexo DualGate `WR_FAKE_OFFSET` (default 256): occupancy fill inside the RSB window.
_WR_FAKE_OFFSETS = {0x100, 256}
# Do not treat a whole `__weird__` function as one window (AES round is ~700KiB).
_MAX_WINDOW_FILL = 0x800
_COMPRESS_AFTER = 384
_KEEP_UNCOMPRESSED = frozenset(
    {
        EventKind.STATE_READ,
        EventKind.STATE_OBSERVE,
        EventKind.STATE_TRAIN,
        EventKind.WINDOW_OPEN,
        EventKind.WINDOW_SQUASH,
        EventKind.ARCH_BRANCH,
    }
)
_INHERITED_WIN = ("cfg.call_rsb", "cfg.call_exception", "cfg.call_timer")


def _has_prov(e: Event, *tags: str) -> bool:
    blob = " ".join(e.provenance)
    if e.note:
        blob = blob + " " + e.note
    return any(t in blob for t in tags)


@dataclass
class HarvestResult:
    source: str
    fragments: List[Fragment]
    events: List[Event]
    funcs: List[int] = field(default_factory=list)

    @property
    def relations(self) -> List[Relation]:
        return self.fragments

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "n_events": len(self.events),
            "n_fragments": len(self.fragments),
            "funcs": self.funcs,
            "fragments": [f.to_dict() for f in self.fragments],
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
    if insn.mnemonic not in _LOAD_MOV or len(insn.operands) < 2:
        return False
    return insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_MEM


def _is_store(insn) -> bool:
    if insn.mnemonic not in _LOAD_MOV or len(insn.operands) < 2:
        return False
    return insn.operands[0].type == X86_OP_MEM and insn.operands[1].type == X86_OP_REG


def _stack_mem(insn, op) -> bool:
    if op.type != X86_OP_MEM:
        return False
    base = insn.reg_name(op.mem.base) if op.mem.base else None
    return _canon(base) in ("rsp", "rbp")


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


def _scan_events(insns: Sequence, text_lo: int, text_hi: int) -> List[Event]:
    """Map x86 recognizers onto the ten EventKinds. One primary event per hit."""
    events: List[Event] = []

    def add(i, kind, *, operand=None, binding=None, subject=None, provenance=(), note="", **attrs):
        insn = insns[i]
        events.append(
            make_event(
                kind,
                addr=insn.address,
                insn=insn.mnemonic,
                operand=operand,
                binding=binding,
                subject=subject,
                provenance=tuple(provenance) if not isinstance(provenance, str) else (provenance,),
                note=note,
                **attrs,
            )
        )

    for i, insn in enumerate(insns):
        mnem = insn.mnemonic
        ops = insn.operands

        if mnem in _FLUSH and ops:
            tgt = _mem_target(insn, ops[0]) if ops[0].type == X86_OP_MEM else "unknown"
            line = "icache" if tgt.startswith("0x") and text_lo <= int(tgt, 16) < text_hi else "dcache"
            add(
                i,
                EventKind.STATE_CLEAR,
                operand=tgt,
                subject=CACHE_OCCUPANCY,
                provenance=("cacm.flush",),
                note="cacm.flush",
                line=line,
            )
            continue
        if mnem in _PREFETCH and ops:
            tgt = _mem_target(insn, ops[0]) if ops[0].type == X86_OP_MEM else "unknown"
            add(
                i,
                EventKind.STATE_WRITE,
                operand=tgt,
                subject=CACHE_OCCUPANCY,
                provenance=("semantic.prefetch",),
                note="semantic.prefetch",
            )
            continue
        if mnem == "invlpg" and ops:
            tgt = _mem_target(insn, ops[0]) if ops[0].type == X86_OP_MEM else "unknown"
            add(
                i,
                EventKind.STATE_CLEAR,
                operand=tgt,
                subject=TLB_ENTRY,
                provenance=("semantic.invlpg",),
                note="semantic.invlpg",
            )
            continue
        if mnem in _TIMER:
            add(i, EventKind.STATE_OBSERVE, provenance=("cacm.timer",), note="cacm.timer")
            continue
        if mnem in ("lfence", "mfence", "sfence"):
            add(i, EventKind.WINDOW_EXTEND, provenance=("semantic.fence",), note="semantic.fence")
            continue
        if mnem == "xbegin":
            add(i, EventKind.WINDOW_OPEN, provenance=("cacm.window.tsx",), note="cacm.window.tsx")
            continue
        if mnem in ("xabort", "xend"):
            add(i, EventKind.WINDOW_SQUASH, provenance=("cacm.window.tsx",), note="cacm.window.tsx")
            continue
        if mnem in ("ud2", "int3"):
            add(
                i,
                EventKind.WINDOW_OPEN,
                provenance=("cacm.window.exception",),
                note="cacm.window.exception",
            )
            continue
        if mnem in _VMX:
            add(i, EventKind.WINDOW_OPEN, provenance=("cacm.vmx",), note="cacm.vmx")
            continue
        if mnem in ("div", "idiv") and ops:
            op = ops[0]
            if op.type == X86_OP_REG:
                reg = _canon(insn.reg_name(op.reg))
                if reg and _zeroed_before(insns, i, reg):
                    add(
                        i,
                        EventKind.WINDOW_OPEN,
                        operand=reg,
                        provenance=("cacm.window.exception",),
                        note="cacm.window.exception",
                    )
            continue
        if mnem == "imul" and len(ops) == 3 and ops[2].type == X86_OP_IMM:
            imm = ops[2].imm
            if 0x100 <= imm <= 0x2000 and imm % 16 == 0:
                hint = TLB_ENTRY if imm % 0x1000 == 0 else CACHE_OCCUPANCY
                add(
                    i,
                    EventKind.ARCH_COMPUTE,
                    operand=hex(imm),
                    provenance=("semantic.wr_stride",),
                    note="semantic.wr_stride",
                    stride=imm,
                    spec_hint=hint,
                )
            continue
        if mnem in ("movzx", "movsx", "movsxd") and _is_load(insn):
            mem_op = insn.operands[1]
            if mem_op.type == X86_OP_MEM and not _stack_mem(insn, mem_op) and not _is_rip_mem(insn):
                add(
                    i,
                    EventKind.STATE_READ,
                    operand=_mem_target(insn, mem_op),
                    subject=CACHE_OCCUPANCY,
                    provenance=("semantic.occupancy_load",),
                    note="semantic.occupancy_load",
                )
                continue
        if (_is_load(insn) or _is_store(insn)) and len(insn.operands) >= 2:
            mem_op = insn.operands[1] if _is_load(insn) else insn.operands[0]
            if (
                mem_op.type == X86_OP_MEM
                and mem_op.mem.disp in _WR_FAKE_OFFSETS
                and not _stack_mem(insn, mem_op)
            ):
                add(
                    i,
                    EventKind.STATE_WRITE,
                    operand=_mem_target(insn, mem_op),
                    subject=CACHE_OCCUPANCY,
                    provenance=("semantic.wr_fake_offset",),
                    note="semantic.wr_fake_offset",
                )
                continue
        if mnem in ("jmp", "call") and ops and ops[0].type != X86_OP_IMM and not _is_rip_mem(insn):
            add(
                i,
                EventKind.ARCH_BRANCH,
                operand=insn.op_str,
                subject=BTB_ENTRY,
                provenance=("cacm.btb.indirect",),
                note="cacm.btb.indirect",
            )
            continue
        if mnem in ("add", "or", "xor") and _rsp_mem(insn):
            add(
                i,
                EventKind.WINDOW_OPEN,
                operand="[rsp]",
                provenance=("cacm.window.rsb",),
                note="cacm.window.rsb",
            )

    timer_idx = [i for i, ins in enumerate(insns) if ins.mnemonic in _TIMER]
    seen_addr = {e.addr for e in events}
    for a, b in zip(timer_idx, timer_idx[1:]):
        if insns[b].address - insns[a].address > 0x40:
            continue
        for k in range(a + 1, b):
            if not _is_load(insns[k]):
                continue
            if insns[k].address in seen_addr:
                continue
            op = insns[k].operands[1]
            tgt = _mem_target(insns[k], op) if op.type == X86_OP_MEM else "unknown"
            add(
                k,
                EventKind.STATE_READ,
                operand=tgt,
                subject=CACHE_OCCUPANCY,
                provenance=("semantic.timed_load",),
                note="semantic.timed_load",
            )
            seen_addr.add(insns[k].address)

    return events


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
    return wr_off, keys


def _classify_func(events: Sequence[Event], n_insns: int, inherited: Sequence[str]) -> str:
    n_m = sum(1 for e in events if e.kind in _STATE_M)
    n_timer = sum(1 for e in events if e.kind == EventKind.STATE_OBSERVE and _has_prov(e, "cacm.timer"))
    n_stride = sum(1 for e in events if _has_prov(e, "semantic.wr_stride"))
    n_btb = sum(1 for e in events if e.kind == EventKind.ARCH_BRANCH)
    rsb = any(_has_prov(e, "cacm.window.rsb") for e in events)
    exc = any(_has_prov(e, "cacm.window.exception") for e in events)
    if n_timer and n_insns <= 24 and n_stride == 0 and n_btb == 0 and not rsb and not exc:
        return "helper_timer"
    if rsb and n_m == 0 and n_stride == 0 and n_btb == 0:
        return "helper_rsb"
    if exc and n_m == 0 and n_stride == 0 and n_insns <= 32:
        return "helper_exception"
    if (rsb or "helper.rsb" in inherited or "helper.exception" in inherited) and n_m == 0 and n_stride == 0 and n_btb == 0:
        return "helper_window"
    if n_m or n_stride or n_btb >= 2 or (exc and n_timer) or (exc and n_m):
        return "candidate"
    if events:
        return "weak"
    return "empty"


def _uses_helpers(events: Sequence[Event]) -> bool:
    for e in events:
        if e.kind in _STATE_M:
            return True
        if e.kind == EventKind.ARCH_COMPUTE and _has_prov(e, "semantic.wr_stride"):
            return True
        if e.kind == EventKind.WINDOW_OPEN and _has_prov(
            e, "cacm.window.exception", "cacm.window.tsx", "cacm.window.rsb"
        ):
            return True
    return False


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


def _split_exception_windows(events: Sequence[Event]) -> Optional[List[List[Event]]]:
    trigs = sorted(
        e.addr
        for e in events
        if e.addr is not None
        and e.kind == EventKind.WINDOW_OPEN
        and _has_prov(e, "cacm.window.exception")
    )
    if len(trigs) < 2:
        return None
    if min(b - a for a, b in zip(trigs, trigs[1:])) < 0x100:
        return None
    groups: List[List[Event]] = [[] for _ in trigs]
    for e in events:
        if e.addr is None:
            groups[0].append(e)
            continue
        nearest = min(range(len(trigs)), key=lambda i: abs(e.addr - trigs[i]))
        if abs(e.addr - trigs[nearest]) <= 0x280:
            groups[nearest].append(e)
    groups = [g for g in groups if g]
    return groups if len(groups) >= 2 else None


def _window_kind(events: Sequence[Event]) -> str:
    if any(_has_prov(e, "cacm.window.rsb") for e in events):
        return "rsb"
    if any(_has_prov(e, "cacm.window.exception") for e in events):
        return "exception"
    if any(_has_prov(e, "cacm.window.tsx") for e in events):
        return "tsx"
    if any(_has_prov(e, "cacm.vmx") for e in events):
        return "vmx"
    if any(e.kind in (EventKind.WINDOW_OPEN, EventKind.WINDOW_SQUASH, EventKind.WINDOW_EXTEND) for e in events):
        return "window"
    return ""


def _inherited_window(e: Event) -> bool:
    return _has_prov(e, *_INHERITED_WIN)


def _window_ranges(events: Sequence[Event], func_exit: int) -> List[Tuple[int, int]]:
    """Local window bounds only. Inherited caller-entry opens must not span a whole function."""
    opens = sorted(
        e.addr
        for e in events
        if e.kind == EventKind.WINDOW_OPEN and e.addr is not None and not _inherited_window(e)
    )
    squashes = sorted(e.addr for e in events if e.kind == EventKind.WINDOW_SQUASH and e.addr is not None)
    if not opens:
        return []
    ranges: List[Tuple[int, int]] = []
    for i, a in enumerate(opens):
        nxt = opens[i + 1] if i + 1 < len(opens) else func_exit
        sq = [s for s in squashes if a < s <= nxt]
        ranges.append((a, sq[0] if sq else nxt))
    return ranges


def _add_rsb_call_windows(
    insns: Sequence,
    func_of: Dict[int, int],
    cls: Dict[int, str],
    by_func: Dict[int, List[Event]],
    events: List[Event],
) -> None:
    """`call` into an RSB helper opens the DualGate window in the callee, not the caller."""
    helpers = {e for e, kind in cls.items() if kind == "helper_rsb"}
    if not helpers:
        return
    occupied = {(e.addr, e.kind) for e in events if e.addr is not None}
    for insn in insns:
        if insn.mnemonic != "call":
            continue
        tgt = _imm_target(insn)
        if tgt not in helpers:
            continue
        src = func_of.get(insn.address)
        if src is None or cls.get(src) == "helper_rsb":
            continue
        if (insn.address, EventKind.WINDOW_OPEN) in occupied:
            continue
        ev = make_event(
            EventKind.WINDOW_OPEN,
            addr=insn.address,
            insn=insn.mnemonic,
            provenance=("cacm.window.rsb", "semantic.rsb_call"),
            note="cacm.window.rsb",
        )
        ev.attrs["func"] = src
        events.append(ev)
        by_func[src].append(ev)
        occupied.add((insn.address, EventKind.WINDOW_OPEN))


def _in_ranges(addr: int, ranges: Sequence[Tuple[int, int]]) -> bool:
    return any(lo <= addr <= hi for lo, hi in ranges)


def _add_inherited(events: List[Event], entry: int, inherited: Sequence[str]) -> None:
    if "helper.rsb" in inherited and not any(_has_prov(e, "cacm.window.rsb") for e in events):
        events.append(
            make_event(
                EventKind.WINDOW_OPEN,
                addr=entry,
                insn="call",
                provenance=("cfg.call_rsb",),
                note="cfg.call_rsb",
            )
        )
    if "helper.exception" in inherited and not any(_has_prov(e, "cacm.window.exception") for e in events):
        events.append(
            make_event(
                EventKind.WINDOW_OPEN,
                addr=entry,
                insn="call",
                provenance=("cfg.call_exception",),
                note="cfg.call_exception",
            )
        )
    if "helper.timer" in inherited and not any(_has_prov(e, "cacm.timer") for e in events):
        events.append(
            make_event(
                EventKind.STATE_OBSERVE,
                addr=entry,
                insn="call",
                provenance=("cfg.call_timer",),
                note="cfg.call_timer",
            )
        )


def _add_rsb_squash(events: List[Event], insns: Sequence) -> None:
    poisons = [e.addr for e in events if e.kind == EventKind.WINDOW_OPEN and _has_prov(e, "cacm.window.rsb") and e.addr is not None]
    if not poisons or any(e.kind == EventKind.WINDOW_SQUASH and _has_prov(e, "cacm.window.rsb") for e in events):
        return
    min_p = min(poisons)
    for insn in insns:
        if insn.address > min_p and insn.mnemonic in ("ret", "retf"):
            events.append(
                make_event(
                    EventKind.WINDOW_SQUASH,
                    addr=insn.address,
                    insn=insn.mnemonic,
                    provenance=("cacm.window.rsb.poison",),
                    note="cacm.window.rsb.poison",
                )
            )
            return


def _add_btb_state(events: List[Event]) -> None:
    """Tentative train/consume. Skip when cache/tlb evidence already dominates."""
    if any(e.subject in (CACHE_OCCUPANCY, TLB_ENTRY) for e in events):
        return
    branches = [e for e in events if e.kind == EventKind.ARCH_BRANCH]
    if not branches:
        return
    for i, e in enumerate(branches):
        kind = EventKind.STATE_READ if (len(branches) >= 3 and i == len(branches) - 1) else EventKind.STATE_TRAIN
        events.append(
            make_event(
                kind,
                addr=e.addr,
                insn=e.insn,
                operand=e.operand,
                subject=BTB_ENTRY,
                provenance=tuple(e.provenance) + ("unresolved.train_or_consume",),
                note="cacm.btb.indirect",
            )
        )


def _compress_events(events: List[Event], cap: int = _COMPRESS_AFTER) -> List[Event]:
    """Keep window/read/branch events; collapse long clflush/imul/fence runs in large functions."""
    if len(events) <= cap:
        return events
    out: List[Event] = []
    i = 0
    n = len(events)
    while i < n:
        e = events[i]
        if e.kind in _KEEP_UNCOMPRESSED:
            out.append(e)
            i += 1
            continue
        j = i + 1
        while j < n and events[j].kind == e.kind and events[j].insn == e.insn:
            j += 1
        run = j - i
        if run >= 6:
            head = events[i]
            head.attrs["repeat"] = run
            out.append(head)
            if j - 1 != i:
                tail = events[j - 1]
                tail.attrs["repeat_end"] = run
                out.append(tail)
        else:
            out.extend(events[i:j])
        i = j
    if len(out) <= cap:
        return out
    pinned = [e for e in out if e.kind in _KEEP_UNCOMPRESSED]
    rest = [e for e in out if e.kind not in _KEEP_UNCOMPRESSED]
    budget = max(0, cap - len(pinned))
    if not rest or budget >= len(rest):
        return pinned + rest
    step = max(1, len(rest) / budget)
    sampled = [rest[int(k * step)] for k in range(budget)]
    keep = pinned + sampled
    keep.sort(key=lambda e: (e.addr or 0, list(EventKind).index(e.kind) if e.kind in EventKind else 99))
    return keep


def _fill_window_arch(events: List[Event], insns: Sequence, func_exit: int) -> None:
    ranges = [(lo, hi) for lo, hi in _window_ranges(events, func_exit) if hi - lo <= _MAX_WINDOW_FILL]
    if not ranges:
        return
    occupied = {e.addr for e in events if e.addr is not None}
    rsb = _window_kind(events) == "rsb"
    cache_like = (
        any(e.subject == CACHE_OCCUPANCY for e in events)
        or any(_has_prov(e, "semantic.wr_stride", "cacm.window.exception") for e in events)
        or rsb
    )
    tlb_like = any(e.subject == TLB_ENTRY for e in events)
    for insn in insns:
        if insn.address in occupied or not _in_ranges(insn.address, ranges):
            continue
        mnem = insn.mnemonic
        ops = insn.operands
        if mnem in ("nop", "endbr64", "push", "pop", "leave", "ret", "retf", "cmp", "test"):
            continue
        if ops and ops[0].type == X86_OP_REG and _reg(insn, ops[0]) == "rsp":
            continue
        if mnem in _ALU:
            events.append(
                make_event(
                    EventKind.ARCH_COMPUTE,
                    addr=insn.address,
                    insn=mnem,
                    operand=insn.op_str,
                    provenance=("semantic.window_alu",),
                    note="semantic.window_alu",
                )
            )
            occupied.add(insn.address)
            continue
        if _is_load(insn) or _is_store(insn):
            mem_op = insn.operands[1] if _is_load(insn) else insn.operands[0]
            tgt = _mem_target(insn, mem_op) if mem_op.type == X86_OP_MEM else "unknown"
            events.append(
                make_event(
                    EventKind.ARCH_MEMORY,
                    addr=insn.address,
                    insn=mnem,
                    operand=tgt,
                    provenance=("semantic.window_mem",),
                    note="semantic.window_mem",
                )
            )
            if not _stack_mem(insn, mem_op):
                if cache_like:
                    events.append(
                        make_event(
                            EventKind.STATE_WRITE,
                            addr=insn.address,
                            insn=mnem,
                            operand=tgt,
                            subject=CACHE_OCCUPANCY,
                            provenance=("semantic.window_fill",),
                            note="semantic.window_fill",
                        )
                    )
                elif tlb_like:
                    events.append(
                        make_event(
                            EventKind.STATE_WRITE,
                            addr=insn.address,
                            insn=mnem,
                            operand=tgt,
                            subject=TLB_ENTRY,
                            provenance=("semantic.window_fill",),
                            note="semantic.window_fill",
                        )
                    )
            occupied.add(insn.address)


def _confidence(events: Sequence[Event], inherited: Sequence[str], n_alias: int) -> float:
    kinds = {e.kind for e in events}
    conf = 0.0
    if kinds & _STATE_M or EventKind.STATE_OBSERVE in kinds:
        conf += 0.22
    if kinds & {EventKind.WINDOW_OPEN, EventKind.WINDOW_SQUASH, EventKind.WINDOW_EXTEND}:
        conf += 0.22
    if EventKind.ARCH_COMPUTE in kinds:
        conf += 0.15
    n_br = sum(1 for e in events if e.kind == EventKind.ARCH_BRANCH)
    if n_br:
        conf += 0.10
    if n_br >= 3:
        conf += 0.15
    if inherited:
        conf += 0.12
    if n_alias:
        conf += 0.08
    if any(_has_prov(e, "semantic.occupancy_load") for e in events) and any(
        _has_prov(e, "semantic.rsb_call", "cacm.window.rsb") for e in events
    ):
        conf += 0.22
    if any(_inherited_window(e) for e in events) and not any(
        e.kind == EventKind.WINDOW_SQUASH for e in events
    ):
        conf = max(0.0, conf - 0.15)
    return round(min(1.0, conf), 3)


def _bind_state(rel: Relation, events: Sequence[Event], aliases: Sequence[str], wr_off: Optional[int]) -> None:
    seen_in: Set[str] = set()
    seen_out: Set[str] = set()

    def put(side: str, spec: str, key: Optional[str], ev: Optional[Event] = None) -> None:
        phys = key or (f"{ev.addr:#x}" if ev is not None and ev.addr is not None else spec)
        name = f"{rel.name}.{phys}"
        bag, seen = (rel.m_in, seen_in) if side == "in" else (rel.m_out, seen_out)
        if name in seen:
            return
        seen.add(name)
        bag[name] = state_var(name, spec, phys_key=phys)

    for e in events:
        spec = e.subject if e.subject in (CACHE_OCCUPANCY, BTB_ENTRY, TLB_ENTRY) else None
        if spec is None:
            continue
        key = e.binding or (e.operand if e.operand and not e.operand.startswith("[") else None)
        if e.kind in (EventKind.STATE_READ, EventKind.STATE_OBSERVE, EventKind.STATE_CLEAR):
            put("in", spec, key, e)
        if e.kind in (EventKind.STATE_WRITE, EventKind.STATE_TRAIN):
            put("out", spec, key, e)

    cache_like = any(e.subject == CACHE_OCCUPANCY for e in events) or any(
        _has_prov(e, "semantic.wr_stride") for e in events
    )
    if cache_like:
        for a in aliases:
            put("in", CACHE_OCCUPANCY, a)
            put("out", CACHE_OCCUPANCY, a)

    if wr_off:
        rel.add_a(ArchInput(name=f"{rel.name}.stride", domain="int", binding=hex(wr_off)))

    wk = _window_kind(events)
    win = [e for e in events if e.kind in (EventKind.WINDOW_OPEN, EventKind.WINDOW_SQUASH, EventKind.WINDOW_EXTEND)]
    if wk or win:
        rel.add_t(
            TimingConstraint(
                name=f"{rel.name}.T",
                kind=wk or "window",
                related_events=[e.id for e in win if e.id],
            )
        )


def _fragment_from(
    name: str,
    events: List[Event],
    entry: int,
    exit: int,
    inherited: Sequence[str],
    insns: Sequence,
) -> Relation:
    evs = list(events)
    wr_off = None
    aliases: List[str] = []
    if any(_has_prov(e, "semantic.wr_stride") for e in evs) and 0 < len(insns) <= 8000:
        wr_off, aliases = _alias_wr_targets(insns)
    _add_inherited(evs, entry, inherited)
    _add_rsb_squash(evs, insns)
    _add_btb_state(evs)
    _fill_window_arch(evs, insns, exit)
    evs.sort(key=lambda e: (e.addr or 0, list(EventKind).index(e.kind) if e.kind in EventKind else 99))
    evs = _compress_events(evs)

    if wr_off:
        tag = f"semantic.wr_stride={wr_off:#x}"
        for e in evs:
            if _has_prov(e, "semantic.wr_stride") and tag not in e.provenance:
                e.provenance.append(tag)
    if aliases:
        for e in evs:
            if e.subject == CACHE_OCCUPANCY and "flexo.copy_prop.dual_rail" not in e.provenance:
                e.provenance.append("flexo.copy_prop.dual_rail")

    rel = Relation(name=name, entry=entry, exit=exit, validation=ValidationStatus.UNRESOLVED)
    for e in evs:
        rel.add_event(e)
    _bind_state(rel, rel.events, aliases, wr_off)
    conf = _confidence(rel.events, inherited, len(aliases))
    obs: List[Dict[str, Any]] = [e.to_dict() for e in rel.events[:24]]
    obs.append(
        {
            "n_events": len(rel.events),
            "inherited": list(inherited),
            "unresolved": True,
            "entry": entry,
            "exit": exit,
            "aliases": list(aliases),
        }
    )
    rel.evidence = Evidence(observations=obs, confidence=conf)
    rel.confidence = conf
    return rel


def harvest_elf(path: str) -> HarvestResult:
    """Locate µWM candidate regions in a (possibly stripped) ELF."""
    path = str(path)
    with open(path, "rb") as f:
        elf = ELFFile(f)
        text_lo, text_hi, code = _text(elf)
    insns = _disasm(code, text_lo)
    if not insns:
        return HarvestResult(source=path, fragments=[], events=[])

    entries = _func_entries(insns, text_lo, text_hi)
    func_of = _assign_funcs(insns, entries)
    graph = _call_graph(insns, func_of, text_lo, text_hi)
    insns_by_func: Dict[int, List] = defaultdict(list)
    for insn in insns:
        e = func_of.get(insn.address)
        if e is not None:
            insns_by_func[e].append(insn)
    events = _scan_events(insns, text_lo, text_hi)
    for e in events:
        if e.addr is not None:
            e.attrs["func"] = func_of.get(e.addr)

    by_func: Dict[int, List[Event]] = defaultdict(list)
    for e in events:
        fn = e.attrs.get("func")
        if fn is not None:
            by_func[fn].append(e)

    n_insns = Counter(func_of[i.address] for i in insns if i.address in func_of)
    cls: Dict[int, str] = {}
    for e in entries:
        cls[e] = _classify_func(by_func.get(e, []), n_insns.get(e, 0), [])
    _add_rsb_call_windows(insns, func_of, cls, by_func, events)
    for e in entries:
        inh = _inherit(e, graph, cls)
        cls[e] = _classify_func(by_func.get(e, []), n_insns.get(e, 0), inh)

    fragments: List[Fragment] = []
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
        if all(ev.kind == EventKind.WINDOW_EXTEND for ev in local):
            continue
        fins = insns_by_func.get(e, [])
        exit_addr = (fins[-1].address + fins[-1].size) if fins else e
        groups = _split_exception_windows(local)
        if groups is None:
            groups = [list(local)]
        for g in groups:
            name = f"c{idx}"
            idx += 1
            frag = _fragment_from(name, g, e, exit_addr, inh, fins)
            frag.source = path
            fragments.append(frag)
            used.update(id(p) for p in g)

    for e in events:
        if id(e) in used:
            continue
        fn = e.attrs.get("func")
        if fn is not None and cls.get(fn, "").startswith("helper"):
            continue
        if e.kind == EventKind.WINDOW_EXTEND and _has_prov(e, "semantic.fence"):
            continue
        name = f"c{idx}"
        idx += 1
        addr = e.addr if e.addr is not None else 0
        frag = _fragment_from(name, [e], addr, addr, [], [])
        frag.source = path
        fragments.append(frag)

    fragments.sort(key=lambda f: (-(f.confidence or 0.0), f.entry or 0))
    return HarvestResult(source=path, fragments=fragments, events=events, funcs=entries)


def _flexo_style(frag: Relation) -> bool:
    kinds = {e.kind for e in frag.events}
    cache = CACHE_OCCUPANCY in frag.specs() or any(e.subject == CACHE_OCCUPANCY for e in frag.events)
    if not cache:
        return False
    has_read = bool(kinds & {EventKind.STATE_READ, EventKind.STATE_CLEAR, EventKind.STATE_OBSERVE})
    has_comp = EventKind.ARCH_COMPUTE in kinds
    has_write = bool(kinds & {EventKind.STATE_WRITE, EventKind.STATE_CLEAR})
    has_win = bool(kinds & {EventKind.WINDOW_OPEN, EventKind.WINDOW_SQUASH})
    return has_read and has_comp and has_write and has_win


def _gitm_style(frag: Relation) -> bool:
    open_exc = any(
        e.kind == EventKind.WINDOW_OPEN and _has_prov(e, "cacm.window.exception") for e in frag.events
    )
    if not open_exc:
        return False
    cache = CACHE_OCCUPANCY in frag.specs() or any(e.subject == CACHE_OCCUPANCY for e in frag.events)
    mem = any(e.kind in (EventKind.ARCH_MEMORY, EventKind.STATE_WRITE, EventKind.STATE_READ, EventKind.STATE_CLEAR) for e in frag.events)
    return cache or mem


def _assert_fragment_schema(frag: Relation) -> None:
    d = frag.to_dict()
    assert "events" in d and d.get("derived") == "unknown"
    assert "resource" not in d and "trigger" not in d
    assert d.get("validation") == ValidationStatus.UNRESOLVED.value
    kinds = {k.value for k in EventKind}
    for e in d["events"]:
        assert e["kind"] in kinds and "role" not in e
        assert "kind_guess" not in e


def _check_event_mapping() -> None:
    # clflush [rax]; rdtsc; ud2; lfence; imul rax, rdi, 0x440; jmp rax; ret
    code = bytes.fromhex("0fae38 0f31 0f0b 0faee8 4869c740040000 ffe0 c3")
    insns = _disasm(code, 0x1000)
    evs = _scan_events(insns, 0x1000, 0x2000)
    kinds = [e.kind for e in evs]
    assert EventKind.STATE_CLEAR in kinds, kinds
    assert EventKind.STATE_OBSERVE in kinds, kinds
    assert EventKind.WINDOW_OPEN in kinds, kinds
    assert EventKind.WINDOW_EXTEND in kinds, kinds
    assert EventKind.ARCH_COMPUTE in kinds, kinds
    assert EventKind.ARCH_BRANCH in kinds, kinds
    assert any(e.subject == CACHE_OCCUPANCY for e in evs)
    assert all(e.kind in EventKind for e in evs)

    # DualGate-shaped occupancy: movzx rdi,[rdi]; mov r10b,[r11+rdi+0x100]
    occ = bytes.fromhex("480fb63f 438a943b00010000")
    oins = _disasm(occ, 0x4000)
    oevs = _scan_events(oins, 0x4000, 0x5000)
    okinds = [e.kind for e in oevs]
    assert EventKind.STATE_READ in okinds, okinds
    assert EventKind.STATE_WRITE in okinds, okinds
    assert any(_has_prov(e, "semantic.occupancy_load") for e in oevs)
    assert any(_has_prov(e, "semantic.wr_fake_offset") for e in oevs)

    # xor rdx,rdx; div dl; mov rax,[rcx]  — exception window + fill
    gate = bytes.fromhex("4831d2 f6f2 488b01")
    gins = _disasm(gate, 0x2000)
    gevs = _scan_events(gins, 0x2000, 0x3000)
    frag = _fragment_from("t_exc", gevs, 0x2000, 0x2000 + len(gate), [], gins)
    _assert_fragment_schema(frag)
    assert any(e.kind == EventKind.WINDOW_OPEN and _has_prov(e, "cacm.window.exception") for e in frag.events)
    assert any(e.kind == EventKind.ARCH_MEMORY for e in frag.events)
    assert any(e.kind == EventKind.STATE_WRITE and e.subject == CACHE_OCCUPANCY for e in frag.events)
    assert frag.unresolved() and frag.t_constraints

    # add qword [rsp], 1; ret  — RSB window
    rsb = bytes.fromhex("4883042401 c3")
    rins = _disasm(rsb, 0x3000)
    revs = _scan_events(rins, 0x3000, 0x4000)
    rfrag = _fragment_from("t_rsb", revs, 0x3000, 0x3000 + len(rsb), [], rins)
    assert any(e.kind == EventKind.WINDOW_OPEN and _has_prov(e, "cacm.window.rsb") for e in rfrag.events)
    assert any(e.kind == EventKind.WINDOW_SQUASH for e in rfrag.events)


def self_check() -> None:
    _check_event_mapping()
    repo = Path(__file__).resolve().parents[2]
    flexo = repo / "src/gates/flexo/gates/gate_and.elf"
    gitm = repo / "src/gates/gitm/main_and.elf"
    tae = repo / "third_party/tae/build/bin/gates.elf"
    messages = ["harvest self-check: event mapping ok"]

    if not flexo.is_file():
        messages.append(f"skip Flexo (missing {flexo})")
    else:
        h = harvest_elf(str(flexo))
        assert h.fragments and h.events
        for f in h.fragments:
            _assert_fragment_schema(f)
        flexo_hits = [f for f in h.fragments if _flexo_style(f)]
        assert flexo_hits, [f.to_dict() for f in h.fragments[:4]]
        hit = flexo_hits[0]
        kinds = [e.kind for e in hit.events]
        assert EventKind.ARCH_COMPUTE in kinds
        assert {EventKind.WINDOW_OPEN, EventKind.WINDOW_SQUASH} & set(kinds)
        keys = [v.phys_key for v in list(hit.m_in.values()) + list(hit.m_out.values()) if v.phys_key]
        assert any(str(k).startswith("w") for k in keys) or any(
            "semantic.wr_stride" in " ".join(e.provenance) for e in hit.events
        ), keys
        assert hit.unresolved()
        messages.append(f"flexo cache+window={len(flexo_hits)}/{len(h.fragments)}")

    if not gitm.is_file():
        messages.append(f"skip GITM (missing {gitm})")
    else:
        g = harvest_elf(str(gitm))
        assert g.fragments and g.events
        for f in g.fragments:
            _assert_fragment_schema(f)
        gitm_hits = [f for f in g.fragments if _gitm_style(f)]
        assert gitm_hits, [f.to_dict() for f in g.fragments[:6]]
        gev = gitm_hits[0].evidence
        assert gev is not None and gev.observations
        assert gitm_hits[0].unresolved()
        messages.append(f"gitm exception+cache={len(gitm_hits)}/{len(g.fragments)}")

    if not tae.is_file():
        messages.append(f"skip TAE (missing {tae})")
    else:
        t = harvest_elf(str(tae))
        assert t.fragments and t.events
        for f in t.fragments:
            _assert_fragment_schema(f)
        btb_hits = [
            f
            for f in t.fragments
            if EventKind.ARCH_BRANCH in {e.kind for e in f.events}
            and (BTB_ENTRY in f.specs() or any(e.subject == BTB_ENTRY for e in f.events))
        ]
        assert btb_hits, [f.to_dict() for f in t.fragments[:6]]
        assert all(f.unresolved() for f in btb_hits)
        messages.append(f"tae branch+btb={len(btb_hits)}/{len(t.fragments)}")

    print("; ".join(messages))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "--self-check":
        res = harvest_elf(sys.argv[1])
        import json

        print(json.dumps(res.to_dict(), indent=2)[:8000])
        print(
            f"# {res.source}: {len(res.events)} events, "
            f"{len(res.fragments)} fragments, "
            f"{sum(1 for f in res.fragments if f.unresolved())} unresolved"
        )
    else:
        self_check()
