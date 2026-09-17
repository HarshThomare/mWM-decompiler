"""Static Flexo lift: DualGate instances + logical wires from WR slots."""

import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from elftools.elf.elffile import ELFFile

from ir.events import EventKind, make_event
from ir.net import Net
from ir.relation import Relation, ValidationStatus, boolean_lut_interp
from ir.state import CACHE_OCCUPANCY, ArchInput, state_var

DUAL_RE = re.compile(r"^__DualGate__(\d+)_(\d+)_(\d+)$")
WEIRD_RE = re.compile(r"__weird__([A-Za-z0-9_]+)")
ITANIUM_RE = re.compile(r"^_Z(\d+)(.+)$")

_CANON = {}
for full, parts in (
    ("rax", "al ah ax eax rax"),
    ("rbx", "bl bh bx ebx rbx"),
    ("rcx", "cl ch cx ecx rcx"),
    ("rdx", "dl dh dx edx rdx"),
    ("rsi", "sil si esi rsi"),
    ("rdi", "dil di edi rdi"),
    ("rbp", "bpl bp ebp rbp"),
    ("rsp", "spl sp esp rsp"),
    ("r8", "r8b r8w r8d r8"),
    ("r9", "r8b r9b r9w r9d r9"),
    ("r10", "r10b r10w r10d r10"),
    ("r11", "r11b r11w r11d r11"),
    ("r12", "r12b r12w r12d r12"),
    ("r13", "r13b r13w r13d r13"),
    ("r14", "r14b r14w r14d r14"),
    ("r15", "r15b r15w r15d r15"),
):
    for p in parts.split():
        _CANON[p] = full
# fix accidental r8b under r9
_CANON["r8b"] = "r8"
_CANON["r9b"] = "r9"

ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
CALLER_SAVED = ARG_REGS + ("rax", "r10", "r11")


def _weird_op(symbol: str) -> Optional[str]:
    m = ITANIUM_RE.match(symbol)
    if m:
        ident = m.group(2)[: int(m.group(1))]
        if "__weird__" in ident:
            return ident.split("__weird__", 1)[1]
    m = WEIRD_RE.search(symbol)
    return m.group(1) if m else None


def _canon(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    return _CANON.get(name, name)


def _symbols(elf: ELFFile) -> Dict[int, Tuple[str, int]]:
    out = {}
    symtab = elf.get_section_by_name(".symtab")
    if symtab is None:
        return out
    for s in symtab.iter_symbols():
        if s["st_value"] and s.name:
            out[s["st_value"]] = (s.name, s["st_size"])
    return out


def _text_bytes(elf: ELFFile) -> Tuple[int, bytes]:
    text = elf.get_section_by_name(".text")
    return text["sh_addr"], text.data()


def _disasm(code: bytes, addr: int, size: int, text_addr: int):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    off = addr - text_addr
    blob = code[off : off + (size or 0x800)]
    return list(md.disasm(blob, addr))


def _reg(insn, op):
    if op.type != X86_OP_REG:
        return None
    return _canon(insn.reg_name(op.reg))


def _find_wr_offset(insns) -> int:
    counts: Counter = Counter()
    for insn in insns:
        if insn.mnemonic != "imul" or len(insn.operands) != 3:
            continue
        imm_op = insn.operands[2]
        if imm_op.type != X86_OP_IMM:
            continue
        imm = imm_op.imm
        if 0x100 <= imm <= 0x2000 and imm % 16 == 0:
            counts[imm] += 1
    return counts.most_common(1)[0][0] if counts else 0x440


def _find_perm(insns) -> Tuple[Optional[int], int]:
    """Return (rbp displacement of perm[0], slot count)."""
    disps = []
    nslots = None
    for insn in insns[:90]:
        if insn.mnemonic == "cmp" and len(insn.operands) == 2:
            if insn.operands[1].type == X86_OP_IMM:
                n = insn.operands[1].imm
                if 4 <= n <= 4096 and nslots is None and disps:
                    nslots = n
        if insn.mnemonic != "mov" or len(insn.operands) < 2:
            continue
        dst = insn.operands[0]
        if dst.type != X86_OP_MEM:
            continue
        if dst.mem.scale != 4:
            continue
        base = insn.reg_name(dst.mem.base) if dst.mem.base else None
        if _canon(base) != "rbp":
            continue
        if dst.mem.index:
            disps.append(dst.mem.disp)
    if not disps:
        return None, nslots or 0
    return Counter(disps).most_common(1)[0][0], nslots or 0


def _perm_id(disp: int, array_disp: Optional[int], nslots: int) -> Optional[int]:
    if array_disp is None:
        return disp
    off = disp - array_disp
    if off % 4:
        return None
    idx = off // 4
    if nslots and not (0 <= idx < nslots):
        return None
    return idx


def _logical_wire(rail_a: int, rail_b: Optional[int] = None) -> str:
    if rail_b is None or rail_a == rail_b:
        return f"w{rail_a // 2}"
    a, b = sorted((rail_a, rail_b))
    if b - a == 1:
        return f"w{a // 2}"
    return f"w{a}_{b}"


def _tag_wire(tag: Any) -> Optional[int]:
    if not tag:
        return None
    kind, val = tag[0], tag[1]
    if kind in ("perm", "idx", "off", "ptr"):
        return val
    return None


def _gate_relation(
    op: str,
    inst: int,
    gname: str,
    n_in: int,
    n_out: int,
    table_id: int,
    in_names: List[str],
    out_names: List[str],
    addr: int,
    source: str,
) -> Relation:
    name = op if inst == 0 else f"{op}.g{inst}"
    rel = Relation(name=name, source=source, entry=addr)
    for nm in in_names:
        rel.add_m_in(state_var(nm, CACHE_OCCUPANCY, phys_key=nm))
        rel.add_a(ArchInput(name=nm, domain="bit", width=1, binding=nm))
    for nm in out_names:
        rel.add_m_out(state_var(nm, CACHE_OCCUPANCY, phys_key=nm))
    rel.set_interpretation(
        boolean_lut_interp(n_in, table_id=table_id, n_out=n_out, inputs=in_names, outputs=out_names)
    )
    rel.validation = ValidationStatus.CONFIRMED
    rel.add_event(
        make_event(
            EventKind.ARCH_COMPUTE,
            addr=addr,
            insn="call",
            operand=gname,
            provenance=("static.dual_gate",),
        )
    )
    return rel


def _lift_function(
    op: str,
    insns,
    dual_by_addr: Dict[int, Tuple[str, int, int, int]],
    source: str,
) -> Net:
    net = Net(name=op, source=source)
    wr_off = _find_wr_offset(insns)
    array_disp, nslots = _find_perm(insns)
    regs: Dict[str, Any] = {}
    stack: Dict[int, Any] = {}
    rbp_slots: Dict[int, Any] = {}
    rsp_delta = 0
    wired = 0
    inst = 0

    def set_reg(r: Optional[str], tag: Any):
        if r:
            regs[r] = tag

    def get_reg(r: Optional[str]) -> Any:
        return regs.get(r) if r else None

    def kill(r: Optional[str]):
        if r:
            regs.pop(r, None)

    for insn in insns:
        ops = insn.operands
        mnem = insn.mnemonic

        if mnem == "call" and ops and ops[0].type == X86_OP_IMM:
            tgt = ops[0].imm
            if tgt in dual_by_addr:
                gname, n_in, n_out, table_id = dual_by_addr[tgt]
                n_ptr = 2 * (n_in + n_out)
                ptrs = []
                for r in ARG_REGS:
                    ptrs.append(get_reg(r))
                extra = n_ptr - 6
                for i in range(max(0, extra)):
                    ptrs.append(stack.get(rsp_delta + 8 * i))
                rails = []
                for tag in ptrs[:n_ptr]:
                    wid = _tag_wire(tag)
                    rails.append(wid)
                in_names, out_names = [], []
                resolved = all(r is not None for r in rails) and len(rails) == n_ptr
                if resolved:
                    wired += 1
                    for i in range(n_in):
                        a, b = rails[2 * i], rails[2 * i + 1]
                        in_names.append(_logical_wire(a, b))
                    base = 2 * n_in
                    for i in range(n_out):
                        a, b = rails[base + 2 * i], rails[base + 2 * i + 1]
                        out_names.append(_logical_wire(a, b))
                else:
                    in_names = [f"{op}.g{inst}.in{i}" for i in range(n_in)]
                    out_names = [f"{op}.g{inst}.out{i}" for i in range(n_out)]
                net.add_relation(
                    _gate_relation(
                        op,
                        inst,
                        gname,
                        n_in,
                        n_out,
                        table_id,
                        in_names,
                        out_names,
                        insn.address,
                        source,
                    )
                )
                inst += 1
            for r in CALLER_SAVED:
                kill(r)
            continue

        if mnem == "push" and ops:
            rsp_delta -= 8
            src = _reg(insn, ops[0])
            stack[rsp_delta] = get_reg(src) if src else None
            continue
        if mnem == "pop" and ops:
            dst = _reg(insn, ops[0])
            set_reg(dst, stack.get(rsp_delta))
            rsp_delta += 8
            continue

        if mnem in ("sub", "add") and ops and _reg(insn, ops[0]) == "rsp":
            if ops[1].type == X86_OP_IMM:
                if mnem == "sub":
                    rsp_delta -= ops[1].imm
                else:
                    rsp_delta += ops[1].imm
            continue

        # copy / kill
        if mnem in ("xor", "sub") and len(ops) >= 2:
            a, b = _reg(insn, ops[0]), _reg(insn, ops[1])
            if a and a == b:
                kill(a)
                continue

        if mnem == "movsxd" and len(ops) >= 2:
            dst, src = _reg(insn, ops[0]), _reg(insn, ops[1])
            if dst:
                set_reg(dst, get_reg(src) if src else None)
            continue

        if mnem in ("movzx", "movsx") and len(ops) >= 2:
            dst = _reg(insn, ops[0])
            if ops[1].type == X86_OP_REG:
                set_reg(dst, get_reg(_reg(insn, ops[1])))
            else:
                kill(dst)
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

        if mnem == "imul" and len(ops) == 3 and ops[2].type == X86_OP_IMM:
            dest, src = _reg(insn, ops[0]), _reg(insn, ops[1])
            if ops[2].imm == wr_off:
                wid = _tag_wire(get_reg(src))
                if wid is not None:
                    set_reg(dest, ("off", wid))
                    continue
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
            if ops[1].type == X86_OP_IMM:
                tag = get_reg(dest)
                if tag and tag[0] in ("off", "ptr"):
                    continue
            if ops[1].type == X86_OP_REG:
                src = _reg(insn, ops[1])
                dt, st = get_reg(dest), get_reg(src)
                if mnem == "add":
                    pick = None
                    for t in (st, dt):
                        if t and t[0] in ("off", "ptr"):
                            pick = t
                            break
                        if t and t[0] == "idx":
                            pick = ("off", t[1])
                    if pick:
                        set_reg(dest, ("ptr", pick[1]) if pick[0] != "ptr" else pick)
                        if pick[0] == "ptr":
                            set_reg(dest, pick)
                        else:
                            set_reg(dest, ("ptr", pick[1]))
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
                        if pid is not None:
                            set_reg(dest, ("perm", pid))
                        else:
                            kill(dest)
                    continue
                if base == "rsp" and not mem.index:
                    set_reg(dest, stack.get(rsp_delta + mem.disp))
                    continue
                kill(dest)
                continue
            if dst.type == X86_OP_MEM and src.type == X86_OP_REG:
                mem = dst.mem
                base = _canon(insn.reg_name(mem.base) if mem.base else None)
                tag = get_reg(_reg(insn, src))
                if base == "rbp" and not mem.index:
                    rbp_slots[mem.disp] = tag
                elif base == "rsp" and not mem.index:
                    stack[rsp_delta + mem.disp] = tag
                continue
            if dst.type == X86_OP_REG:
                kill(_reg(insn, dst))
            continue

        # default: kill dest register if present
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
        if mnem in ("and", "or", "shr", "shl", "sar") and ops and ops[0].type == X86_OP_REG:
            kill(_reg(insn, ops[0]))

    net.native["wr_offset"] = wr_off
    net.native["perm_disp"] = array_disp
    net.native["perm_slots"] = nslots
    net.native["dual_gate_instances"] = inst
    net.native["wired_instances"] = wired
    net.native["op"] = op
    return net


def lift_flexo_circuits(path: str) -> List[Net]:
    path = str(path)
    with open(path, "rb") as f:
        elf = ELFFile(f)
        syms = _symbols(elf)
        text_addr, text = _text_bytes(elf)

        dual_by_addr = {}
        for addr, (name, size) in syms.items():
            m = DUAL_RE.match(name)
            if not m:
                continue
            n_in, n_out, table_id = map(int, m.groups())
            dual_by_addr[addr] = (name, n_in, n_out, table_id)

        weird_fns = []
        for addr, (name, size) in sorted(syms.items()):
            op = _weird_op(name)
            if op:
                weird_fns.append((addr, name, op, size))

        circuits = []
        for addr, full, short, size in weird_fns:
            insns = _disasm(text, addr, size, text_addr)
            net = _lift_function(short, insns, dual_by_addr, path)
            net.native["symbol"] = full
            net.native["func_addr"] = addr
            circuits.append(net)
        return circuits


def lift_flexo_elf(path: str) -> Net:
    """Union of per-function DualGate relations (CLI helper). Prefer lift_flexo_circuits."""
    circuits = lift_flexo_circuits(path)
    if len(circuits) == 1:
        return circuits[0]
    path = str(path)
    net = Net(name=Path(path).stem, source=path)
    for c in circuits:
        for r in c.relations.values():
            nm = r.name if r.name not in net.relations else f"{c.name}.{r.name}"
            if nm != r.name:
                r.name = nm
            net.add_relation(r)
        net.native.setdefault("circuits", []).append(
            {
                "op": c.name,
                "relations": len(c.relations),
                "gates": c.native.get("dual_gate_instances"),
            }
        )
    return net
