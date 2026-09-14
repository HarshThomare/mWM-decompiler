"""Gold BLIF for Flexo circuits that have a closed-form spec."""

from typing import Optional


def _header(model, ins, outs):
    return [f".model {model}", ".inputs " + " ".join(ins), ".outputs " + " ".join(outs)]


def _and(a, b, y):
    return [f".names {a} {b} {y}", "11 1"]


def _or(a, b, y):
    return [f".names {a} {b} {y}", "01 1", "10 1", "11 1"]


def _xor(a, b, y):
    return [f".names {a} {b} {y}", "01 1", "10 1"]


def _not(a, y):
    return [f".names {a} {y}", "0 1"]


def gate_blif(name: str) -> Optional[str]:
    n = name.lower()
    if n == "and":
        lines = _header("and", ["i0", "i1"], ["o0"]) + _and("i0", "i1", "o0")
    elif n == "or":
        lines = _header("or", ["i0", "i1"], ["o0"]) + _or("i0", "i1", "o0")
    elif n == "not":
        lines = _header("not", ["i0"], ["o0"]) + _not("i0", "o0")
    elif n == "nand":
        lines = _header("nand", ["i0", "i1"], ["o0"]) + [".names i0 i1 o0", "00 1", "01 1", "10 1"]
    elif n == "xor":
        lines = _header("xor", ["i0", "i1"], ["o0"]) + _xor("i0", "i1", "o0")
    elif n == "mux":
        # o = s ? i1 : i0
        lines = _header("mux", ["i0", "i1", "s"], ["o0"]) + [
            ".names i0 i1 s o0",
            "100 1",
            "110 1",
            "011 1",
            "111 1",
        ]
    elif n == "xor3":
        lines = _header("xor3", ["i0", "i1", "i2"], ["o0"]) + [
            ".names i0 i1 i2 o0",
            "100 1",
            "010 1",
            "001 1",
            "111 1",
        ]
    elif n == "xor4":
        lines = _header("xor4", ["i0", "i1", "i2", "i3"], ["o0"])
        rows = []
        for bits in range(16):
            if bin(bits).count("1") % 2 == 1:
                rows.append("".join(str((bits >> k) & 1) for k in range(4)) + " 1")
        lines += [".names i0 i1 i2 i3 o0"] + rows
    else:
        return None
    return "\n".join(lines + [".end", ""])


def adder_blif(bits: int, cout: bool = True) -> str:
    ins = [f"a{i}" for i in range(bits)] + [f"b{i}" for i in range(bits)]
    outs = [f"s{i}" for i in range(bits)]
    if cout:
        outs.append("cout")
    lines = _header(f"add{bits}", ins, outs)
    # HA for bit 0
    lines += _xor("a0", "b0", "s0")
    lines += _and("a0", "b0", "c0")
    for i in range(1, bits):
        # FA: s = a^b^cin, cout = majority
        lines += _xor(f"a{i}", f"b{i}", f"x{i}")
        lines += _xor(f"x{i}", f"c{i-1}", f"s{i}")
        lines += _and(f"a{i}", f"b{i}", f"ab{i}")
        lines += _and(f"x{i}", f"c{i-1}", f"xc{i}")
        lines += _or(f"ab{i}", f"xc{i}", f"c{i}")
    if cout:
        lines.append(f".names c{bits-1} cout")
        lines.append("1 1")
    lines += [".end", ""]
    return "\n".join(lines)


def alu_blif() -> str:
    """4-bit Hack-style ALU matching src/gates/flexo/alu/source/ALU.v."""
    return _alu_blif_clean()


def _mux(s, a, b, y):
    # y = s ? b : a
    return [f".names {s} {a} {b} {y}", "010 1", "011 1", "101 1", "111 1"]


def _alu_blif_clean() -> str:
    ins = [f"x{i}" for i in range(4)] + [f"y{i}" for i in range(4)] + ["zx", "nx", "zy", "ny", "f", "no"]
    outs = [f"o{i}" for i in range(4)] + ["zr", "ng"]
    lines = _header("alu", ins, outs)
    for i in range(4):
        lines += [f".names zx x{i} zxo{i}", "01 1"]
        lines += _not(f"zxo{i}", f"notx{i}")
        lines += _mux("nx", f"zxo{i}", f"notx{i}", f"nxo{i}")
        lines += [f".names zy y{i} zyo{i}", "01 1"]
        lines += _not(f"zyo{i}", f"noty{i}")
        lines += _mux("ny", f"zyo{i}", f"noty{i}", f"nyo{i}")
        lines += _and(f"nxo{i}", f"nyo{i}", f"ando{i}")
    # 4-bit add of nxo + nyo
    lines += _xor("nxo0", "nyo0", "add0")
    lines += _and("nxo0", "nyo0", "ac0")
    for i in range(1, 4):
        lines += _xor(f"nxo{i}", f"nyo{i}", f"ax{i}")
        lines += _xor(f"ax{i}", f"ac{i-1}", f"add{i}")
        lines += _and(f"nxo{i}", f"nyo{i}", f"ab{i}")
        lines += _and(f"ax{i}", f"ac{i-1}", f"xc{i}")
        lines += _or(f"ab{i}", f"xc{i}", f"ac{i}")
    for i in range(4):
        lines += _mux("f", f"ando{i}", f"add{i}", f"fo{i}")
        lines += _not(f"fo{i}", f"nfo{i}")
        lines += _mux("no", f"fo{i}", f"nfo{i}", f"o{i}")
    # zr = ~|result
    lines += [".names o0 o1 o2 o3 any", "0001 1", "0010 1", "0011 1", "0100 1", "0101 1", "0110 1", "0111 1",
              "1000 1", "1001 1", "1010 1", "1011 1", "1100 1", "1101 1", "1110 1", "1111 1"]
    lines += _not("any", "zr")
    lines += [".names o3 ng", "1 1"]
    lines += [".end", ""]
    return "\n".join(lines)


def gold_for(circuit: str, n_out: Optional[int] = None) -> Optional[str]:
    n = circuit.lower().replace(" ", "").replace("-", "").replace("_", "")
    g = gate_blif(n)
    if g:
        return g
    if n in ("alu",):
        return alu_blif()
    adders = {
        "adder8": 8,
        "add8": 8,
        "add8bit": 8,
        "adder16": 16,
        "add16": 16,
        "adder32": 32,
        "add32": 32,
    }
    if n in adders:
        bits = adders[n]
        # Flexo MASK(sum, bits) drops carry-out; only emit cout when the
        # recovered interface actually has the extra PO.
        include_cout = True if n_out is None else n_out == bits + 1
        return adder_blif(bits, cout=include_cout)
    return None
