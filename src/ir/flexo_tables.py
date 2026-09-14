"""Flexo DualGate truth tables and dual-rail AND/XOR (spec gate_table).

Flexo names gadgets `__DualGate__{n_in}_{n_out}_{id}` where `id` is the
n-input truth table as a bitvector: bit i is f(A=i) for Yosys ``$lut`` INIT
(A[0] = LSB). DualGate in0 is Yosys A[WIDTH-1] (MSB of i), matching
``write_blif`` ``.names`` order. AND/XOR are symmetric under that reversal;
MUX ``__DualGate__3_1_172`` is not. Dual-rail AND/XOR match Flexo §3.1 /
Listing 4–5.
"""

from typing import Dict, Tuple

# Logical bits: 0/1. Dual-rail wires: (minus, plus) with valid HL=0, LH=1.
Color = int
Dual = Tuple[Color, Color]  # (w_minus, w_plus)


def decode_dual_gate(n_in: int, table_id: int) -> Dict[Tuple[int, ...], int]:
    """Return gate_table: input tuple -> 1-bit output.

    Flexo DualGate in0 is the first Yosys ``$lut`` BLIF input, which
    ``write_blif`` emits as ``A[WIDTH-1]`` (MSB of the LUT index). Bit ``i`` of
    ``table_id`` is still ``LUT[i]`` with ``A[0]`` as LSB, so ``inputs[0]`` is
    bit ``n_in-1`` of ``i``. AND/XOR hide this; MUX ``3_1_172`` does not.
    """
    table = {}
    for bits in range(1 << n_in):
        inputs = tuple((bits >> (n_in - 1 - k)) & 1 for k in range(n_in))
        table[inputs] = (table_id >> bits) & 1
    return table


def encode_dual_gate(n_in: int, table: Dict[Tuple[int, ...], int]) -> int:
    """Inverse of decode_dual_gate. Missing minterms are 0."""
    tid = 0
    for bits in range(1 << n_in):
        inputs = tuple((bits >> (n_in - 1 - k)) & 1 for k in range(n_in))
        if table.get(inputs, 0):
            tid |= 1 << bits
    return tid


def decode_outputs(n_in: int, n_out: int, table_id: int):
    """Split a multi-output DualGate id into per-output truth tables.

    Flexo packs output *o*'s 2^{n_in}-bit table at bit offset ``o * 2^{n_in}``.
    ``__DualGate__1_2_10`` is a 1-bit fanout (both tables = identity).
    """
    width = 1 << n_in
    mask = (1 << width) - 1
    return [decode_dual_gate(n_in, (table_id >> (o * width)) & mask) for o in range(n_out)]


def _rail(logical: int) -> Dual:
    return (1, 0) if logical == 0 else (0, 1)


# o+ = i1+ ∧ i2+ ; o- = i1- ∨ i2-
DUAL_RAIL_AND: Dict[Tuple[Dual, Dual], Dual] = {}
for a in (0, 1):
    for b in (0, 1):
        DUAL_RAIL_AND[(_rail(a), _rail(b))] = _rail(a & b)

# o+ = (i1+ ∧ i2-) ∨ (i1- ∧ i2+) ; o- = (i1+ ∧ i2+) ∨ (i1- ∧ i2-)
DUAL_RAIL_XOR: Dict[Tuple[Dual, Dual], Dual] = {}
for a in (0, 1):
    for b in (0, 1):
        DUAL_RAIL_XOR[(_rail(a), _rail(b))] = _rail(a ^ b)


KNOWN_GATES = {
    (2, 8): "AND",
    (2, 14): "OR",
    (1, 1): "NOT",
    (2, 7): "NAND",
    (2, 6): "XOR",
    (3, 172): "MUX",
    (3, 150): "XOR3",
    (4, 27030): "XOR4",
}


def name_dual_gate(n_in: int, table_id: int) -> str:
    return KNOWN_GATES.get((n_in, table_id), f"LUT{n_in}_{table_id}")


def _lsb_decode(n_in: int, table_id: int) -> Dict[Tuple[int, ...], int]:
    """Wrong packing: DualGate in0 as LSB of the minterm index."""
    table = {}
    for bits in range(1 << n_in):
        inputs = tuple((bits >> k) & 1 for k in range(n_in))
        table[inputs] = (table_id >> bits) & 1
    return table


def _is_21_mux(table: Dict[Tuple[int, ...], int]) -> bool:
    """True if a 3-input table is o = s ? d1 : d0 for some input permutation."""
    if not table:
        return False
    n = len(next(iter(table)))
    if n != 3:
        return False
    for s in range(3):
        data = [i for i in range(3) if i != s]
        for d0, d1 in (data, list(reversed(data))):
            if all(out == (ins[d1] if ins[s] else ins[d0]) for ins, out in table.items()):
                return True
    return False


def check_decode() -> None:
    """Assert DualGate packing against AND/XOR and asymmetric MUX / 2_1_4."""
    and_t = decode_dual_gate(2, 8)
    xor_t = decode_dual_gate(2, 6)
    assert and_t[(1, 1)] == 1 and and_t[(1, 0)] == 0
    assert xor_t[(1, 0)] == 1 and xor_t[(1, 1)] == 0
    assert encode_dual_gate(2, and_t) == 8
    assert encode_dual_gate(2, xor_t) == 6

    # __DualGate__3_1_172 (Flexo mux): DualGate in0 is Yosys A[MSB], so
    # o = in0 ? in2 : in1. AND/XOR cannot distinguish this from in0-as-LSB;
    # the bound formula can. LSB packing yields o = in2 ? in0 : in1 instead.
    mux_t = decode_dual_gate(3, 172)
    for ins, bit in mux_t.items():
        assert bit == (ins[2] if ins[0] else ins[1]), ins
    assert _is_21_mux(mux_t)
    lsb_mux = _lsb_decode(3, 172)
    assert any(lsb_mux[ins] != (ins[2] if ins[0] else ins[1]) for ins in lsb_mux)

    # Adder DualGate 2_1_4: in0 & ~in1. LSB packing would be ~in0 & in1.
    t4 = decode_dual_gate(2, 4)
    assert t4[(0, 0)] == 0 and t4[(0, 1)] == 0
    assert t4[(1, 0)] == 1 and t4[(1, 1)] == 0
    lsb4 = _lsb_decode(2, 4)
    assert lsb4[(0, 1)] == 1 and lsb4[(1, 0)] == 0

    xor3_t = decode_dual_gate(3, 150)
    for ins, bit in xor3_t.items():
        assert bit == (ins[0] ^ ins[1] ^ ins[2])

    fanout = decode_outputs(1, 2, 10)
    assert fanout[0][(0,)] == 0 and fanout[0][(1,)] == 1
    assert fanout[1][(0,)] == 0 and fanout[1][(1,)] == 1
