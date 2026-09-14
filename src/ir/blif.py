"""Export a Flexo µWM net as a single-rail combinational BLIF."""

from typing import Iterable, List, Set

from .net import Net, TransKind


def _lut_rows(inputs: List[str], output: str, table) -> List[str]:
    lines = [f".names {' '.join(inputs)} {output}"]
    ones = 0
    n_in = len(inputs)
    for bits in range(1 << n_in):
        key = tuple((bits >> k) & 1 for k in range(n_in))
        bit = table.get(key, 0) if table else 0
        if bit:
            ones += 1
            row = "".join(str((bits >> k) & 1) for k in range(n_in))
            lines.append(f"{row} 1")
    if ones == 0 and n_in == 0:
        return [f".names {output}"]
    if ones == (1 << n_in) and n_in == 0:
        return [f".names {output}", "1"]
    return lines


def net_ports(net: Net):
    used_in: Set[str] = set()
    used_out: Set[str] = set()
    for t in net.transitions.values():
        if t.kind != TransKind.GATE:
            continue
        used_in.update(t.inputs)
        used_out.update(t.outputs)
    pis = sorted(used_in - used_out)
    pos = sorted(used_out - used_in)
    if not pos:
        pos = sorted(used_out)
    return pis, pos


def net_to_blif(net: Net, model: str = None) -> str:
    model = model or net.name
    pis, pos = net_ports(net)
    lines = [f".model {model}"]
    if pis:
        lines.append(".inputs " + " ".join(pis))
    if pos:
        lines.append(".outputs " + " ".join(pos))
    for t in net.transitions.values():
        if t.kind != TransKind.GATE:
            continue
        tables = t.gate_tables or ([t.gate_table] if t.gate_table else [])
        n_out = max(t.n_out, len(t.outputs), len(tables))
        for i, out in enumerate(t.outputs[:n_out]):
            table = tables[i] if i < len(tables) else t.gate_table
            lines.extend(_lut_rows(t.inputs, out, table))
    lines.append(".end")
    lines.append("")
    return "\n".join(lines)


def rename_ports(blif: str, inputs: Iterable[str], outputs: Iterable[str]) -> str:
    """Rewrite .inputs/.outputs names in order (for ABC cec)."""
    ins = list(inputs)
    outs = list(outputs)
    out_lines = []
    for line in blif.splitlines():
        if line.startswith(".inputs "):
            old = line.split()[1:]
            mapping = {o: n for o, n in zip(old, ins)} if len(old) == len(ins) else {}
            if mapping:
                # apply throughout later; here just rewrite header
                out_lines.append(".inputs " + " ".join(ins))
                continue
        if line.startswith(".outputs "):
            old = line.split()[1:]
            if len(old) == len(outs):
                out_lines.append(".outputs " + " ".join(outs))
                continue
        out_lines.append(line)
    text = "\n".join(out_lines)
    # remap body names if counts match
    in_old = None
    out_old = None
    for line in blif.splitlines():
        if line.startswith(".inputs "):
            in_old = line.split()[1:]
        if line.startswith(".outputs "):
            out_old = line.split()[1:]
    mapping = {}
    if in_old and len(in_old) == len(ins):
        mapping.update(zip(in_old, ins))
    if out_old and len(out_old) == len(outs):
        mapping.update(zip(out_old, outs))
    if not mapping:
        return blif if blif.endswith("\n") else blif + "\n"
    # rebuild from original with mapping
    rebuilt = []
    for line in blif.splitlines():
        if line.startswith(".model"):
            rebuilt.append(line)
        elif line.startswith(".inputs "):
            rebuilt.append(".inputs " + " ".join(ins))
        elif line.startswith(".outputs "):
            rebuilt.append(".outputs " + " ".join(outs))
        elif line.startswith(".names "):
            parts = line.split()
            rebuilt.append(".names " + " ".join(mapping.get(p, p) for p in parts[1:]))
        else:
            rebuilt.append(line)
    return "\n".join(rebuilt) + "\n"
