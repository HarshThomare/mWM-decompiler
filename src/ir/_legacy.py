"""Temporary stubs so oracle/eval/flexo_static keep importing.

Later phases DELETE this file. New code must use Event/Relation/StateVariable
from events.py, relation.py, and state.py — not these resource/trigger/lut/isa names.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .events import Evidence
from .flexo_tables import decode_dual_gate, decode_outputs


class Kind(str, Enum):
    VOLATILE = "volatile"
    PERSISTENT = "persistent"


class TransKind(str, Enum):
    GATE = "gate"
    EXPR = "expr"
    ROLLBACK = "rollback"


class ResourceKind(str, Enum):
    DCACHE = "dcache"
    BTB = "btb"
    TLB = "tlb"


class RegionKind(str, Enum):
    LUT = "lut"
    ISA = "isa"


def _res(kind: Any) -> str:
    return kind.value if isinstance(kind, Enum) else str(kind)


@dataclass(frozen=True)
class ResourceSpec:
    kind: str
    encoding: str
    destructive_read: bool
    persistent: bool
    width: int = 1
    trigger: str = ""
    phys_key_role: str = ""


_RESOURCE_SPECS: Dict[str, ResourceSpec] = {
    ResourceKind.DCACHE.value: ResourceSpec(
        kind=ResourceKind.DCACHE.value,
        encoding="dual_rail",
        destructive_read=True,
        persistent=False,
        width=1,
        trigger="rsb",
        phys_key_role="line",
    ),
    ResourceKind.BTB.value: ResourceSpec(
        kind=ResourceKind.BTB.value,
        encoding="btb_target",
        destructive_read=False,
        persistent=True,
        width=16,
        trigger="indirect_jmp",
        phys_key_role="btb_index",
    ),
    ResourceKind.TLB.value: ResourceSpec(
        kind=ResourceKind.TLB.value,
        encoding="hit_miss",
        destructive_read=True,
        persistent=False,
        width=1,
        trigger="rsb",
        phys_key_role="vpn",
    ),
}


def register_resource(spec: ResourceSpec) -> ResourceSpec:
    _RESOURCE_SPECS[spec.kind] = spec
    return spec


def resource_spec(kind: str) -> ResourceSpec:
    key = _res(kind)
    if key not in _RESOURCE_SPECS:
        raise KeyError(f"unknown resource {key!r}; register_resource() first")
    return _RESOURCE_SPECS[key]


@dataclass
class Place:
    name: str
    kind: Kind = Kind.VOLATILE
    col: str = "bit"
    token: Any = None
    resource: Optional[str] = None
    phys_key: Optional[str] = None
    encoding: Optional[str] = None
    destructive_read: Optional[bool] = None
    evidence: Optional[Evidence] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"name": self.name, "kind": self.kind.value, "col": self.col}
        if self.resource is not None:
            d["resource"] = self.resource
        if self.phys_key is not None:
            d["phys_key"] = self.phys_key
        if self.encoding is not None:
            d["encoding"] = self.encoding
        if self.destructive_read is not None:
            d["destructive_read"] = self.destructive_read
        if self.evidence is not None:
            d["evidence"] = self.evidence.to_dict()
        return d


@dataclass
class Transition:
    name: str
    kind: TransKind
    window_len: Optional[int] = None
    n_in: int = 0
    n_out: int = 1
    table_id: Optional[int] = None
    gate_table: Optional[Dict[Tuple[int, ...], int]] = None
    gate_tables: Optional[List[Dict[Tuple[int, ...], int]]] = None
    expr: Any = None
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    addr: Optional[int] = None
    trigger: Optional[str] = None
    resource: Optional[str] = None
    evidence: Optional[Evidence] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "kind": self.kind.value,
            "n_in": self.n_in,
            "n_out": self.n_out,
            "table_id": self.table_id,
            "gate_table": (
                {"".join(map(str, k)): v for k, v in self.gate_table.items()}
                if self.gate_table
                else None
            ),
            "expr": self.expr,
            "inputs": self.inputs,
            "outputs": self.outputs,
        }
        if self.window_len is not None:
            d["window_len"] = self.window_len
        if self.addr is not None:
            d["addr"] = self.addr
        if self.trigger is not None:
            d["trigger"] = self.trigger
        if self.resource is not None:
            d["resource"] = self.resource
        if self.evidence is not None:
            d["evidence"] = self.evidence.to_dict()
        return d


@dataclass
class Region:
    name: str
    kind: RegionKind
    resource: str
    places: List[str] = field(default_factory=list)
    transitions: List[str] = field(default_factory=list)
    window_len: Optional[int] = None
    trigger: Optional[str] = None
    evidence: Optional[Evidence] = None
    entry: Optional[int] = None
    exit: Optional[int] = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, RegionKind):
            self.kind = RegionKind(self.kind)
        self.resource = _res(self.resource)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "kind": self.kind.value,
            "resource": self.resource,
            "places": list(self.places),
            "transitions": list(self.transitions),
        }
        if self.window_len is not None:
            d["window_len"] = self.window_len
        if self.trigger is not None:
            d["trigger"] = self.trigger
        if self.entry is not None:
            d["entry"] = self.entry
        if self.exit is not None:
            d["exit"] = self.exit
        if self.evidence is not None:
            d["evidence"] = self.evidence.to_dict()
        return d


def wr_place(
    name: str,
    resource: str,
    phys_key: Optional[str] = None,
    col: str = "bit",
    evidence: Optional[Evidence] = None,
) -> Place:
    spec = resource_spec(_res(resource))
    return Place(
        name,
        Kind.PERSISTENT if spec.persistent else Kind.VOLATILE,
        col,
        resource=spec.kind,
        phys_key=phys_key,
        encoding=spec.encoding,
        destructive_read=spec.destructive_read,
        evidence=evidence,
    )


def lut_region(
    name: str,
    resource: str = ResourceKind.DCACHE.value,
    places: Optional[Iterable[str]] = None,
    transitions: Optional[Iterable[str]] = None,
    trigger: Optional[str] = None,
    window_len: Optional[int] = None,
    evidence: Optional[Evidence] = None,
    entry: Optional[int] = None,
    exit: Optional[int] = None,
) -> Region:
    spec = _RESOURCE_SPECS.get(_res(resource))
    spec_trigger = spec.trigger if spec else None
    return Region(
        name=name,
        kind=RegionKind.LUT,
        resource=_res(resource),
        places=list(places or []),
        transitions=list(transitions or []),
        window_len=window_len,
        trigger=trigger if trigger is not None else spec_trigger,
        evidence=evidence,
        entry=entry,
        exit=exit,
    )


def isa_region(
    name: str,
    resource: str = ResourceKind.BTB.value,
    places: Optional[Iterable[str]] = None,
    transitions: Optional[Iterable[str]] = None,
    trigger: Optional[str] = None,
    window_len: Optional[int] = None,
    evidence: Optional[Evidence] = None,
    entry: Optional[int] = None,
    exit: Optional[int] = None,
) -> Region:
    spec = _RESOURCE_SPECS.get(_res(resource))
    spec_trigger = spec.trigger if spec else None
    return Region(
        name=name,
        kind=RegionKind.ISA,
        resource=_res(resource),
        places=list(places or []),
        transitions=list(transitions or []),
        window_len=window_len,
        trigger=trigger if trigger is not None else spec_trigger,
        evidence=evidence,
        entry=entry,
        exit=exit,
    )


def gate_transition(
    name: str,
    n_in: int,
    table_id: int,
    inputs: List[str],
    outputs: List[str],
    n_out: int = 1,
    addr: Optional[int] = None,
) -> Transition:
    tables = decode_outputs(n_in, n_out, table_id)
    return Transition(
        name=name,
        kind=TransKind.GATE,
        n_in=n_in,
        n_out=n_out,
        table_id=table_id,
        gate_table=tables[0] if tables else decode_dual_gate(n_in, table_id),
        gate_tables=tables,
        expr=None,
        inputs=inputs,
        outputs=outputs,
        addr=addr,
    )
