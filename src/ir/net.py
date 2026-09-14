"""µWM net IR: N = (P, T, F, C, col, kind, W, R) plus typed evidence."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

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


BOT = None  # ⊥


class MixedCompositionError(ValueError):
    """LUT/ISA or multi-resource fusion without an explicit conversion edge."""


@dataclass(frozen=True)
class ResourceSpec:
    """Resource-specific WR / window semantics.

    ``kind`` is a ResourceKind value or a name registered via register_resource.
    """

    kind: str
    encoding: str
    destructive_read: bool
    persistent: bool
    width: int = 1
    trigger: str = ""
    phys_key_role: str = ""  # what Place.phys_key names (line, btb_index, vpn, ...)


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
    """Add or replace a resource kind (PHT, RSB, ...)."""
    _RESOURCE_SPECS[spec.kind] = spec
    return spec


def resource_spec(kind: str) -> ResourceSpec:
    if kind not in _RESOURCE_SPECS:
        raise KeyError(f"unknown resource {kind!r}; register_resource() first")
    return _RESOURCE_SPECS[kind]


def _res(kind: Any) -> str:
    return kind.value if isinstance(kind, Enum) else str(kind)


@dataclass
class Evidence:
    trigger: Optional[str] = None
    observations: List[Dict[str, Any]] = field(default_factory=list)
    confidence: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        if self.trigger is not None:
            d["trigger"] = self.trigger
        if self.observations:
            d["observations"] = list(self.observations)
        if self.confidence is not None:
            d["confidence"] = self.confidence
        return d


@dataclass
class ConversionEdge:
    """Explicit conversion between resources. Never inferred from wiring."""

    name: str
    src: str
    dst: str
    src_resource: str
    dst_resource: str
    encoding: Optional[str] = None
    evidence: Optional[Evidence] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "src": self.src,
            "dst": self.dst,
            "src_resource": self.src_resource,
            "dst_resource": self.dst_resource,
        }
        if self.encoding is not None:
            d["encoding"] = self.encoding
        if self.evidence is not None:
            d["evidence"] = self.evidence.to_dict()
        return d


@dataclass
class Region:
    """Boolean LUT region or TAE-style ISA region. Kept as separate objects."""

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


@dataclass
class Place:
    name: str
    kind: Kind = Kind.VOLATILE
    col: str = "bit"  # color domain name
    token: Any = BOT
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
    expr: Any = None  # uninterpreted; None means ⊥
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


def wr_place(
    name: str,
    resource: str,
    phys_key: Optional[str] = None,
    col: str = "bit",
    evidence: Optional[Evidence] = None,
) -> Place:
    """Place with resource-default encoding, persistence, and destructive-read."""
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


@dataclass
class Net:
    name: str
    places: Dict[str, Place] = field(default_factory=dict)
    transitions: Dict[str, Transition] = field(default_factory=dict)
    source: str = ""
    native: Dict[str, Any] = field(default_factory=dict)
    regions: Dict[str, Region] = field(default_factory=dict)
    conversions: Dict[str, ConversionEdge] = field(default_factory=dict)
    evidence: Optional[Evidence] = None

    def add_place(self, p: Place) -> Place:
        self.places[p.name] = p
        return p

    def add_transition(self, t: Transition) -> Transition:
        self.transitions[t.name] = t
        return t

    def add_region(self, r: Region) -> Region:
        self.regions[r.name] = r
        return r

    def add_conversion(self, e: ConversionEdge) -> ConversionEdge:
        self.conversions[e.name] = e
        return e

    def flexo_classifiable(self) -> bool:
        if not self.transitions:
            return False
        for t in self.transitions.values():
            if t.kind == TransKind.ROLLBACK:
                continue
            if t.expr is not None or t.kind != TransKind.GATE:
                return False
        return all(p.kind == Kind.VOLATILE for p in self.places.values())

    def tae_classifiable(self) -> bool:
        has_persistent = any(p.kind == Kind.PERSISTENT for p in self.places.values())
        has_expr = any(t.kind == TransKind.EXPR and t.expr is not None for t in self.transitions.values())
        return has_persistent and has_expr

    def classify(self) -> str:
        """Derived Flexo/TAE view. Typed fusion uses compose() instead."""
        f, t = self.flexo_classifiable(), self.tae_classifiable()
        if f and not t:
            return "flexo"
        if t and not f:
            return "tae"
        if f or t:
            return "mixed"
        return "unclassified"

    def fire_gate(self, t: Transition, inputs: Tuple[int, ...]) -> int:
        if t.gate_table is None:
            raise ValueError(f"{t.name} has no gate_table")
        return t.gate_table[inputs]

    def compose(self) -> str:
        """Single typed class, or MixedCompositionError if fusion is unsupported.

        Homogeneous LUT → ``lut``; homogeneous ISA → ``isa``; untyped nets fall
        back to classify() except ``mixed``, which is rejected. Distinct
        resources or LUT+ISA in one net are allowed only with conversion edges.
        """
        self._reject_mixed()
        resources = self._typed_resources()
        if self.regions:
            kinds = {r.kind for r in self.regions.values()}
            if len(resources) > 1 or kinds == {RegionKind.LUT, RegionKind.ISA}:
                return "converted"
            if kinds == {RegionKind.LUT}:
                return "lut"
            if kinds == {RegionKind.ISA}:
                return "isa"
        if len(resources) > 1:
            return "converted"
        c = self.classify()
        if c == "mixed":
            raise MixedCompositionError(f"{self.name}: classify() is mixed; refuse to fuse")
        return c

    def compose_region(self, name: str) -> str:
        r = self.regions[name]
        self._check_region(r)
        return r.kind.value

    def _reject_mixed(self) -> None:
        for r in self.regions.values():
            self._check_region(r)
        self._reject_implicit_resource_edges()
        region_kinds = {r.kind for r in self.regions.values()}
        resources = self._typed_resources()
        heterogeneous = (
            (RegionKind.LUT in region_kinds and RegionKind.ISA in region_kinds)
            or len(resources) > 1
        )
        if heterogeneous and not self._resources_bridged(resources):
            raise MixedCompositionError(
                f"{self.name}: mixed composition {sorted(_res(k) for k in region_kinds)} "
                f"resources={sorted(resources)} without conversion edges"
            )

    def _check_region(self, r: Region) -> None:
        allow = TransKind.GATE if r.kind == RegionKind.LUT else TransKind.EXPR
        for tn in r.transitions:
            t = self.transitions.get(tn)
            if t is None:
                raise MixedCompositionError(f"{r.name}: missing transition {tn}")
            if t.kind == TransKind.ROLLBACK:
                continue
            if t.kind != allow:
                raise MixedCompositionError(
                    f"{r.name}: {r.kind.value} region cannot contain {t.kind.value} {tn}"
                )
        for pn in r.places:
            p = self.places.get(pn)
            if p is None:
                raise MixedCompositionError(f"{r.name}: missing place {pn}")
            if p.resource and p.resource != r.resource:
                raise MixedCompositionError(
                    f"{r.name}: place {pn} resource {p.resource} != region {r.resource}"
                )

    def _typed_resources(self) -> Set[str]:
        typed: Set[str] = set()
        for p in self.places.values():
            if p.resource:
                typed.add(p.resource)
        for t in self.transitions.values():
            if t.resource:
                typed.add(t.resource)
        for r in self.regions.values():
            typed.add(r.resource)
        return typed

    def _resources_bridged(self, resources: Set[str]) -> bool:
        if len(resources) <= 1:
            # LUT+ISA on one resource still needs an explicit conversion
            if (
                RegionKind.LUT in {r.kind for r in self.regions.values()}
                and RegionKind.ISA in {r.kind for r in self.regions.values()}
            ):
                return bool(self.conversions)
            return True
        if not self.conversions:
            return False
        parent = {r: r for r in resources}

        def find(x: str) -> str:
            while parent.setdefault(x, x) != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for e in self.conversions.values():
            a, b = find(e.src_resource), find(e.dst_resource)
            parent[a] = b
        roots = {find(r) for r in resources}
        return len(roots) == 1

    def _reject_implicit_resource_edges(self) -> None:
        for t in self.transitions.values():
            if t.kind == TransKind.ROLLBACK:
                continue
            names = list(t.inputs) + list(t.outputs)
            rmap = {}
            for n in names:
                p = self.places.get(n)
                if p is not None and p.resource:
                    rmap[n] = p.resource
            kinds = set(rmap.values())
            if len(kinds) <= 1:
                continue
            # a GATE/EXPR that mixes resources is an inferred conversion
            raise MixedCompositionError(
                f"{t.name}: mixes resources {sorted(kinds)}; use a conversion edge"
            )

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "source": self.source,
            "class": self.classify(),
            "places": [p.to_dict() for p in self.places.values()],
            "transitions": [t.to_dict() for t in self.transitions.values()],
            "native": self.native,
        }
        if self.regions:
            d["regions"] = [r.to_dict() for r in self.regions.values()]
        if self.conversions:
            d["conversions"] = [e.to_dict() for e in self.conversions.values()]
        if self.evidence is not None:
            d["evidence"] = self.evidence.to_dict()
        return d


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
