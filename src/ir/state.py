"""Microarchitectural state variables (M), architectural inputs (A), timing (T).

M is weakly represented / invisible at ISA. Native adapters validate claims
about M against StateVarSpec (cache occupancy, BTB train/observe, TLB evict/walk).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from .events import Evidence


class Persistence(str, Enum):
    VOLATILE = "volatile"
    PERSISTENT = "persistent"


@dataclass(frozen=True)
class StateVarSpec:
    """Defaults for a class of microarchitectural state variables."""

    name: str
    encoding: str
    destructive_read: bool
    persistent: bool
    width: int = 1
    phys_key_role: str = ""
    adapter: str = ""  # occupancy | train_observe | evict_walk | ...


CACHE_OCCUPANCY = "cache_occupancy"
BTB_ENTRY = "btb_entry"
TLB_ENTRY = "tlb_entry"

_SPECS: Dict[str, StateVarSpec] = {
    CACHE_OCCUPANCY: StateVarSpec(
        name=CACHE_OCCUPANCY,
        encoding="dual_rail",
        destructive_read=True,
        persistent=False,
        width=1,
        phys_key_role="line",
        adapter="occupancy",
    ),
    BTB_ENTRY: StateVarSpec(
        name=BTB_ENTRY,
        encoding="btb_target",
        destructive_read=False,
        persistent=True,
        width=16,
        phys_key_role="btb_index",
        adapter="train_observe",
    ),
    TLB_ENTRY: StateVarSpec(
        name=TLB_ENTRY,
        encoding="hit_miss",
        destructive_read=True,
        persistent=False,
        width=1,
        phys_key_role="vpn",
        adapter="evict_walk",
    ),
}


def register_state_spec(spec: StateVarSpec) -> StateVarSpec:
    _SPECS[spec.name] = spec
    return spec


def state_var_spec(name: str) -> StateVarSpec:
    if name not in _SPECS:
        raise KeyError(f"unknown state-variable spec {name!r}; register_state_spec() first")
    return _SPECS[name]


def _spec_name(spec: Union[str, StateVarSpec]) -> str:
    return spec.name if isinstance(spec, StateVarSpec) else str(spec)


@dataclass
class StateVariable:
    """One M variable: a weird register plus its physical key, when known."""

    name: str
    spec: str = ""
    phys_key: Optional[str] = None
    encoding: Optional[str] = None
    width: Optional[int] = None
    persistence: Persistence = Persistence.VOLATILE
    destructive_read: Optional[bool] = None
    evidence: Optional[Evidence] = None

    def __post_init__(self) -> None:
        if not isinstance(self.persistence, Persistence):
            self.persistence = Persistence(self.persistence)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "spec": self.spec,
            "persistence": self.persistence.value,
        }
        if self.phys_key is not None:
            d["phys_key"] = self.phys_key
        if self.encoding is not None:
            d["encoding"] = self.encoding
        if self.width is not None:
            d["width"] = self.width
        if self.destructive_read is not None:
            d["destructive_read"] = self.destructive_read
        if self.evidence is not None:
            d["evidence"] = self.evidence.to_dict()
        return d


def state_var(
    name: str,
    spec: Union[str, StateVarSpec],
    phys_key: Optional[str] = None,
    evidence: Optional[Evidence] = None,
) -> StateVariable:
    """State variable filled from a registered spec (replaces wr_place)."""
    s = state_var_spec(_spec_name(spec))
    return StateVariable(
        name,
        spec=s.name,
        phys_key=phys_key,
        encoding=s.encoding,
        width=s.width,
        persistence=Persistence.PERSISTENT if s.persistent else Persistence.VOLATILE,
        destructive_read=s.destructive_read,
        evidence=evidence,
    )


@dataclass
class ArchInput:
    """Architectural or transient operand feeding F (the A in M_out = F(M_in, A, T))."""

    name: str
    domain: str = "bit"
    width: Optional[int] = None
    binding: Optional[str] = None
    transient: bool = False
    evidence: Optional[Evidence] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"name": self.name, "domain": self.domain, "transient": self.transient}
        if self.width is not None:
            d["width"] = self.width
        if self.binding is not None:
            d["binding"] = self.binding
        if self.evidence is not None:
            d["evidence"] = self.evidence.to_dict()
        return d


@dataclass
class TimingConstraint:
    """Window / timing condition (the T in M_out = F(M_in, A, T))."""

    name: str
    kind: str = ""
    window_len: Optional[int] = None
    pred: Optional[str] = None
    related_events: List[str] = field(default_factory=list)
    evidence: Optional[Evidence] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"name": self.name}
        if self.kind:
            d["kind"] = self.kind
        if self.window_len is not None:
            d["window_len"] = self.window_len
        if self.pred is not None:
            d["pred"] = self.pred
        if self.related_events:
            d["related_events"] = list(self.related_events)
        if self.evidence is not None:
            d["evidence"] = self.evidence.to_dict()
        return d
