"""Canonical harvest event vocabulary.

Concrete instruction, address, operand/binding, state subject, and provenance
are attributes on these primitives — not additional primitive names.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence


class EventKind(str, Enum):
    STATE_READ = "STATE_READ"
    STATE_WRITE = "STATE_WRITE"
    STATE_CLEAR = "STATE_CLEAR"
    STATE_TRAIN = "STATE_TRAIN"
    STATE_OBSERVE = "STATE_OBSERVE"
    WINDOW_OPEN = "WINDOW_OPEN"
    WINDOW_SQUASH = "WINDOW_SQUASH"
    WINDOW_EXTEND = "WINDOW_EXTEND"
    ARCH_COMPUTE = "ARCH_COMPUTE"
    ARCH_BRANCH = "ARCH_BRANCH"
    ARCH_MEMORY = "ARCH_MEMORY"


CANONICAL_EVENT_KINDS = frozenset(EventKind)


@dataclass
class Evidence:
    """Observations plus an optional confidence. No resource/trigger labels."""

    observations: List[Dict[str, Any]] = field(default_factory=list)
    confidence: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        if self.observations:
            d["observations"] = list(self.observations)
        if self.confidence is not None:
            d["confidence"] = self.confidence
        return d


@dataclass
class Event:
    kind: EventKind
    id: str = ""
    addr: Optional[int] = None
    insn: Optional[str] = None
    operand: Optional[str] = None
    binding: Optional[str] = None
    subject: Optional[str] = None  # M state-variable name, when known
    provenance: List[str] = field(default_factory=list)
    note: str = ""
    evidence: Optional[Evidence] = None
    attrs: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, EventKind):
            self.kind = EventKind(self.kind)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"id": self.id, "kind": self.kind.value}
        if self.addr is not None:
            d["addr"] = self.addr
        if self.insn is not None:
            d["insn"] = self.insn
        if self.operand is not None:
            d["operand"] = self.operand
        if self.binding is not None:
            d["binding"] = self.binding
        if self.subject is not None:
            d["subject"] = self.subject
        if self.provenance:
            d["provenance"] = list(self.provenance)
        if self.note:
            d["note"] = self.note
        if self.evidence is not None:
            d["evidence"] = self.evidence.to_dict()
        if self.attrs:
            d["attrs"] = dict(self.attrs)
        return d


def make_event(
    kind: EventKind | str,
    *,
    id: str = "",
    addr: Optional[int] = None,
    insn: Optional[str] = None,
    operand: Optional[str] = None,
    binding: Optional[str] = None,
    subject: Optional[str] = None,
    provenance: Optional[Sequence[str]] = None,
    note: str = "",
    evidence: Optional[Evidence] = None,
    **attrs: Any,
) -> Event:
    return Event(
        kind=EventKind(kind) if not isinstance(kind, EventKind) else kind,
        id=id,
        addr=addr,
        insn=insn,
        operand=operand,
        binding=binding,
        subject=subject,
        provenance=list(provenance or ()),
        note=note,
        evidence=evidence,
        attrs=dict(attrs),
    )
