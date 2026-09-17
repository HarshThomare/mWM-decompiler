"""Relation IR: M_out = F(M_in, A, T) plus at most one derived interpretation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from .events import Event, EventKind, Evidence
from .state import ArchInput, StateVariable, TimingConstraint


class DerivedForm(str, Enum):
    UNKNOWN = "unknown"
    BOOLEAN_LUT = "boolean_lut"
    BITVECTOR = "bitvector"
    TRANSITION_SYSTEM = "transition_system"
    INDEXED_MEMORY = "indexed_memory"
    BRANCH_DEPENDENT = "branch_dependent"
    SEQUENTIAL_MACHINE = "sequential_machine"


DERIVED_FORMS = frozenset(DerivedForm)


class ValidationStatus(str, Enum):
    UNRESOLVED = "unresolved"
    HYPOTHESIS = "hypothesis"
    CONFIRMED = "confirmed"
    REFINED = "refined"
    REJECTED = "rejected"
    ABSTAINED = "abstained"


def _table_to_json(table: Optional[Dict[Any, Any]]) -> Optional[Dict[str, Any]]:
    if not table:
        return None
    out: Dict[str, Any] = {}
    for k, v in table.items():
        if isinstance(k, tuple):
            out["".join(map(str, k))] = v
        else:
            out[str(k)] = v
    return out


@dataclass
class Interpretation:
    """One derived model of a relation. Absent/unknown means unresolved."""

    form: DerivedForm = DerivedForm.UNKNOWN
    payload: Dict[str, Any] = field(default_factory=dict)
    evidence: Optional[Evidence] = None

    def __post_init__(self) -> None:
        if not isinstance(self.form, DerivedForm):
            self.form = DerivedForm(self.form)

    def to_dict(self) -> Dict[str, Any]:
        payload = dict(self.payload)
        if "gate_table" in payload:
            payload["gate_table"] = _table_to_json(payload.get("gate_table"))
        if "gate_tables" in payload and payload["gate_tables"] is not None:
            payload["gate_tables"] = [_table_to_json(t) for t in payload["gate_tables"]]
        d: Dict[str, Any] = {"form": self.form.value, "payload": payload}
        if self.evidence is not None:
            d["evidence"] = self.evidence.to_dict()
        return d


def boolean_lut_interp(
    n_in: int,
    table_id: Optional[int] = None,
    n_out: int = 1,
    gate_table: Optional[Dict[Tuple[int, ...], int]] = None,
    gate_tables: Optional[List[Dict[Tuple[int, ...], int]]] = None,
    inputs: Optional[List[str]] = None,
    outputs: Optional[List[str]] = None,
) -> Interpretation:
    table = gate_table
    tables = gate_tables
    if table_id is not None and table is None:
        from .flexo_tables import decode_dual_gate, decode_outputs

        tables = decode_outputs(n_in, n_out, table_id)
        table = tables[0] if tables else decode_dual_gate(n_in, table_id)
    return Interpretation(
        form=DerivedForm.BOOLEAN_LUT,
        payload={
            "n_in": n_in,
            "n_out": n_out,
            "table_id": table_id,
            "gate_table": table,
            "gate_tables": tables,
            "inputs": list(inputs or []),
            "outputs": list(outputs or []),
        },
    )


def bitvector_interp(expr: Any, width: Optional[int] = None, **extra: Any) -> Interpretation:
    payload: Dict[str, Any] = {"expr": expr}
    if width is not None:
        payload["width"] = width
    payload.update(extra)
    return Interpretation(form=DerivedForm.BITVECTOR, payload=payload)


def transition_system_interp(
    states: Optional[List[Any]] = None,
    step: Optional[Any] = None,
    **extra: Any,
) -> Interpretation:
    payload: Dict[str, Any] = {"states": list(states or []), "step": step}
    payload.update(extra)
    return Interpretation(form=DerivedForm.TRANSITION_SYSTEM, payload=payload)


def indexed_memory_interp(
    index: Optional[Any] = None,
    cells: Optional[Any] = None,
    **extra: Any,
) -> Interpretation:
    payload: Dict[str, Any] = {"index": index, "cells": cells}
    payload.update(extra)
    return Interpretation(form=DerivedForm.INDEXED_MEMORY, payload=payload)


def branch_dependent_interp(
    predicate: Any,
    then: Optional[Any] = None,
    otherwise: Optional[Any] = None,
    **extra: Any,
) -> Interpretation:
    payload: Dict[str, Any] = {"predicate": predicate, "then": then, "else": otherwise}
    payload.update(extra)
    return Interpretation(form=DerivedForm.BRANCH_DEPENDENT, payload=payload)


def sequential_machine_interp(
    registers: Optional[Any] = None,
    step: Optional[Any] = None,
    **extra: Any,
) -> Interpretation:
    payload: Dict[str, Any] = {"registers": registers, "step": step}
    payload.update(extra)
    return Interpretation(form=DerivedForm.SEQUENTIAL_MACHINE, payload=payload)


def eval_boolean_lut(interp: Interpretation, inputs: Tuple[int, ...]) -> int:
    if interp.form != DerivedForm.BOOLEAN_LUT:
        raise ValueError(f"not a boolean_lut: {interp.form.value}")
    table = interp.payload.get("gate_table")
    if table is None:
        raise ValueError("boolean_lut has no gate_table")
    return table[inputs]


def check_interpretation(name: str, interp: Interpretation) -> None:
    """Structural payload checks. Derivation itself is a later phase."""
    form = interp.form
    p = interp.payload
    if form in (DerivedForm.UNKNOWN,):
        return
    if form == DerivedForm.BOOLEAN_LUT:
        if p.get("gate_table") is None and p.get("table_id") is None:
            raise ValueError(f"{name}: boolean_lut needs gate_table or table_id")
        return
    if form == DerivedForm.BITVECTOR:
        if p.get("expr") is None and p.get("width") is None:
            raise ValueError(f"{name}: bitvector needs expr or width")
        return
    if form == DerivedForm.TRANSITION_SYSTEM:
        if not p.get("states") and p.get("step") is None:
            raise ValueError(f"{name}: transition_system needs states or step")
        return
    if form == DerivedForm.INDEXED_MEMORY:
        if p.get("index") is None and p.get("cells") is None:
            raise ValueError(f"{name}: indexed_memory needs index or cells")
        return
    if form == DerivedForm.BRANCH_DEPENDENT:
        if p.get("predicate") is None:
            raise ValueError(f"{name}: branch_dependent needs predicate")
        return
    if form == DerivedForm.SEQUENTIAL_MACHINE:
        if p.get("registers") is None and p.get("step") is None:
            raise ValueError(f"{name}: sequential_machine needs registers or step")
        return
    raise ValueError(f"{name}: unsupported derived form {form!r}")


@dataclass
class Relation:
    """One fragment: M_out = F(M_in, A, T), with an ordered event trace.

    At most one derived interpretation. Incomplete relations stay unknown.
    """

    name: str
    m_in: Dict[str, StateVariable] = field(default_factory=dict)
    m_out: Dict[str, StateVariable] = field(default_factory=dict)
    a_inputs: Dict[str, ArchInput] = field(default_factory=dict)
    t_constraints: Dict[str, TimingConstraint] = field(default_factory=dict)
    events: List[Event] = field(default_factory=list)
    evidence: Optional[Evidence] = None
    confidence: Optional[float] = None
    validation: ValidationStatus = ValidationStatus.UNRESOLVED
    interpretation: Optional[Interpretation] = None
    source: str = ""
    entry: Optional[int] = None
    exit: Optional[int] = None

    def __post_init__(self) -> None:
        if not isinstance(self.validation, ValidationStatus):
            self.validation = ValidationStatus(self.validation)
        if self.interpretation is not None:
            check_interpretation(self.name, self.interpretation)

    def add_m_in(self, v: StateVariable) -> StateVariable:
        self.m_in[v.name] = v
        return v

    def add_m_out(self, v: StateVariable) -> StateVariable:
        self.m_out[v.name] = v
        return v

    def add_a(self, a: ArchInput) -> ArchInput:
        self.a_inputs[a.name] = a
        return a

    def add_t(self, t: TimingConstraint) -> TimingConstraint:
        self.t_constraints[t.name] = t
        return t

    def add_event(self, event: Event) -> Event:
        if not isinstance(event.kind, EventKind):
            event.kind = EventKind(event.kind)
        if not event.id:
            # Auto-ids are unique by construction; skip the O(n) scan (AES-sized traces).
            event.id = f"{self.name}.e{len(self.events)}"
            self.events.append(event)
            return event
        if any(e.id == event.id for e in self.events):
            raise ValueError(f"{self.name}: duplicate event id {event.id!r}")
        self.events.append(event)
        return event

    def set_interpretation(self, interp: Optional[Interpretation]) -> Optional[Interpretation]:
        """Attach at most one derived form. None/unknown leaves the relation unresolved."""
        if interp is None or interp.form == DerivedForm.UNKNOWN:
            self.interpretation = None
            return None
        check_interpretation(self.name, interp)
        self.interpretation = interp
        return interp

    def derived_form(self) -> DerivedForm:
        if self.interpretation is None:
            return DerivedForm.UNKNOWN
        return self.interpretation.form

    def unresolved(self) -> bool:
        return self.derived_form() == DerivedForm.UNKNOWN

    def specs(self) -> Set[str]:
        names: Set[str] = set()
        for v in list(self.m_in.values()) + list(self.m_out.values()):
            if v.spec:
                names.add(v.spec)
        return names

    def to_dict(self) -> Dict[str, Any]:
        conf = self.confidence
        if conf is None and self.evidence is not None:
            conf = self.evidence.confidence
        d: Dict[str, Any] = {
            "name": self.name,
            "m_in": [v.to_dict() for v in self.m_in.values()],
            "m_out": [v.to_dict() for v in self.m_out.values()],
            "a_inputs": [a.to_dict() for a in self.a_inputs.values()],
            "t_constraints": [t.to_dict() for t in self.t_constraints.values()],
            "events": [e.to_dict() for e in self.events],
            "validation": self.validation.value,
            "derived": self.derived_form().value,
        }
        if self.source:
            d["source"] = self.source
        if self.entry is not None:
            d["entry"] = self.entry
        if self.exit is not None:
            d["exit"] = self.exit
        if conf is not None:
            d["confidence"] = conf
        if self.evidence is not None:
            d["evidence"] = self.evidence.to_dict()
        if self.interpretation is not None and self.interpretation.form != DerivedForm.UNKNOWN:
            d["interpretation"] = self.interpretation.to_dict()
        return d


# Harvest emits one Relation per fragment. Later phases import this name.
Fragment = Relation
