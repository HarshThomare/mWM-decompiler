"""Relation-first µWM IR: nets of M_out = F(M_in, A, T) fragments.

Typed composition refuses unsupported fusion of derived forms or state-variable
domains unless an explicit ConversionEdge bridges them. Incomplete relations
stay unknown rather than being forced into a family.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .events import CANONICAL_EVENT_KINDS, Event, EventKind, Evidence, make_event
# Temporary stubs: oracle/eval/flexo_static still import these; delete _legacy with them.
from ._legacy import (
    Kind,
    Place,
    Region,
    RegionKind,
    ResourceKind,
    ResourceSpec,
    TransKind,
    Transition,
    gate_transition,
    isa_region,
    lut_region,
    register_resource,
    resource_spec,
    wr_place,
)
from .relation import (
    DERIVED_FORMS,
    DerivedForm,
    Fragment,
    Interpretation,
    Relation,
    ValidationStatus,
    bitvector_interp,
    boolean_lut_interp,
    branch_dependent_interp,
    check_interpretation,
    eval_boolean_lut,
    indexed_memory_interp,
    sequential_machine_interp,
    transition_system_interp,
)
from .state import (
    BTB_ENTRY,
    CACHE_OCCUPANCY,
    TLB_ENTRY,
    ArchInput,
    Persistence,
    StateVariable,
    StateVarSpec,
    TimingConstraint,
    register_state_spec,
    state_var,
    state_var_spec,
)


class MixedCompositionError(ValueError):
    """Unsupported fusion of derived forms or state domains without a conversion."""


@dataclass
class ConversionEdge:
    """Explicit conversion between relations / derived forms / M specs. Never inferred."""

    name: str
    src: str
    dst: str
    src_form: Optional[str] = None
    dst_form: Optional[str] = None
    src_spec: Optional[str] = None
    dst_spec: Optional[str] = None
    encoding: Optional[str] = None
    evidence: Optional[Evidence] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"name": self.name, "src": self.src, "dst": self.dst}
        if self.src_form is not None:
            d["src_form"] = self.src_form
        if self.dst_form is not None:
            d["dst_form"] = self.dst_form
        if self.src_spec is not None:
            d["src_spec"] = self.src_spec
        if self.dst_spec is not None:
            d["dst_spec"] = self.dst_spec
        if self.encoding is not None:
            d["encoding"] = self.encoding
        if self.evidence is not None:
            d["evidence"] = self.evidence.to_dict()
        return d


@dataclass
class Net:
    name: str
    relations: Dict[str, Relation] = field(default_factory=dict)
    conversions: Dict[str, ConversionEdge] = field(default_factory=dict)
    evidence: Optional[Evidence] = None
    source: str = ""
    native: Dict[str, Any] = field(default_factory=dict)

    def add_relation(self, r: Relation) -> Relation:
        self.relations[r.name] = r
        return r

    def add_conversion(self, e: ConversionEdge) -> ConversionEdge:
        self.conversions[e.name] = e
        return e

    def compose_relation(self, name: str) -> str:
        r = self.relations[name]
        check_interpretation(r.name, r.interpretation or Interpretation())
        for ev in r.events:
            if ev.kind not in CANONICAL_EVENT_KINDS:
                raise MixedCompositionError(f"{r.name}: non-canonical event {ev.kind!r}")
        return r.derived_form().value

    def compose(self) -> str:
        """Single derived form, or MixedCompositionError if fusion is unsupported.

        Homogeneous resolved relations compose to that form. Distinct derived
        forms or M specs in one net are allowed only with conversion edges.
        A net of unresolved relations stays ``unknown``.
        """
        self._reject_mixed()
        active = self._active()
        if not active:
            if self.relations:
                return ValidationStatus.REJECTED.value
            return DerivedForm.UNKNOWN.value
        forms = self._form_labels(active)
        specs = self._typed_specs(active)
        if forms == {DerivedForm.UNKNOWN.value}:
            return DerivedForm.UNKNOWN.value
        resolved = forms - {DerivedForm.UNKNOWN.value}
        if len(resolved) == 1 and len(forms) == 1 and len(specs) <= 1:
            return next(iter(resolved))
        if len(resolved) == 1 and len(forms) == 1 and self._bridged(active, specs, forms):
            return "converted"
        if self._bridged(active, specs, forms):
            return "converted"
        return next(iter(resolved)) if len(resolved) == 1 else DerivedForm.UNKNOWN.value

    def derived(self) -> str:
        """Non-raising compose summary for serialization."""
        try:
            return self.compose()
        except MixedCompositionError:
            return "mixed"

    def _active(self) -> List[Relation]:
        return [r for r in self.relations.values() if r.validation != ValidationStatus.REJECTED]

    def _form_labels(self, rels: List[Relation]) -> Set[str]:
        return {r.derived_form().value for r in rels}

    def _typed_specs(self, rels: List[Relation]) -> Set[str]:
        specs: Set[str] = set()
        for r in rels:
            specs.update(r.specs())
        return specs

    def _reject_mixed(self) -> None:
        rejected = [r for r in self.relations.values() if r.validation == ValidationStatus.REJECTED]
        active = self._active()
        if rejected and active:
            raise MixedCompositionError(
                f"{self.name}: rejected relations {[r.name for r in rejected]} cannot fuse with others"
            )
        for r in self.relations.values():
            self._check_relation(r)
        if len(active) <= 1:
            return
        forms = self._form_labels(active)
        specs = self._typed_specs(active)
        heterogeneous = len(forms) > 1 or len(specs) > 1
        if heterogeneous and not self._bridged(active, specs, forms):
            raise MixedCompositionError(
                f"{self.name}: mixed composition forms={sorted(forms)} "
                f"specs={sorted(specs)} without conversion edges"
            )

    def _check_relation(self, r: Relation) -> None:
        seen: Set[str] = set()
        for ev in r.events:
            if ev.kind not in CANONICAL_EVENT_KINDS:
                raise MixedCompositionError(f"{r.name}: non-canonical event {ev.kind!r}")
            if ev.id in seen:
                raise MixedCompositionError(f"{r.name}: duplicate event id {ev.id!r}")
            if ev.id:
                seen.add(ev.id)
        if r.interpretation is not None:
            try:
                check_interpretation(r.name, r.interpretation)
            except ValueError as e:
                raise MixedCompositionError(str(e)) from e

    def _bridged(self, rels: List[Relation], specs: Set[str], forms: Set[str]) -> bool:
        if len(rels) <= 1:
            return True
        if len(forms) <= 1 and len(specs) <= 1:
            return True
        if not self.conversions:
            return False
        names = {r.name for r in rels}
        parent: Dict[str, str] = {n: n for n in names}
        spec_parent: Dict[str, str] = {s: s for s in specs}

        def find(x: str, p: Dict[str, str]) -> str:
            while p.setdefault(x, x) != x:
                p[x] = p[p[x]]
                x = p[x]
            return x

        def union(a: str, b: str, p: Dict[str, str]) -> None:
            p[find(a, p)] = find(b, p)

        rel_by_name = {r.name: r for r in rels}
        linked = False
        for e in self.conversions.values():
            if e.src not in names or e.dst not in names:
                raise MixedCompositionError(
                    f"{self.name}: conversion {e.name} endpoints {e.src}/{e.dst} missing"
                )
            union(e.src, e.dst, parent)
            linked = True
            if e.src_spec and e.dst_spec:
                union(e.src_spec, e.dst_spec, spec_parent)
            else:
                src_specs = rel_by_name[e.src].specs()
                dst_specs = rel_by_name[e.dst].specs()
                if src_specs and dst_specs:
                    a0 = next(iter(src_specs))
                    b0 = next(iter(dst_specs))
                    for s in src_specs:
                        union(s, a0, spec_parent)
                    for s in dst_specs:
                        union(s, b0, spec_parent)
                    union(a0, b0, spec_parent)
        if not linked:
            return False
        rel_roots = {find(n, parent) for n in names}
        if len(rel_roots) != 1:
            return False
        if len(specs) > 1:
            spec_roots = {find(s, spec_parent) for s in specs}
            if len(spec_roots) != 1:
                return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "source": self.source,
            "derived": self.derived(),
            "relations": [r.to_dict() for r in self.relations.values()],
            "native": self.native,
        }
        if self.conversions:
            d["conversions"] = [e.to_dict() for e in self.conversions.values()]
        if self.evidence is not None:
            d["evidence"] = self.evidence.to_dict()
        return d


__all__ = [
    "ArchInput",
    "BTB_ENTRY",
    "CACHE_OCCUPANCY",
    "CANONICAL_EVENT_KINDS",
    "ConversionEdge",
    "DERIVED_FORMS",
    "DerivedForm",
    "Event",
    "EventKind",
    "Evidence",
    "Fragment",
    "Interpretation",
    "MixedCompositionError",
    "Net",
    "Persistence",
    "Relation",
    "StateVarSpec",
    "StateVariable",
    "TLB_ENTRY",
    "TimingConstraint",
    "ValidationStatus",
    "bitvector_interp",
    "boolean_lut_interp",
    "branch_dependent_interp",
    "check_interpretation",
    "eval_boolean_lut",
    "indexed_memory_interp",
    "make_event",
    "register_state_spec",
    "sequential_machine_interp",
    "state_var",
    "state_var_spec",
    "transition_system_interp",
    # stubs; later phases delete
    "Kind",
    "Place",
    "Region",
    "RegionKind",
    "ResourceKind",
    "ResourceSpec",
    "TransKind",
    "Transition",
    "gate_transition",
    "isa_region",
    "lut_region",
    "register_resource",
    "resource_spec",
    "wr_place",
]
