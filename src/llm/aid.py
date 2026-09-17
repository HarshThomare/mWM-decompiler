"""Optional LLM overlay. Never mutates a net or relation."""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

from ir.events import Event
from ir.net import MixedCompositionError, Net
from ir.relation import DerivedForm, Fragment, Relation, ValidationStatus

from .client import ask_json, should_run

# T1 wr_kind, T2 wr_rw, T3 same_wr, T4 window_ios, T5 window_body, T6 name_lut
# stay off the correctness path. Kind / merge / window I/O / LUT identity
# come from typed IR + native/static recovery, not the model.
# Relation hypothesis is allowed but non-authoritative: it never becomes derived.
ALLOWED = ("rank", "names", "cluster", "render_c", "relation")
FORBIDDEN = ("wr_kind", "wr_rw", "same_wr", "window_ios", "window_body", "name_lut")

_PROMPTS = Path(__file__).resolve().parent / "prompts"
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_C_LOOP = re.compile(r"\b(for|while|goto|do)\b")
_C_TYPES = {"uint8_t", "uint16_t", "uint32_t", "uint64_t", "int", "unsigned", "void"}
_C_KEYS = _C_TYPES | {"return", "if", "else", "true", "false"}
_FORM_VALUES = frozenset(f.value for f in DerivedForm)
_EVIDENCE_DROP = frozenset(
    {
        "resource",
        "trigger",
        "class",
        "family",
        "native",
        "kind_guess",
        "interpretation",
        "derived",
        "validation",
        "lut",
        "isa",
    }
)
_MAX_EVIDENCE_EVENTS = 64
_MAX_EVIDENCE_STATE = 24
Candidate = Union[str, Dict[str, Any]]
FragmentLike = Union[Relation, Fragment, Dict[str, Any], List[Any]]


@dataclass(frozen=True)
class RelationHypothesis:
    """Structurally checked LLM guess. Not an Interpretation; confirmation is later."""

    form: str
    confidence: float
    cited_events: Tuple[str, ...]
    facts: Tuple[str, ...]
    inferences: Tuple[str, ...]
    note: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        status = (
            ValidationStatus.ABSTAINED.value
            if self.form == DerivedForm.UNKNOWN.value
            else ValidationStatus.HYPOTHESIS.value
        )
        return {
            "form": self.form,
            "confidence": self.confidence,
            "cited_events": list(self.cited_events),
            "facts": list(self.facts),
            "inferences": list(self.inferences),
            "note": self.note,
            "status": status,
            "confirmed": False,
        }


def verified_class(net: Net) -> str:
    if not net.relations:
        raise ValueError("unverified IR: empty")
    try:
        cls = net.compose()
    except MixedCompositionError as e:
        raise ValueError(f"unverified IR: {e}") from e
    if cls in (DerivedForm.UNKNOWN.value, ValidationStatus.REJECTED.value, "unclassified"):
        raise ValueError("unverified IR: unclassified")
    return cls


def snapshot(
    net: Net,
    relations: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """JSON-ready verified subgraph. Omits native logs."""
    cls = verified_class(net)
    rset = set(relations) if relations is not None else set(net.relations)
    missing = rset - set(net.relations)
    if missing:
        raise ValueError(f"subgraph ids not in net: {sorted(missing)}")
    d: Dict[str, Any] = {
        "name": net.name,
        "derived": cls,
        "relations": [net.relations[n].to_dict() for n in sorted(rset)],
    }
    convs = [
        e.to_dict()
        for e in net.conversions.values()
        if e.src in rset or e.dst in rset
    ]
    if convs:
        d["conversions"] = convs
    return d


def _fill(name: str, **kw: str) -> str:
    text = (_PROMPTS / name).read_text()
    for k, v in kw.items():
        text = text.replace("{" + k + "}", v)
    return text


def _node_ids(net: Net) -> Set[str]:
    ids = set(net.relations) | set(net.conversions)
    for r in net.relations.values():
        ids.update(r.m_in)
        ids.update(r.m_out)
        ids.update(r.a_inputs)
        ids.update(r.t_constraints)
        ids.update(e.id for e in r.events if e.id)
    return ids


def _candidate_ids(candidates: Sequence[Candidate]) -> List[str]:
    ids = []
    for c in candidates:
        ids.append(c if isinstance(c, str) else c["id"])
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate candidate ids")
    if not ids:
        raise ValueError("no candidates")
    return ids


def check_rank(payload: Dict[str, Any], candidate_ids: Sequence[str]) -> Dict[str, Any]:
    ranking = payload.get("ranking")
    if not isinstance(ranking, list) or not ranking:
        raise ValueError("ranking must be a non-empty list")
    allowed = set(candidate_ids)
    seen: Set[str] = set()
    out: List[str] = []
    for item in ranking:
        if not isinstance(item, str) or item not in allowed:
            raise ValueError(f"ranking id not a candidate: {item!r}")
        if item in seen:
            raise ValueError(f"duplicate ranking id: {item}")
        seen.add(item)
        out.append(item)
    note = payload.get("note", "unknown")
    if note is not None and not isinstance(note, str):
        raise ValueError("note must be a string")
    return {"ranking": out, "note": note if isinstance(note, str) else "unknown"}


def check_names(payload: Dict[str, Any], net: Net) -> Dict[str, Any]:
    names = payload.get("names")
    if not isinstance(names, dict):
        raise ValueError("names must be an object")
    known = _node_ids(net)
    out: Dict[str, str] = {}
    used: Set[str] = set()
    for old, new in names.items():
        if old not in known:
            raise ValueError(f"name key not in IR: {old!r}")
        if not isinstance(new, str):
            raise ValueError(f"name for {old!r} must be a string")
        if new == "unknown":
            continue
        if not _IDENT.match(new):
            raise ValueError(f"name {new!r} is not an identifier")
        if new in used:
            raise ValueError(f"duplicate proposed name: {new}")
        used.add(new)
        out[old] = new
    return {"names": out}


def check_cluster(payload: Dict[str, Any], net: Net) -> Dict[str, Any]:
    clusters = payload.get("clusters")
    if not isinstance(clusters, list):
        raise ValueError("clusters must be a list")
    known = {e.id for r in net.relations.values() for e in r.events if e.id}
    seen: Set[str] = set()
    out = []
    for c in clusters:
        if not isinstance(c, dict):
            raise ValueError("cluster must be an object")
        name = c.get("name")
        members = c.get("members")
        if name == "unknown":
            continue
        if not isinstance(name, str) or not _IDENT.match(name):
            raise ValueError(f"cluster name {name!r} is not an identifier")
        if not isinstance(members, list) or not members:
            raise ValueError(f"cluster {name} has no members")
        clean = []
        for m in members:
            if m not in known:
                raise ValueError(f"cluster member not an event: {m!r}")
            if m in seen:
                raise ValueError(f"event in two clusters: {m}")
            seen.add(m)
            clean.append(m)
        out.append({"name": name, "members": clean})
    return {"clusters": out}


def check_render_c(
    payload: Dict[str, Any],
    net: Net,
    names: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    src = payload.get("c")
    if src == "unknown":
        raise ValueError("render_c abstain")
    if not isinstance(src, str) or not src.strip():
        raise ValueError("c must be a non-empty string")
    if _C_LOOP.search(src) or "#" in src or "->" in src or "include" in src:
        raise ValueError("c failed structural check")
    allowed = _node_ids(net) | set((names or {}).values()) | _C_KEYS
    idents = set(re.findall(r"[A-Za-z_]\w*", src))
    m = re.search(r"(?:uint\d+_t|int|unsigned|void)\s+([A-Za-z_]\w*)\s*\(", src)
    if not m:
        raise ValueError("c is not a single typed function")
    allowed.add(m.group(1))
    extra = sorted(idents - allowed)
    if extra:
        raise ValueError(f"c identifiers not in IR: {extra}")
    return {"c": src.strip()}


def rank(
    net: Net,
    candidates: Sequence[Candidate],
    *,
    no_llm: bool = False,
    relations: Optional[Iterable[str]] = None,
) -> Optional[Dict[str, Any]]:
    if not should_run(no_llm):
        return None
    ids = _candidate_ids(candidates)
    ir = json.dumps(snapshot(net, relations=relations), indent=2)
    cand = json.dumps(list(candidates), indent=2)
    return check_rank(ask_json(_fill("rank.txt", ir=ir, candidates=cand)), ids)


def propose_names(
    net: Net,
    *,
    no_llm: bool = False,
    relations: Optional[Iterable[str]] = None,
) -> Optional[Dict[str, Any]]:
    if not should_run(no_llm):
        return None
    ir = json.dumps(snapshot(net, relations=relations), indent=2)
    return check_names(ask_json(_fill("names.txt", ir=ir)), net)


def cluster(
    net: Net,
    *,
    no_llm: bool = False,
    relations: Optional[Iterable[str]] = None,
) -> Optional[Dict[str, Any]]:
    if not should_run(no_llm):
        return None
    ir = json.dumps(snapshot(net, relations=relations), indent=2)
    return check_cluster(ask_json(_fill("cluster.txt", ir=ir)), net)


def render_c(
    net: Net,
    *,
    no_llm: bool = False,
    names: Optional[Dict[str, str]] = None,
    relations: Optional[Iterable[str]] = None,
) -> Optional[Dict[str, Any]]:
    if not should_run(no_llm):
        return None
    ir = json.dumps(snapshot(net, relations=relations), indent=2)
    raw = ask_json(_fill("render_c.txt", ir=ir, names=json.dumps(names or {}, indent=2)))
    return check_render_c(raw, net, names)


def _strip_record(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_record(v) for k, v in value.items() if k not in _EVIDENCE_DROP}
    if isinstance(value, list):
        return [_strip_record(v) for v in value]
    return value


def _event_dict(event: Any, index: int) -> Dict[str, Any]:
    if isinstance(event, Event):
        d = event.to_dict()
    elif isinstance(event, dict):
        d = _strip_record(event)
        if not isinstance(d, dict):
            raise ValueError("event must be an object")
    else:
        raise ValueError(f"event must be Event or dict, not {type(event).__name__}")
    if not d.get("id"):
        d["id"] = f"e{index}"
    if not isinstance(d["id"], str) or not d["id"]:
        raise ValueError(f"event id must be a string, got {d.get('id')!r}")
    return d


def _events_of(fragment: FragmentLike) -> List[Dict[str, Any]]:
    if isinstance(fragment, Relation):
        raw: Sequence[Any] = fragment.events
    elif isinstance(fragment, list):
        raw = fragment
    elif isinstance(fragment, dict):
        if "events" in fragment:
            raw = fragment.get("events") or []
        elif "trace" in fragment:
            raw = fragment.get("trace") or []
        else:
            raise ValueError("event-trace dict needs events")
        if not isinstance(raw, list):
            raise ValueError("events must be a list")
    else:
        raise TypeError(
            f"fragment must be Relation or event-trace dict, not {type(fragment).__name__}"
        )
    return [_event_dict(e, i) for i, e in enumerate(raw)]


def event_ids(fragment: FragmentLike) -> List[str]:
    ids = [e["id"] for e in _events_of(fragment)]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate event ids")
    return ids


def fragment_evidence(fragment: FragmentLike) -> Dict[str, Any]:
    """Harvested event/dataflow evidence only. No native logs, no family labels."""
    events = _events_of(fragment)
    if isinstance(fragment, Relation):
        d: Dict[str, Any] = {"name": fragment.name, "events": events}
        if fragment.m_in:
            d["m_in"] = [_strip_record(v.to_dict()) for v in fragment.m_in.values()]
        if fragment.m_out:
            d["m_out"] = [_strip_record(v.to_dict()) for v in fragment.m_out.values()]
        if fragment.a_inputs:
            d["a_inputs"] = [_strip_record(a.to_dict()) for a in fragment.a_inputs.values()]
        if fragment.t_constraints:
            d["t_constraints"] = [_strip_record(t.to_dict()) for t in fragment.t_constraints.values()]
        return d
    if isinstance(fragment, list):
        return {"events": events}
    d = {"events": events}
    name = fragment.get("name")
    if isinstance(name, str) and name:
        d["name"] = name
    for key in ("m_in", "m_out", "a_inputs", "t_constraints"):
        if key in fragment:
            d[key] = _strip_record(fragment[key])
    return d


def _event_priority(event: Dict[str, Any]) -> int:
    kind = event.get("kind")
    prov = " ".join(event.get("provenance") or [])
    if kind in ("WINDOW_OPEN", "WINDOW_SQUASH", "STATE_READ", "STATE_OBSERVE", "STATE_TRAIN"):
        return 0
    if kind == "STATE_WRITE" and "wr_fake_offset" in prov:
        return 1
    if kind == "STATE_CLEAR":
        return 2
    if kind == "ARCH_BRANCH":
        return 2
    if kind == "ARCH_COMPUTE" and "wr_stride" in prov:
        return 3
    if kind == "WINDOW_EXTEND":
        return 4
    return 5


def compact_fragment_evidence(
    fragment: FragmentLike,
    *,
    max_events: int = _MAX_EVIDENCE_EVENTS,
) -> Dict[str, Any]:
    """Summary + stratified sample so large functions fit in one hypothesis prompt."""
    blob = fragment_evidence(fragment)
    events = list(blob.get("events") or [])
    kinds: Dict[str, int] = {}
    insns: Dict[str, int] = {}
    strides: List[str] = []
    for e in events:
        k = str(e.get("kind") or "?")
        kinds[k] = kinds.get(k, 0) + int(e.get("attrs", {}).get("repeat") or 1)
        ins = str(e.get("insn") or "?")
        insns[ins] = insns.get(ins, 0) + int(e.get("attrs", {}).get("repeat") or 1)
        if k == "ARCH_COMPUTE" and e.get("operand"):
            strides.append(str(e["operand"]))
    motifs = [f"{k} x{n}" for k, n in sorted(kinds.items(), key=lambda kv: -kv[1])]
    insn_top = [f"{n} x{c}" for n, c in sorted(insns.items(), key=lambda kv: -kv[1])[:8]]
    stride_u = sorted(set(strides))[:8]
    sent = events
    truncated = len(events) > max_events
    if truncated:
        ranked = sorted(range(len(events)), key=lambda i: (_event_priority(events[i]), i))
        pick = sorted(ranked[:max_events])
        sent = [events[i] for i in pick]
    blob["events"] = sent
    blob["summary"] = {
        "n_events": len(events),
        "n_events_sent": len(sent),
        "truncated": truncated,
        "kinds": kinds,
        "insns": insn_top,
        "motifs": motifs,
        "strides": stride_u,
        "n_windows": kinds.get("WINDOW_OPEN", 0) + kinds.get("WINDOW_SQUASH", 0),
    }
    for key in ("m_in", "m_out", "a_inputs"):
        vals = blob.get(key)
        if isinstance(vals, list) and len(vals) > _MAX_EVIDENCE_STATE:
            blob[key] = vals[:_MAX_EVIDENCE_STATE]
            blob["summary"][f"n_{key}"] = len(vals)
    return blob


def _str_list(payload: Dict[str, Any], key: str) -> List[str]:
    value = payload.get(key)
    if not isinstance(value, list):
        raise ValueError(f"{key} must be a list")
    out: List[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{key} items must be strings")
        out.append(item)
    return out


def check_relation_hypothesis(payload: Dict[str, Any], fragment: FragmentLike) -> RelationHypothesis:
    """Structural gates only. Does not confirm or attach an Interpretation."""
    if not isinstance(payload, dict):
        raise ValueError("hypothesis must be an object")
    form = payload.get("form")
    if not isinstance(form, str) or form not in _FORM_VALUES:
        raise ValueError(f"unsupported derived form: {form!r}")
    conf = payload.get("confidence")
    if isinstance(conf, bool) or not isinstance(conf, (int, float)):
        raise ValueError("confidence must be a number in [0, 1]")
    confidence = float(conf)
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be a number in [0, 1]")
    cited = payload.get("cited_events")
    if not isinstance(cited, list):
        raise ValueError("cited_events must be a list")
    known = set(event_ids(fragment))
    seen: Set[str] = set()
    cited_events: List[str] = []
    for item in cited:
        if not isinstance(item, str) or item not in known:
            raise ValueError(f"cited event id not in fragment: {item!r}")
        if item in seen:
            raise ValueError(f"duplicate cited event id: {item}")
        seen.add(item)
        cited_events.append(item)
    if form != DerivedForm.UNKNOWN.value and not cited_events:
        raise ValueError("non-unknown form must cite event ids")
    facts = _str_list(payload, "facts")
    inferences = _str_list(payload, "inferences")
    overlap = sorted(set(facts) & set(inferences))
    if overlap:
        raise ValueError(f"facts and inferences must be distinct: {overlap}")
    if form != DerivedForm.UNKNOWN.value and not facts:
        raise ValueError("non-unknown form must include facts")
    note = payload.get("note", "unknown")
    if note is not None and not isinstance(note, str):
        raise ValueError("note must be a string")
    return RelationHypothesis(
        form=form,
        confidence=confidence,
        cited_events=tuple(cited_events),
        facts=tuple(facts),
        inferences=tuple(inferences),
        note=note if isinstance(note, str) else "unknown",
    )


def propose_relation(
    fragment: FragmentLike,
    *,
    no_llm: bool = False,
    complete_fn: Optional[Callable[[str], str]] = None,
) -> Optional[RelationHypothesis]:
    """Hypothesis only. Does not mutate `fragment` or write an Interpretation."""
    if no_llm:
        return None
    if complete_fn is None and not should_run(False):
        return None
    compact = compact_fragment_evidence(fragment)
    evidence = json.dumps(compact, indent=2)
    raw = ask_json(_fill("relation.txt", evidence=evidence), complete_fn=complete_fn)
    return check_relation_hypothesis(raw, compact)
