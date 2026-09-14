"""Optional LLM overlay on verified typed IR. Never mutates the net."""

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Union

from ir.net import MixedCompositionError, Net, TransKind

from .client import ask_json, should_run

# T1 wr_kind, T2 wr_rw, T3 same_wr, T4 window_ios, T5 window_body, T6 name_lut
# stay off the correctness path. Kind / merge / window I/O / LUT identity
# come from typed IR + native/static recovery, not the model.
ALLOWED = ("rank", "names", "cluster", "render_c")
FORBIDDEN = ("wr_kind", "wr_rw", "same_wr", "window_ios", "window_body", "name_lut")

_PROMPTS = Path(__file__).resolve().parent / "prompts"
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_C_LOOP = re.compile(r"\b(for|while|goto|do)\b")
_C_TYPES = {"uint8_t", "uint16_t", "uint32_t", "uint64_t", "int", "unsigned", "void"}
_C_KEYS = _C_TYPES | {"return", "if", "else", "true", "false"}
Candidate = Union[str, Dict[str, Any]]


def verified_class(net: Net) -> str:
    useful = any(t.kind != TransKind.ROLLBACK for t in net.transitions.values()) or bool(net.regions)
    if not useful:
        raise ValueError("unverified IR: empty")
    try:
        cls = net.compose()
    except MixedCompositionError as e:
        raise ValueError(f"unverified IR: {e}") from e
    if cls == "unclassified":
        raise ValueError("unverified IR: unclassified")
    return cls


def snapshot(
    net: Net,
    places: Optional[Iterable[str]] = None,
    transitions: Optional[Iterable[str]] = None,
    regions: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """JSON-ready verified subgraph. Omits native logs."""
    cls = verified_class(net)
    pset = set(places) if places is not None else set(net.places)
    tset = set(transitions) if transitions is not None else set(net.transitions)
    rset = set(regions) if regions is not None else set(net.regions)
    missing = (pset - set(net.places)) | (tset - set(net.transitions)) | (rset - set(net.regions))
    if missing:
        raise ValueError(f"subgraph ids not in net: {sorted(missing)}")
    d: Dict[str, Any] = {
        "name": net.name,
        "class": cls,
        "places": [net.places[n].to_dict() for n in sorted(pset)],
        "transitions": [net.transitions[n].to_dict() for n in sorted(tset)],
    }
    if rset:
        d["regions"] = [net.regions[n].to_dict() for n in sorted(rset)]
    convs = [
        e.to_dict()
        for e in net.conversions.values()
        if e.src in pset or e.dst in pset
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
    return set(net.places) | set(net.transitions) | set(net.regions)


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
    known = {n for n, t in net.transitions.items() if t.kind != TransKind.ROLLBACK}
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
                raise ValueError(f"cluster member not a transition: {m!r}")
            if m in seen:
                raise ValueError(f"transition in two clusters: {m}")
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
    # function name may be new; drop the first identifier after a type
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
    places: Optional[Iterable[str]] = None,
    transitions: Optional[Iterable[str]] = None,
) -> Optional[Dict[str, Any]]:
    if not should_run(no_llm):
        return None
    ids = _candidate_ids(candidates)
    ir = json.dumps(snapshot(net, places=places, transitions=transitions), indent=2)
    cand = json.dumps(list(candidates), indent=2)
    return check_rank(ask_json(_fill("rank.txt", ir=ir, candidates=cand)), ids)


def propose_names(
    net: Net,
    *,
    no_llm: bool = False,
    places: Optional[Iterable[str]] = None,
    transitions: Optional[Iterable[str]] = None,
) -> Optional[Dict[str, Any]]:
    if not should_run(no_llm):
        return None
    ir = json.dumps(snapshot(net, places=places, transitions=transitions), indent=2)
    return check_names(ask_json(_fill("names.txt", ir=ir)), net)


def cluster(
    net: Net,
    *,
    no_llm: bool = False,
    places: Optional[Iterable[str]] = None,
    transitions: Optional[Iterable[str]] = None,
) -> Optional[Dict[str, Any]]:
    if not should_run(no_llm):
        return None
    ir = json.dumps(snapshot(net, places=places, transitions=transitions), indent=2)
    return check_cluster(ask_json(_fill("cluster.txt", ir=ir)), net)


def render_c(
    net: Net,
    *,
    no_llm: bool = False,
    names: Optional[Dict[str, str]] = None,
    places: Optional[Iterable[str]] = None,
    transitions: Optional[Iterable[str]] = None,
) -> Optional[Dict[str, Any]]:
    if not should_run(no_llm):
        return None
    ir = json.dumps(snapshot(net, places=places, transitions=transitions), indent=2)
    raw = ask_json(_fill("render_c.txt", ir=ir, names=json.dumps(names or {}, indent=2)))
    return check_render_c(raw, net, names)
