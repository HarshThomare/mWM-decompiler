"""Exception-window occupancy: confirm boolean_lut on harvested traces.

GITM-style #DE windows are timing (T), not a family label. Native occupancy
may fill a LUT; unemulated windows stay unknown rather than faking one.
"""

from __future__ import annotations

from typing import List, Tuple

from ir.events import EventKind
from ir.flexo_tables import encode_dual_gate
from ir.relation import Relation, ValidationStatus
from ir.state import CACHE_OCCUPANCY
from oracle.cache import CacheAdapter

from .flexo import (
    HIT,
    MISS,
    apply_boolean_lut,
    evidence_from_native,
    lut_from_dual_rail,
    occupancy_io,
)

_EXC = "cacm.window.exception"


def is_exception_window(rel: Relation) -> bool:
    return any(
        e.kind == EventKind.WINDOW_OPEN and (_EXC in " ".join(e.provenance) or _EXC in (e.note or ""))
        for e in rel.events
    )


def hex_keys(rel: Relation) -> List[str]:
    keys: List[str] = []
    for v in list(rel.m_in.values()) + list(rel.m_out.values()):
        s = str(v.phys_key or "")
        if not s.startswith("0x"):
            continue
        try:
            int(s, 16)
        except ValueError:
            continue
        if s not in keys:
            keys.append(s)
    keys.sort(key=lambda s: int(s, 16), reverse=True)
    return keys


def exception_window(rel: Relation) -> Tuple[int, int]:
    """Stop at the first timer after the exception; later flushes are the next trial."""
    start = rel.entry if rel.entry is not None else 0
    trigs = sorted(
        e.addr
        for e in rel.events
        if e.addr is not None
        and e.kind == EventKind.WINDOW_OPEN
        and (_EXC in " ".join(e.provenance) or _EXC in (e.note or ""))
    )
    timers = sorted(
        e.addr for e in rel.events if e.addr is not None and e.kind == EventKind.STATE_OBSERVE
    )
    if not trigs:
        return start, rel.exit or (start + 0x200)
    t0 = trigs[0]
    t1 = trigs[1] if len(trigs) > 1 else None
    after = [a for a in timers if a > t0 and (t1 is None or a < t1)]
    if after:
        end = after[0]
    elif t1 is not None:
        end = t1
    else:
        end = t0 + 0x120
    return start, end


def refine_exception_occupancy(rel: Relation, ctx) -> None:
    """Fill a LUT from occupancy samples on an exception window. No samples → no LUT."""
    if not is_exception_window(rel):
        return
    if CACHE_OCCUPANCY not in rel.specs() and not any(e.subject == CACHE_OCCUPANCY for e in rel.events):
        return
    keys = hex_keys(rel)
    ins, out = occupancy_io(rel)
    if len(keys) >= 2:
        ins, out = keys[:-1], keys[-1:]
    trials = (ctx.occupancy or {}).get(rel.name)
    if not trials:
        lo, hi = exception_window(rel)
        if rel.t_constraints:
            t0 = next(iter(rel.t_constraints.values()))
            t0.window_len = hi - lo
        return
    n_in = len(next(iter(trials)))
    adapter: CacheAdapter = ctx.cache or CacheAdapter()
    if not adapter.cal.ok:
        adapter.calibrate_occupancy([HIT] * 8, [MISS] * 8)
    table = lut_from_dual_rail(adapter, n_in, trials)
    if table is None:
        if rel.interpretation is not None:
            return
        rel.set_interpretation(None)
        rel.validation = ValidationStatus.REJECTED
        ctx.reject(rel, "occupancy_invalid")
        return
    apply_boolean_lut(
        rel,
        n_in=n_in,
        table=table,
        table_id=encode_dual_gate(n_in, table),
        inputs=ins[:n_in],
        outputs=out[:1] or [f"{rel.name}.out"],
    )
    ones = sum(table.values())
    rec = adapter.recover_dual_rail(next(iter(trials.values())))
    ev = evidence_from_native(rec)
    ev.observations = list(ev.observations) + [
        {"table": {"".join(map(str, k)): v for k, v in table.items()}, "window": list(exception_window(rel))}
    ]
    ev.confidence = 0.85 if 0 < ones < (1 << n_in) else 0.4
    rel.evidence = ev
    rel.confidence = ev.confidence
    rel.validation = ValidationStatus.CONFIRMED
