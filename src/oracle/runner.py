"""Shared native runner: affinity, repeats, thresholds, evidence."""

from __future__ import annotations

import os
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from ir.net import Evidence, Net, Place, wr_place


@dataclass
class AdapterConfig:
    core: int = 0
    repetitions: int = 32
    warmup: int = 4
    timeout_s: int = 60
    admit_confidence: float = 0.9
    overlap_limit: float = 0.2
    invalid_frac: float = 0.1


@dataclass
class Calibration:
    kind: str = "bimodal"
    threshold: Optional[float] = None
    low_median: Optional[float] = None
    high_median: Optional[float] = None
    separation: float = 0.0
    overlap: float = 1.0
    invalid_margin: float = 0.0
    ok: bool = False
    notes: str = ""

    def classify(self, x: float) -> Optional[int]:
        """0 = low cluster, 1 = high cluster, None = invalid band."""
        if not self.ok or self.threshold is None:
            return None
        if abs(x - self.threshold) < self.invalid_margin:
            return None
        return 0 if x < self.threshold else 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "threshold": self.threshold,
            "low_median": self.low_median,
            "high_median": self.high_median,
            "separation": self.separation,
            "overlap": self.overlap,
            "invalid_margin": self.invalid_margin,
            "ok": self.ok,
            "notes": self.notes,
        }


@dataclass
class NativeResult:
    resource: str
    protocol: str
    value: Any = None
    causal: Optional[bool] = None
    confidence: Optional[float] = None
    invalid: bool = False
    uncertainty: Optional[str] = None
    observations: List[Dict[str, Any]] = field(default_factory=list)
    calibration: Dict[str, Any] = field(default_factory=dict)
    trigger: Optional[str] = None
    flush_state: Optional[str] = None
    phys_key: Optional[str] = None
    wemu_supported: bool = False
    core: int = 0
    repetitions: int = 0

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "resource": self.resource,
            "protocol": self.protocol,
            "value": self.value,
            "causal": self.causal,
            "invalid": self.invalid,
            "wemu_supported": self.wemu_supported,
            "core": self.core,
            "repetitions": self.repetitions,
        }
        if self.confidence is not None:
            d["confidence"] = self.confidence
        if self.uncertainty is not None:
            d["uncertainty"] = self.uncertainty
        if self.trigger is not None:
            d["trigger"] = self.trigger
        if self.flush_state is not None:
            d["flush_state"] = self.flush_state
        if self.phys_key is not None:
            d["phys_key"] = self.phys_key
        if self.observations:
            d["observations"] = list(self.observations)
        if self.calibration:
            d["calibration"] = dict(self.calibration)
        return d

    def to_evidence(self) -> Evidence:
        obs = list(self.observations)
        meta = {
            "protocol": self.protocol,
            "invalid": self.invalid,
            "wemu_supported": self.wemu_supported,
        }
        if self.causal is not None:
            meta["causal"] = self.causal
        if self.uncertainty is not None:
            meta["uncertainty"] = self.uncertainty
        if self.flush_state is not None:
            meta["flush_state"] = self.flush_state
        if self.phys_key is not None:
            meta["phys_key"] = self.phys_key
        if self.value is not None:
            meta["value"] = self.value
        obs.append(meta)
        return Evidence(trigger=self.trigger, observations=obs, confidence=self.confidence)


def _median(xs: Sequence[float]) -> float:
    s = sorted(xs)
    return float(s[len(s) // 2])


def majority(values: Iterable[Any]) -> Tuple[Any, float, int]:
    seq = list(values)
    if not seq:
        return None, 0.0, 0
    counts = Counter(seq)
    val, n = counts.most_common(1)[0]
    return val, n / len(seq), len(seq)


class NativeRunner:
    """Pin a core, repeat trials, calibrate bimodal thresholds, attach evidence."""

    def __init__(self, cfg: Optional[AdapterConfig] = None):
        self.cfg = cfg or AdapterConfig()

    def taskset_cmd(self, argv: Sequence[str]) -> List[str]:
        return ["taskset", "-c", str(self.cfg.core), *list(argv)]

    def pin(self) -> List[int]:
        try:
            os.sched_setaffinity(0, {self.cfg.core})
            return sorted(os.sched_getaffinity(0))
        except (AttributeError, OSError, PermissionError, ValueError):
            return []

    def repeat(self, fn: Callable[[], Any], n: Optional[int] = None) -> List[Any]:
        n = self.cfg.repetitions if n is None else n
        return [fn() for _ in range(n)]

    def calibrate_bimodal(
        self,
        low: Sequence[float],
        high: Sequence[float],
    ) -> Calibration:
        if not low or not high:
            return Calibration(ok=False, notes="empty samples")
        lo, hi = _median(low), _median(high)
        if hi < lo:
            return Calibration(
                ok=False,
                low_median=lo,
                high_median=hi,
                notes="clusters inverted",
            )
        gap = hi - lo
        spread = max(
            (max(low) - min(low)) if len(low) > 1 else 0.0,
            (max(high) - min(high)) if len(high) > 1 else 0.0,
            1.0,
        )
        thr = (lo + hi) / 2.0
        n_bad = sum(1 for x in low if x >= thr) + sum(1 for x in high if x <= thr)
        overlap = n_bad / float(len(low) + len(high))
        sep = gap / spread
        margin = max(gap * self.cfg.invalid_frac, 0.0)
        ok = gap > 0 and overlap <= self.cfg.overlap_limit
        return Calibration(
            kind="bimodal",
            threshold=thr,
            low_median=lo,
            high_median=hi,
            separation=sep,
            overlap=overlap,
            invalid_margin=margin,
            ok=ok,
            notes="" if ok else "overlap",
        )

    def run_argv(
        self,
        argv: Sequence[str],
        warmup: bool = True,
        timeout_s: Optional[int] = None,
    ) -> Dict[str, Any]:
        cmd = self.taskset_cmd([str(a) for a in argv])
        timeout_s = self.cfg.timeout_s if timeout_s is None else timeout_s
        if warmup:
            wcmd = list(cmd)
            if "-t" in wcmd:
                i = wcmd.index("-t") + 1
                if i < len(wcmd):
                    try:
                        trials = int(wcmd[i])
                        wcmd[i] = str(min(400, max(self.cfg.warmup, trials // 4)))
                    except ValueError:
                        pass
            subprocess.run(
                wcmd, capture_output=True, text=True, timeout=timeout_s, check=False
            )
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s, check=False
        )
        text = (proc.stdout or "") + (proc.stderr or "")
        return {
            "cmd": cmd,
            "returncode": proc.returncode,
            "text": text,
            "core": self.cfg.core,
        }

    def attach(self, net: Net, result: NativeResult) -> None:
        bucket = net.native.setdefault("adapters", {})
        bucket.setdefault(result.resource, []).append(result.to_dict())
        if net.evidence is None:
            net.evidence = result.to_evidence()


class AdapterBase:
    """IR recording + calibration state. Not a write0/write1/read oracle."""

    resource: str = ""
    wemu_supported: bool = False
    protocol: str = ""
    trigger: str = ""

    def __init__(self, runner: Optional[NativeRunner] = None, cfg: Optional[AdapterConfig] = None):
        self.runner = runner or NativeRunner(cfg)
        self.cfg = self.runner.cfg
        self.cal = Calibration()
        self.flush_state = "unknown"

    def unavailable(self, reason: str = "unemulated", phys_key: Optional[str] = None) -> NativeResult:
        # WeMu has no model: keep the WR, do not invent occupancy / target / walk.
        if reason == "unemulated" and self.wemu_supported:
            reason = "no_samples"
        return NativeResult(
            resource=self.resource,
            protocol=self.protocol,
            value=None,
            causal=None,
            confidence=None,
            invalid=True,
            uncertainty=reason,
            observations=[{"uncertainty": reason, "wemu_supported": self.wemu_supported}],
            calibration=self.cal.to_dict(),
            trigger=self.trigger,
            flush_state=self.flush_state,
            phys_key=phys_key,
            wemu_supported=self.wemu_supported,
            core=self.cfg.core,
            repetitions=self.cfg.repetitions,
        )

    def _result(
        self,
        *,
        value: Any = None,
        causal: Optional[bool] = None,
        confidence: Optional[float] = None,
        invalid: bool = False,
        uncertainty: Optional[str] = None,
        observations: Optional[List[Dict[str, Any]]] = None,
        phys_key: Optional[str] = None,
        protocol: Optional[str] = None,
    ) -> NativeResult:
        if not invalid and uncertainty is None and confidence is not None:
            if confidence < self.cfg.admit_confidence:
                uncertainty = "low_confidence"
        return NativeResult(
            resource=self.resource,
            protocol=protocol or self.protocol,
            value=value,
            causal=causal,
            confidence=confidence,
            invalid=invalid,
            uncertainty=uncertainty,
            observations=list(observations or []),
            calibration=self.cal.to_dict(),
            trigger=self.trigger,
            flush_state=self.flush_state,
            phys_key=phys_key,
            wemu_supported=self.wemu_supported,
            core=self.cfg.core,
            repetitions=self.cfg.repetitions,
        )

    def record(
        self,
        net: Net,
        name: str,
        phys_key: Optional[str] = None,
        result: Optional[NativeResult] = None,
    ) -> Place:
        if result is None:
            result = self.unavailable(phys_key=phys_key)
        if result.phys_key is None:
            result.phys_key = phys_key
        place = wr_place(name, self.resource, phys_key=phys_key, evidence=result.to_evidence())
        net.add_place(place)
        self.runner.attach(net, result)
        return place
