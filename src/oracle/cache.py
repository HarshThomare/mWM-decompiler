"""Cache / Flexo native adapter: occupancy, dual-rail, flush+reload causality.

Not a generic write0/write1/read oracle. Operations are line flush, line fill,
timed access, and dual-rail decode — matching Flexo/GITM WRs, not BTB/TLB.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from ir.net import resource_spec

from .native import parse_flexo_output, run_flexo_elf as run_flexo_binary
from .runner import AdapterBase, AdapterConfig, NativeResult, NativeRunner, majority


class CacheAdapter(AdapterBase):
    """dcache WR: dual-rail occupancy after RSB rollback (Flexo) or #DE (GITM)."""

    resource = "dcache"
    wemu_supported = False
    protocol = "flush_reload"
    trigger = "rsb"

    def __init__(self, runner: Optional[NativeRunner] = None, cfg: Optional[AdapterConfig] = None):
        super().__init__(runner, cfg)
        spec = resource_spec(self.resource)
        self.trigger = spec.trigger
        self.flush_state = "unknown"

    def mark_flushed(self) -> None:
        self.flush_state = "flushed"

    def mark_primed(self) -> None:
        self.flush_state = "primed"

    def calibrate_occupancy(
        self, hit_times: Sequence[float], miss_times: Sequence[float]
    ):
        """Hit = low latency, miss = high. Threshold sits between medians."""
        self.cal = self.runner.calibrate_bimodal(hit_times, miss_times)
        return self.cal

    def decode_occupancy(self, latency: float, phys_key: Optional[str] = None) -> NativeResult:
        """Single-rail: cached=1, uncached=0. Timed read is destructive."""
        bit = self.cal.classify(latency)
        if bit is None:
            reason = "uncalibrated" if not self.cal.ok else "threshold"
            return self._result(
                invalid=True,
                uncertainty=reason,
                observations=[{"latency": latency, "class": None}],
                phys_key=phys_key,
                protocol="occupancy",
            )
        # classify 0 = hit (cached = logical 1 in GITM prime-probe)
        value = 1 if bit == 0 else 0
        return self._result(
            value=value,
            confidence=1.0 if self.cal.ok else None,
            observations=[{"latency": latency, "class": bit, "cached": bool(value)}],
            phys_key=phys_key,
            protocol="occupancy",
        )

    def decode_dual_rail(
        self,
        t_minus: float,
        t_plus: float,
        phys_key: Optional[str] = None,
    ) -> NativeResult:
        """Flexo rails: valid HL=0, LH=1; HH/LL is error-detected (invalid)."""
        minus = self.cal.classify(t_minus)
        plus = self.cal.classify(t_plus)
        obs = {
            "t_minus": t_minus,
            "t_plus": t_plus,
            "minus_class": minus,
            "plus_class": plus,
        }
        if minus is None or plus is None:
            reason = "uncalibrated" if not self.cal.ok else "threshold"
            return self._result(
                invalid=True,
                uncertainty=reason,
                observations=[obs],
                phys_key=phys_key,
                protocol="dual_rail",
            )
        minus_hit = minus == 0
        plus_hit = plus == 0
        if minus_hit == plus_hit:
            return self._result(
                invalid=True,
                uncertainty="both_rails",
                observations=[obs],
                phys_key=phys_key,
                protocol="dual_rail",
            )
        value = 1 if plus_hit else 0
        return self._result(
            value=value,
            confidence=1.0,
            observations=[obs],
            phys_key=phys_key,
            protocol="dual_rail",
        )

    def recover_dual_rail(
        self,
        trials: Sequence[tuple],
        phys_key: Optional[str] = None,
    ) -> NativeResult:
        """Majority of valid dual-rail decodes across repetitions."""
        bits: List[int] = []
        invalid = 0
        obs: List[Dict[str, Any]] = []
        for pair in trials:
            t_minus, t_plus = pair[0], pair[1]
            r = self.decode_dual_rail(t_minus, t_plus, phys_key=phys_key)
            obs.extend(r.observations)
            if r.invalid or r.value is None:
                invalid += 1
            else:
                bits.append(int(r.value))
        n = len(trials)
        if not bits:
            return self._result(
                invalid=True,
                uncertainty="both_rails" if invalid else "no_samples",
                confidence=0.0,
                observations=obs,
                phys_key=phys_key,
                protocol="dual_rail",
            )
        val, agr, _ = majority(bits)
        conf = agr * (len(bits) / n if n else 0.0)
        return self._result(
            value=int(val),
            confidence=conf,
            invalid=False,
            uncertainty=None if conf >= self.cfg.admit_confidence else "low_confidence",
            observations=obs + [{"valid": len(bits), "invalid": invalid, "n": n}],
            phys_key=phys_key,
            protocol="dual_rail",
        )

    def test_line_causality(
        self,
        phys_key: str,
        flushed_times: Sequence[float],
        after_times: Sequence[float],
    ) -> NativeResult:
        """Did the candidate fill `phys_key`? Control is a flushed (miss) line."""
        if not self.cal.ok:
            self.calibrate_occupancy(after_times, flushed_times)
        if not self.cal.ok:
            return self._result(
                causal=False,
                invalid=True,
                uncertainty="uncalibrated",
                observations=[
                    {"flushed": list(flushed_times), "after": list(after_times)}
                ],
                phys_key=phys_key,
            )
        self.mark_flushed()
        ctrl = [self.cal.classify(x) for x in flushed_times]
        treat = [self.cal.classify(x) for x in after_times]
        ctrl_hit = [c == 0 for c in ctrl if c is not None]
        treat_hit = [c == 0 for c in treat if c is not None]
        if not ctrl_hit or not treat_hit:
            return self._result(
                causal=False,
                invalid=True,
                uncertainty="threshold",
                phys_key=phys_key,
            )
        p_ctrl = sum(ctrl_hit) / len(ctrl_hit)
        p_treat = sum(treat_hit) / len(treat_hit)
        causal = (p_treat - p_ctrl) >= 0.5
        conf = abs(p_treat - p_ctrl)
        return self._result(
            value=1 if causal else 0,
            causal=causal,
            confidence=conf,
            uncertainty=None if causal else "no_effect",
            observations=[
                {
                    "p_hit_control": p_ctrl,
                    "p_hit_treatment": p_treat,
                    "n_control": len(ctrl_hit),
                    "n_treatment": len(treat_hit),
                }
            ],
            phys_key=phys_key,
        )

    def run_flexo_elf(
        self,
        path: str,
        trials: Optional[int] = None,
        retry: bool = False,
    ) -> NativeResult:
        """Architectural Flexo readout the binary already performs after ρ."""
        trials = self.cfg.repetitions if trials is None else trials
        raw = run_flexo_binary(
            path,
            trials=trials,
            core=self.cfg.core,
            retry=retry,
            timeout_s=self.cfg.timeout_s,
        )
        rows = raw.get("circuits") or parse_flexo_output(raw.get("raw") or "")
        median = float(raw.get("median_accuracy_pct") or 0.0)
        admitted = bool(raw.get("admitted"))
        conf = (median / 100.0) if rows else None
        return self._result(
            value=admitted,
            causal=admitted,
            confidence=conf,
            invalid=not admitted,
            uncertainty=None if admitted else "low_confidence",
            observations=[{"circuits": rows, "median_accuracy_pct": median}],
            protocol="flexo_elf",
        )
