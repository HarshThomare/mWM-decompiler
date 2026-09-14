"""TLB native adapter: evict / walk / timed translation.

WeMu is not used. Without native hit/miss samples this adapter
still records a typed WR with uncertainty rather than pretending occupancy.
No cache dual-rail API and no BTB train-target API.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from ir.net import resource_spec

from .runner import AdapterBase, AdapterConfig, NativeResult, NativeRunner, majority


class TlbAdapter(AdapterBase):
    """tlb WR: page-walk hit/miss. Timed read fills the entry (destructive)."""

    resource = "tlb"
    wemu_supported = False
    protocol = "evict_walk"
    trigger = "rsb"

    def __init__(self, runner: Optional[NativeRunner] = None, cfg: Optional[AdapterConfig] = None):
        super().__init__(runner, cfg)
        spec = resource_spec(self.resource)
        self.trigger = spec.trigger
        self.flush_state = "unknown"

    def mark_evicted(self) -> None:
        self.flush_state = "evicted"

    def mark_filled(self) -> None:
        self.flush_state = "filled"

    def calibrate_translation(
        self, hit_times: Sequence[float], miss_times: Sequence[float]
    ):
        """Hit = filled entry (low), miss = walk (high)."""
        self.cal = self.runner.calibrate_bimodal(hit_times, miss_times)
        return self.cal

    def decode_translation(self, latency: float, phys_key: Optional[str] = None) -> NativeResult:
        bit = self.cal.classify(latency)
        if bit is None:
            reason = "uncalibrated" if not self.cal.ok else "threshold"
            return self._result(
                invalid=True,
                uncertainty=reason,
                observations=[{"latency": latency, "class": None}],
                phys_key=phys_key,
                protocol="hit_miss",
            )
        value = 1 if bit == 0 else 0  # hit = 1
        return self._result(
            value=value,
            confidence=1.0 if self.cal.ok else None,
            observations=[{"latency": latency, "class": bit, "hit": bool(value)}],
            phys_key=phys_key,
            protocol="hit_miss",
        )

    def recover_hit_miss(
        self,
        latencies: Sequence[float],
        phys_key: Optional[str] = None,
    ) -> NativeResult:
        bits: List[int] = []
        invalid = 0
        obs: List[Dict[str, Any]] = []
        for lat in latencies:
            r = self.decode_translation(lat, phys_key=phys_key)
            obs.extend(r.observations)
            if r.invalid or r.value is None:
                invalid += 1
            else:
                bits.append(int(r.value))
        n = len(latencies)
        if not bits:
            if not n:
                return self.unavailable("unemulated", phys_key=phys_key)
            return self._result(
                invalid=True,
                uncertainty="threshold",
                observations=obs,
                phys_key=phys_key,
                protocol="hit_miss",
            )
        val, agr, _ = majority(bits)
        conf = agr * (len(bits) / n if n else 0.0)
        return self._result(
            value=int(val),
            confidence=conf,
            uncertainty=None if conf >= self.cfg.admit_confidence else "low_confidence",
            observations=obs + [{"valid": len(bits), "invalid": invalid, "n": n}],
            phys_key=phys_key,
            protocol="hit_miss",
        )

    def test_vpn_causality(
        self,
        phys_key: str,
        evicted_times: Sequence[float],
        after_times: Sequence[float],
    ) -> NativeResult:
        """Did the candidate fill `phys_key`? Control is an evicted VPN."""
        if not evicted_times or not after_times:
            return self.unavailable("unemulated", phys_key=phys_key)
        if not self.cal.ok:
            self.calibrate_translation(after_times, evicted_times)
        if not self.cal.ok:
            return self._result(
                causal=False,
                invalid=True,
                uncertainty="uncalibrated",
                observations=[
                    {"evicted": list(evicted_times), "after": list(after_times)}
                ],
                phys_key=phys_key,
            )
        self.mark_evicted()
        ctrl = [self.cal.classify(x) for x in evicted_times]
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
        if causal:
            self.mark_filled()
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
