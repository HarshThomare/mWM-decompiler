"""BTB / TAE native adapter: train indirect jumps, observe taken targets.

Without native train/observe samples this adapter still records a typed WR
with uncertainty rather than inventing a target.
No cache-style flush/load occupancy API.
"""

from __future__ import annotations

import os
import subprocess
from typing import Any, Dict, List, Optional, Sequence

from ir.net import resource_spec

from .native import parse_flexo_output
from .runner import AdapterBase, AdapterConfig, NativeResult, NativeRunner, majority


class BtbAdapter(AdapterBase):
    """btb WR: persistent target of an indirect jump (TAE)."""

    resource = "btb"
    wemu_supported = False
    protocol = "train_observe"
    trigger = "indirect_jmp"

    def __init__(self, runner: Optional[NativeRunner] = None, cfg: Optional[AdapterConfig] = None):
        super().__init__(runner, cfg)
        spec = resource_spec(self.resource)
        self.trigger = spec.trigger
        self.trained: Dict[str, Any] = {}
        self.flush_state = "untrained"

    def train(self, index: str, target: Any) -> None:
        self.trained[str(index)] = target
        self.flush_state = "trained"

    def flush(self, index: Optional[str] = None) -> None:
        if index is None:
            self.trained.clear()
        else:
            self.trained.pop(str(index), None)
        self.flush_state = "flushed" if not self.trained else "trained"

    def observe_target(
        self,
        samples: Sequence[Any],
        phys_key: Optional[str] = None,
    ) -> NativeResult:
        """Non-destructive: majority taken target. Mixed targets are invalid."""
        if not samples:
            return self.unavailable("no_samples" if self.trained else "unemulated", phys_key=phys_key)
        val, agr, n = majority(samples)
        unstable = agr < 0.5
        return self._result(
            value=val,
            confidence=agr,
            invalid=unstable,
            uncertainty="unstable" if unstable else None,
            observations=[{"targets": list(samples), "agreement": agr, "n": n}],
            phys_key=phys_key,
            protocol="observe_target",
        )

    def test_index_causality(
        self,
        phys_key: str,
        untrained: Sequence[Any],
        trained: Sequence[Any],
        expected_target: Any = None,
    ) -> NativeResult:
        """Does training this BTB index change the observed target?"""
        if not untrained or not trained:
            return self.unavailable("unemulated", phys_key=phys_key)
        u_val, u_agr, _ = majority(untrained)
        t_val, t_agr, _ = majority(trained)
        if t_agr < 0.5:
            return self._result(
                value=t_val,
                causal=False,
                invalid=True,
                uncertainty="unstable",
                confidence=t_agr,
                observations=[
                    {"untrained": u_val, "trained": t_val, "u_agr": u_agr, "t_agr": t_agr}
                ],
                phys_key=phys_key,
            )
        causal = t_val != u_val
        if expected_target is not None:
            causal = causal and t_val == expected_target
        if causal:
            self.train(phys_key, t_val)
        conf = min(t_agr, abs(t_agr - u_agr) if u_val != t_val else t_agr)
        return self._result(
            value=t_val if causal else None,
            causal=causal,
            confidence=conf if causal else 0.0,
            invalid=False,
            uncertainty=None if causal else "no_effect",
            observations=[
                {
                    "untrained": u_val,
                    "trained": t_val,
                    "u_agr": u_agr,
                    "t_agr": t_agr,
                    "expected": expected_target,
                }
            ],
            phys_key=phys_key,
        )

    def run_tae_elf(
        self,
        path: str,
        trials: Optional[int] = None,
        extra_args: Optional[List[str]] = None,
    ) -> NativeResult:
        """Pin a core and parse TAE-style accuracy banners if the ELF prints them."""
        trials = self.cfg.repetitions if trials is None else trials
        argv = [os.path.abspath(path)]
        if extra_args:
            argv.extend(extra_args)
        else:
            argv.extend(["-t", str(trials)])
        try:
            raw = self.runner.run_argv(argv, warmup=True)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return self.unavailable("unemulated")
        rows = parse_flexo_output(raw.get("text") or "")
        if not rows:
            return self._result(
                invalid=True,
                uncertainty="unemulated",
                confidence=None,
                observations=[{"returncode": raw.get("returncode"), "cmd": raw.get("cmd")}],
                protocol="tae_elf",
            )
        accs = [r["accuracy_pct"] for r in rows]
        median = sorted(accs)[len(accs) // 2]
        admitted = any(r.get("admitted") for r in rows)
        conf = median / 100.0
        return self._result(
            value=admitted,
            causal=admitted,
            confidence=conf,
            invalid=not admitted,
            uncertainty=None if admitted else "low_confidence",
            observations=[{"circuits": rows, "median_accuracy_pct": median}],
            protocol="tae_elf",
        )

