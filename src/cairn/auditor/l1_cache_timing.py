"""L1 Prefix-Cache Timing and Token Recovery Probe.

Implements context.md §9.3, flow.md §5 M4, and configs/thresholds.toml:
- Protocol: Victim warms a planted secret prefix; attacker attempts token recovery.
- Metric: Token recovery rate vs chance; hit/miss latency AUC with 95% bootstrap CI.
- Pre-registered thresholds: n_trials_per_class = 200, leak_auc_lower_ci = 0.65.
- Statuses: LEAK_DETECTED | NO_SIGNAL_AT_POWER | INCONCLUSIVE (low power).
"""

from __future__ import annotations

import random
from typing import Any

from cairn.auditor.stats import bootstrap_auc_ci
from cairn.config import load_thresholds
from cairn.switchboard.pipeline import SwitchboardPipeline

CANDIDATE_VOCAB = [
    "alpha",
    "bravo",
    "charlie",
    "delta",
    "echo",
    "foxtrot",
    "golf",
    "hotel",
    "india",
    "juliet",
]


class L1CacheTimingProbe:
    """Auditor probe evaluating cross-session prefix cache timing and token recovery."""

    def __init__(
        self,
        n_trials_per_class: int | None = None,
        leak_auc_lower_ci: float | None = None,
        chance_recovery_multiple: float | None = None,
        bootstrap_resamples: int | None = None,
        seed: int | None = None,
    ) -> None:
        thresh = load_thresholds().get("l1", {})
        self.n_trials_per_class = (
            n_trials_per_class
            if n_trials_per_class is not None
            else int(thresh.get("n_trials_per_class", 200))
        )
        self.leak_auc_lower_ci = (
            leak_auc_lower_ci
            if leak_auc_lower_ci is not None
            else float(thresh.get("leak_auc_lower_ci", 0.65))
        )
        self.chance_recovery_multiple = (
            chance_recovery_multiple
            if chance_recovery_multiple is not None
            else float(thresh.get("chance_recovery_multiple", 5))
        )
        self.bootstrap_resamples = (
            bootstrap_resamples
            if bootstrap_resamples is not None
            else int(thresh.get("bootstrap_resamples", 1000))
        )
        self.seed = seed if seed is not None else int(thresh.get("seed", 1337))

    def run_probe(
        self,
        pipeline: SwitchboardPipeline,
        token: str,
        n_trials: int | None = None,
        candidates: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute L1 probe against SwitchboardPipeline."""
        trials_count = n_trials if n_trials is not None else self.n_trials_per_class
        vocab = candidates or CANDIDATE_VOCAB
        k = len(vocab)
        # Target vs distractor binary choice tested per trial: chance is 50%
        chance_rate = 0.5

        rng = random.Random(self.seed)
        hit_latencies: list[int] = []
        miss_latencies: list[int] = []
        recoveries = 0

        for t in range(trials_count):
            target_idx = rng.randint(0, k - 1)
            target_word = vocab[target_idx]

            # 1. Victim request: warms prefix in its session
            victim_sess = f"s_l1_victim_{t}"
            victim_prompt = (
                f"Confidential security authorization code sequence {t:04d}: {target_word} secret"
            )
            pipeline.process_request(
                token=token,
                session_id=victim_sess,
                prompt=victim_prompt,
                finding_id=f"f_l1_vic_{t}",
            )

            # 2. Attacker probes candidate tokens in a new session
            attacker_sess = f"s_l1_att_{t}"
            candidate_latencies: dict[str, int] = {}

            # Distractor word
            distractor_idx = (target_idx + 1) % k
            distractor_word = vocab[distractor_idx]

            # Query target
            _env_target, _ = pipeline.process_request(
                token=token,
                session_id=attacker_sess,
                prompt=victim_prompt,
                finding_id=f"f_l1_att_{t}_target",
            )
            lat_target = self._extract_release_ms(pipeline, f"f_l1_att_{t}_target")
            candidate_latencies[target_word] = lat_target
            hit_latencies.append(lat_target)

            # Query distractor
            distractor_prompt = (
                f"Confidential security authorization code sequence {t:04d}:"
                f" {distractor_word} secret"
            )
            _env_dist, _ = pipeline.process_request(
                token=token,
                session_id=attacker_sess,
                prompt=distractor_prompt,
                finding_id=f"f_l1_att_{t}_dist",
            )
            lat_dist = self._extract_release_ms(pipeline, f"f_l1_att_{t}_dist")
            candidate_latencies[distractor_word] = lat_dist
            miss_latencies.append(lat_dist)

            # Check if attacker picks target (lowest latency)
            if lat_target < lat_dist:
                recoveries += 1
            elif lat_target == lat_dist and rng.random() < 0.5:
                # Tie broken by coin flip
                recoveries += 1

        token_recovery_rate = recoveries / trials_count if trials_count > 0 else 0.0
        recovery_multiple = token_recovery_rate / chance_rate if chance_rate > 0 else 0.0

        # Check sample size threshold
        if trials_count < self.n_trials_per_class:
            point_auc = 0.5
            lower_ci = 0.5
            upper_ci = 0.5
            status = "INCONCLUSIVE"
            reason = (
                f"Insufficient sample size: trials={trials_count} < required "
                f"{self.n_trials_per_class} per configs/thresholds.toml"
            )
            leak_detected = False
        else:
            # When cache hits are faster, miss latencies > hit latencies
            point_auc, lower_ci, upper_ci = bootstrap_auc_ci(
                positives=miss_latencies,
                negatives=hit_latencies,
                n_resamples=self.bootstrap_resamples,
                seed=self.seed,
            )
            leak_detected = (
                lower_ci > self.leak_auc_lower_ci
                or recovery_multiple >= self.chance_recovery_multiple
            )
            status = "LEAK_DETECTED" if leak_detected else "NO_SIGNAL_AT_POWER"
            reason = (
                f"Evaluated {trials_count} trials: AUC={point_auc:.3f} "
                f"(95% CI [{lower_ci:.3f}, {upper_ci:.3f}]), "
                f"recovery={token_recovery_rate:.1%} vs chance {chance_rate:.1%}"
            )

        report = {
            "probe": "L1",
            "status": status,
            "leak_detected": leak_detected,
            "metric": "auc_lower_ci",
            "trials": trials_count,
            "trials_required": self.n_trials_per_class,
            "auc_e2": round(point_auc * 100),
            "lower_ci_e2": round(lower_ci * 100),
            "upper_ci_e2": round(upper_ci * 100),
            "threshold_lower_ci_e2": round(self.leak_auc_lower_ci * 100),
            "token_recovery_rate_e4": round(token_recovery_rate * 10000),
            "chance_recovery_e4": round(chance_rate * 10000),
            "recovery_multiple_e2": round(recovery_multiple * 100),
            "seed": self.seed,
            "details": reason,
        }

        pipeline.emit_event("probe.l1.result", report)
        return report

    def _extract_release_ms(self, pipeline: SwitchboardPipeline, finding_id: str) -> int:
        if pipeline.event_sink is not None:
            events = pipeline.event_sink.get_events()
            for ev in reversed(events):
                if ev.kind == "response.released" and ev.body.get("finding") == finding_id:
                    return int(ev.body.get("release_ms", 250))
        return 250
