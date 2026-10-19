"""L3 Quota and Token Call Limit Probe per context.md §8.4 and flow.md §5 M4.

Validates that:
- Per-token call budgets are strictly enforced
- Input size caps (>16 KB) are strictly rejected
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519

from cairn.common.schemas import TokenClaims
from cairn.crypto.tokens import mint_token
from cairn.switchboard.pipeline import SwitchboardPipeline


class L3QuotaProbe:
    """Auditor probe evaluating call budget and size cap enforcement."""

    def __init__(
        self,
        max_allowed_calls: int = 5,
        size_cap_bytes: int = 16384,
    ) -> None:
        self.max_allowed_calls = max_allowed_calls
        self.size_cap_bytes = size_cap_bytes

    def run_probe(
        self,
        pipeline: SwitchboardPipeline,
        target: Any,
        run_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute L3 probe against SwitchboardPipeline.

        Target can be an ed25519.Ed25519PrivateKey or an already minted token string.
        """
        if isinstance(target, ed25519.Ed25519PrivateKey):
            active_run_id = run_id or pipeline.state.run_id or "r_l3"
            # 1. Budget enforcement test
            budget_token = mint_token(
                TokenClaims(
                    role="red",
                    run=active_run_id,
                    sess="s_l3_probe",
                    caps=["attack.submit"],
                    max_calls=self.max_allowed_calls,
                    exp_ns=2_000_000_000_000_000_000,
                ),
                target,
            )
            statuses = []
            for i in range(self.max_allowed_calls):
                _, s = pipeline.process_request(
                    budget_token, "s_l3_probe", f"hello {i}", f"f_l3_{i}"
                )
                statuses.append(s)
            _, status_over = pipeline.process_request(
                budget_token, "s_l3_probe", "over", "f_l3_over"
            )
            budget_enforced = all(s == 200 for s in statuses) and status_over == 401

            # 2. Size cap enforcement test
            size_token = mint_token(
                TokenClaims(
                    role="red",
                    run=active_run_id,
                    sess="s_l3_size",
                    caps=["attack.submit"],
                    max_calls=10,
                    exp_ns=2_000_000_000_000_000_000,
                ),
                target,
            )
            oversized_prompt = "A" * (self.size_cap_bytes + 1000)
            _, status_size = pipeline.process_request(
                size_token, "s_l3_size", oversized_prompt, "f_l3_size"
            )
            size_cap_enforced = status_size == 400
        else:
            token = str(target)
            # Size cap first (uses 1 call from quota)
            oversized_prompt = "A" * (self.size_cap_bytes + 1000)
            _, status_size = pipeline.process_request(
                token, "s_test", oversized_prompt, "f_l3_size"
            )
            size_cap_enforced = status_size == 400

            # Remaining calls up to max_allowed_calls
            statuses = []
            for i in range(1, self.max_allowed_calls):
                _, s = pipeline.process_request(token, "s_test", f"hello {i}", f"f_l3_{i}")
                statuses.append(s)
            _, status_over = pipeline.process_request(token, "s_test", "hello over", "f_l3_over")
            all_valid = len(statuses) == 0 or all(s == 200 for s in statuses)
            budget_enforced = all_valid and status_over == 401

        passed = budget_enforced and size_cap_enforced
        report = {
            "probe": "L3",
            "budget_enforced": budget_enforced,
            "quota_enforced": budget_enforced,
            "size_cap_enforced": size_cap_enforced,
            "passed": passed,
        }

        pipeline.emit_event("probe.l3.result", report)
        return report
