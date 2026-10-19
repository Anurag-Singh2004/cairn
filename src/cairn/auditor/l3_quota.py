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

    def run_probe(
        self,
        pipeline: SwitchboardPipeline,
        private_key: ed25519.Ed25519PrivateKey,
        run_id: str,
    ) -> dict[str, Any]:
        """Execute L3 probe against SwitchboardPipeline."""
        # 1. Budget enforcement test: max_calls = 2
        token = mint_token(
            TokenClaims(
                role="red",
                run=run_id,
                sess="s_l3_probe",
                caps=["attack.submit"],
                max_calls=2,
                exp_ns=2_000_000_000_000_000_000,
            ),
            private_key,
        )

        # Call 1: OK
        _, status1 = pipeline.process_request(token, "s_l3_probe", "hello 1", "f_l3_1")
        # Call 2: OK
        _, status2 = pipeline.process_request(token, "s_l3_probe", "hello 2", "f_l3_2")
        # Call 3: Exceeds budget -> should be denied (401)
        _, status3 = pipeline.process_request(token, "s_l3_probe", "hello 3", "f_l3_3")

        budget_enforced = status1 == 200 and status2 == 200 and status3 == 401

        # 2. Size cap enforcement test (> 16384 bytes)
        oversized_prompt = "A" * 17000
        oversized_token = mint_token(
            TokenClaims(
                role="red",
                run=run_id,
                sess="s_l3_size",
                caps=["attack.submit"],
                max_calls=10,
                exp_ns=2_000_000_000_000_000_000,
            ),
            private_key,
        )
        _, status_size = pipeline.process_request(
            oversized_token, "s_l3_size", oversized_prompt, "f_l3_size"
        )
        size_cap_enforced = status_size == 400

        passed = budget_enforced and size_cap_enforced
        report = {
            "probe": "L3",
            "budget_enforced": budget_enforced,
            "size_cap_enforced": size_cap_enforced,
            "passed": passed,
        }

        pipeline.emit_event("probe.l3.result", report)
        return report
