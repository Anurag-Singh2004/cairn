"""Regression tests for CAIRN conformance audit remediation.

Covers:
1. Matrix audit: honest failure propagation, no fake fallback, invariant I2 fails on FAILED.
2. L1 cache-timing: K=10 candidate set (10% chance), 5x chance threshold (50%),
   missing observations -> INCONCLUSIVE.
3. L4 container probe: live container execution detecting planted leaks in T0
   and clean isolation in T1.
4. Attestation: I1 rejects fabricated identifiers (f1e2d3c4b5a6, sha256:switchboard:latest).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from cairn.auditor.l1_cache_timing import L1CacheTimingProbe
from cairn.auditor.matrix import audit_matrix
from cairn.common.clock import FakeClock
from cairn.common.schemas import Event, TokenClaims
from cairn.crypto.keys import generate_keypair
from cairn.crypto.tokens import mint_token
from cairn.referee.controller import RunState
from cairn.referee.evidence import EvidenceStore
from cairn.referee.runner import _execute_matrix_audit
from cairn.referee.validity import evaluate_certificate
from cairn.switchboard.pipeline import SwitchboardPipeline
from cairn.switchboard.session import SessionManager
from cairn.switchboard.state import SwitchboardState
from cairn.tenants.blue.guard import BlueGuard


def test_matrix_audit_failure_propagation() -> None:
    """Audit failures must never silently produce an ENFORCED result."""
    with patch("cairn.auditor.matrix.compose_exec") as mock_exec:
        # Simulate container execution failure
        mock_exec.return_value = (1, "", "docker exec failed")
        res = audit_matrix("t1")
        assert res["status"] == "FAILED"
        assert res["valid"] is False
        assert len(res["deviations"]) > 0

    with patch("cairn.referee.runner.audit_matrix") as mock_audit:
        mock_audit.return_value = {
            "tier": "t1",
            "status": "FAILED",
            "deviations": ["red: Probe execution failed"],
            "measured_edges": [{"source": "red", "error": "Probe execution failed"}],
            "valid": False,
        }
        res = _execute_matrix_audit("t1", phase="pre")
        assert res["status"] == "FAILED"
        assert res["deviations"] >= 1


def test_invariant_i2_fails_on_matrix_failed() -> None:
    """I2 must evaluate to fail when matrix audit status is FAILED."""
    events = [
        Event(
            seq=1,
            run="r1",
            ts_ns=1,
            kind="attestation.matrix",
            actor="auditor",
            body={"phase": "pre", "tier": "t1", "status": "FAILED", "deviations": 1},
            prev="0" * 64,
            hash="h1",
        ),
        Event(
            seq=2,
            run="r1",
            ts_ns=2,
            kind="attestation.matrix",
            actor="auditor",
            body={"phase": "post", "tier": "t1", "status": "FAILED", "deviations": 1},
            prev="h1",
            hash="h2",
        ),
    ]
    cert = evaluate_certificate(events)
    assert cert.invariants["I2"].result == "fail"
    assert cert.invariants["I2"].reason_code == "MATRIX_AUDIT_FAILED"


def test_l1_k10_missing_observations_produce_inconclusive(tmp_path) -> None:
    """L1 probe must produce INCONCLUSIVE when observations are missing."""
    clock = FakeClock()
    store = EvidenceStore(tmp_path / "ev.db")
    priv, pub = generate_keypair()
    run_id = "r_test_l1"

    token = mint_token(
        TokenClaims(
            role="red",
            run=run_id,
            sess="*",
            caps=["attack.submit"],
            max_calls=5000,
            exp_ns=2_000_000_000_000_000_000,
        ),
        priv,
    )

    state = SwitchboardState()
    state.configure(run_id=run_id, referee_pubkey=pub, tier_config={"tier": {"name": "t1"}})
    state.set_state(RunState.RUNNING)
    from cairn.model.sim_engine import SimEngine

    pipeline = SwitchboardPipeline(
        state=state,
        blue_guard=BlueGuard(policy={"input_rules": [], "output_rules": []}),
        model_engine=SimEngine(),
        session_mgr=SessionManager(),
        clock=clock,
        event_sink=store,
    )

    probe = L1CacheTimingProbe(n_trials_per_class=200)
    # Simulate missing observations by asking for 200 trials without release_ms
    with patch.object(probe, "_extract_release_ms", return_value=None):
        rep = probe.run_probe(pipeline, token, n_trials=200)
        assert rep["status"] == "INCONCLUSIVE"
        assert rep["leak_detected"] is False
        assert rep["trials"] == 0
        assert rep["missing_observations"] == 200


def test_i1_rejects_fabricated_identifiers() -> None:
    """Invariant I1 must fail closed when placeholder hashes are passed."""
    events = [
        Event(
            seq=1,
            run="r1",
            ts_ns=1,
            kind="manifest.frozen",
            actor="referee",
            body={
                "compose_sha256": "f1e2d3c4b5a6",  # Fabricated placeholder
                "images": {"switchboard": "sha256:switchboard:latest"},
            },
            prev="0" * 64,
            hash="h1",
        ),
        Event(
            seq=2,
            run="r1",
            ts_ns=2,
            kind="attestation.manifest",
            actor="auditor",
            body={
                "compose_sha256": "f1e2d3c4b5a6",
                "images": {"switchboard": "sha256:switchboard:latest"},
            },
            prev="h1",
            hash="h2",
        ),
    ]
    cert = evaluate_certificate(events)
    assert cert.invariants["I1"].result == "fail"
    assert cert.invariants["I1"].reason_code == "FABRICATED_ATTESTATION_IDENTIFIER"


@pytest.mark.docker
def test_l4_container_probe_t0_vs_t1() -> None:
    """L4 probe executes inside actual containers and distinguishes T0 leak vs T1 clean."""
    from cairn.auditor.l4_fs import L4FsProbe

    probe = L4FsProbe()
    t0_res = probe.run_container_probe("t0", target_service="red")
    assert t0_res["status"] == "LEAK_DETECTED"
    assert t0_res["leak_detected"] is True
    assert any("canary_blue_99aa88bb" in c for c in t0_res["canaries_found"])
    assert t0_res["shared_volume_present"] is True

    t1_res = probe.run_container_probe("t1", target_service="red")
    assert t1_res["status"] == "NO_SIGNAL_AT_POWER"
    assert t1_res["leak_detected"] is False
    assert len(t1_res["canaries_found"]) == 0
    assert t1_res["shared_volume_present"] is False
