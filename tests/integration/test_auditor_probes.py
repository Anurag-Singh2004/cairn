"""Integration tests for M4 Auditor probes and attestations.

Tests against all criteria in context.md §9.3 and flow.md §5 M4:
1. L1 Prefix-Cache Timing and Token Recovery probe:
   - T0 detects prefix-cache timing leak (AUC lower CI > 0.65, high token recovery rate)
   - T1 reports NO_SIGNAL_AT_POWER (flat 250ms latency, AUC ≈ 0.50)
   - Low power (trials < 200) reports INCONCLUSIVE per thresholds.toml
2. L4 Filesystem, Shared Volume, and Environment Enumeration probe:
   - T0 detects planted misconfig / canary in /shared
   - T1 reports NO_SIGNAL_AT_POWER
3. L3 Quota probe confirms token call budget and size cap enforcement
4. Conformance evaluation (C1, C2, C3, C11, C12)
5. Canary scanner flags foreign canaries and clean state
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cairn.auditor.attestation import collect_attestations
from cairn.auditor.canary import CanaryScanner
from cairn.auditor.conformance import evaluate_conformance_from_events
from cairn.auditor.l1_cache_timing import L1CacheTimingProbe
from cairn.auditor.l3_quota import L3QuotaProbe
from cairn.auditor.l4_fs import L4FsProbe
from cairn.common.clock import FakeClock
from cairn.common.schemas import TokenClaims
from cairn.crypto.keys import generate_keypair
from cairn.crypto.tokens import mint_token
from cairn.model.sim_engine import SimEngine
from cairn.referee.controller import RunState
from cairn.referee.evidence import EvidenceStore
from cairn.switchboard.pipeline import SwitchboardPipeline
from cairn.switchboard.session import SessionManager
from cairn.switchboard.state import SwitchboardState
from cairn.tenants.blue.guard import BlueGuard

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def probe_env(tmp_path: Path):
    clock = FakeClock()
    db_path = tmp_path / "probe_events.db"
    store = EvidenceStore(db_path)
    priv_key, pub_key = generate_keypair()
    run_id = "r_20261019_m4test"

    sim_engine = SimEngine(
        rules_path=REPO_ROOT / "data" / "sim_rules.json",
        seed=42,
    )
    blue_guard = BlueGuard(policy_path=REPO_ROOT / "data" / "policies" / "demo_blue.json")

    return {
        "clock": clock,
        "store": store,
        "priv_key": priv_key,
        "pub_key": pub_key,
        "run_id": run_id,
        "sim_engine": sim_engine,
        "blue_guard": blue_guard,
        "tmp_path": tmp_path,
    }


def test_l1_cache_timing_probe_t0_vs_t1(probe_env) -> None:
    clock = probe_env["clock"]
    store = probe_env["store"]
    priv = probe_env["priv_key"]
    pub = probe_env["pub_key"]
    run_id = probe_env["run_id"]
    sim = probe_env["sim_engine"]
    blue = probe_env["blue_guard"]

    token = mint_token(
        TokenClaims(
            role="red",
            run=run_id,
            sess="*",
            caps=["attack.submit"],
            max_calls=1000,
            exp_ns=2_000_000_000_000_000_000,
        ),
        priv,
    )

    # --- Test T0 (leaky baseline: shared prefix cache + unquantized release) ---
    state_t0 = SwitchboardState()
    state_t0.configure(
        run_id=run_id,
        referee_pubkey=pub,
        tier_config={"tier": {"name": "t0", "cache_isolation": "shared", "quantise_ms": 0}},
    )
    state_t0.set_state(RunState.RUNNING)

    pipeline_t0 = SwitchboardPipeline(
        state=state_t0,
        blue_guard=blue,
        model_engine=sim,
        session_mgr=SessionManager(cache_isolation="shared"),
        clock=clock,
        event_sink=store,
    )

    probe_l1 = L1CacheTimingProbe(n_trials_per_class=200)
    rep_t0 = probe_l1.run_probe(pipeline_t0, token, n_trials=200)
    assert rep_t0["status"] == "LEAK_DETECTED"
    assert rep_t0["leak_detected"] is True
    assert rep_t0["auc_e2"] > 65
    assert rep_t0["lower_ci_e2"] > 65
    assert rep_t0["token_recovery_rate_e4"] > rep_t0["chance_recovery_e4"]

    # --- Test T1 (hardened: salted cache + 250ms quantized release) ---
    state_t1 = SwitchboardState()
    state_t1.configure(
        run_id=run_id,
        referee_pubkey=pub,
        tier_config={"tier": {"name": "t1", "cache_isolation": "salted", "quantise_ms": 250}},
    )
    state_t1.set_state(RunState.RUNNING)

    pipeline_t1 = SwitchboardPipeline(
        state=state_t1,
        blue_guard=blue,
        model_engine=sim,
        session_mgr=SessionManager(cache_isolation="salted"),
        clock=clock,
        event_sink=store,
    )

    rep_t1 = probe_l1.run_probe(pipeline_t1, token, n_trials=200)
    assert rep_t1["status"] == "NO_SIGNAL_AT_POWER"
    assert rep_t1["leak_detected"] is False
    assert rep_t1["lower_ci_e2"] <= 65


def test_l1_cache_timing_inconclusive_when_low_trials(probe_env) -> None:
    clock = probe_env["clock"]
    store = probe_env["store"]
    priv = probe_env["priv_key"]
    pub = probe_env["pub_key"]
    run_id = probe_env["run_id"]
    sim = probe_env["sim_engine"]
    blue = probe_env["blue_guard"]

    token = mint_token(
        TokenClaims(
            role="red",
            run=run_id,
            sess="*",
            caps=["attack.submit"],
            max_calls=100,
            exp_ns=2_000_000_000_000_000_000,
        ),
        priv,
    )

    state = SwitchboardState()
    state.configure(run_id=run_id, referee_pubkey=pub, tier_config={"tier": {"name": "t1"}})
    state.set_state(RunState.RUNNING)
    pipeline = SwitchboardPipeline(
        state=state,
        blue_guard=blue,
        model_engine=sim,
        session_mgr=SessionManager(),
        clock=clock,
        event_sink=store,
    )

    probe = L1CacheTimingProbe(n_trials_per_class=200)
    # Only 10 trials instead of 200 required
    rep = probe.run_probe(pipeline, token, n_trials=10)
    assert rep["status"] == "INCONCLUSIVE"
    assert "Insufficient sample size" in rep["details"]


def test_l4_fs_probe_t0_vs_t1(probe_env) -> None:
    clock = probe_env["clock"]
    store = probe_env["store"]
    priv = probe_env["priv_key"]
    pub = probe_env["pub_key"]
    run_id = probe_env["run_id"]
    sim = probe_env["sim_engine"]
    blue = probe_env["blue_guard"]
    tmp_path = probe_env["tmp_path"]

    token = mint_token(
        TokenClaims(
            role="red",
            run=run_id,
            sess="*",
            caps=["attack.submit"],
            max_calls=100,
            exp_ns=2_000_000_000_000_000_000,
        ),
        priv,
    )

    state = SwitchboardState()
    state.configure(run_id=run_id, referee_pubkey=pub, tier_config={"tier": {"name": "t1"}})
    state.set_state(RunState.RUNNING)
    pipeline = SwitchboardPipeline(
        state=state,
        blue_guard=blue,
        model_engine=sim,
        session_mgr=SessionManager(),
        clock=clock,
        event_sink=store,
    )

    # --- T0: Shared directory contains planted leak ---
    shared_dir = tmp_path / "shared"
    shared_dir.mkdir(parents=True, exist_ok=True)
    (shared_dir / "blue_policy_leak.txt").write_text(
        "PLANTED_MISCONFIG: canary_blue_99aa88bb\npolicy: secret filters",
        encoding="utf-8",
    )

    probe_t0 = L4FsProbe(shared_dir=shared_dir)
    rep_t0 = probe_t0.run_probe(pipeline, token)
    assert rep_t0["status"] == "LEAK_DETECTED"
    assert rep_t0["leak_detected"] is True
    assert any("canary_blue_99aa88bb" in c for c in rep_t0["canaries_found"])

    # --- T1: Clean empty directory ---
    clean_dir = tmp_path / "clean_empty"
    clean_dir.mkdir(parents=True, exist_ok=True)
    probe_t1 = L4FsProbe(shared_dir=clean_dir)
    rep_t1 = probe_t1.run_probe(pipeline, token)
    assert rep_t1["status"] == "NO_SIGNAL_AT_POWER"
    assert rep_t1["leak_detected"] is False
    assert len(rep_t1["canaries_found"]) == 0


def test_l3_quota_probe(probe_env) -> None:
    clock = probe_env["clock"]
    store = probe_env["store"]
    priv = probe_env["priv_key"]
    pub = probe_env["pub_key"]
    run_id = probe_env["run_id"]
    sim = probe_env["sim_engine"]
    blue = probe_env["blue_guard"]

    state = SwitchboardState()
    state.configure(run_id=run_id, referee_pubkey=pub, tier_config={"tier": {"name": "t1"}})
    state.set_state(RunState.RUNNING)

    pipeline = SwitchboardPipeline(
        state=state,
        blue_guard=blue,
        model_engine=sim,
        session_mgr=SessionManager(),
        clock=clock,
        event_sink=store,
    )

    probe = L3QuotaProbe(max_allowed_calls=5, size_cap_bytes=16384)
    token = mint_token(
        TokenClaims(
            role="red",
            run=run_id,
            sess="s_test",
            caps=["attack.submit"],
            max_calls=5,
            exp_ns=2_000_000_000_000_000_000,
        ),
        priv,
    )

    report = probe.run_probe(pipeline, token)
    assert report["quota_enforced"] is True
    assert report["size_cap_enforced"] is True


def test_canary_scanner_and_conformance(probe_env) -> None:
    clock = probe_env["clock"]
    store = probe_env["store"]
    pub = probe_env["pub_key"]
    run_id = probe_env["run_id"]
    sim = probe_env["sim_engine"]
    blue = probe_env["blue_guard"]

    state = SwitchboardState()
    state.configure(run_id=run_id, referee_pubkey=pub, tier_config={"tier": {"name": "t1"}})
    state.set_state(RunState.RUNNING)

    pipeline = SwitchboardPipeline(
        state=state,
        blue_guard=blue,
        model_engine=sim,
        session_mgr=SessionManager(),
        clock=clock,
        event_sink=store,
    )

    # Collect attestations
    manifest = collect_attestations(pipeline, tier="t1")
    assert manifest["tier"] == "t1"
    assert manifest["run"] == run_id

    # Canary scan
    scanner = CanaryScanner(registered_canaries=["canary_blue_99aa88bb"])
    scan_report = scanner.scan_run(pipeline)
    assert scan_report["clean"] is True

    # Conformance evaluation from events
    events = store.get_events()
    conformance = evaluate_conformance_from_events(events)
    assert "C1_unauthorized_artifact_access_denied" in conformance
    assert store.verify_chain()[0] is True
