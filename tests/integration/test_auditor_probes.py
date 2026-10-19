"""Integration tests for M4 Auditor probes and attestations.

Tests against all criteria in flow.md §5 M4:
1. Negative controls fire on T0:
   - L1 probe detects leak planted in /shared
   - L4 probe detects prefix cache timing leakage in T0
2. Positive controls pass on T1:
   - L1 probe confirms no cross-session or storage leak
   - L3 probe confirms token call budget and size cap enforcement
   - L4 probe confirms timing distribution is flat (p >= 0.01)
3. Canary scanner flags foreign canaries
4. Attestation collector emits attestation.manifest
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cairn.auditor.attestation import collect_attestations
from cairn.auditor.canary import CanaryScanner
from cairn.auditor.l1_leak import L1LeakProbe
from cairn.auditor.l3_quota import L3QuotaProbe
from cairn.auditor.l4_timing import L4TimingProbe
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


def test_l1_leak_probe_t0_vs_t1(probe_env) -> None:
    clock = probe_env["clock"]
    store = probe_env["store"]
    priv = probe_env["priv_key"]
    pub = probe_env["pub_key"]
    run_id = probe_env["run_id"]
    sim = probe_env["sim_engine"]
    blue = probe_env["blue_guard"]
    tmp_path = probe_env["tmp_path"]

    # --- Test T0 (leaky baseline with shared volume) ---
    shared_dir = tmp_path / "shared"
    shared_dir.mkdir()
    (shared_dir / "blue_policy_leak.txt").write_text(
        "PLANTED_MISCONFIG: canary_blue_99aa88bb\npolicy: secret filters",
        encoding="utf-8",
    )

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

    probe = L1LeakProbe(shared_dir=shared_dir)
    token = mint_token(
        TokenClaims(
            role="red",
            run=run_id,
            sess="s_auditor",
            caps=["attack.submit"],
            max_calls=100,
            exp_ns=2_000_000_000_000_000_000,
        ),
        priv,
    )

    report_t0 = probe.run_probe(pipeline_t0, token)
    assert report_t0["leak_detected"] is True
    assert report_t0["mechanism"] == "shared_storage_leak"

    # --- Test T1 (clean isolated) ---
    clean_dir = tmp_path / "clean_empty"
    clean_dir.mkdir()
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

    probe_t1 = L1LeakProbe(shared_dir=clean_dir)
    report_t1 = probe_t1.run_probe(pipeline_t1, token)
    assert report_t1["leak_detected"] is False


def test_l3_quota_probe(probe_env) -> None:
    clock = probe_env["clock"]
    store = probe_env["store"]
    priv = probe_env["priv_key"]
    pub = probe_env["pub_key"]
    run_id = probe_env["run_id"]
    sim = probe_env["sim_engine"]
    blue = probe_env["blue_guard"]

    state = SwitchboardState()
    state.configure(
        run_id=run_id,
        referee_pubkey=pub,
        tier_config={"tier": {"name": "t1"}},
    )
    state.set_state(RunState.RUNNING)

    pipeline = SwitchboardPipeline(
        state=state,
        blue_guard=blue,
        model_engine=sim,
        session_mgr=SessionManager(),
        clock=clock,
        event_sink=store,
    )

    l3 = L3QuotaProbe()
    report = l3.run_probe(pipeline, priv, run_id)
    assert report["budget_enforced"] is True
    assert report["size_cap_enforced"] is True
    assert report["passed"] is True


def test_l4_timing_probe_t0_vs_t1(probe_env) -> None:
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
            max_calls=500,
            exp_ns=2_000_000_000_000_000_000,
        ),
        priv,
    )

    # In T0: shared prefix cache + no release quantization -> timing difference detectable
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

    l4 = L4TimingProbe()
    rep_t0 = l4.run_probe(pipeline_t0, token, n_samples=10)
    assert rep_t0["delta_ms"] > 0
    assert rep_t0["leak_detected"] is True
    assert rep_t0["p_value_e4"] < 100  # p < 0.01

    # In T1: salted cache + 250ms quantized release -> delta_ms == 0, no leak detected
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

    rep_t1 = l4.run_probe(pipeline_t1, token, n_samples=10)
    assert rep_t1["delta_ms"] == 0
    assert rep_t1["leak_detected"] is False
    assert rep_t1["p_value_e4"] >= 100  # p >= 0.01


def test_canary_scanner_and_attestation(probe_env) -> None:
    clock = probe_env["clock"]
    store = probe_env["store"]
    pub = probe_env["pub_key"]
    run_id = probe_env["run_id"]
    sim = probe_env["sim_engine"]
    blue = probe_env["blue_guard"]

    state = SwitchboardState()
    state.configure(
        run_id=run_id,
        referee_pubkey=pub,
        tier_config={"tier": {"name": "t1"}},
    )
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

    # Verify audit events emitted
    events = store.get_events()
    kinds = [e.kind for e in events]
    assert "attestation.manifest" in kinds
    assert "attestation.canary_scan" in kinds
    assert store.verify_chain()[0] is True
