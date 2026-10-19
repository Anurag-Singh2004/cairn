"""End-to-end container and tier verification tests for M3.

Marked @pytest.mark.docker.
Validates:
- Live N x N reachability matrix in T1 (C3)
- Container security properties (non-root, read-only, cap_drop ALL, no docker.sock)
- Real request flow: red -> switchboard -> blue -> model -> red
- cairn doctor live check passes
"""

from __future__ import annotations

import json

import pytest

from cairn.auditor.matrix import audit_matrix
from cairn.common.schemas import TokenClaims
from cairn.crypto.keys import generate_keypair, public_key_to_b64
from cairn.crypto.tokens import mint_token
from cairn.referee.docker_ctl import (
    compose_exec,
    inspect_service_container,
)
from cairn.referee.doctor import run_doctor


@pytest.mark.docker
def test_t1_matrix_and_egress() -> None:
    """Validate N x N reachability and zero egress in T1."""
    report = audit_matrix("t1")
    assert report["valid"] is True, f"Matrix deviations: {report['deviations']}"
    for src, has_egress in report["egress_detected"].items():
        assert has_egress is False, f"Service '{src}' has unexpected external egress in T1"


@pytest.mark.docker
def test_t1_container_hardening_inspection() -> None:
    """Inspect low-level container security properties in T1."""
    services = ["red", "blue", "model", "switchboard"]
    for svc in services:
        info = inspect_service_container("t1", svc)
        host_cfg = info.get("HostConfig", {})
        config = info.get("Config", {})

        # Assert non-root
        assert config.get("User") == "10001:10001", f"{svc} must run as user 10001:10001"

        # Assert read-only rootfs
        assert host_cfg.get("ReadonlyRootfs") is True, f"{svc} rootfs must be read-only"

        # Assert cap_drop ALL
        assert "ALL" in host_cfg.get("CapDrop", []), f"{svc} must drop ALL capabilities"

        # Assert no docker.sock mounted
        mounts = info.get("Mounts", [])
        for m in mounts:
            assert "docker.sock" not in m.get("Source", ""), f"{svc} must not mount docker.sock"


@pytest.mark.docker
def test_t1_live_doctor_preflight() -> None:
    """Validate cairn doctor live check passes on T1."""
    ok, report = run_doctor(tier="t1", live_check=True)
    assert ok is True
    assert report["passed"] is True


@pytest.mark.docker
def test_t1_live_attack_request() -> None:
    """Execute end-to-end attack from inside red container to switchboard."""
    priv, pub = generate_keypair()
    pub_b64 = public_key_to_b64(pub)
    run_id = "r_e2e_m3_test"

    # Configure switchboard via UDS admin
    cfg_payload = {
        "run_id": run_id,
        "pubkey_b64": pub_b64,
        "tier_config": {
            "tier": {
                "name": "t1",
                "quantise_ms": 250,
                "request_deadline_ms": 2000,
                "fail_mode": "closed",
                "cache_isolation": "salted",
            }
        },
        "secret_flag": "FLAG{e2e_secret}",
    }

    rc, _, _ = compose_exec(
        "t1",
        "switchboard",
        [
            "python",
            "-c",
            """
import sys, json, httpx
data = json.load(sys.stdin)
client = httpx.Client(transport=httpx.HTTPTransport(uds='/run/cairn/admin.sock'), base_url='http://admin')
client.post('/admin/run/configure', json=data)
client.post('/admin/run/state', json={'state': 'Running'})
""",
        ],
        input_str=json.dumps(cfg_payload),
    )
    assert rc == 0

    # Mint token for red
    token = mint_token(
        TokenClaims(
            role="red",
            run=run_id,
            sess="s_e2e",
            caps=["attack.submit"],
            max_calls=50,
            exp_ns=2_000_000_000_000_000_000,
        ),
        priv,
    )

    # Submit request from inside red container
    script = f"""
import httpx
resp = httpx.post('http://switchboard:8000/v1/submit', json={{
    'session_id': 's_e2e',
    'prompt': 'say hello',
    'finding_id': 'f_e2e'
}}, headers={{'X-Cairn-Token': '{token}'}})
assert resp.status_code == 200
data = resp.json()
assert data['v'] == 1
assert data['bucket'] == 128
"""
    rc_req, _, err_req = compose_exec("t1", "red", ["python", "-c", script])
    assert rc_req == 0, f"Request failed: {err_req}"
