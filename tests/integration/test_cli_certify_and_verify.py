"""Integration tests for CLI cairn certify, cairn verify, and cairn verify-run commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cairn.cli import main
from cairn.crypto.commit import compute_commit_blue, compute_commit_red
from cairn.crypto.keys import generate_keypair, save_keypair
from cairn.referee.evidence import EvidenceStore


@pytest.fixture
def run_dir_with_evidence(tmp_path: Path):
    keys_dir = tmp_path / "keys"
    runs_dir = tmp_path / "runs"
    run_id = "r_cli_test_01"
    run_path = runs_dir / run_id
    run_path.mkdir(parents=True, exist_ok=True)

    privkey, _pubkey = generate_keypair()
    save_keypair(privkey, keys_dir, "ref_ed25519")

    db_path = run_path / "evidence.db"
    store = EvidenceStore(db_path)

    red_nonce = "33" * 32
    pack_data = [{"id": "f_demo_1", "prompt": "extract secret"}]
    commit_r = compute_commit_red(red_nonce, pack_data)

    blue_nonce = "44" * 32
    policy_data = {"regex": ["secret"]}
    image_id = "sha256:blueimg"
    commit_b = compute_commit_blue(blue_nonce, image_id, policy_data)

    manifest = {
        "run": run_id,
        "tier": "t1",
        "compose_sha256": "compose_hash_abc",
        "images": {"switchboard": "img_sb", "blue": image_id, "model": "img_model"},
        "cache_isolation": "salted",
        "model": {"backend": "sim_engine"},
        "commitments": {"red": commit_r, "blue": commit_b},
    }

    # Add events
    store.append_event(run_id, 1000, "run.created", "referee", {"tier": "t1"})
    store.append_event(run_id, 2000, "manifest.frozen", "referee", manifest)
    store.append_event(
        run_id,
        3000,
        "attestation.matrix",
        "auditor",
        {"phase": "pre", "deviations": 0, "observed_edges": []},
    )

    # Finding f_demo_1
    store.append_event(
        run_id,
        4000,
        "request.received",
        "switchboard",
        {"finding": "f_demo_1", "session_id": "sess_1"},
    )
    store.append_event(
        run_id,
        5000,
        "blue.input.verdict",
        "blue",
        {"finding": "f_demo_1", "verdict": "allow", "reason": "R_NONE"},
    )
    store.append_event(
        run_id,
        6000,
        "model.call",
        "switchboard",
        {
            "finding": "f_demo_1",
            "session_id": "sess_1",
            "namespace_id": "ns_sess_1",
            "cache_isolation": "salted",
            "simulated": True,
            "finish_reason": "stop",
        },
    )
    store.append_event(
        run_id,
        7000,
        "blue.output.verdict",
        "blue",
        {"finding": "f_demo_1", "verdict": "allow", "reason": "R_NONE"},
    )
    store.append_event(
        run_id,
        8000,
        "response.released",
        "switchboard",
        {
            "finding": "f_demo_1",
            "bucket": 256,
            "flag_hit": False,
            "proc_ms": 110,
            "release_ms": 250,
        },
    )

    # Audits
    store.append_event(
        run_id, 9000, "probe.l1.result", "auditor", {"status": "NO_SIGNAL_AT_POWER", "trials": 200}
    )
    store.append_event(
        run_id, 10000, "probe.l4.result", "auditor", {"status": "NO_SIGNAL", "canaries_found": 0}
    )
    store.append_event(
        run_id, 11000, "attestation.canary_scan", "auditor", {"canaries_found": 0, "leaks": []}
    )
    store.append_event(
        run_id,
        12000,
        "attestation.matrix",
        "auditor",
        {"phase": "post", "deviations": 0, "observed_edges": []},
    )
    store.append_event(
        run_id,
        13000,
        "attestation.manifest",
        "auditor",
        {"compose_sha256": "compose_hash_abc", "images": manifest["images"]},
    )
    store.append_event(
        run_id,
        14000,
        "reveal.verification",
        "referee",
        {
            "verified": True,
            "red_verified": True,
            "blue_verified": True,
            "commit_red": commit_r,
            "commit_blue": commit_b,
            "revealed_red": {"nonce": red_nonce, "pack": pack_data},
            "revealed_blue": {"nonce": blue_nonce, "image_id": image_id, "policy": policy_data},
        },
    )
    store.append_event(run_id, 15000, "run.concluded", "referee", {"status": "complete"})

    store.create_checkpoint(run=run_id, private_key=privkey, ts_ns=16000)

    return run_path


def test_cli_certify_and_verify_run(run_dir_with_evidence: Path, monkeypatch):
    run_path = run_dir_with_evidence

    # Run cairn certify --run <run_path>
    exit_code_certify = main(["certify", "--run", str(run_path)])
    assert exit_code_certify == 0

    receipt_file = run_path / "receipts" / "receipt_f_demo_1.json"
    assert receipt_file.is_file()

    certs_summary = run_path / "certificates.json"
    assert certs_summary.is_file()
    summary_data = json.loads(certs_summary.read_text(encoding="utf-8"))
    assert "f_demo_1" in summary_data
    assert summary_data["f_demo_1"]["status"] == "VALID_WITH_WARNINGS"

    # Run cairn verify <receipt_file>
    exit_code_verify = main(["verify", str(receipt_file)])
    assert exit_code_verify == 0

    # Run cairn verify-run --run <run_path>
    exit_code_verify_run = main(["verify-run", "--run", str(run_path)])
    assert exit_code_verify_run == 0


def test_cli_verify_tampered_receipt_exits_1(run_dir_with_evidence: Path):
    run_path = run_dir_with_evidence

    # Certify to generate receipt
    main(["certify", "--run", str(run_path)])
    receipt_file = run_path / "receipts" / "receipt_f_demo_1.json"

    # Tamper receipt
    data = json.loads(receipt_file.read_text(encoding="utf-8"))
    data["certificate"]["status"] = "VALID"  # Tamper Step 5
    tampered_file = run_path / "receipts" / "receipt_tampered.json"
    tampered_file.write_text(json.dumps(data), encoding="utf-8")

    exit_code = main(["verify", str(tampered_file)])
    assert exit_code == 1
