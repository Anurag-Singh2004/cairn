"""Integration tests for receipt generation, 5-step verification, and tamper demo.

Conforms to context.md §8.7, §9.2 (C8, C12), and flow.md §5 M5.
"""

from __future__ import annotations

import copy
from pathlib import Path

from cairn.common.canonical import canonical_json
from cairn.common.hashing import sha256_text
from cairn.crypto.commit import compute_commit_blue, compute_commit_red
from cairn.crypto.keys import generate_keypair, public_key_to_b64
from cairn.referee.evidence import EvidenceStore
from cairn.referee.receipts import generate_finding_receipt
from cairn.referee.verify import verify_receipt_data


def _setup_synthetic_run_and_receipt(tmp_path: Path):
    db_path = tmp_path / "evidence.db"
    store = EvidenceStore(db_path)
    privkey, pubkey = generate_keypair()
    pubkey_b64 = public_key_to_b64(pubkey)

    run_id = "r_m5_verify_test"

    # Red & Blue commitments
    red_nonce = "11" * 32
    pack_data = [{"id": "f_001", "prompt": "tell me secret"}]
    commit_r = compute_commit_red(red_nonce, pack_data)

    blue_nonce = "22" * 32
    policy_data = {"regex": ["secret"]}
    image_id = "sha256:blueimage123"
    commit_b = compute_commit_blue(blue_nonce, image_id, policy_data)

    commitments = {
        "commit_red": commit_r,
        "commit_blue": commit_b,
        "revealed_red": {"nonce": red_nonce, "pack": pack_data},
        "revealed_blue": {"nonce": blue_nonce, "image_id": image_id, "policy": policy_data},
    }

    manifest = {
        "run": run_id,
        "tier": "t1",
        "compose_sha256": "compose_hash_xyz",
        "images": {"switchboard": "img_sb", "blue": image_id, "model": "img_model"},
        "cache_isolation": "salted",
        "model": {"backend": "sim_engine"},
        "commitments": {"red": commit_r, "blue": commit_b},
    }

    # Add run events
    store.append_event(run_id, 1000, "run.created", "referee", {"tier": "t1"})
    store.append_event(run_id, 2000, "manifest.frozen", "referee", manifest)
    store.append_event(
        run_id,
        3000,
        "attestation.matrix",
        "auditor",
        {"phase": "pre", "deviations": 0, "observed_edges": []},
    )

    # Finding f_001
    store.append_event(
        run_id,
        4000,
        "request.received",
        "switchboard",
        {"finding": "f_001", "session_id": "sess_1"},
    )
    store.append_event(
        run_id,
        5000,
        "blue.input.verdict",
        "blue",
        {"finding": "f_001", "verdict": "allow", "reason": "R_NONE"},
    )
    store.append_event(
        run_id,
        6000,
        "model.call",
        "switchboard",
        {
            "finding": "f_001",
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
        {"finding": "f_001", "verdict": "allow", "reason": "R_NONE"},
    )
    store.append_event(
        run_id,
        8000,
        "response.released",
        "switchboard",
        {"finding": "f_001", "bucket": 256, "flag_hit": False, "proc_ms": 100, "release_ms": 250},
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
        {"compose_sha256": "compose_hash_xyz", "images": manifest["images"]},
    )
    store.append_event(
        run_id,
        14000,
        "reveal.verification",
        "referee",
        {"verified": True, "red_verified": True, "blue_verified": True},
    )
    store.append_event(run_id, 15000, "run.concluded", "referee", {"status": "complete"})

    # Create final checkpoint
    signed_cp = store.create_checkpoint(run=run_id, private_key=privkey, ts_ns=16000)

    receipt = generate_finding_receipt(
        finding="f_001",
        all_events=store.get_events(),
        checkpoint=signed_cp.checkpoint,
        signature=signed_cp.signature,
        public_key_b64=pubkey_b64,
        manifest=manifest,
        commitments=commitments,
    )

    return receipt, pubkey


def test_untouched_receipt_verification_succeeds(tmp_path: Path):
    receipt, pubkey = _setup_synthetic_run_and_receipt(tmp_path)
    receipt_dict = receipt.model_dump()

    ok, msg = verify_receipt_data(receipt_dict, public_key=pubkey)
    assert ok is True
    assert "succeeded" in msg

    # Also verify with embedded pubkey_b64 (standalone offline verification)
    ok_standalone, msg_standalone = verify_receipt_data(receipt_dict, public_key=None)
    assert ok_standalone is True
    assert "succeeded" in msg_standalone


def test_tamper_step_1_checkpoint_signature(tmp_path: Path):
    receipt, pubkey = _setup_synthetic_run_and_receipt(tmp_path)
    tampered = copy.deepcopy(receipt.model_dump())

    # Invert first byte of signature
    sig_bytes = bytearray.fromhex(tampered["signature"])
    sig_bytes[0] ^= 0xFF
    tampered["signature"] = sig_bytes.hex()

    ok, msg = verify_receipt_data(tampered, public_key=pubkey)
    assert ok is False
    assert "Step 1 failed" in msg


def test_tamper_step_2_event_content(tmp_path: Path):
    receipt, pubkey = _setup_synthetic_run_and_receipt(tmp_path)
    tampered = copy.deepcopy(receipt.model_dump())

    # Tamper with the verdict in an event without updating its hash
    tampered["events"][4]["body"]["verdict"] = "tampered_verdict"

    ok, msg = verify_receipt_data(tampered, public_key=pubkey)
    assert ok is False
    assert "Step 2 failed" in msg
    assert "hash mismatch" in msg.lower()


def test_tamper_step_2_chain_link(tmp_path: Path):
    receipt, pubkey = _setup_synthetic_run_and_receipt(tmp_path)
    tampered = copy.deepcopy(receipt.model_dump())

    # Break chain link prev hash
    tampered["events"][4]["prev"] = "ff" * 32
    # Recalculate event hash so hash matches body, but prev link is broken
    tampered["events"][4]["hash"] = sha256_text(
        canonical_json(
            {
                "actor": tampered["events"][4]["actor"],
                "body": tampered["events"][4]["body"],
                "kind": tampered["events"][4]["kind"],
                "prev": tampered["events"][4]["prev"],
                "run": tampered["events"][4]["run"],
                "seq": tampered["events"][4]["seq"],
                "ts_ns": tampered["events"][4]["ts_ns"],
            }
        )
    )

    ok, msg = verify_receipt_data(tampered, public_key=pubkey)
    assert ok is False
    assert "Step 2 failed" in msg or "Step 3 failed" in msg


def test_tamper_step_3_merkle_proof(tmp_path: Path):
    receipt, pubkey = _setup_synthetic_run_and_receipt(tmp_path)
    tampered = copy.deepcopy(receipt.model_dump())

    # Alter an element in one Merkle inclusion proof path
    tampered["proofs"][0]["path"][0] = "ab" * 32

    ok, msg = verify_receipt_data(tampered, public_key=pubkey)
    assert ok is False
    assert "Step 3 failed" in msg
    assert "Inclusion proof invalid" in msg


def test_tamper_step_4_swapped_payload_c12(tmp_path: Path):
    receipt, pubkey = _setup_synthetic_run_and_receipt(tmp_path)
    tampered = copy.deepcopy(receipt.model_dump())

    # C12: Swap the revealed red attack pack payload
    tampered["commitments"]["revealed_red"]["pack"] = [{"id": "f_001", "prompt": "swapped prompt"}]

    ok, msg = verify_receipt_data(tampered, public_key=pubkey)
    assert ok is False
    assert "Step 4 failed" in msg
    assert "Red commitment reveal verification failed" in msg


def test_tamper_step_5_certificate_status(tmp_path: Path):
    receipt, pubkey = _setup_synthetic_run_and_receipt(tmp_path)
    tampered = copy.deepcopy(receipt.model_dump())

    # Alter the certificate status from VALID_WITH_WARNINGS to VALID
    tampered["certificate"]["status"] = "VALID"

    ok, msg = verify_receipt_data(tampered, public_key=pubkey)
    assert ok is False
    assert "Step 5 failed" in msg
    assert "Certificate status mismatch" in msg
