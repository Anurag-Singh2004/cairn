"""Unit and integration tests for EvidenceStore, receipt verification, and tamper detection."""

from __future__ import annotations

import json
from pathlib import Path

from cairn.crypto.keys import generate_keypair, public_key_to_b64
from cairn.crypto.merkle import compute_inclusion_proof_hex
from cairn.referee.evidence import EvidenceStore
from cairn.referee.validity import evaluate_certificate
from cairn.referee.verify import verify_receipt_data


def test_evidence_store_chain_and_50_synthetic_events(tmp_path: Path) -> None:
    db_path = tmp_path / "test_events.db"
    store = EvidenceStore(db_path)
    run_id = "r_20261019_test01"

    # Append 50 synthetic events
    for i in range(1, 51):
        store.append_event(
            run=run_id,
            ts_ns=1_760_000_000_000_000_000 + i * 10_000_000,
            kind="test.step",
            actor="test_runner",
            body={"step": i, "status": "ok"},
        )

    assert store.count_events() == 50
    valid, msg = store.verify_chain()
    assert valid is True
    assert msg == "Chain valid"

    # Merkle root calculation
    root_hex = store.compute_merkle_root_hex()
    assert len(root_hex) == 64

    # Create signed checkpoint
    priv, pub = generate_keypair()
    signed_cp = store.create_checkpoint(
        run=run_id,
        private_key=priv,
        ts_ns=1_760_000_001_000_000_000,
    )
    assert signed_cp.checkpoint.tree_size == 50
    assert signed_cp.checkpoint.root == root_hex

    # Assemble synthetic receipt for finding f_001 (includes event 10)
    events = store.get_events()
    target_event = events[9]  # index 9 is seq 10
    leaves_bytes = store.get_event_hashes_bytes()
    proof_hex = compute_inclusion_proof_hex(9, leaves_bytes)

    receipt = {
        "receipt_version": 1,
        "run": run_id,
        "finding": "f_001",
        "manifest": {"run": run_id, "tier": "t1"},
        "commitments": {},
        "events": [
            {
                "seq": target_event.seq,
                "run": target_event.run,
                "ts_ns": target_event.ts_ns,
                "kind": target_event.kind,
                "actor": target_event.actor,
                "body": target_event.body,
                "prev": target_event.prev,
                "hash": target_event.hash,
            }
        ],
        "proofs": [
            {
                "index": 9,
                "leaf_hash": target_event.hash,
                "path": proof_hex,
            }
        ],
        "checkpoint": signed_cp.checkpoint.canonical_dict(),
        "signature": signed_cp.signature,
        "certificate": evaluate_certificate(
            events=[target_event],
            finding="f_001",
            manifest={"run": run_id, "tier": "t1"},
        ).model_dump(),
        "pubkey_b64": public_key_to_b64(pub),
        "key_id": signed_cp.checkpoint.key_id,
    }

    # 1. Untouched receipt must verify
    ok, verify_msg = verify_receipt_data(receipt, pub)
    assert ok is True
    assert "succeeded" in verify_msg

    # 2. Negative Control: Edit one stored event in receipt -> fails Step 2
    tampered_receipt_step2 = json.loads(json.dumps(receipt))
    tampered_receipt_step2["events"][0]["body"]["status"] = "tampered"
    ok, err_msg = verify_receipt_data(tampered_receipt_step2, pub)
    assert ok is False
    assert err_msg.startswith("Step 2 failed")

    # 3. Negative Control: Corrupt checkpoint signature -> fails Step 1
    tampered_receipt_step1 = json.loads(json.dumps(receipt))
    bad_sig = bytearray.fromhex(tampered_receipt_step1["signature"])
    bad_sig[0] ^= 0xFF
    tampered_receipt_step1["signature"] = bad_sig.hex()
    ok, err_msg = verify_receipt_data(tampered_receipt_step1, pub)
    assert ok is False
    assert err_msg.startswith("Step 1 failed")

    # 4. Negative Control: Tamper inclusion proof leaf -> fails Step 3
    tampered_receipt_step3 = json.loads(json.dumps(receipt))
    bad_leaf = bytearray.fromhex(tampered_receipt_step3["proofs"][0]["leaf_hash"])
    bad_leaf[0] ^= 0xFF
    tampered_receipt_step3["proofs"][0]["leaf_hash"] = bad_leaf.hex()
    ok, err_msg = verify_receipt_data(tampered_receipt_step3, pub)
    assert ok is False
    assert err_msg.startswith("Step 3 failed")
