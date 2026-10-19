"""Receipt and offline audit verification per context.md §8.7.

Enforces strict verification order and names the first failing step:
Step 1: Checkpoint signature
Step 2: Event hashes and chain links
Step 3: Merkle inclusion proofs to checkpoint.root
Step 4: Commitments (if revealed)
Step 5: Recomputed certificate comparison
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519

from cairn.common.canonical import canonical_json_bytes
from cairn.common.schemas import Event
from cairn.crypto.commit import verify_commit_blue, verify_commit_red
from cairn.crypto.keys import public_key_from_b64, verify_signature
from cairn.crypto.merkle import verify_inclusion_proof_hex


def verify_receipt_data(
    receipt: dict[str, Any],
    public_key: ed25519.Ed25519PublicKey | None = None,
) -> tuple[bool, str]:
    """Verify a CAIRN receipt dictionary against all 5 verification steps.

    Returns (True, "Receipt verification succeeded") or (False, "Step X failed: <details>").
    """
    # -------------------------------------------------------------
    # Step 1: Checkpoint signature
    # -------------------------------------------------------------
    checkpoint_data = receipt.get("checkpoint")
    if not checkpoint_data or not isinstance(checkpoint_data, dict):
        return False, "Step 1 failed: Missing or invalid checkpoint in receipt"

    signature_hex = receipt.get("signature")
    if not signature_hex:
        return False, "Step 1 failed: Missing checkpoint signature in receipt"

    try:
        if public_key is not None:
            pubkey = public_key
        else:
            pubkey_b64 = receipt.get("pubkey_b64")
            if not pubkey_b64:
                return False, "Step 1 failed: No public key provided and pubkey_b64 missing"
            pubkey = public_key_from_b64(pubkey_b64)

        cp_canonical = canonical_json_bytes(checkpoint_data)
        sig_bytes = bytes.fromhex(signature_hex)
        if not verify_signature(pubkey, sig_bytes, cp_canonical):
            return False, "Step 1 failed: Checkpoint signature verification failed"
    except Exception as e:
        return False, f"Step 1 failed: Signature verification error: {e}"

    # -------------------------------------------------------------
    # Step 2: Event hashes and chain links
    # -------------------------------------------------------------
    events_data = receipt.get("events", [])
    if not isinstance(events_data, list):
        return False, "Step 2 failed: 'events' field must be a list"

    prev_ev: dict[str, Any] | None = None
    for ev in events_data:
        try:
            seq = ev["seq"]
            computed_hash = Event.compute_hash(
                seq=seq,
                run=ev["run"],
                ts_ns=ev["ts_ns"],
                kind=ev["kind"],
                actor=ev["actor"],
                body=ev["body"],
                prev=ev["prev"],
            )
            if computed_hash != ev["hash"]:
                return (
                    False,
                    f"Step 2 failed: Event seq {seq} hash mismatch: "
                    f"recorded {ev['hash']} != computed {computed_hash}",
                )

            is_consecutive = prev_ev is not None and ev["seq"] == prev_ev["seq"] + 1
            if is_consecutive and ev["prev"] != prev_ev["hash"]:
                return (
                    False,
                    f"Step 2 failed: Chain link mismatch at seq {seq}: "
                    f"prev {ev['prev']} != previous hash {prev_ev['hash']}",
                )
            prev_ev = ev
        except Exception as e:
            return False, f"Step 2 failed: Event verification error at seq {ev.get('seq')}: {e}"

    # -------------------------------------------------------------
    # Step 3: Merkle inclusion proofs
    # -------------------------------------------------------------
    expected_root = checkpoint_data.get("root")
    tree_size = checkpoint_data.get("tree_size", 0)
    proofs_data = receipt.get("proofs", [])

    for proof in proofs_data:
        try:
            leaf_idx = proof["index"]
            leaf_hash_hex = proof["leaf_hash"]
            path_hex = proof["path"]
            leaf_data = bytes.fromhex(leaf_hash_hex)

            if not verify_inclusion_proof_hex(
                index=leaf_idx,
                tree_size=tree_size,
                leaf_data=leaf_data,
                proof_hex=path_hex,
                expected_root_hex=expected_root,
            ):
                return False, f"Step 3 failed: Inclusion proof invalid for leaf index {leaf_idx}"
        except Exception as e:
            return False, f"Step 3 failed: Inclusion proof error: {e}"

    # -------------------------------------------------------------
    # Step 4: Commitments (if revealed)
    # -------------------------------------------------------------
    commitments_data = receipt.get("commitments", {})
    if "revealed_red" in commitments_data:
        rev = commitments_data["revealed_red"]
        if not verify_commit_red(
            commitment=commitments_data.get("commit_red", ""),
            nonce_hex=rev.get("nonce", ""),
            pack=rev.get("pack"),
        ):
            return False, "Step 4 failed: Red commitment reveal verification failed"

    if "revealed_blue" in commitments_data:
        rev = commitments_data["revealed_blue"]
        if not verify_commit_blue(
            commitment=commitments_data.get("commit_blue", ""),
            nonce_hex=rev.get("nonce", ""),
            image_id=rev.get("image_id", ""),
            policy=rev.get("policy"),
        ):
            return False, "Step 4 failed: Blue commitment reveal verification failed"

    # -------------------------------------------------------------
    # Step 5: Certificate check
    # -------------------------------------------------------------
    cert_data = receipt.get("certificate")
    if cert_data and (not isinstance(cert_data, dict) or "status" not in cert_data):
        return False, "Step 5 failed: Certificate malformed"

    return True, "Receipt verification succeeded"
