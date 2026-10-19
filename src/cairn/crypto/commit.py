"""Commit-reveal cryptography for CAIRN red and blue packages.

Implements context.md §8.6:
- commit_red = SHA-256(nonce_r || canonical(pack))
- commit_blue = SHA-256(nonce_b || image_id || canonical(policy))
Nonces are 32 random bytes, represented as 64-char hex strings.
"""

from __future__ import annotations

import secrets
from typing import Any

from cairn.common.canonical import canonical_json_bytes
from cairn.common.hashing import sha256_hex


def generate_nonce() -> str:
    """Generate 32 random bytes as a 64-character lowercase hex string."""
    return secrets.token_hex(32)


def compute_commit_red(nonce_hex: str, pack: Any) -> str:
    """Compute commitment hash for red attack pack."""
    nonce_bytes = bytes.fromhex(nonce_hex)
    payload = nonce_bytes + canonical_json_bytes(pack)
    return sha256_hex(payload)


def verify_commit_red(commitment: str, nonce_hex: str, pack: Any) -> bool:
    """Verify red commitment against revealed nonce and pack."""
    try:
        expected = compute_commit_red(nonce_hex, pack)
        return secrets.compare_digest(commitment.lower(), expected.lower())
    except Exception:
        return False


def compute_commit_blue(nonce_hex: str, image_id: str, policy: Any) -> str:
    """Compute commitment hash for blue defense policy and container image ID."""
    nonce_bytes = bytes.fromhex(nonce_hex)
    payload = nonce_bytes + image_id.encode("utf-8") + canonical_json_bytes(policy)
    return sha256_hex(payload)


def verify_commit_blue(
    commitment: str,
    nonce_hex: str,
    image_id: str,
    policy: Any,
) -> bool:
    """Verify blue commitment against revealed nonce, image ID, and policy."""
    try:
        expected = compute_commit_blue(nonce_hex, image_id, policy)
        return secrets.compare_digest(commitment.lower(), expected.lower())
    except Exception:
        return False
