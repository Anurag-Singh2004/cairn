"""AES-256-GCM authenticated encryption vault for CAIRN blobs per context.md §8.5/§10.

Encrypts raw prompts and responses for host-side storage with optional AAD
binding (e.g. run ID and finding ID).
"""

from __future__ import annotations

import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cairn.common.errors import CryptoError


def generate_vault_key() -> bytes:
    """Generate a 256-bit (32-byte) random AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_blob(
    key: bytes,
    plaintext: bytes,
    aad: bytes | None = None,
) -> dict[str, str]:
    """Encrypt plaintext using AES-256-GCM with a random 96-bit nonce.

    Returns dictionary with hex-encoded 'nonce' and 'ciphertext_and_tag'.
    """
    if len(key) != 32:
        raise CryptoError(f"AES-256 key must be 32 bytes, got {len(key)}")

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    try:
        ct = aesgcm.encrypt(nonce, plaintext, aad)
    except Exception as e:
        raise CryptoError(f"AES-GCM encryption failed: {e}") from e

    return {
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
        "aad": aad.hex() if aad else "",
    }


def decrypt_blob(
    key: bytes,
    vault_payload: dict[str, Any],
) -> bytes:
    """Decrypt AES-256-GCM payload dictionary.

    Fails closed with CryptoError on authentication failure or tampering.
    """
    if len(key) != 32:
        raise CryptoError(f"AES-256 key must be 32 bytes, got {len(key)}")

    try:
        nonce = bytes.fromhex(vault_payload["nonce"])
        ct = bytes.fromhex(vault_payload["ciphertext"])
        aad_hex = vault_payload.get("aad", "")
        aad = bytes.fromhex(aad_hex) if aad_hex else None
    except Exception as e:
        raise CryptoError(f"Malformed vault payload: {e}") from e

    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ct, aad)
    except Exception as e:
        raise CryptoError(f"AES-GCM decryption/authentication failed: {e}") from e
