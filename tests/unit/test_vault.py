"""Unit tests for AES-256-GCM vault encryption and negative controls."""

from __future__ import annotations

import pytest

from cairn.common.errors import CryptoError
from cairn.crypto.vault import decrypt_blob, encrypt_blob, generate_vault_key


def test_vault_roundtrip_with_aad():
    key = generate_vault_key()
    assert len(key) == 32

    plaintext = b"sensitive_attack_payload_or_prompt_123"
    aad = b"run_id:r_123;finding_id:f_001"

    payload = encrypt_blob(key, plaintext, aad)
    decrypted = decrypt_blob(key, payload)
    assert decrypted == plaintext


def test_vault_roundtrip_without_aad():
    key = generate_vault_key()
    plaintext = b"plaintext_without_aad"

    payload = encrypt_blob(key, plaintext, None)
    decrypted = decrypt_blob(key, payload)
    assert decrypted == plaintext


def test_vault_tampered_ciphertext_fails_closed():
    key = generate_vault_key()
    plaintext = b"secret_data"
    payload = encrypt_blob(key, plaintext)

    # Mutate 1 byte of ciphertext
    ct_bytes = bytearray.fromhex(payload["ciphertext"])
    ct_bytes[0] ^= 0xFF
    payload["ciphertext"] = ct_bytes.hex()

    with pytest.raises(CryptoError, match="authentication failed"):
        decrypt_blob(key, payload)


def test_vault_tampered_aad_fails_closed():
    key = generate_vault_key()
    plaintext = b"secret_data"
    aad = b"finding:f_001"
    payload = encrypt_blob(key, plaintext, aad)

    # Swap AAD to different finding
    payload["aad"] = b"finding:f_002".hex()

    with pytest.raises(CryptoError, match="authentication failed"):
        decrypt_blob(key, payload)


def test_vault_wrong_key_fails_closed():
    key1 = generate_vault_key()
    key2 = generate_vault_key()
    plaintext = b"secret_data"
    payload = encrypt_blob(key1, plaintext)

    with pytest.raises(CryptoError, match="authentication failed"):
        decrypt_blob(key2, payload)
