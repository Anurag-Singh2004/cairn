"""Unit tests for Ed25519 keys, tokens, and commitments."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from cairn.common.errors import TokenError
from cairn.common.schemas import TokenClaims
from cairn.crypto.commit import (
    compute_commit_blue,
    compute_commit_red,
    generate_nonce,
    verify_commit_blue,
    verify_commit_red,
)
from cairn.crypto.keys import (
    compute_key_id,
    generate_keypair,
    load_private_key,
    load_public_key,
    public_key_from_b64,
    public_key_to_b64,
    save_keypair,
    sign_data,
    verify_signature,
)
from cairn.crypto.tokens import mint_token, verify_token


def test_ed25519_sign_verify_roundtrip() -> None:
    priv, pub = generate_keypair()
    data = b"evidence payload"
    sig = sign_data(priv, data)
    assert verify_signature(pub, sig, data) is True

    # Tampered data
    assert verify_signature(pub, sig, b"tampered") is False

    # Corrupted signature
    bad_sig = bytearray(sig)
    bad_sig[0] ^= 0xFF
    assert verify_signature(pub, bytes(bad_sig), data) is False

    # Wrong key
    _, other_pub = generate_keypair()
    assert verify_signature(other_pub, sig, data) is False


def test_key_saving_and_file_permissions(tmp_path: Path) -> None:
    priv, _pub = generate_keypair()
    key_dir = tmp_path / "keys"
    priv_path, pub_path = save_keypair(priv, key_dir)

    # Check 0600 on private key
    mode = stat.S_IMODE(os.stat(priv_path).st_mode)
    assert mode == 0o600

    # Load and test
    loaded_priv = load_private_key(priv_path)
    loaded_pub = load_public_key(pub_path)
    sig = sign_data(loaded_priv, b"test")
    assert verify_signature(loaded_pub, sig, b"test") is True


def test_public_key_b64_serialization() -> None:
    _, pub = generate_keypair()
    b64_str = public_key_to_b64(pub)
    loaded_pub = public_key_from_b64(b64_str)
    assert public_key_to_b64(loaded_pub) == b64_str
    assert compute_key_id(pub) == compute_key_id(loaded_pub)


def test_capability_tokens() -> None:
    priv, pub = generate_keypair()
    claims = TokenClaims(
        role="red",
        run="r_20261019_001",
        sess="s_test",
        caps=["attack.submit", "status.read"],
        max_calls=200,
        exp_ns=2_000_000_000_000_000_000,
    )

    token = mint_token(claims, priv)
    verified = verify_token(
        token,
        pub,
        expected_run="r_20261019_001",
        required_cap="attack.submit",
        expected_role="red",
        session_id="s_test",
        now_ns=1_500_000_000_000_000_000,
    )
    assert verified.role == "red"
    assert verified.run == "r_20261019_001"

    # Expired token
    with pytest.raises(TokenError, match="Token expired"):
        verify_token(token, pub, now_ns=2_500_000_000_000_000_000)

    # Wrong run
    with pytest.raises(TokenError, match="does not match expected run"):
        verify_token(token, pub, expected_run="r_other")

    # Missing capability
    with pytest.raises(TokenError, match="lacks required capability"):
        verify_token(token, pub, required_cap="admin.reset")

    # Tampered token
    parts = token.split(".")
    tampered_token = parts[0] + "tamper." + parts[1]
    with pytest.raises(TokenError):
        verify_token(tampered_token, pub)


def test_commit_reveal_red_and_blue() -> None:
    nonce_r = generate_nonce()
    pack = {"attacks": [{"id": "a1", "prompt": "benign test"}]}
    commit_r = compute_commit_red(nonce_r, pack)
    assert verify_commit_red(commit_r, nonce_r, pack) is True
    assert verify_commit_red(commit_r, nonce_r, {"attacks": []}) is False

    nonce_b = generate_nonce()
    policy = {"rules": ["block forbidden"]}
    image_id = "sha256:1234567890abcdef"
    commit_b = compute_commit_blue(nonce_b, image_id, policy)
    assert verify_commit_blue(commit_b, nonce_b, image_id, policy) is True
    assert verify_commit_blue(commit_b, nonce_b, "sha256:other", policy) is False
