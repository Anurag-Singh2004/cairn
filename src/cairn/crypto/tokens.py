"""Ed25519-signed capability tokens per context.md §8.1.

Format: base64url(canonical_json(claims)) + "." + base64url(ed25519_signature)
Claims schema: TokenClaims (v, role, run, sess, caps, max_calls, exp_ns)
"""

from __future__ import annotations

import base64
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519

from cairn.common.canonical import canonical_json_bytes
from cairn.common.errors import TokenError
from cairn.common.schemas import TokenClaims
from cairn.crypto.keys import sign_data, verify_signature


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    padded = s + "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(padded)


def mint_token(
    claims: TokenClaims | dict[str, Any],
    private_key: ed25519.Ed25519PrivateKey,
) -> str:
    """Mint an Ed25519-signed capability token."""
    claims_obj = TokenClaims(**claims) if isinstance(claims, dict) else claims
    claims_dict = claims_obj.model_dump()
    payload_bytes = canonical_json_bytes(claims_dict)
    sig_bytes = sign_data(private_key, payload_bytes)

    claims_b64 = _b64url_encode(payload_bytes)
    sig_b64 = _b64url_encode(sig_bytes)
    return f"{claims_b64}.{sig_b64}"


def verify_token(
    token: str,
    public_key: ed25519.Ed25519PublicKey,
    *,
    expected_run: str | None = None,
    required_cap: str | None = None,
    expected_role: str | None = None,
    session_id: str | None = None,
    now_ns: int | None = None,
) -> TokenClaims:
    """Verify an Ed25519-signed capability token against public key and policy constraints.

    Raises TokenError on any verification or claim failure.
    """
    parts = token.split(".")
    if len(parts) != 2:
        raise TokenError(f"Malformed token: expected 2 parts, got {len(parts)}")

    claims_b64, sig_b64 = parts
    try:
        payload_bytes = _b64url_decode(claims_b64)
        sig_bytes = _b64url_decode(sig_b64)
    except Exception as e:
        raise TokenError(f"Token base64 decoding failed: {e}") from e

    if not verify_signature(public_key, sig_bytes, payload_bytes):
        raise TokenError("Invalid token Ed25519 signature")

    import json

    try:
        raw_claims = json.loads(payload_bytes.decode("utf-8"))
        claims = TokenClaims(**raw_claims)
    except Exception as e:
        raise TokenError(f"Token claims schema validation failed: {e}") from e

    if now_ns is not None and claims.exp_ns <= now_ns:
        raise TokenError(f"Token expired at {claims.exp_ns} (current time {now_ns})")

    if expected_run is not None and claims.run != expected_run:
        raise TokenError(f"Token run '{claims.run}' does not match expected run '{expected_run}'")

    if expected_role is not None and claims.role != expected_role:
        raise TokenError(
            f"Token role '{claims.role}' does not match expected role '{expected_role}'"
        )

    if required_cap is not None and required_cap not in claims.caps:
        raise TokenError(f"Token lacks required capability '{required_cap}'")

    if session_id is not None and claims.sess != "*" and claims.sess != session_id:
        raise TokenError(
            f"Token session '{claims.sess}' does not match target session '{session_id}'"
        )

    return claims
