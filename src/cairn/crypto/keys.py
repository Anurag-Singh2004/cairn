"""Ed25519 key management and digital signatures for CAIRN.

Uses cryptography.hazmat.primitives.asymmetric.ed25519 exclusively.
Enforces strict 0600 file permissions on private keys per context.md §13/§15.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from cairn.common.errors import CryptoError
from cairn.common.hashing import sha256_hex


def generate_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate a new Ed25519 private/public keypair."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def public_key_raw_bytes(public_key: ed25519.Ed25519PublicKey) -> bytes:
    """Return raw 32-byte representation of public key."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_to_b64(public_key: ed25519.Ed25519PublicKey) -> str:
    """Encode raw public key as URL-safe base64 string without padding."""
    return base64.urlsafe_b64encode(public_key_raw_bytes(public_key)).decode("ascii").rstrip("=")


def public_key_from_b64(b64_str: str) -> ed25519.Ed25519PublicKey:
    """Decode raw public key from base64 string."""
    padded = b64_str + "=" * ((4 - len(b64_str) % 4) % 4)
    raw = base64.urlsafe_b64decode(padded)
    if len(raw) != 32:
        raise CryptoError(f"Ed25519 public key must be 32 bytes, got {len(raw)}")
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


def compute_key_id(public_key: ed25519.Ed25519PublicKey) -> str:
    """Compute 16-char hex key_id from public key hash."""
    return sha256_hex(public_key_raw_bytes(public_key))[:16]


def save_keypair(
    private_key: ed25519.Ed25519PrivateKey,
    target_dir: Path,
    key_name: str = "ref_ed25519",
) -> tuple[Path, Path]:
    """Save private (0600) and public keys to target_dir."""
    target_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(target_dir, 0o700)

    priv_path = target_dir / f"{key_name}.key"
    pub_path = target_dir / f"{key_name}.pub"

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Write private key with 0600 permissions
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(priv_path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(priv_bytes)
    except Exception:
        os.close(fd)
        raise
    os.chmod(priv_path, 0o600)

    with open(pub_path, "wb") as f:
        f.write(pub_bytes)

    return priv_path, pub_path


def load_private_key(path: Path) -> ed25519.Ed25519PrivateKey:
    """Load private key from PEM file."""
    if not path.is_file():
        raise CryptoError(f"Private key file not found: {path}")
    data = path.read_bytes()
    try:
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise CryptoError("Key is not an Ed25519 private key")
        return key
    except Exception as e:
        raise CryptoError(f"Failed to load private key from {path}: {e}") from e


def load_public_key(path: Path) -> ed25519.Ed25519PublicKey:
    """Load public key from PEM or raw b64 file."""
    if not path.is_file():
        raise CryptoError(f"Public key file not found: {path}")
    data = path.read_bytes().strip()
    try:
        if b"BEGIN PUBLIC KEY" in data:
            key = serialization.load_pem_public_key(data)
            if not isinstance(key, ed25519.Ed25519PublicKey):
                raise CryptoError("Key is not an Ed25519 public key")
            return key
        return public_key_from_b64(data.decode("ascii"))
    except Exception as e:
        raise CryptoError(f"Failed to load public key from {path}: {e}") from e


def sign_data(private_key: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    """Sign data using Ed25519 private key."""
    return private_key.sign(data)


def verify_signature(
    public_key: ed25519.Ed25519PublicKey,
    signature: bytes,
    data: bytes,
) -> bool:
    """Verify Ed25519 signature. Returns True if valid, False otherwise."""
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
