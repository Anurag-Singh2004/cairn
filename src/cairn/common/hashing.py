"""Hashing primitives for CAIRN.

Uses stdlib hashlib SHA-256 exclusively.
Includes RFC 6962 domain-separated hashing for Merkle tree nodes.
"""

from __future__ import annotations

import hashlib

GENESIS_PREV_HASH: str = "0" * 64
EMPTY_STRING_HASH_BYTES: bytes = hashlib.sha256(b"").digest()
EMPTY_STRING_HASH_HEX: str = hashlib.sha256(b"").hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    """Compute SHA-256 digest returning raw 32 bytes."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 digest returning lowercase 64-char hex string."""
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    """Compute SHA-256 of UTF-8 text returning hex string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def rfc6962_leaf_hash(leaf_data: bytes) -> bytes:
    """RFC 6962 leaf hash: SHA-256(0x00 || leaf_data)."""
    return sha256_bytes(b"\x00" + leaf_data)


def rfc6962_node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 internal node hash: SHA-256(0x01 || left || right)."""
    return sha256_bytes(b"\x01" + left + right)
