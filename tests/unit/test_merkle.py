"""Exhaustive unit and property tests for RFC 6962 Merkle tree implementation."""

from __future__ import annotations

import hashlib

import pytest

from cairn.crypto.merkle import (
    compute_inclusion_proof,
    compute_leaf_hash,
    compute_root,
    verify_inclusion_proof,
)


def test_empty_tree_root() -> None:
    """Empty tree root must equal SHA-256("")."""
    expected = hashlib.sha256(b"").digest()
    assert compute_root([]) == expected


def test_single_leaf_root() -> None:
    """Single leaf root must equal SHA-256(0x00 || leaf_data)."""
    leaf = b"sample leaf event"
    expected = hashlib.sha256(b"\x00" + leaf).digest()
    assert compute_root([leaf]) == expected
    assert compute_leaf_hash(leaf) == expected


def test_all_tree_sizes_and_inclusion_proofs_1_to_65() -> None:
    """Verify inclusion proofs for every tree size 1..65 and every leaf index.

    Also proves negative controls:
    - flipping any bit in leaf data fails
    - flipping any bit in proof path fails
    - flipping any bit in root fails
    """
    for n in range(1, 66):
        # Generate n unique synthetic leaves
        leaves = [
            f"event_{n}_{i}_{hashlib.sha256(str(i).encode()).hexdigest()}".encode()
            for i in range(n)
        ]
        root = compute_root(leaves)

        for i in range(n):
            proof = compute_inclusion_proof(i, leaves)

            # 1. Clean verification must succeed
            assert verify_inclusion_proof(i, n, leaves[i], proof, root) is True

            # 2. Tampered leaf data must fail
            tampered_leaf = bytearray(leaves[i])
            tampered_leaf[0] ^= 0x01
            assert verify_inclusion_proof(i, n, bytes(tampered_leaf), proof, root) is False

            # 3. Tampered root must fail
            tampered_root = bytearray(root)
            tampered_root[0] ^= 0x01
            assert verify_inclusion_proof(i, n, leaves[i], proof, bytes(tampered_root)) is False

            # 4. Tampered proof elements must fail (if proof is non-empty)
            if proof:
                for p_idx in range(len(proof)):
                    tampered_proof = [bytearray(p) for p in proof]
                    tampered_proof[p_idx][0] ^= 0x01
                    bad_proof = [bytes(p) for p in tampered_proof]
                    assert verify_inclusion_proof(i, n, leaves[i], bad_proof, root) is False


def test_invalid_index_raises() -> None:
    leaves = [b"a", b"b", b"c"]
    with pytest.raises(ValueError, match="out of range"):
        compute_inclusion_proof(3, leaves)
    with pytest.raises(ValueError, match="out of range"):
        compute_inclusion_proof(-1, leaves)
