"""RFC 6962 Merkle tree implementation with inclusion proof generation and verification.

Conforms to RFC 6962 §2.1 and §2.1.1:
- Empty tree root is SHA-256("")
- Leaf hash: SHA-256(0x00 || leaf_data)
- Internal node: SHA-256(0x01 || left || right)
- Split point: largest power of two strictly less than n
"""

from __future__ import annotations

from cairn.common.errors import VerificationError
from cairn.common.hashing import (
    EMPTY_STRING_HASH_BYTES,
    rfc6962_leaf_hash,
    rfc6962_node_hash,
)


def largest_power_of_two_less_than(n: int) -> int:
    """Return the largest power of two strictly less than n (for n >= 2)."""
    if n < 2:
        return 0
    return 1 << ((n - 1).bit_length() - 1)


def compute_leaf_hash(leaf_data: bytes) -> bytes:
    """Compute RFC 6962 leaf hash: SHA-256(0x00 || leaf_data)."""
    return rfc6962_leaf_hash(leaf_data)


def compute_root(leaves: list[bytes]) -> bytes:
    """Compute RFC 6962 Merkle Tree Hash (MTH) for a list of raw leaf payloads."""
    n = len(leaves)
    if n == 0:
        return EMPTY_STRING_HASH_BYTES
    if n == 1:
        return compute_leaf_hash(leaves[0])
    k = largest_power_of_two_less_than(n)
    left_root = compute_root(leaves[:k])
    right_root = compute_root(leaves[k:])
    return rfc6962_node_hash(left_root, right_root)


def compute_root_hex(leaves: list[bytes]) -> str:
    """Compute RFC 6962 Merkle root returning lowercase hex string."""
    return compute_root(leaves).hex()


def compute_inclusion_proof(index: int, leaves: list[bytes]) -> list[bytes]:
    """Generate RFC 6962 §2.1.1 inclusion proof (audit path) for leaf at index.

    The returned path is ordered from leaf-level sibling to root-level sibling.
    """
    n = len(leaves)
    if not (0 <= index < n):
        raise ValueError(f"Leaf index {index} out of range for tree size {n}")
    if n == 1:
        return []

    k = largest_power_of_two_less_than(n)
    if index < k:
        sub_path = compute_inclusion_proof(index, leaves[:k])
        sub_path.append(compute_root(leaves[k:]))
        return sub_path
    else:
        sub_path = compute_inclusion_proof(index - k, leaves[k:])
        sub_path.append(compute_root(leaves[:k]))
        return sub_path


def compute_inclusion_proof_hex(index: int, leaves: list[bytes]) -> list[str]:
    """Generate inclusion proof returning list of hex strings."""
    return [p.hex() for p in compute_inclusion_proof(index, leaves)]


def _reconstruct_root(
    index: int,
    tree_size: int,
    leaf_data: bytes,
    proof: list[bytes],
) -> bytes:
    """Recursively reconstruct the root hash from leaf_data and proof path."""
    if tree_size == 1:
        if len(proof) != 0:
            raise VerificationError("Proof path contains superfluous elements for tree size 1")
        return compute_leaf_hash(leaf_data)

    if not proof:
        raise VerificationError(f"Insufficient proof elements for tree size {tree_size}")

    k = largest_power_of_two_less_than(tree_size)
    sibling = proof[-1]
    remaining_proof = proof[:-1]

    if index < k:
        left = _reconstruct_root(index, k, leaf_data, remaining_proof)
        right = sibling
    else:
        left = sibling
        right = _reconstruct_root(index - k, tree_size - k, leaf_data, remaining_proof)

    return rfc6962_node_hash(left, right)


def verify_inclusion_proof(
    index: int,
    tree_size: int,
    leaf_data: bytes,
    proof: list[bytes],
    expected_root: bytes,
) -> bool:
    """Verify an RFC 6962 inclusion proof against expected root."""
    if tree_size <= 0:
        return False
    if not (0 <= index < tree_size):
        return False

    try:
        calculated_root = _reconstruct_root(index, tree_size, leaf_data, proof)
        return calculated_root == expected_root
    except VerificationError:
        return False
    except Exception:
        return False


def verify_inclusion_proof_hex(
    index: int,
    tree_size: int,
    leaf_data: bytes,
    proof_hex: list[str],
    expected_root_hex: str,
) -> bool:
    """Verify inclusion proof using hex strings."""
    try:
        proof_bytes = [bytes.fromhex(h) for h in proof_hex]
        expected_root_bytes = bytes.fromhex(expected_root_hex)
        return verify_inclusion_proof(
            index,
            tree_size,
            leaf_data,
            proof_bytes,
            expected_root_bytes,
        )
    except Exception:
        return False
