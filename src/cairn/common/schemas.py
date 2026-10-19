"""Pydantic wire models for CAIRN contracts per context.md §8."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cairn.common.canonical import canonical_json
from cairn.common.hashing import sha256_text


class TokenClaims(BaseModel):
    """Capability token claims per context.md §8.1."""

    v: int = 1
    role: str
    run: str
    sess: str
    caps: list[str]
    max_calls: int
    exp_ns: int


class EventBody(BaseModel):
    """Base model for structured event bodies."""

    model_config = ConfigDict(extra="allow")


class Event(BaseModel):
    """The unit of evidence per context.md §8.5."""

    seq: int
    run: str
    ts_ns: int
    kind: str
    actor: str
    body: dict[str, Any]
    prev: str
    hash: str

    @classmethod
    def compute_hash(
        cls,
        seq: int,
        run: str,
        ts_ns: int,
        kind: str,
        actor: str,
        body: dict[str, Any],
        prev: str,
    ) -> str:
        """Compute SHA-256 hash of canonical event dictionary without 'hash' field."""
        canonical_dict = {
            "actor": actor,
            "body": body,
            "kind": kind,
            "prev": prev,
            "run": run,
            "seq": seq,
            "ts_ns": ts_ns,
        }
        return sha256_text(canonical_json(canonical_dict))


class Checkpoint(BaseModel):
    """Merkle tree checkpoint per context.md §8.7."""

    run: str
    tree_size: int
    root: str
    prev_checkpoint_hash: str
    ts_ns: int
    key_id: str

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "prev_checkpoint_hash": self.prev_checkpoint_hash,
            "root": self.root,
            "run": self.run,
            "tree_size": self.tree_size,
            "ts_ns": self.ts_ns,
        }


class SignedCheckpoint(BaseModel):
    """Checkpoint paired with Ed25519 signature."""

    checkpoint: Checkpoint
    signature: str


class InvariantResult(BaseModel):
    """Per-invariant evaluation result per context.md §8.8 / §9.1."""

    result: str  # "pass" | "fail" | "warn" | "missing"
    reason_code: str
    evidence_seqs: list[int] = Field(default_factory=list)


class Certificate(BaseModel):
    """Per-finding validity certificate per context.md §8.8."""

    finding: str
    status: str  # "VALID" | "VALID_WITH_WARNINGS" | "QUARANTINED" | "INCOMPLETE"
    invariants: dict[str, InvariantResult]
    residual_risk: list[str] = Field(default_factory=list)
    simulated: bool = False
    dev_only: bool = False


class Receipt(BaseModel):
    """Self-contained verification receipt per context.md §8.7."""

    receipt_version: int = 1
    run: str
    finding: str
    manifest: dict[str, Any]
    commitments: dict[str, Any]
    events: list[dict[str, Any]]
    proofs: list[dict[str, Any]]
    checkpoint: dict[str, Any]
    signature: str
    certificate: dict[str, Any]
    tool_versions: dict[str, str] = Field(default_factory=dict)
    key_id: str
    pubkey_b64: str
