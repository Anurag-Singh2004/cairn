"""Append-only SQLite evidence store and hash-chained audit log.

Implements context.md §8.5 & §8.7:
- SQLite in WAL mode
- Hash-chained events: hash = SHA-256(canonical_json({seq,run,ts_ns,kind,actor,body,prev}))
- Genesis prev = 64 zeros
- Merkle root calculation & checkpoint creation
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519

from cairn.common.canonical import canonical_json_bytes
from cairn.common.hashing import GENESIS_PREV_HASH
from cairn.common.schemas import Checkpoint, Event, SignedCheckpoint
from cairn.crypto.keys import compute_key_id, sign_data
from cairn.crypto.merkle import compute_root_hex


class EvidenceStore:
    """Manages the append-only SQLite database for a run's events and checkpoints."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self):
        import sqlite3

        conn = sqlite3.connect(str(self.db_path))
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY,
                    run TEXT NOT NULL,
                    ts_ns INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    body TEXT NOT NULL,
                    prev TEXT NOT NULL,
                    hash TEXT NOT NULL
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS checkpoints (
                    tree_size INTEGER PRIMARY KEY,
                    run TEXT NOT NULL,
                    root TEXT NOT NULL,
                    prev_checkpoint_hash TEXT NOT NULL,
                    ts_ns INTEGER NOT NULL,
                    key_id TEXT NOT NULL,
                    signature TEXT NOT NULL
                );
                """
            )
            conn.commit()

    def get_last_event(self) -> Event | None:
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT seq, run, ts_ns, kind, actor, body, prev, hash "
                "FROM events ORDER BY seq DESC LIMIT 1"
            )
            row = cursor.fetchone()
            if not row:
                return None
            return Event(
                seq=row[0],
                run=row[1],
                ts_ns=row[2],
                kind=row[3],
                actor=row[4],
                body=json.loads(row[5]),
                prev=row[6],
                hash=row[7],
            )

    def append_event(
        self,
        run: str,
        ts_ns: int,
        kind: str,
        actor: str,
        body: dict[str, Any],
    ) -> Event:
        """Append a new event, computing its hash-chain linkage."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1")
            row = cursor.fetchone()
            if row is None:
                next_seq = 1
                prev_hash = GENESIS_PREV_HASH
            else:
                next_seq = row[0] + 1
                prev_hash = row[1]

            event_hash = Event.compute_hash(
                seq=next_seq,
                run=run,
                ts_ns=ts_ns,
                kind=kind,
                actor=actor,
                body=body,
                prev=prev_hash,
            )

            conn.execute(
                """
                INSERT INTO events (seq, run, ts_ns, kind, actor, body, prev, hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    next_seq,
                    run,
                    ts_ns,
                    kind,
                    actor,
                    json.dumps(body),
                    prev_hash,
                    event_hash,
                ),
            )
            conn.commit()

            return Event(
                seq=next_seq,
                run=run,
                ts_ns=ts_ns,
                kind=kind,
                actor=actor,
                body=body,
                prev=prev_hash,
                hash=event_hash,
            )

    def get_events(self, after_seq: int = 0) -> list[Event]:
        """Retrieve all events with seq > after_seq, in ascending order."""
        events: list[Event] = []
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT seq, run, ts_ns, kind, actor, body, prev, hash
                FROM events WHERE seq > ? ORDER BY seq ASC
                """,
                (after_seq,),
            )
            for row in cursor.fetchall():
                events.append(
                    Event(
                        seq=row[0],
                        run=row[1],
                        ts_ns=row[2],
                        kind=row[3],
                        actor=row[4],
                        body=json.loads(row[5]),
                        prev=row[6],
                        hash=row[7],
                    )
                )
        return events

    def count_events(self) -> int:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM events")
            return cursor.fetchone()[0]

    def verify_chain(self) -> tuple[bool, str]:
        """Verify the cryptographic hash-chain across all stored events."""
        events = self.get_events()
        if not events:
            return True, "Empty chain"

        expected_prev = GENESIS_PREV_HASH
        for i, ev in enumerate(events, start=1):
            if ev.seq != i:
                return False, f"Event sequence discontinuity at seq {ev.seq} (expected {i})"
            if ev.prev != expected_prev:
                return False, f"Chain broken at seq {ev.seq}: prev does not match previous hash"
            computed_hash = Event.compute_hash(
                seq=ev.seq,
                run=ev.run,
                ts_ns=ev.ts_ns,
                kind=ev.kind,
                actor=ev.actor,
                body=ev.body,
                prev=ev.prev,
            )
            if computed_hash != ev.hash:
                return (
                    False,
                    f"Hash mismatch at seq {ev.seq}: "
                    f"recorded {ev.hash} != computed {computed_hash}",
                )
            expected_prev = ev.hash

        return True, "Chain valid"

    def get_event_hashes_bytes(self) -> list[bytes]:
        """Return list of 32-byte event hashes for Merkle leaf computation."""
        events = self.get_events()
        return [bytes.fromhex(ev.hash) for ev in events]

    def compute_merkle_root_hex(self) -> str:
        """Compute Merkle root over all current events."""
        leaves = self.get_event_hashes_bytes()
        return compute_root_hex(leaves)

    def create_checkpoint(
        self,
        run: str,
        private_key: ed25519.Ed25519PrivateKey,
        ts_ns: int,
        key_id: str | None = None,
    ) -> SignedCheckpoint:
        """Create and sign a Merkle checkpoint at the current tree size."""
        tree_size = self.count_events()
        root_hex = self.compute_merkle_root_hex()

        actual_key_id = key_id or compute_key_id(private_key.public_key())

        with self._get_connection() as conn:
            cursor = conn.execute("SELECT root FROM checkpoints ORDER BY tree_size DESC LIMIT 1")
            row = cursor.fetchone()
            prev_cp_hash = GENESIS_PREV_HASH if row is None else row[0]

        cp = Checkpoint(
            run=run,
            tree_size=tree_size,
            root=root_hex,
            prev_checkpoint_hash=prev_cp_hash,
            ts_ns=ts_ns,
            key_id=actual_key_id,
        )

        cp_bytes = canonical_json_bytes(cp.canonical_dict())
        sig = sign_data(private_key, cp_bytes).hex()

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO checkpoints (
                    tree_size, run, root, prev_checkpoint_hash, ts_ns, key_id, signature
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (tree_size, run, root_hex, prev_cp_hash, ts_ns, actual_key_id, sig),
            )
            conn.commit()

        return SignedCheckpoint(checkpoint=cp, signature=sig)

    def get_latest_checkpoint(self) -> SignedCheckpoint | None:
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT tree_size, run, root, prev_checkpoint_hash, ts_ns, key_id, signature
                FROM checkpoints ORDER BY tree_size DESC LIMIT 1
                """
            )
            row = cursor.fetchone()
            if not row:
                return None
            cp = Checkpoint(
                tree_size=row[0],
                run=row[1],
                root=row[2],
                prev_checkpoint_hash=row[3],
                ts_ns=row[4],
                key_id=row[5],
            )
            return SignedCheckpoint(checkpoint=cp, signature=row[6])
