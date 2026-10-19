"""Identifier generation for CAIRN runs, sessions, and findings."""

from __future__ import annotations

import datetime
import secrets


def make_run_id(timestamp: datetime.datetime | None = None) -> str:
    """Generate a run ID like 'r_20261021_ab12'."""
    ts = timestamp or datetime.datetime.now(datetime.UTC)
    date_str = ts.strftime("%Y%m%d")
    suffix = secrets.token_hex(2)
    return f"r_{date_str}_{suffix}"


def make_session_id() -> str:
    """Generate a session ID like 's_1a2b3c4d'."""
    return f"s_{secrets.token_hex(4)}"


def make_finding_id(seq: int) -> str:
    """Generate a 1-indexed finding ID like 'f_001'."""
    return f"f_{seq:03d}"
