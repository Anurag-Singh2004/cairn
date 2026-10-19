"""Time abstraction for CAIRN.

Enables deterministic testing by allowing tests to inject a FakeClock.
All times are stored as integers (nanoseconds, milliseconds) per DEC-19.
"""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    """Protocol for time sources."""

    def now_ns(self) -> int:
        """Return current timestamp in nanoseconds since epoch."""
        ...

    def now_ms(self) -> int:
        """Return current timestamp in milliseconds since epoch."""
        ...


class WallClock:
    """Production clock using system time."""

    def now_ns(self) -> int:
        return time.time_ns()

    def now_ms(self) -> int:
        return time.time_ns() // 1_000_000


class FakeClock:
    """Deterministic clock for testing."""

    def __init__(self, start_ns: int = 1_760_000_000_000_000_000) -> None:
        self._current_ns = start_ns

    def now_ns(self) -> int:
        return self._current_ns

    def now_ms(self) -> int:
        return self._current_ns // 1_000_000

    def advance_ns(self, delta_ns: int) -> None:
        if delta_ns < 0:
            raise ValueError("Time cannot travel backwards")
        self._current_ns += delta_ns

    def advance_ms(self, delta_ms: int) -> None:
        self.advance_ns(delta_ms * 1_000_000)
