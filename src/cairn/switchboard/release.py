"""Time-quantized response release logic per context.md §8.2.

Release rule:
- Response is released at Δ * ceil(proc_ms / Δ) after receipt.
- If proc_ms exceeds request_deadline_ms, release generic refusal at deadline and flag timeout.
"""

from __future__ import annotations


def calculate_release_time_ms(
    proc_ms: int,
    quantise_ms: int = 250,
    deadline_ms: int = 2000,
) -> tuple[int, bool]:
    """Calculate quantized release time in milliseconds.

    Returns:
        (release_ms, is_timeout)
    """
    if proc_ms > deadline_ms:
        return deadline_ms, True

    if quantise_ms <= 0:
        return proc_ms, False

    # ceil(proc_ms / quantise_ms) * quantise_ms
    steps = (proc_ms + quantise_ms - 1) // quantise_ms
    release_ms = max(quantise_ms, steps * quantise_ms)

    if release_ms > deadline_ms:
        return deadline_ms, True

    return release_ms, False
