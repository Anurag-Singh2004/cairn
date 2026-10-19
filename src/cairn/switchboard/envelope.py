"""Uniform response envelope and body padding per context.md §8.2 and DEC-13.

All tenant responses follow the uniform envelope:
{"v": 1, "body": "<text padded with spaces to a bucket>", "bucket": <int>}

Every non-allowed outcome (blue block, model refusal, timeout, error)
normalizes to refusal_text before padding.
"""

from __future__ import annotations

DEFAULT_BUCKETS = [128, 256, 512, 1024]
DEFAULT_REFUSAL = "I can't help with that."


def pad_to_bucket(
    text: str,
    buckets: list[int] | None = None,
) -> tuple[str, int]:
    """Pad text with spaces to the smallest bucket that accommodates it.

    Returns (padded_text, bucket_size).
    """
    sorted_buckets = sorted(buckets or DEFAULT_BUCKETS)
    length = len(text)

    chosen_bucket = None
    for b in sorted_buckets:
        if length <= b:
            chosen_bucket = b
            break

    if chosen_bucket is None:
        # If longer than largest bucket, pad to next multiple of largest bucket
        max_b = sorted_buckets[-1]
        chosen_bucket = ((length + max_b - 1) // max_b) * max_b

    padded = text.ljust(chosen_bucket)
    return padded, chosen_bucket


def make_envelope(
    body: str,
    buckets: list[int] | None = None,
) -> dict[str, int | str]:
    """Create uniform envelope dictionary."""
    padded, bucket = pad_to_bucket(body, buckets)
    return {
        "v": 1,
        "body": padded,
        "bucket": bucket,
    }
