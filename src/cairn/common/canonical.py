"""Canonical JSON serialization per DEC-19.

DEC-19 rules:
- Signed bodies contain no floats (integers only: ts_ns, *_ms, *_us).
- Keys sorted lexicographically at all nesting levels.
- Strict separators: (',', ':') with zero whitespace.
- UTF-8 encoding without BOM.
"""

from __future__ import annotations

import json
from typing import Any

from cairn.common.errors import CanonicalizationError


def _check_no_floats(obj: Any) -> None:
    """Recursively verify that no float values exist in obj."""
    if isinstance(obj, float):
        raise CanonicalizationError(
            f"Floats are forbidden in signed CAIRN structures per DEC-19, got float: {obj}"
        )
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CanonicalizationError(
                    f"Dict keys must be strings, got {type(k).__name__}: {k}"
                )
            _check_no_floats(v)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _check_no_floats(item)


def canonical_json(obj: Any) -> str:
    """Serialize obj into canonical JSON string.

    Raises CanonicalizationError if any float is encountered.
    """
    _check_no_floats(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize obj into canonical JSON UTF-8 encoded bytes."""
    return canonical_json(obj).encode("utf-8")
