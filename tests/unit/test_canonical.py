"""Unit tests for canonical JSON serialization per DEC-19."""

from __future__ import annotations

import pytest

from cairn.common.canonical import canonical_json, canonical_json_bytes
from cairn.common.errors import CanonicalizationError


def test_canonical_json_key_sorting() -> None:
    d1 = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
    d2 = {"a": 2, "m": {"a": 4, "b": 3}, "z": 1}
    assert canonical_json(d1) == canonical_json(d2)
    assert canonical_json(d1) == '{"a":2,"m":{"a":4,"b":3},"z":1}'


def test_canonical_json_separators_no_whitespace() -> None:
    data = {"hello": "world", "items": [1, 2, 3]}
    res = canonical_json(data)
    assert " " not in res
    assert res == '{"hello":"world","items":[1,2,3]}'


def test_canonical_json_rejects_floats() -> None:
    with pytest.raises(CanonicalizationError, match="Floats are forbidden"):
        canonical_json({"latency_ms": 12.5})

    with pytest.raises(CanonicalizationError, match="Floats are forbidden"):
        canonical_json([1, 2, 3.14])

    with pytest.raises(CanonicalizationError, match="Floats are forbidden"):
        canonical_json({"nested": {"val": 0.0}})


def test_canonical_json_utf8_bytes() -> None:
    data = {"msg": "cairn-test-ü"}
    b = canonical_json_bytes(data)
    assert isinstance(b, bytes)
    assert b == '{"msg":"cairn-test-ü"}'.encode()
