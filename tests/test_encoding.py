"""Tests for rcan.encoding — canonical JSON serialization."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from rcan.encoding import canonical_json


FIXTURE = Path(__file__).parent / "fixtures" / "canonical-json-v1.json"


def test_canonical_json_matches_fixture():
    """CRITICAL: rcan-py's canonical_json bytes MUST match the shared fixture exactly.

    If this test fails, either (a) the fixture was regenerated with different
    semantics, or (b) rcan-py drifted. Investigate immediately; do not edit
    the fixture or the test.
    """
    fixture = json.loads(FIXTURE.read_text())
    assert fixture["format"] == "rcan-canonical-json-v1"
    for case in fixture["cases"]:
        actual = canonical_json(case["input"])
        expected = base64.b64decode(case["expected_bytes_base64"])
        assert actual == expected, (
            f"canonical_json drift on case {case['name']!r}:\n"
            f"  expected: {expected!r}\n"
            f"  actual:   {actual!r}"
        )


def test_canonical_json_key_order():
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_canonical_json_no_whitespace():
    assert canonical_json({"a": [1, 2, 3]}) == b'{"a":[1,2,3]}'


def test_canonical_json_unicode_raw_utf8():
    """Non-ASCII MUST be emitted as raw UTF-8 bytes, not \\uXXXX escape sequences."""
    out = canonical_json({"name": "Café"})
    assert out == '{"name":"Café"}'.encode("utf-8")
    assert b"\\u" not in out


def test_canonical_json_nested_sort():
    """Key ordering applies at every nesting level."""
    assert canonical_json({"z": {"b": 2, "a": 1}}) == b'{"z":{"a":1,"b":2}}'


def test_canonical_json_empty_containers():
    assert canonical_json({"a": {}, "b": []}) == b'{"a":{},"b":[]}'


def test_canonical_json_returns_bytes():
    """Return type MUST be bytes, not str — downstream hashes/signs it directly."""
    result = canonical_json({"a": 1})
    assert isinstance(result, bytes)
