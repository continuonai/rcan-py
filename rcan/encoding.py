"""rcan.encoding — Canonical JSON serialization for RCAN wire formats.

This module provides the deterministic JSON serializer used by hybrid
signing (rcan.hybrid) and by any downstream consumer that needs
byte-stable output (e.g., content hashing, cross-language verification).

Invariants (pinned by rcan-spec/fixtures/canonical-json-v1.json):
    - Keys sorted lexicographically at every nesting level
    - No whitespace anywhere in the output
    - Non-ASCII Unicode emitted as raw UTF-8 bytes (NOT \\uXXXX escapes)
    - Whole-number floats normalized to integers (50.0 emits as 50, not
      50.0). Recurses through arrays and nested dicts. JS's JSON.parse
      loses the int/float distinction, so cross-language parity requires
      Python emitters to drop trailing .0 from whole-number floats.
    - Empty object = {}, empty array = []
    - No trailing newline

Both rcan-py and rcan-ts MUST produce identical bytes for the same input.
The cross-language parity fixture is the authoritative test vector.
"""

from __future__ import annotations

import json
from typing import Any

__all__ = ["canonical_json"]


def _normalize_for_canonical(v: Any) -> Any:
    # bool is a subclass of int (not float), so it doesn't hit the float
    # branch — but the explicit early-return defends against refactors.
    if isinstance(v, bool):
        return v
    if isinstance(v, float) and v.is_integer():
        return int(v)
    if isinstance(v, dict):
        return {k: _normalize_for_canonical(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_normalize_for_canonical(x) for x in v]
    return v


def canonical_json(body: dict[str, Any]) -> bytes:
    """Return the canonical UTF-8 bytes of ``body``.

    Deterministic: calling this twice on equivalent inputs yields identical
    bytes. Used as the pre-image for hybrid signing in :mod:`rcan.hybrid`
    and as the serialization spine for cross-language wire-format parity.

    Whole-number floats are normalized to integers before serialization to
    match rcan-ts (which inherits this from JS's JSON.parse coercion).
    Without this normalization, a body containing ``50.0`` signs as
    ``{"x":50.0}`` in Python but verifies against ``{"x":50}`` in TS.

    Args:
        body: A dict serializable by :func:`json.dumps`. Keys MUST be strings.

    Returns:
        Bytes (UTF-8 encoded).

    Example:
        >>> canonical_json({"b": 1, "a": 2})
        b'{"a":2,"b":1}'
        >>> canonical_json({"x": 50.0})
        b'{"x":50}'
    """
    return json.dumps(
        _normalize_for_canonical(body),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
