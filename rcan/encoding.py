"""rcan.encoding — Canonical JSON serialization for RCAN wire formats.

This module provides the deterministic JSON serializer used by hybrid
signing (rcan.hybrid) and by any downstream consumer that needs
byte-stable output (e.g., content hashing, cross-language verification).

Invariants (pinned by rcan-spec/fixtures/canonical-json-v1.json):
    - Keys sorted lexicographically at every nesting level
    - No whitespace anywhere in the output
    - Non-ASCII Unicode emitted as raw UTF-8 bytes (NOT \\uXXXX escapes)
    - Integers emit without trailing .0
    - Empty object = {}, empty array = []
    - No trailing newline

Both rcan-py and rcan-ts MUST produce identical bytes for the same input.
The cross-language parity fixture is the authoritative test vector.
"""

from __future__ import annotations

import json
from typing import Any

__all__ = ["canonical_json"]


def canonical_json(body: dict[str, Any]) -> bytes:
    """Return the canonical UTF-8 bytes of ``body``.

    Deterministic: calling this twice on equivalent inputs yields identical
    bytes. Used as the pre-image for hybrid signing in :mod:`rcan.hybrid`
    and as the serialization spine for cross-language wire-format parity.

    Args:
        body: A dict serializable by :func:`json.dumps`. Keys MUST be strings.

    Returns:
        Bytes (UTF-8 encoded).

    Example:
        >>> canonical_json({"b": 1, "a": 2})
        b'{"a":2,"b":1}'
    """
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
