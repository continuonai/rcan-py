"""Tests for RCAN v2.2 envelope types — DelegationHop, MediaChunk, and
RCANMessage delegation_chain depth validation.

Issue: #45
"""

from __future__ import annotations

import hashlib

import pytest

from rcan.envelope import DelegationHop, MediaChunk
from rcan.message import RCANMessage

# ---------------------------------------------------------------------------
# DelegationHop
# ---------------------------------------------------------------------------


def test_delegation_hop_creates_ok() -> None:
    hop = DelegationHop(
        robot_rrn="rcan://registry.rcan.dev/acme/arm/v1/unit-001",
        scope="operator",
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2026-01-02T00:00:00Z",
    )
    assert hop.robot_rrn == "rcan://registry.rcan.dev/acme/arm/v1/unit-001"
    assert hop.scope == "operator"
    assert hop.issued_at == "2026-01-01T00:00:00Z"
    assert hop.expires_at == "2026-01-02T00:00:00Z"
    assert hop.sig == ""


# ---------------------------------------------------------------------------
# MediaChunk.verify_hash
# ---------------------------------------------------------------------------


def test_media_chunk_verify_hash_ok() -> None:
    data = "hello world"
    correct_hash = "sha256:" + hashlib.sha256(data.encode()).hexdigest()
    chunk = MediaChunk(
        chunk_id="chunk-1",
        mime_type="text/plain",
        size_bytes=len(data.encode()),
        hash_sha256=correct_hash,
        data=data,
    )
    # Should not raise
    chunk.verify_hash()


def test_media_chunk_verify_hash_fail() -> None:
    chunk = MediaChunk(
        chunk_id="chunk-2",
        mime_type="text/plain",
        size_bytes=5,
        hash_sha256="sha256:deadbeef",
        data="hello",
    )
    with pytest.raises(ValueError, match="hash mismatch"):
        chunk.verify_hash()


# ---------------------------------------------------------------------------
# RCANMessage — delegation_chain max depth
# ---------------------------------------------------------------------------


def _make_hop(n: int) -> dict:
    return {
        "robot_rrn": f"rcan://rrf.rcan.dev/test/bot/v1/unit-{n:03d}",
        "scope": "operator",
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-12-31T23:59:59Z",
    }


def test_delegation_chain_max_depth_raises() -> None:
    four_hops = [_make_hop(i) for i in range(4)]
    with pytest.raises(ValueError, match="delegation chain max depth is 3"):
        RCANMessage(
            cmd="move",
            target="rcan://registry.rcan.dev/acme/arm/v1/unit-001",
            delegation_chain=four_hops,
        )


def test_delegation_chain_three_hops_ok() -> None:
    three_hops = [_make_hop(i) for i in range(3)]
    msg = RCANMessage(
        cmd="move",
        target="rcan://registry.rcan.dev/acme/arm/v1/unit-001",
        delegation_chain=three_hops,
    )
    assert len(msg.delegation_chain) == 3


# ---------------------------------------------------------------------------
# RCANMessage — new v2.2 fields have defaults
# ---------------------------------------------------------------------------


def test_new_fields_have_defaults() -> None:
    msg = RCANMessage(
        cmd="ping",
        target="rcan://registry.rcan.dev/acme/arm/v1/unit-001",
    )
    assert msg.firmware_hash is None
    assert msg.attestation_ref is None
    assert msg.pq_sig == ""
    assert msg.pq_alg == "ml-dsa-65"
    assert msg.delegation_chain == []
    assert msg.media_chunks == []
