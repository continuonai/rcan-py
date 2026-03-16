"""Tests for rcan.revocation — Robot Identity Revocation (GAP-02)."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from rcan.revocation import (
    RevocationStatus,
    RevocationCache,
    check_revocation,
    make_revocation_broadcast,
)
from rcan.message import RCANMessage, MessageType


RRN = "RRN-000000000042"
REGISTRY = "https://rcan.dev"


class TestRevocationStatus:
    def test_active_status(self):
        status = RevocationStatus(rrn=RRN, status="active")
        assert status.is_active is True
        assert status.is_revoked is False
        assert status.is_suspended is False

    def test_revoked_status(self):
        status = RevocationStatus(rrn=RRN, status="revoked", revoked_at=time.time())
        assert status.is_revoked is True
        assert status.is_active is False

    def test_suspended_status(self):
        status = RevocationStatus(rrn=RRN, status="suspended")
        assert status.is_suspended is True

    def test_roundtrip(self):
        now = time.time()
        status = RevocationStatus(
            rrn=RRN,
            status="revoked",
            revoked_at=now,
            reason="Stolen",
            authority="rcan.dev",
        )
        restored = RevocationStatus.from_dict(status.to_dict())
        assert restored.rrn == RRN
        assert restored.status == "revoked"
        assert restored.reason == "Stolen"


class TestRevocationCache:
    def test_miss_returns_none(self):
        cache = RevocationCache()
        result = cache.get(RRN)
        assert result is None

    def test_set_and_get(self):
        cache = RevocationCache()
        status = RevocationStatus(rrn=RRN, status="active")
        cache.set(status)
        result = cache.get(RRN)
        assert result is not None
        assert result.rrn == RRN

    def test_invalidate(self):
        cache = RevocationCache()
        cache.set(RevocationStatus(rrn=RRN, status="active"))
        cache.invalidate(RRN)
        assert cache.get(RRN) is None

    def test_ttl_expiry(self):
        cache = RevocationCache(ttl_s=0.01)  # 10ms TTL
        cache.set(RevocationStatus(rrn=RRN, status="active"))
        time.sleep(0.05)  # wait for TTL to expire
        assert cache.get(RRN) is None

    def test_size(self):
        cache = RevocationCache()
        cache.set(RevocationStatus(rrn="RRN-000000000001", status="active"))
        cache.set(RevocationStatus(rrn="RRN-000000000002", status="active"))
        assert cache.size() == 2


class TestCheckRevocation:
    def test_returns_active_when_unreachable(self):
        """When registry is unreachable, should assume active (fail open)."""
        with patch("urllib.request.urlopen", side_effect=ConnectionError("offline")):
            status = check_revocation(RRN, REGISTRY)
            assert isinstance(status, RevocationStatus)
            assert status.rrn == RRN
            assert status.status == "active"

    def test_parses_revoked_response(self):
        """Should parse a revoked response from the registry."""
        import json
        from unittest.mock import MagicMock

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "status": "revoked",
            "revoked_at": time.time(),
            "reason": "Stolen",
            "authority": "rcan.dev",
        }).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            status = check_revocation(RRN, REGISTRY)
            assert status.status == "revoked"
            assert status.reason == "Stolen"


class TestMakeRevocationBroadcast:
    def test_returns_rcan_message(self):
        msg = make_revocation_broadcast(RRN, reason="Stolen")
        assert isinstance(msg, RCANMessage)
        assert msg.cmd == "ROBOT_REVOCATION"

    def test_rrn_in_params(self):
        msg = make_revocation_broadcast(RRN, reason="Decommissioned")
        assert msg.params["rrn"] == RRN
        assert msg.params["status"] == "revoked"
        assert msg.params["reason"] == "Decommissioned"

    def test_robot_revocation_message_type(self):
        assert MessageType.ROBOT_REVOCATION == 19
