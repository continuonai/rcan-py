"""Tests for rcan.consent — Consent Wire Protocol (GAP-05)."""

from __future__ import annotations

import time

import pytest

from rcan.consent import (
    ConsentRequestPayload,
    ConsentGrantPayload,
    ConsentDenyPayload,
    make_consent_request,
    make_consent_grant,
    make_consent_deny,
    validate_consent_message,
)
from rcan.message import RCANMessage, MessageType

TARGET_RRN = "RRN-000000000001"
REQUESTER_RRN = "RRN-000000000002"


class TestConsentRequestPayload:
    def test_construction(self):
        payload = ConsentRequestPayload(
            target_rrn=TARGET_RRN,
            requester_rrn=REQUESTER_RRN,
            requested_scopes=["teleop", "status"],
            reason="Integration test",
            expires_at=time.time() + 3600,
        )
        assert payload.target_rrn == TARGET_RRN
        assert "teleop" in payload.requested_scopes

    def test_roundtrip(self):
        payload = ConsentRequestPayload(
            target_rrn=TARGET_RRN,
            requester_rrn=REQUESTER_RRN,
            requested_scopes=["teleop"],
            reason="Test",
            expires_at=time.time() + 3600,
        )
        restored = ConsentRequestPayload.from_dict(payload.to_dict())
        assert restored.target_rrn == payload.target_rrn
        assert restored.request_id == payload.request_id


class TestConsentGrantPayload:
    def test_construction(self):
        payload = ConsentGrantPayload(
            request_id="req-001",
            granted_scopes=["teleop"],
            expires_at=time.time() + 3600,
        )
        assert payload.request_id == "req-001"

    def test_roundtrip(self):
        payload = ConsentGrantPayload(
            request_id="req-001",
            granted_scopes=["teleop", "status"],
            expires_at=time.time() + 3600,
            conditions={"max_speed": 0.5},
        )
        restored = ConsentGrantPayload.from_dict(payload.to_dict())
        assert restored.conditions == {"max_speed": 0.5}


class TestConsentDenyPayload:
    def test_construction(self):
        payload = ConsentDenyPayload(request_id="req-001", reason="Access denied")
        assert payload.reason == "Access denied"

    def test_roundtrip(self):
        payload = ConsentDenyPayload(request_id="req-002")
        restored = ConsentDenyPayload.from_dict(payload.to_dict())
        assert restored.request_id == "req-002"


class TestMakeConsentRequest:
    def test_returns_rcan_message(self):
        msg = make_consent_request(
            target_rrn=TARGET_RRN,
            requester_rrn=REQUESTER_RRN,
            requested_scopes=["teleop"],
            reason="Test",
        )
        assert isinstance(msg, RCANMessage)
        assert msg.cmd == "CONSENT_REQUEST"

    def test_payload_fields(self):
        msg = make_consent_request(
            target_rrn=TARGET_RRN,
            requester_rrn=REQUESTER_RRN,
            requested_scopes=["teleop"],
            reason="Integration test",
            duration_hours=2.0,
        )
        assert msg.params["target_rrn"] == TARGET_RRN
        assert msg.params["requester_rrn"] == REQUESTER_RRN
        assert msg.params["expires_at"] > time.time()


class TestMakeConsentGrant:
    def test_returns_rcan_message(self):
        msg = make_consent_grant(
            request_id="req-001",
            granted_scopes=["teleop"],
        )
        assert isinstance(msg, RCANMessage)
        assert msg.cmd == "CONSENT_GRANT"

    def test_scopes_set(self):
        msg = make_consent_grant(
            request_id="req-001",
            granted_scopes=["teleop", "status"],
        )
        assert msg.params["granted_scopes"] == ["teleop", "status"]


class TestMakeConsentDeny:
    def test_returns_rcan_message(self):
        msg = make_consent_deny(request_id="req-001", reason="Not authorized")
        assert isinstance(msg, RCANMessage)
        assert msg.cmd == "CONSENT_DENY"

    def test_reason_set(self):
        msg = make_consent_deny(request_id="req-001", reason="Not authorized")
        assert msg.params["reason"] == "Not authorized"


class TestValidateConsentMessage:
    def test_valid_request(self):
        msg = make_consent_request(
            target_rrn=TARGET_RRN,
            requester_rrn=REQUESTER_RRN,
            requested_scopes=["teleop"],
            reason="Test",
        )
        valid, reason = validate_consent_message(msg)
        assert valid is True

    def test_valid_grant(self):
        msg = make_consent_grant(request_id="req-001", granted_scopes=["teleop"])
        valid, reason = validate_consent_message(msg)
        assert valid is True

    def test_valid_deny(self):
        msg = make_consent_deny(request_id="req-001")
        valid, reason = validate_consent_message(msg)
        assert valid is True

    def test_request_missing_target_rrn(self):
        msg = make_consent_request(
            target_rrn=TARGET_RRN,
            requester_rrn=REQUESTER_RRN,
            requested_scopes=["teleop"],
            reason="Test",
        )
        msg.params.pop("target_rrn")
        valid, reason = validate_consent_message(msg)
        assert valid is False
        assert "target_rrn" in reason

    def test_expired_request_invalid(self):
        msg = make_consent_request(
            target_rrn=TARGET_RRN,
            requester_rrn=REQUESTER_RRN,
            requested_scopes=["teleop"],
            reason="Test",
        )
        msg.params["expires_at"] = time.time() - 1  # expired
        valid, reason = validate_consent_message(msg)
        assert valid is False

    def test_unknown_cmd_invalid(self):
        from rcan.message import RCANMessage
        msg = RCANMessage(cmd="CONSENT_UNKNOWN", target="rcan://rcan.dev/system/consent/v1/local")
        valid, reason = validate_consent_message(msg)
        assert valid is False


class TestConsentMessageTypes:
    def test_consent_request_type_value(self):
        assert MessageType.CONSENT_REQUEST == 20

    def test_consent_grant_type_value(self):
        assert MessageType.CONSENT_GRANT == 21

    def test_consent_deny_type_value(self):
        assert MessageType.CONSENT_DENY == 22
