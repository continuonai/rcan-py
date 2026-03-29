"""Tests for rcan.training_consent — Training Data Consent (GAP-10)."""

from __future__ import annotations

import time

import pytest

from rcan.message import MessageType, RCANMessage
from rcan.training_consent import (
    EU_AI_ACT_ARTICLE,
    DataCategory,
    TrainingConsentRequest,
    make_training_consent_deny,
    make_training_consent_grant,
    make_training_consent_request,
)


class TestDataCategory:
    def test_values(self):
        assert DataCategory.VIDEO == "video"
        assert DataCategory.AUDIO == "audio"
        assert DataCategory.LOCATION == "location"
        assert DataCategory.BIOMETRIC == "biometric"
        assert DataCategory.TELEMETRY == "telemetry"

    def test_from_string(self):
        assert DataCategory("video") == DataCategory.VIDEO


class TestTrainingConsentRequest:
    def test_construction(self):
        req = TrainingConsentRequest(
            data_categories=[DataCategory.VIDEO, DataCategory.AUDIO],
            purpose="Model training for navigation",
            retention_days=90,
        )
        assert DataCategory.VIDEO in req.data_categories
        assert req.eu_ai_act_article == EU_AI_ACT_ARTICLE

    def test_roundtrip(self):
        req = TrainingConsentRequest(
            data_categories=[DataCategory.BIOMETRIC],
            purpose="Face recognition training",
            retention_days=30,
        )
        restored = TrainingConsentRequest.from_dict(req.to_dict())
        assert restored.retention_days == 30
        assert DataCategory.BIOMETRIC in restored.data_categories

    def test_consent_type_is_training(self):
        req = TrainingConsentRequest(
            data_categories=[DataCategory.VIDEO],
            purpose="Test",
        )
        d = req.to_dict()
        assert d["consent_type"] == "training_data"


class TestMakeTrainingConsentRequest:
    def test_returns_rcan_message(self):
        msg = make_training_consent_request(
            categories=[DataCategory.VIDEO],
            purpose="Navigation model training",
        )
        assert isinstance(msg, RCANMessage)
        assert msg.cmd == "TRAINING_CONSENT_REQUEST"

    def test_string_category_normalized(self):
        msg = make_training_consent_request(
            categories=["video", "audio"],
            purpose="Test",
        )
        cats = msg.params["data_categories"]
        assert "video" in cats
        assert "audio" in cats

    def test_invalid_category_raises(self):
        with pytest.raises(ValueError):
            make_training_consent_request(
                categories=["not_a_category"],
                purpose="Test",
            )

    def test_retention_days_in_params(self):
        msg = make_training_consent_request(
            categories=[DataCategory.TELEMETRY],
            purpose="Fleet analytics",
            retention_days=30,
        )
        assert msg.params["retention_days"] == 30

    def test_expires_at_in_future(self):
        msg = make_training_consent_request(
            categories=[DataCategory.VIDEO],
            purpose="Test",
            duration_hours=24.0,
        )
        assert msg.params["expires_at"] > time.time()


class TestMakeTrainingConsentGrant:
    def test_returns_rcan_message(self):
        msg = make_training_consent_grant(
            request_id="req-001",
            granted_categories=[DataCategory.VIDEO],
        )
        assert isinstance(msg, RCANMessage)
        assert msg.cmd == "TRAINING_CONSENT_GRANT"

    def test_eu_ai_act_article_present(self):
        msg = make_training_consent_grant(
            request_id="req-001",
            granted_categories=[DataCategory.AUDIO],
        )
        assert msg.params["eu_ai_act_article"] == EU_AI_ACT_ARTICLE

    def test_string_categories_accepted(self):
        msg = make_training_consent_grant(
            request_id="req-001",
            granted_categories=["video"],
        )
        assert "video" in msg.params["granted_categories"]


class TestMakeTrainingConsentDeny:
    def test_returns_rcan_message(self):
        msg = make_training_consent_deny(request_id="req-001", reason="Privacy concern")
        assert isinstance(msg, RCANMessage)
        assert msg.cmd == "TRAINING_CONSENT_DENY"

    def test_reason_set(self):
        msg = make_training_consent_deny(request_id="req-001", reason="Not consenting")
        assert msg.params["reason"] == "Not consenting"


class TestTrainingConsentMessageTypes:
    def test_training_consent_request_type(self):
        assert MessageType.TRAINING_CONSENT_REQUEST == 30

    def test_training_consent_grant_type(self):
        assert MessageType.TRAINING_CONSENT_GRANT == 31

    def test_training_consent_deny_type(self):
        assert MessageType.TRAINING_CONSENT_DENY == 32
