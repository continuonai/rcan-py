"""
rcan.training_consent — Training Data Consent (GAP-10).

Implements the consent framework for biometric and training data collection
required by GDPR Article 9 and EU AI Act Annex III §5.

Spec: §17 — Biometric and Training Data Consent
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)

# EU AI Act Article reference for training data consent
EU_AI_ACT_ARTICLE = "Annex III §5"


class DataCategory(str, Enum):
    """Categories of training data requiring explicit consent.

    Per GDPR Article 9 and EU AI Act Annex III §5.
    """

    VIDEO = "video"
    AUDIO = "audio"
    LOCATION = "location"
    BIOMETRIC = "biometric"
    TELEMETRY = "telemetry"


@dataclass
class TrainingConsentRequest:
    """Training data consent request payload.

    Attributes:
        data_categories:   Categories of data to be collected.
        purpose:           Human-readable purpose statement.
        retention_days:    How long data will be retained.
        eu_ai_act_article: EU AI Act article reference.
        request_id:        Unique identifier for this consent request.
        subject_id:        Identity of the data subject (if known).
        expires_at:        When this consent request expires.
    """

    data_categories: list[DataCategory]
    purpose: str
    retention_days: int = 90
    eu_ai_act_article: str = EU_AI_ACT_ARTICLE
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    subject_id: Optional[str] = None
    expires_at: float = field(default_factory=lambda: time.time() + 86400)

    def to_dict(self) -> dict[str, Any]:
        return {
            "data_categories": [c.value for c in self.data_categories],
            "purpose": self.purpose,
            "retention_days": self.retention_days,
            "eu_ai_act_article": self.eu_ai_act_article,
            "request_id": self.request_id,
            "subject_id": self.subject_id,
            "expires_at": self.expires_at,
            "consent_type": "training_data",
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TrainingConsentRequest":
        cats = []
        for c in data.get("data_categories", []):
            try:
                cats.append(DataCategory(c))
            except ValueError:
                logger.warning("Unknown data category: %r", c)
        return cls(
            data_categories=cats,
            purpose=data.get("purpose", ""),
            retention_days=data.get("retention_days", 90),
            eu_ai_act_article=data.get("eu_ai_act_article", EU_AI_ACT_ARTICLE),
            request_id=data.get("request_id", str(uuid.uuid4())),
            subject_id=data.get("subject_id"),
            expires_at=data.get("expires_at", time.time() + 86400),
        )


def make_training_consent_request(
    categories: list[DataCategory | str],
    purpose: str,
    retention_days: int = 90,
    subject_id: Optional[str] = None,
    duration_hours: float = 24.0,
    target_uri: str = "rcan://rcan.dev/system/consent/v1/local",
) -> Any:
    """Build a TRAINING_CONSENT_REQUEST RCANMessage.

    Args:
        categories:     Data categories to be collected.
        purpose:        Human-readable purpose.
        retention_days: Data retention period.
        subject_id:     Data subject identity.
        duration_hours: How long the request is valid.
        target_uri:     Where to send the request.

    Returns:
        :class:`~rcan.message.RCANMessage` with TRAINING_CONSENT_REQUEST command.
    """
    from rcan.message import RCANMessage

    # Normalize string categories
    normalized = []
    for c in categories:
        if isinstance(c, str):
            try:
                normalized.append(DataCategory(c))
            except ValueError:
                raise ValueError(f"Unknown data category: {c!r}")
        else:
            normalized.append(c)

    payload = TrainingConsentRequest(
        data_categories=normalized,
        purpose=purpose,
        retention_days=retention_days,
        subject_id=subject_id,
        expires_at=time.time() + (duration_hours * 3600),
    )

    return RCANMessage(
        cmd="TRAINING_CONSENT_REQUEST",
        target=target_uri,
        params=payload.to_dict(),
    )


def make_training_consent_grant(
    request_id: str,
    granted_categories: list[DataCategory | str],
    retention_days: int = 90,
    duration_hours: float = 24.0,
    conditions: Optional[dict[str, Any]] = None,
    target_uri: str = "rcan://rcan.dev/system/consent/v1/local",
) -> Any:
    """Build a TRAINING_CONSENT_GRANT RCANMessage.

    Args:
        request_id:          ID from the originating consent request.
        granted_categories:  Categories actually granted.
        retention_days:      Agreed retention period.
        duration_hours:      How long this grant is valid.
        conditions:          Additional conditions.
        target_uri:          Where to send the grant.

    Returns:
        :class:`~rcan.message.RCANMessage` with TRAINING_CONSENT_GRANT command.
    """
    from rcan.message import RCANMessage

    normalized = []
    for c in granted_categories:
        if isinstance(c, str):
            try:
                normalized.append(DataCategory(c).value)
            except ValueError:
                normalized.append(c)
        else:
            normalized.append(c.value)

    return RCANMessage(
        cmd="TRAINING_CONSENT_GRANT",
        target=target_uri,
        params={
            "request_id": request_id,
            "granted_categories": normalized,
            "retention_days": retention_days,
            "expires_at": time.time() + (duration_hours * 3600),
            "conditions": conditions or {},
            "eu_ai_act_article": EU_AI_ACT_ARTICLE,
        },
    )


def make_training_consent_deny(
    request_id: str,
    reason: str = "",
    target_uri: str = "rcan://rcan.dev/system/consent/v1/local",
) -> Any:
    """Build a TRAINING_CONSENT_DENY RCANMessage.

    Args:
        request_id: ID from the originating consent request.
        reason:     Human-readable reason for denial.
        target_uri: Where to send the denial.

    Returns:
        :class:`~rcan.message.RCANMessage` with TRAINING_CONSENT_DENY command.
    """
    from rcan.message import RCANMessage

    return RCANMessage(
        cmd="TRAINING_CONSENT_DENY",
        target=target_uri,
        params={
            "request_id": request_id,
            "reason": reason,
        },
    )


__all__ = [
    "DataCategory",
    "TrainingConsentRequest",
    "make_training_consent_request",
    "make_training_consent_grant",
    "make_training_consent_deny",
    "EU_AI_ACT_ARTICLE",
]
