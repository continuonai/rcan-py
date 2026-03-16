"""
rcan.consent — Consent Wire Protocol (GAP-05).

Defines the on-wire consent message types for RCAN v1.5. Provides
dataclasses for consent request/grant/deny payloads and helper functions
to build properly formatted RCANMessage instances.

Message types:
    CONSENT_REQUEST  = 20
    CONSENT_GRANT    = 21
    CONSENT_DENY     = 22

Spec: §11.2 — Consent Wire Protocol
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from rcan.exceptions import ConsentError, RCANValidationError

logger = logging.getLogger(__name__)


@dataclass
class ConsentRequestPayload:
    """Payload for CONSENT_REQUEST (MessageType 20).

    Attributes:
        target_rrn:       RRN of the robot being requested access to.
        requester_rrn:    RRN of the robot requesting access.
        requested_scopes: List of scopes being requested (e.g. ``["teleop", "status"]``).
        reason:           Human-readable justification for the request.
        expires_at:       Unix timestamp after which this request expires.
        request_id:       Unique identifier for this consent request.
        consent_type:     Type of consent: ``"cross_robot"``, ``"training_data"``, ``"observer"``.
        data_categories:  Data categories for training consent (e.g. ``["video", "audio"]``).
    """

    target_rrn: str
    requester_rrn: str
    requested_scopes: list[str]
    reason: str
    expires_at: float
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    consent_type: str = "cross_robot"
    data_categories: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_rrn": self.target_rrn,
            "requester_rrn": self.requester_rrn,
            "requested_scopes": self.requested_scopes,
            "reason": self.reason,
            "expires_at": self.expires_at,
            "request_id": self.request_id,
            "consent_type": self.consent_type,
            "data_categories": self.data_categories,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConsentRequestPayload":
        return cls(
            target_rrn=data["target_rrn"],
            requester_rrn=data["requester_rrn"],
            requested_scopes=data.get("requested_scopes", []),
            reason=data.get("reason", ""),
            expires_at=data.get("expires_at", time.time() + 86400),
            request_id=data.get("request_id", str(uuid.uuid4())),
            consent_type=data.get("consent_type", "cross_robot"),
            data_categories=data.get("data_categories", []),
        )


@dataclass
class ConsentGrantPayload:
    """Payload for CONSENT_GRANT (MessageType 21).

    Attributes:
        request_id:     Echo of the originating ConsentRequest.request_id.
        granted_scopes: Scopes actually granted (may be subset of requested).
        expires_at:     Unix timestamp after which the grant expires.
        conditions:     Free-form conditions attached to the grant.
    """

    request_id: str
    granted_scopes: list[str]
    expires_at: float
    conditions: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "granted_scopes": self.granted_scopes,
            "expires_at": self.expires_at,
            "conditions": self.conditions,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConsentGrantPayload":
        return cls(
            request_id=data["request_id"],
            granted_scopes=data.get("granted_scopes", []),
            expires_at=data.get("expires_at", time.time() + 3600),
            conditions=data.get("conditions", {}),
        )


@dataclass
class ConsentDenyPayload:
    """Payload for CONSENT_DENY (MessageType 22).

    Attributes:
        request_id: Echo of the originating ConsentRequest.request_id.
        reason:     Human-readable reason for denial.
    """

    request_id: str
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConsentDenyPayload":
        return cls(
            request_id=data["request_id"],
            reason=data.get("reason", ""),
        )


# ---------------------------------------------------------------------------
# Builder helpers
# ---------------------------------------------------------------------------

def make_consent_request(
    target_rrn: str,
    requester_rrn: str,
    requested_scopes: list[str],
    reason: str,
    duration_hours: float = 24.0,
    consent_type: str = "cross_robot",
    data_categories: Optional[list[str]] = None,
    target_uri: str = "rcan://rcan.dev/system/consent/v1/local",
) -> Any:
    """Build a CONSENT_REQUEST RCANMessage.

    Args:
        target_rrn:       RRN of the robot being requested access to.
        requester_rrn:    RRN of the robot making the request.
        requested_scopes: Scopes being requested.
        reason:           Justification for access.
        duration_hours:   How long consent is requested for.
        consent_type:     ``"cross_robot"``, ``"training_data"``, or ``"observer"``.
        data_categories:  Data categories (for training_data consent).
        target_uri:       RCAN URI to send the request to.

    Returns:
        :class:`~rcan.message.RCANMessage` of type CONSENT_REQUEST.
    """
    from rcan.message import RCANMessage

    payload = ConsentRequestPayload(
        target_rrn=target_rrn,
        requester_rrn=requester_rrn,
        requested_scopes=requested_scopes,
        reason=reason,
        expires_at=time.time() + (duration_hours * 3600),
        consent_type=consent_type,
        data_categories=data_categories or [],
    )
    return RCANMessage(
        cmd="CONSENT_REQUEST",
        target=target_uri,
        params=payload.to_dict(),
    )


def make_consent_grant(
    request_id: str,
    granted_scopes: list[str],
    duration_hours: float = 24.0,
    conditions: Optional[dict[str, Any]] = None,
    target_uri: str = "rcan://rcan.dev/system/consent/v1/local",
) -> Any:
    """Build a CONSENT_GRANT RCANMessage.

    Args:
        request_id:     ID from the originating consent request.
        granted_scopes: Scopes being granted.
        duration_hours: How long this grant is valid.
        conditions:     Additional conditions on the grant.
        target_uri:     Where to send the grant.

    Returns:
        :class:`~rcan.message.RCANMessage` of type CONSENT_GRANT.
    """
    from rcan.message import RCANMessage

    payload = ConsentGrantPayload(
        request_id=request_id,
        granted_scopes=granted_scopes,
        expires_at=time.time() + (duration_hours * 3600),
        conditions=conditions or {},
    )
    return RCANMessage(
        cmd="CONSENT_GRANT",
        target=target_uri,
        params=payload.to_dict(),
    )


def make_consent_deny(
    request_id: str,
    reason: str = "",
    target_uri: str = "rcan://rcan.dev/system/consent/v1/local",
) -> Any:
    """Build a CONSENT_DENY RCANMessage.

    Args:
        request_id: ID from the originating consent request.
        reason:     Human-readable reason for denial.
        target_uri: Where to send the denial.

    Returns:
        :class:`~rcan.message.RCANMessage` of type CONSENT_DENY.
    """
    from rcan.message import RCANMessage

    payload = ConsentDenyPayload(request_id=request_id, reason=reason)
    return RCANMessage(
        cmd="CONSENT_DENY",
        target=target_uri,
        params=payload.to_dict(),
    )


def validate_consent_message(msg: Any) -> tuple[bool, str]:
    """Validate a CONSENT_REQUEST, CONSENT_GRANT, or CONSENT_DENY message.

    Args:
        msg: :class:`~rcan.message.RCANMessage` to validate.

    Returns:
        ``(valid: bool, reason: str)`` — reason empty if valid.
    """
    cmd = getattr(msg, "cmd", "")
    params = getattr(msg, "params", {})

    if cmd == "CONSENT_REQUEST":
        if not params.get("target_rrn"):
            return False, "CONSENT_REQUEST missing 'target_rrn'"
        if not params.get("requester_rrn"):
            return False, "CONSENT_REQUEST missing 'requester_rrn'"
        if not params.get("requested_scopes"):
            return False, "CONSENT_REQUEST missing 'requested_scopes'"
        if not params.get("reason"):
            return False, "CONSENT_REQUEST missing 'reason'"
        expires_at = params.get("expires_at", 0)
        if expires_at < time.time():
            return False, "CONSENT_REQUEST has already expired"
        return True, ""

    elif cmd in ("CONSENT_GRANT", "CONSENT_DENY"):
        if not params.get("request_id"):
            return False, f"{cmd} missing 'request_id'"
        if cmd == "CONSENT_GRANT":
            if not params.get("granted_scopes"):
                return False, "CONSENT_GRANT missing 'granted_scopes'"
            expires_at = params.get("expires_at", 0)
            if expires_at < time.time():
                return False, "CONSENT_GRANT has already expired"
        return True, ""

    else:
        return False, f"Unknown consent command: {cmd!r}"


from typing import Optional  # noqa: E402 — needed for type hints above

__all__ = [
    "ConsentRequestPayload",
    "ConsentGrantPayload",
    "ConsentDenyPayload",
    "make_consent_request",
    "make_consent_grant",
    "make_consent_deny",
    "validate_consent_message",
]
