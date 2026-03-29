"""
rcan.safety — RCAN Safety Message helpers (MessageType 6).

RCAN MessageType 6 is the SAFETY message class (STOP / ESTOP / RESUME).
Safety messages bypass all queues and gates per RCAN §6 and have the
highest delivery priority in the protocol.

Spec: https://rcan.dev/spec#section-6

Quick start::

    from rcan.safety import (
        make_estop_message, is_safety_message, validate_safety_message
    )

    msg = make_estop_message(
        ruri="rcan://rcan.dev/boston-dynamics/spot/bd-spot-001a2b3c",
        reason="Obstacle detected in path",
    )
    assert is_safety_message(msg)
    assert validate_safety_message(msg) == []
"""

from __future__ import annotations

import time
import uuid
from typing import Any

__all__ = [
    "SAFETY_MESSAGE_TYPE",
    "VALID_SAFETY_EVENTS",
    "make_estop_message",
    "make_stop_message",
    "make_resume_message",
    "is_safety_message",
    "validate_safety_message",
    "TRANSPARENCY_MESSAGE_TYPE",
    "make_transparency_message",
]

# RCAN MessageType 6 — SAFETY
SAFETY_MESSAGE_TYPE = 6

# RCAN MessageType 18 — TRANSPARENCY (EU AI Act Art. 13)
TRANSPARENCY_MESSAGE_TYPE = 18

# Valid safety_event values per RCAN §6
VALID_SAFETY_EVENTS = frozenset({"ESTOP", "STOP", "RESUME"})

# Max reason length per spec (audit trail requirement)
_MAX_REASON_LEN = 512


def _make_safety_message(ruri: str, safety_event: str, reason: str) -> dict[str, Any]:
    """Internal factory for safety messages."""
    return {
        "message_type": SAFETY_MESSAGE_TYPE,
        "ruri": ruri,
        "safety_event": safety_event,
        "reason": reason[:_MAX_REASON_LEN],
        "timestamp_ms": int(time.time() * 1000),
        "message_id": str(uuid.uuid4()),
    }


def make_estop_message(ruri: str, reason: str) -> dict[str, Any]:
    """Create an ESTOP safety message (MessageType 6).

    ESTOP triggers immediate halt with no controlled deceleration.
    Bypasses all queues per RCAN §6. Requires explicit hardware-level
    clear before RESUME can be sent.

    Args:
        ruri:   Target robot's RURI
                (e.g. ``"rcan://rcan.dev/boston-dynamics/spot/bd-spot-001a2b3c"``).
        reason: Human-readable reason for the ESTOP (required for audit trail,
                truncated to 512 chars).

    Returns:
        A dict representing the ESTOP safety message.

    Example::

        msg = make_estop_message(
            ruri="rcan://rcan.dev/acme/arm/v1/unit-001",
            reason="Worker entered exclusion zone",
        )
    """
    return _make_safety_message(ruri, "ESTOP", reason)


def make_stop_message(ruri: str, reason: str) -> dict[str, Any]:
    """Create a STOP safety message (MessageType 6).

    STOP triggers a controlled deceleration to rest.  Unlike ESTOP, the
    robot may resume via :func:`make_resume_message` without a hardware
    reset step.

    Args:
        ruri:   Target robot's RURI.
        reason: Human-readable reason (truncated to 512 chars).

    Returns:
        A dict representing the STOP safety message.
    """
    return _make_safety_message(ruri, "STOP", reason)


def make_resume_message(ruri: str, reason: str) -> dict[str, Any]:
    """Create a RESUME safety message (MessageType 6).

    Clears a prior STOP and allows the robot to continue operation.
    RESUME does **not** clear an ESTOP — ESTOP requires explicit
    hardware acknowledgement before RESUME takes effect.

    Args:
        ruri:   Target robot's RURI.
        reason: Human-readable reason / operator note (truncated to 512 chars).

    Returns:
        A dict representing the RESUME safety message.
    """
    return _make_safety_message(ruri, "RESUME", reason)


def is_safety_message(msg: dict[str, Any]) -> bool:
    """Return ``True`` if *msg* is an RCAN safety message (MessageType 6).

    Args:
        msg: Any dict that may represent an RCAN message.

    Returns:
        ``True`` when ``msg["message_type"] == 6``.
    """
    return msg.get("message_type") == SAFETY_MESSAGE_TYPE


def validate_safety_message(msg: dict[str, Any]) -> list[str]:
    """Validate an RCAN safety message dict and return a list of errors.

    Args:
        msg: Dict to validate.

    Returns:
        An empty list if the message is valid; otherwise a list of
        human-readable error strings describing each violation.

    Example::

        errors = validate_safety_message(msg)
        if errors:
            raise ValueError("Invalid safety message: " + "; ".join(errors))
    """
    errors: list[str] = []

    # message_type must be 6
    mt = msg.get("message_type")
    if mt != SAFETY_MESSAGE_TYPE:
        errors.append(f"message_type must be {SAFETY_MESSAGE_TYPE}, got {mt!r}")

    # ruri must be present and non-empty
    ruri = msg.get("ruri")
    if not ruri:
        errors.append("ruri is required and must not be empty")

    # safety_event must be one of the valid values
    event = msg.get("safety_event")
    if not event:
        errors.append("safety_event is required")
    elif event not in VALID_SAFETY_EVENTS:
        errors.append(
            f"safety_event must be one of {sorted(VALID_SAFETY_EVENTS)}, got {event!r}"
        )

    # reason is required (audit trail)
    reason = msg.get("reason")
    if reason is None:
        errors.append("reason is required for audit trail")
    elif not isinstance(reason, str):
        errors.append("reason must be a string")
    elif len(reason) == 0:
        errors.append("reason must not be empty")

    # timestamp_ms must be a positive integer
    ts = msg.get("timestamp_ms")
    if ts is None:
        errors.append("timestamp_ms is required")
    elif not isinstance(ts, int):
        errors.append("timestamp_ms must be an integer")
    elif ts <= 0:
        errors.append("timestamp_ms must be a positive integer")

    # message_id must be present
    mid = msg.get("message_id")
    if not mid:
        errors.append("message_id is required")

    return errors


def make_transparency_message(
    source_ruri: str,
    target_ruri: str,
    operator: str,
    capabilities: list[str],
    model_family: str = "unknown",
    limitations: list[str] | None = None,
    contact: str = "",
    rcan_version: str = "1.4",
    p66_conformance_pct: float = 0.0,
    audit_enabled: bool = True,
) -> dict[str, Any]:
    """Build a RCAN Art. 13 EU AI Act transparency disclosure message.

    EU AI Act Article 13 requires AI systems to disclose their AI nature,
    capabilities, operator identity, and contact information to persons
    they interact with. For RCAN robots, this is expressed as a
    MessageType 18 (TRANSPARENCY) message.

    Args:
        source_ruri:         RURI of the robot sending the disclosure.
        target_ruri:         RURI of the recipient (human display or broadcast).
        operator:            Name of the deploying operator / organisation.
        capabilities:        List of robot capabilities (e.g. ["navigation", "speech"]).
        model_family:        AI model family in use (not version, e.g. "claude-sonnet").
        limitations:         Known limitations of the robot.
        contact:             Contact address for complaints / inquiries.
        rcan_version:        RCAN protocol version string.
        p66_conformance_pct: Protocol 66 conformance percentage (0–100).
        audit_enabled:       Whether actions are recorded to an audit trail.

    Returns:
        A dict representing the TRANSPARENCY disclosure message.

    Example::

        from rcan.safety import make_transparency_message

        msg = make_transparency_message(
            source_ruri="rcan://rcan.dev/acme/arm/v1/unit-001",
            target_ruri="rcan://local/human-display",
            operator="Acme Robotics",
            capabilities=["navigation", "manipulation", "speech"],
            model_family="claude-sonnet",
            limitations=["cannot lift > 5 kg", "outdoor use only in dry conditions"],
            contact="safety@acme-robotics.example",
            p66_conformance_pct=87.5,
            audit_enabled=True,
        )
    """
    return {
        "type": TRANSPARENCY_MESSAGE_TYPE,
        "source": source_ruri,
        "target": target_ruri,
        "message_id": str(uuid.uuid4()),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "payload": {
            "ai_system": True,  # always True per EU AI Act Art. 13
            "model_family": model_family,
            "operator": operator,
            "capabilities": capabilities,
            "limitations": limitations if limitations is not None else [],
            "contact": contact,
            "rcan_version": rcan_version,
            "p66_conformance_pct": p66_conformance_pct,
            "audit_enabled": audit_enabled,
        },
    }
