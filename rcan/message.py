"""
RCAN message types — command, response, and status.

Spec: https://rcan.dev/spec#section-3
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from rcan.address import RobotURI
from rcan.exceptions import RCANValidationError

# Required fields for a valid RCAN command message
_REQUIRED_CMD_FIELDS = {"rcan", "cmd", "target"}

# RCAN spec version this SDK implements
SPEC_VERSION = "1.4"


@dataclass
class RCANMessage:
    """
    An RCAN command message.

    Attributes:
        cmd:        Command name (e.g. ``move_forward``, ``stop``, ``speak``).
        target:     Destination robot URI.
        params:     Command parameters (free-form dict).
        confidence: AI inference confidence [0.0–1.0]. None if not AI-driven.
        rcan:       RCAN spec version. Defaults to ``"1.2"``.
        msg_id:     Unique message ID. Auto-generated if not provided.
        timestamp:  Unix timestamp. Auto-set if not provided.
        sender:     Sender identity (operator URI or name).
        scope:      Authorization scope (e.g. ``"operator"``, ``"fleet"``).
        signature:  Ed25519 signature dict (``alg``, ``kid``, ``value``).
    """

    cmd: str
    target: RobotURI | str
    params: dict[str, Any] = field(default_factory=dict)
    confidence: float | None = None
    rcan: str = SPEC_VERSION
    msg_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    sender: str | None = None
    scope: str | None = None
    signature: dict[str, str] | None = None

    def __post_init__(self) -> None:
        # Normalize target to RobotURI
        if isinstance(self.target, str):
            self.target = RobotURI.parse(self.target)
        # Validate confidence range
        if self.confidence is not None and not (0.0 <= self.confidence <= 1.0):
            raise RCANValidationError(
                f"confidence must be in [0.0, 1.0], got {self.confidence}"
            )
        if not self.cmd:
            raise RCANValidationError("cmd must not be empty")

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict representation."""
        d: dict[str, Any] = {
            "rcan": self.rcan,
            "msg_id": self.msg_id,
            "timestamp": self.timestamp,
            "cmd": self.cmd,
            "target": str(self.target),
            "params": self.params,
        }
        if self.confidence is not None:
            d["confidence"] = self.confidence
        if self.sender is not None:
            d["sender"] = self.sender
        if self.scope is not None:
            d["scope"] = self.scope
        if self.signature is not None:
            d["sig"] = self.signature
        return d

    def to_json(self, indent: int | None = None) -> str:
        """Serialize to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RCANMessage":
        """
        Deserialize a dict into an :class:`RCANMessage`.

        Raises:
            RCANValidationError: If required fields are missing.
        """
        missing = _REQUIRED_CMD_FIELDS - data.keys()
        if missing:
            raise RCANValidationError(f"Missing required RCAN fields: {missing}")
        return cls(
            rcan=data.get("rcan", SPEC_VERSION),
            msg_id=data.get("msg_id", str(uuid.uuid4())),
            timestamp=data.get("timestamp", time.time()),
            cmd=data["cmd"],
            target=RobotURI.parse(data["target"]),
            params=data.get("params", {}),
            confidence=data.get("confidence"),
            sender=data.get("sender"),
            scope=data.get("scope"),
            signature=data.get("sig"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "RCANMessage":
        """Deserialize from a JSON string."""
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise RCANValidationError(f"Invalid JSON: {e}") from e
        return cls.from_dict(data)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def is_signed(self) -> bool:
        """True if this message carries a signature."""
        return self.signature is not None

    @property
    def is_ai_driven(self) -> bool:
        """True if this message carries an AI confidence score."""
        return self.confidence is not None

    def __repr__(self) -> str:
        return (
            f"RCANMessage(cmd={self.cmd!r}, target={self.target!r}, "
            f"confidence={self.confidence})"
        )


@dataclass
class RCANResponse:
    """
    Response from a robot to an RCAN command.

    Attributes:
        msg_id:            Echo of the originating message ID.
        status:            ``"ok"``, ``"error"``, ``"pending"``, or ``"blocked"``.
        message:           Human-readable status description.
        result:            Free-form result data from the command.
        safety_approved:   Whether the safety gate approved the action.
        safety_reason:     Reason if blocked.
        commitment_id:     ID of the :class:`CommitmentRecord` for this action.
        duration_ms:       Execution time in milliseconds.
        timestamp:         Unix timestamp of the response.
    """

    msg_id: str
    status: str  # ok | error | pending | blocked
    message: str = ""
    result: dict[str, Any] = field(default_factory=dict)
    safety_approved: bool = True
    safety_reason: str = ""
    commitment_id: str | None = None
    duration_ms: float | None = None
    timestamp: float = field(default_factory=time.time)

    @property
    def ok(self) -> bool:
        """True if status is ``"ok"``."""
        return self.status == "ok"

    @property
    def blocked(self) -> bool:
        """True if status is ``"blocked"`` (safety gate rejected)."""
        return self.status == "blocked"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RCANResponse":
        return cls(
            msg_id=data.get("msg_id", ""),
            status=data.get("status", "error"),
            message=data.get("message", ""),
            result=data.get("result", {}),
            safety_approved=data.get("safety_approved", True),
            safety_reason=data.get("safety_reason", ""),
            commitment_id=data.get("commitment_id"),
            duration_ms=data.get("duration_ms"),
            timestamp=data.get("timestamp", time.time()),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "msg_id": self.msg_id,
            "status": self.status,
            "message": self.message,
            "result": self.result,
            "safety_approved": self.safety_approved,
            "safety_reason": self.safety_reason,
            "commitment_id": self.commitment_id,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp,
        }
