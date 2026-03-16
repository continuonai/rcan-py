"""
rcan.fault — Structured Fault Reporting (GAP-20).

Defines a standard fault code taxonomy and builder for FAULT_REPORT messages.

Spec: §16 — Fault Reporting Taxonomy
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Optional

logger = logging.getLogger(__name__)

FaultSeverity = Literal["info", "warning", "error", "critical"]


class FaultCode(str, Enum):
    """Standard RCAN fault code taxonomy (prefixed by subsystem)."""

    # Sensor faults
    SENSOR_PROXIMITY_FAILURE = "SENSOR_PROXIMITY_FAILURE"
    SENSOR_CAMERA_FAILURE = "SENSOR_CAMERA_FAILURE"
    SENSOR_IMU_FAILURE = "SENSOR_IMU_FAILURE"
    SENSOR_LIDAR_FAILURE = "SENSOR_LIDAR_FAILURE"

    # Motor / actuator faults
    MOTOR_OVERCURRENT = "MOTOR_OVERCURRENT"
    MOTOR_OVERTEMP = "MOTOR_OVERTEMP"
    MOTOR_ENCODER_FAILURE = "MOTOR_ENCODER_FAILURE"
    ACTUATOR_STUCK = "ACTUATOR_STUCK"

    # Power faults
    BATTERY_CRITICAL = "BATTERY_CRITICAL"
    BATTERY_LOW = "BATTERY_LOW"
    POWER_SUPPLY_FAILURE = "POWER_SUPPLY_FAILURE"

    # Network / comms faults
    NETWORK_DISCONNECTED = "NETWORK_DISCONNECTED"
    NETWORK_LATENCY_HIGH = "NETWORK_LATENCY_HIGH"
    REGISTRY_UNREACHABLE = "REGISTRY_UNREACHABLE"

    # Software / AI faults
    AI_CONFIDENCE_LOW = "AI_CONFIDENCE_LOW"
    AI_MODEL_FAILURE = "AI_MODEL_FAILURE"
    WATCHDOG_TIMEOUT = "WATCHDOG_TIMEOUT"
    CONFIG_INVALID = "CONFIG_INVALID"

    # Safety faults
    SAFETY_ESTOP_TRIGGERED = "SAFETY_ESTOP_TRIGGERED"
    SAFETY_PROXIMITY_BREACH = "SAFETY_PROXIMITY_BREACH"
    SAFETY_CLOCK_UNSYNC = "SAFETY_CLOCK_UNSYNC"

    # Generic
    UNKNOWN_FAULT = "UNKNOWN_FAULT"


@dataclass
class FaultReport:
    """A structured fault report.

    Attributes:
        fault_code:       Standard fault code from :class:`FaultCode`.
        severity:         Severity level: ``"info"``, ``"warning"``, ``"error"``, ``"critical"``.
        subsystem:        Subsystem name (e.g. ``"sensor.proximity"``, ``"motor.left"``).
        affects_safety:   True if this fault degrades safety guarantees.
        safe_to_continue: True if the robot can continue operation despite the fault.
        detail:           Human-readable detail about the fault.
        fault_id:         Unique identifier for this fault report.
        reported_at:      Unix timestamp of the fault.
    """

    fault_code: FaultCode | str
    severity: FaultSeverity
    subsystem: str
    affects_safety: bool = False
    safe_to_continue: bool = True
    detail: str = ""
    fault_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    reported_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        code = self.fault_code.value if isinstance(self.fault_code, FaultCode) else str(self.fault_code)
        return {
            "fault_id": self.fault_id,
            "fault_code": code,
            "severity": self.severity,
            "subsystem": self.subsystem,
            "affects_safety": self.affects_safety,
            "safe_to_continue": self.safe_to_continue,
            "detail": self.detail,
            "reported_at": self.reported_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FaultReport":
        code_raw = data.get("fault_code", "UNKNOWN_FAULT")
        try:
            code: FaultCode | str = FaultCode(code_raw)
        except ValueError:
            code = code_raw
        return cls(
            fault_code=code,
            severity=data.get("severity", "error"),  # type: ignore[arg-type]
            subsystem=data.get("subsystem", "unknown"),
            affects_safety=data.get("affects_safety", False),
            safe_to_continue=data.get("safe_to_continue", True),
            detail=data.get("detail", ""),
            fault_id=data.get("fault_id", str(uuid.uuid4())),
            reported_at=data.get("reported_at", time.time()),
        )


def make_fault_report(
    fault_code: FaultCode | str,
    severity: FaultSeverity,
    subsystem: str,
    affects_safety: bool = False,
    safe_to_continue: bool = True,
    detail: str = "",
    target_uri: str = "rcan://rcan.dev/system/fault/v1/local",
) -> Any:
    """Build a FAULT_REPORT RCANMessage.

    Args:
        fault_code:       Fault code (from :class:`FaultCode` or custom string).
        severity:         ``"info"``, ``"warning"``, ``"error"``, or ``"critical"``.
        subsystem:        Subsystem name.
        affects_safety:   True if safety guarantees are degraded.
        safe_to_continue: True if operation can continue.
        detail:           Human-readable detail.
        target_uri:       Where to send the fault report.

    Returns:
        :class:`~rcan.message.RCANMessage` with FAULT_REPORT command.
    """
    from rcan.message import RCANMessage

    report = FaultReport(
        fault_code=fault_code,
        severity=severity,
        subsystem=subsystem,
        affects_safety=affects_safety,
        safe_to_continue=safe_to_continue,
        detail=detail,
    )

    return RCANMessage(
        cmd="FAULT_REPORT",
        target=target_uri,
        params=report.to_dict(),
    )


__all__ = [
    "FaultCode",
    "FaultReport",
    "FaultSeverity",
    "make_fault_report",
]
