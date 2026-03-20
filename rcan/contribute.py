"""
rcan.contribute — Idle Compute Contribution messages and scope.

Implements the contribute scope and message types for RCAN v1.7+.
Robots can donate idle NPU/GPU/CPU compute to distributed science projects.

Spec: §3 MessageTypes 33–35, Identity scope level 2.5
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from rcan.exceptions import RCANError
from rcan.message import MessageType

logger = logging.getLogger(__name__)


# ── Scope ────────────────────────────────────────────────────────────────

CONTRIBUTE_SCOPE_LEVEL = 2.5  # Between chat (2) and control (3)


class ContributeError(RCANError):
    """Raised for contribute-related protocol errors."""


class WorkUnitStatus(str, Enum):
    """Status of a contributed work unit."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PREEMPTED = "preempted"  # P66 safety preemption


class ComputeResource(str, Enum):
    """Type of compute resource being contributed."""

    NPU = "npu"
    GPU = "gpu"
    CPU = "cpu"
    SENSOR = "sensor"


# ── Messages ─────────────────────────────────────────────────────────────


@dataclass
class ContributeRequest:
    """CONTRIBUTE_REQUEST (type 33) — request to start a work unit.

    Sent by a coordinator to a robot to start contributing idle compute.
    """

    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    project_id: str = ""
    project_name: str = ""
    work_unit_id: str = ""
    resource_type: ComputeResource = ComputeResource.CPU
    estimated_duration_s: float = 0.0
    priority: int = 0  # 0 = lowest
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    @property
    def message_type(self) -> MessageType:
        return MessageType.CONTRIBUTE_REQUEST

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.message_type.value,
            "request_id": self.request_id,
            "project_id": self.project_id,
            "project_name": self.project_name,
            "work_unit_id": self.work_unit_id,
            "resource_type": self.resource_type.value,
            "estimated_duration_s": self.estimated_duration_s,
            "priority": self.priority,
            "payload": self.payload,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ContributeRequest:
        return cls(
            request_id=data.get("request_id", str(uuid.uuid4())),
            project_id=data.get("project_id", ""),
            project_name=data.get("project_name", ""),
            work_unit_id=data.get("work_unit_id", ""),
            resource_type=ComputeResource(data.get("resource_type", "cpu")),
            estimated_duration_s=float(data.get("estimated_duration_s", 0)),
            priority=int(data.get("priority", 0)),
            payload=data.get("payload", {}),
            timestamp=float(data.get("timestamp", time.time())),
        )


@dataclass
class ContributeResult:
    """CONTRIBUTE_RESULT (type 34) — result of a completed work unit.

    Sent by a robot back to the coordinator after finishing a work unit.
    """

    request_id: str = ""
    work_unit_id: str = ""
    status: WorkUnitStatus = WorkUnitStatus.COMPLETED
    resource_type: ComputeResource = ComputeResource.CPU
    duration_s: float = 0.0
    compute_units: float = 0.0
    result_payload: dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    @property
    def message_type(self) -> MessageType:
        return MessageType.CONTRIBUTE_RESULT

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": self.message_type.value,
            "request_id": self.request_id,
            "work_unit_id": self.work_unit_id,
            "status": self.status.value,
            "resource_type": self.resource_type.value,
            "duration_s": self.duration_s,
            "compute_units": self.compute_units,
            "result_payload": self.result_payload,
            "timestamp": self.timestamp,
        }
        if self.error_message:
            d["error_message"] = self.error_message
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ContributeResult:
        return cls(
            request_id=data.get("request_id", ""),
            work_unit_id=data.get("work_unit_id", ""),
            status=WorkUnitStatus(data.get("status", "completed")),
            resource_type=ComputeResource(data.get("resource_type", "cpu")),
            duration_s=float(data.get("duration_s", 0)),
            compute_units=float(data.get("compute_units", 0)),
            result_payload=data.get("result_payload", {}),
            error_message=data.get("error_message"),
            timestamp=float(data.get("timestamp", time.time())),
        )


@dataclass
class ContributeCancel:
    """CONTRIBUTE_CANCEL (type 35) — cancel an in-progress work unit.

    Sent by coordinator or robot. Robot MUST honor immediately (P66).
    """

    request_id: str = ""
    work_unit_id: str = ""
    reason: str = ""
    timestamp: float = field(default_factory=time.time)

    @property
    def message_type(self) -> MessageType:
        return MessageType.CONTRIBUTE_CANCEL

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.message_type.value,
            "request_id": self.request_id,
            "work_unit_id": self.work_unit_id,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ContributeCancel:
        return cls(
            request_id=data.get("request_id", ""),
            work_unit_id=data.get("work_unit_id", ""),
            reason=data.get("reason", ""),
            timestamp=float(data.get("timestamp", time.time())),
        )


# ── Scope Validation ────────────────────────────────────────────────────


def validate_contribute_scope(
    scope_level: float,
    action: str = "request",
) -> bool:
    """Check if the given scope level permits contribute operations.

    Contribute requires scope >= 2.5 (between chat and control).
    Any active command (scope >= 3) immediately preempts contribute (P66).
    """
    if action in ("request", "result"):
        return scope_level >= CONTRIBUTE_SCOPE_LEVEL
    if action == "cancel":
        # Cancel is always permitted at chat level and above
        return scope_level >= 2.0
    return False


def is_preempted_by(scope_level: float) -> bool:
    """Check if the given scope level preempts contribution.

    Any scope >= control (3.0) preempts contribute immediately.
    This is the P66 safety invariant — non-negotiable.
    """
    return scope_level >= 3.0
