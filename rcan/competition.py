"""
rcan.competition — Competition protocol messages and scope.

Implements the competition scope and message types for RCAN v1.10+.
Robots can enter competitions, publish scores, receive season standings,
and log private personal research results.

Spec: §3 MessageTypes 37–40
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from rcan.exceptions import RCANError
from rcan.message import MessageType

logger = logging.getLogger(__name__)


# ── Scope ────────────────────────────────────────────────────────────────

COMPETITION_SCOPE_LEVEL = 2.0  # Chat-level scope — observation, not control


# ── Enums ────────────────────────────────────────────────────────────────


class CompetitionError(RCANError):
    """Raised for competition-related protocol errors."""


class CompetitionFormat(str, Enum):
    """Format of a competition."""

    SPRINT = "sprint"
    ENDURANCE = "endurance"
    PRECISION = "precision"
    EFFICIENCY = "efficiency"


class CompetitionBadge(str, Enum):
    """Badge awarded for a season standing."""

    GOLD = "gold"
    SILVER = "silver"
    BRONZE = "bronze"
    PARTICIPANT = "participant"


class RunType(str, Enum):
    """Type of a personal research result run."""

    PERSONAL = "personal"
    COMMUNITY = "community"


# ── Messages ─────────────────────────────────────────────────────────────


@dataclass
class CompetitionEnter:
    """COMPETITION_ENTER (type 37) — robot announces competition entry.

    Broadcast robot → fleet. Signals that a robot is entering a named
    competition. Fleet members use this to track participation.
    """

    competition_id: str = ""
    competition_format: CompetitionFormat = CompetitionFormat.SPRINT
    hardware_tier: str = ""
    model_id: str = ""
    robot_rrn: str = ""
    entered_at: float = field(default_factory=time.time)

    @property
    def message_type(self) -> MessageType:
        return MessageType.COMPETITION_ENTER

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.message_type.value,
            "competition_id": self.competition_id,
            "competition_format": self.competition_format.value,
            "hardware_tier": self.hardware_tier,
            "model_id": self.model_id,
            "robot_rrn": self.robot_rrn,
            "entered_at": self.entered_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CompetitionEnter:
        return cls(
            competition_id=data.get("competition_id", ""),
            competition_format=CompetitionFormat(
                data.get("competition_format", "sprint")
            ),
            hardware_tier=data.get("hardware_tier", ""),
            model_id=data.get("model_id", ""),
            robot_rrn=data.get("robot_rrn", ""),
            entered_at=float(data.get("entered_at", time.time())),
        )


@dataclass
class CompetitionScore:
    """COMPETITION_SCORE (type 38) — robot publishes a verified score.

    Broadcast robot → fleet. Contains a verified score submission for a
    named competition. `verified` must be True before fleet broadcast.
    """

    competition_id: str = ""
    candidate_id: str = ""
    score: float = 0.0
    hardware_tier: str = ""
    verified: bool = False
    submitted_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not (0.0 <= self.score <= 1.0):
            raise CompetitionError(
                f"score must be in [0.0, 1.0], got {self.score}"
            )

    @property
    def message_type(self) -> MessageType:
        return MessageType.COMPETITION_SCORE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.message_type.value,
            "competition_id": self.competition_id,
            "candidate_id": self.candidate_id,
            "score": self.score,
            "hardware_tier": self.hardware_tier,
            "verified": self.verified,
            "submitted_at": self.submitted_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CompetitionScore:
        return cls(
            competition_id=data.get("competition_id", ""),
            candidate_id=data.get("candidate_id", ""),
            score=float(data.get("score", 0.0)),
            hardware_tier=data.get("hardware_tier", ""),
            verified=bool(data.get("verified", False)),
            submitted_at=float(data.get("submitted_at", time.time())),
        )


@dataclass
class SeasonStanding:
    """SEASON_STANDING (type 39) — cloud broadcasts current standings.

    Broadcast cloud → fleet. Delivers ranked season standings for a
    hardware/model class. Robots use this to observe competitive position.
    """

    season_id: str = ""
    class_id: str = ""
    standings: List[Dict[str, Any]] = field(default_factory=list)
    days_remaining: int = 0
    broadcast_at: float = field(default_factory=time.time)

    @property
    def message_type(self) -> MessageType:
        return MessageType.SEASON_STANDING

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.message_type.value,
            "season_id": self.season_id,
            "class_id": self.class_id,
            "standings": self.standings,
            "days_remaining": self.days_remaining,
            "broadcast_at": self.broadcast_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SeasonStanding:
        return cls(
            season_id=data.get("season_id", ""),
            class_id=data.get("class_id", ""),
            standings=list(data.get("standings", [])),
            days_remaining=int(data.get("days_remaining", 0)),
            broadcast_at=float(data.get("broadcast_at", time.time())),
        )


@dataclass
class PersonalResearchResult:
    """PERSONAL_RESEARCH_RESULT (type 40) — private run result.

    Unicast robot → local gateway only. NEVER broadcast to fleet.
    Captures a private personal or community run result with full metrics.
    The `submitted_to_community` flag controls whether the result is
    eligible for community aggregation.
    """

    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    run_type: RunType = RunType.PERSONAL
    candidate_id: str = ""
    score: float = 0.0
    hardware_tier: str = ""
    model_id: str = ""
    owner_uid: str = ""
    metrics: Dict[str, float] = field(default_factory=dict)
    submitted_to_community: bool = False
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not (0.0 <= self.score <= 1.0):
            raise CompetitionError(
                f"score must be in [0.0, 1.0], got {self.score}"
            )

    @property
    def message_type(self) -> MessageType:
        return MessageType.PERSONAL_RESEARCH_RESULT

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.message_type.value,
            "run_id": self.run_id,
            "run_type": self.run_type.value,
            "candidate_id": self.candidate_id,
            "score": self.score,
            "hardware_tier": self.hardware_tier,
            "model_id": self.model_id,
            "owner_uid": self.owner_uid,
            "metrics": self.metrics,
            "submitted_to_community": self.submitted_to_community,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PersonalResearchResult:
        return cls(
            run_id=data.get("run_id", str(uuid.uuid4())),
            run_type=RunType(data.get("run_type", "personal")),
            candidate_id=data.get("candidate_id", ""),
            score=float(data.get("score", 0.0)),
            hardware_tier=data.get("hardware_tier", ""),
            model_id=data.get("model_id", ""),
            owner_uid=data.get("owner_uid", ""),
            metrics=dict(data.get("metrics", {})),
            submitted_to_community=bool(data.get("submitted_to_community", False)),
            created_at=float(data.get("created_at", time.time())),
        )


# ── Scope Validation ─────────────────────────────────────────────────────


def validate_competition_scope(scope_level: float) -> bool:
    """Check if the given scope level permits competition operations.

    Competition messages require scope >= 2.0 (chat level).
    They are observational — no control actions.
    """
    return scope_level >= COMPETITION_SCOPE_LEVEL


__all__ = [
    "COMPETITION_SCOPE_LEVEL",
    "CompetitionError",
    "CompetitionFormat",
    "CompetitionBadge",
    "RunType",
    "CompetitionEnter",
    "CompetitionScore",
    "SeasonStanding",
    "PersonalResearchResult",
    "validate_competition_scope",
]
