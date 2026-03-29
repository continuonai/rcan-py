"""Tests for rcan.competition — competition protocol messages (v1.10)."""

import time

import pytest

from rcan.competition import (
    COMPETITION_SCOPE_LEVEL,
    CompetitionBadge,
    CompetitionEnter,
    CompetitionError,
    CompetitionFormat,
    CompetitionScore,
    PersonalResearchResult,
    RunType,
    SeasonStanding,
    validate_competition_scope,
)
from rcan.message import MessageType


class TestCompetitionEnter:
    def test_create_with_defaults(self):
        msg = CompetitionEnter()
        assert msg.competition_id == ""
        assert msg.competition_format == CompetitionFormat.SPRINT
        assert msg.message_type == MessageType.COMPETITION_ENTER

    def test_message_type_value(self):
        assert CompetitionEnter().message_type.value == 37

    def test_round_trip(self):
        msg = CompetitionEnter(
            competition_id="sprint-2026-04-pi5-hailo8l",
            competition_format=CompetitionFormat.SPRINT,
            hardware_tier="pi5-hailo8l",
            model_id="gemini-2.5-flash",
            robot_rrn="RRN-000000000001",
        )
        d = msg.to_dict()
        assert d["type"] == 37
        assert d["competition_format"] == "sprint"
        assert d["robot_rrn"] == "RRN-000000000001"

        restored = CompetitionEnter.from_dict(d)
        assert restored.competition_id == "sprint-2026-04-pi5-hailo8l"
        assert restored.competition_format == CompetitionFormat.SPRINT
        assert restored.hardware_tier == "pi5-hailo8l"
        assert restored.model_id == "gemini-2.5-flash"
        assert restored.robot_rrn == "RRN-000000000001"

    def test_all_formats(self):
        for fmt in CompetitionFormat:
            msg = CompetitionEnter(competition_format=fmt)
            d = msg.to_dict()
            restored = CompetitionEnter.from_dict(d)
            assert restored.competition_format == fmt

    def test_entered_at_defaults_to_now(self):
        before = time.time()
        msg = CompetitionEnter()
        after = time.time()
        assert before <= msg.entered_at <= after


class TestCompetitionScore:
    def test_create_with_defaults(self):
        msg = CompetitionScore()
        assert msg.verified is False
        assert msg.score == 0.0
        assert msg.message_type == MessageType.COMPETITION_SCORE

    def test_message_type_value(self):
        assert CompetitionScore().message_type.value == 38

    def test_round_trip(self):
        msg = CompetitionScore(
            competition_id="sprint-2026-04-pi5-hailo8l",
            candidate_id="lower_cost_gate",
            score=0.8846,
            hardware_tier="pi5-hailo8l",
            verified=True,
        )
        d = msg.to_dict()
        assert d["type"] == 38
        assert d["score"] == 0.8846
        assert d["verified"] is True

        restored = CompetitionScore.from_dict(d)
        assert restored.score == 0.8846
        assert restored.verified is True
        assert restored.candidate_id == "lower_cost_gate"

    def test_score_boundary_zero(self):
        msg = CompetitionScore(score=0.0)
        assert msg.score == 0.0

    def test_score_boundary_one(self):
        msg = CompetitionScore(score=1.0)
        assert msg.score == 1.0

    def test_score_out_of_range_raises(self):
        with pytest.raises(CompetitionError):
            CompetitionScore(score=1.01)

    def test_score_negative_raises(self):
        with pytest.raises(CompetitionError):
            CompetitionScore(score=-0.1)

    def test_verified_defaults_false(self):
        msg = CompetitionScore(score=0.5)
        assert msg.verified is False
        d = msg.to_dict()
        assert d["verified"] is False


class TestSeasonStanding:
    def test_create_with_defaults(self):
        msg = SeasonStanding()
        assert msg.standings == []
        assert msg.days_remaining == 0
        assert msg.message_type == MessageType.SEASON_STANDING

    def test_message_type_value(self):
        assert SeasonStanding().message_type.value == 39

    def test_round_trip(self):
        standings = [
            {"rank": 1, "rrn": "RRN-000000000001", "score": 0.9101, "badge": "gold"},
            {"rank": 2, "rrn": "RRN-000000000005", "score": 0.8812, "badge": "silver"},
            {"rank": 3, "rrn": "RRN-000000000012", "score": 0.8503, "badge": "bronze"},
        ]
        msg = SeasonStanding(
            season_id="2026-03",
            class_id="pi5-hailo8l__gemini-2.5-flash",
            standings=standings,
            days_remaining=9,
        )
        d = msg.to_dict()
        assert d["type"] == 39
        assert len(d["standings"]) == 3
        assert d["days_remaining"] == 9

        restored = SeasonStanding.from_dict(d)
        assert restored.season_id == "2026-03"
        assert restored.class_id == "pi5-hailo8l__gemini-2.5-flash"
        assert len(restored.standings) == 3
        assert restored.standings[0]["badge"] == "gold"
        assert restored.days_remaining == 9

    def test_empty_standings(self):
        msg = SeasonStanding(season_id="2026-04", standings=[])
        d = msg.to_dict()
        restored = SeasonStanding.from_dict(d)
        assert restored.standings == []


class TestPersonalResearchResult:
    def test_create_with_defaults(self):
        msg = PersonalResearchResult()
        assert msg.run_id  # auto-generated UUID
        assert msg.run_type == RunType.PERSONAL
        assert msg.submitted_to_community is False
        assert msg.message_type == MessageType.PERSONAL_RESEARCH_RESULT

    def test_message_type_value(self):
        assert PersonalResearchResult().message_type.value == 40

    def test_round_trip(self):
        metrics = {
            "success_rate": 0.93,
            "p66_rate": 0.97,
            "token_efficiency": 0.72,
            "latency_score": 0.68,
        }
        msg = PersonalResearchResult(
            run_type=RunType.PERSONAL,
            candidate_id="lower_cost_gate",
            score=0.8846,
            hardware_tier="pi5-hailo8l",
            model_id="gemini-2.5-flash",
            owner_uid="GAi2kq961zWUnXMQzu6qLCmCOtR2",
            metrics=metrics,
            submitted_to_community=False,
        )
        d = msg.to_dict()
        assert d["type"] == 40
        assert d["run_type"] == "personal"
        assert d["score"] == 0.8846
        assert d["submitted_to_community"] is False

        restored = PersonalResearchResult.from_dict(d)
        assert restored.candidate_id == "lower_cost_gate"
        assert restored.score == 0.8846
        assert restored.owner_uid == "GAi2kq961zWUnXMQzu6qLCmCOtR2"
        assert restored.metrics["success_rate"] == 0.93
        assert restored.submitted_to_community is False

    def test_community_run_type(self):
        msg = PersonalResearchResult(run_type=RunType.COMMUNITY, score=0.75)
        d = msg.to_dict()
        assert d["run_type"] == "community"
        restored = PersonalResearchResult.from_dict(d)
        assert restored.run_type == RunType.COMMUNITY

    def test_submitted_to_community_flag(self):
        msg = PersonalResearchResult(score=0.9, submitted_to_community=True)
        d = msg.to_dict()
        assert d["submitted_to_community"] is True

    def test_score_boundary_values(self):
        PersonalResearchResult(score=0.0)
        PersonalResearchResult(score=1.0)

    def test_score_out_of_range_raises(self):
        with pytest.raises(CompetitionError):
            PersonalResearchResult(score=1.5)

    def test_run_id_auto_generated(self):
        a = PersonalResearchResult()
        b = PersonalResearchResult()
        assert a.run_id != b.run_id

    def test_run_id_preserved_in_round_trip(self):
        msg = PersonalResearchResult(run_id="my-run-123", score=0.5)
        d = msg.to_dict()
        restored = PersonalResearchResult.from_dict(d)
        assert restored.run_id == "my-run-123"


class TestCompetitionBadge:
    def test_badge_values(self):
        assert CompetitionBadge.GOLD.value == "gold"
        assert CompetitionBadge.SILVER.value == "silver"
        assert CompetitionBadge.BRONZE.value == "bronze"
        assert CompetitionBadge.PARTICIPANT.value == "participant"


class TestScopeValidation:
    def test_scope_level_constant(self):
        assert COMPETITION_SCOPE_LEVEL == 2.0

    def test_chat_scope_permitted(self):
        assert validate_competition_scope(2.0) is True

    def test_control_scope_permitted(self):
        assert validate_competition_scope(3.0) is True

    def test_below_chat_rejected(self):
        assert validate_competition_scope(1.9) is False

    def test_observe_scope_rejected(self):
        assert validate_competition_scope(1.0) is False
