"""Tests for rcan.contribute — contribute messages and scope validation."""

from rcan.contribute import (
    CONTRIBUTE_SCOPE_LEVEL,
    ComputeResource,
    ContributeCancel,
    ContributeRequest,
    ContributeResult,
    WorkUnitStatus,
    is_preempted_by,
    validate_contribute_scope,
)
from rcan.message import MessageType


class TestContributeRequest:
    def test_create_with_defaults(self):
        req = ContributeRequest()
        assert req.request_id  # auto-generated UUID
        assert req.resource_type == ComputeResource.CPU
        assert req.message_type == MessageType.CONTRIBUTE_REQUEST

    def test_round_trip(self):
        req = ContributeRequest(
            project_id="climate-sim-42",
            project_name="Climate Modeling",
            work_unit_id="wu-001",
            resource_type=ComputeResource.NPU,
            estimated_duration_s=300.0,
            priority=5,
            payload={"model": "weatherbench"},
        )
        d = req.to_dict()
        assert d["type"] == 33
        assert d["resource_type"] == "npu"

        restored = ContributeRequest.from_dict(d)
        assert restored.project_id == "climate-sim-42"
        assert restored.resource_type == ComputeResource.NPU
        assert restored.estimated_duration_s == 300.0

    def test_message_type_value(self):
        assert ContributeRequest().message_type.value == 33


class TestContributeResult:
    def test_create_completed(self):
        result = ContributeResult(
            request_id="req-1",
            work_unit_id="wu-001",
            duration_s=120.5,
            compute_units=42.0,
        )
        assert result.status == WorkUnitStatus.COMPLETED
        assert result.message_type == MessageType.CONTRIBUTE_RESULT

    def test_create_failed(self):
        result = ContributeResult(
            status=WorkUnitStatus.FAILED,
            error_message="Out of memory",
        )
        d = result.to_dict()
        assert d["status"] == "failed"
        assert d["error_message"] == "Out of memory"

    def test_preempted_status(self):
        result = ContributeResult(status=WorkUnitStatus.PREEMPTED)
        assert result.status.value == "preempted"

    def test_round_trip(self):
        result = ContributeResult(
            request_id="req-1",
            work_unit_id="wu-001",
            resource_type=ComputeResource.GPU,
            compute_units=100.0,
        )
        d = result.to_dict()
        assert d["type"] == 34

        restored = ContributeResult.from_dict(d)
        assert restored.compute_units == 100.0
        assert restored.resource_type == ComputeResource.GPU

    def test_error_message_omitted_when_none(self):
        result = ContributeResult()
        d = result.to_dict()
        assert "error_message" not in d


class TestContributeCancel:
    def test_create(self):
        cancel = ContributeCancel(
            request_id="req-1",
            work_unit_id="wu-001",
            reason="P66 safety preemption",
        )
        assert cancel.message_type == MessageType.CONTRIBUTE_CANCEL

    def test_round_trip(self):
        cancel = ContributeCancel(reason="Manual stop")
        d = cancel.to_dict()
        assert d["type"] == 35

        restored = ContributeCancel.from_dict(d)
        assert restored.reason == "Manual stop"


class TestScopeValidation:
    def test_scope_level_constant(self):
        assert CONTRIBUTE_SCOPE_LEVEL == 2.5

    def test_chat_scope_insufficient(self):
        assert not validate_contribute_scope(2.0, "request")

    def test_contribute_scope_sufficient(self):
        assert validate_contribute_scope(2.5, "request")

    def test_control_scope_sufficient(self):
        assert validate_contribute_scope(3.0, "request")

    def test_cancel_at_chat_level(self):
        # Cancel is allowed at chat level
        assert validate_contribute_scope(2.0, "cancel")

    def test_cancel_below_chat(self):
        assert not validate_contribute_scope(1.0, "cancel")


class TestP66Preemption:
    def test_control_preempts(self):
        assert is_preempted_by(3.0)

    def test_admin_preempts(self):
        assert is_preempted_by(4.0)

    def test_contribute_does_not_preempt(self):
        assert not is_preempted_by(2.5)

    def test_chat_does_not_preempt(self):
        assert not is_preempted_by(2.0)


class TestEnums:
    def test_work_unit_statuses(self):
        statuses = [s.value for s in WorkUnitStatus]
        assert "pending" in statuses
        assert "preempted" in statuses

    def test_compute_resources(self):
        resources = [r.value for r in ComputeResource]
        assert set(resources) == {"npu", "gpu", "cpu", "sensor"}
