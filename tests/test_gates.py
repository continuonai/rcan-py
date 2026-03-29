"""Tests for rcan.gates — ConfidenceGate and HiTLGate."""

import pytest

from rcan import ConfidenceGate, GateResult, HiTLGate
from rcan.exceptions import RCANGateError

# ---------------------------------------------------------------------------
# ConfidenceGate
# ---------------------------------------------------------------------------


def test_confidence_gate_pass():
    gate = ConfidenceGate(threshold=0.8)
    assert gate.check(0.9) == GateResult.PASS


def test_confidence_gate_exact_threshold():
    gate = ConfidenceGate(threshold=0.8)
    assert gate.check(0.8) == GateResult.PASS


def test_confidence_gate_block():
    gate = ConfidenceGate(threshold=0.8)
    assert gate.check(0.79) == GateResult.BLOCK


def test_confidence_gate_allows():
    gate = ConfidenceGate(threshold=0.7)
    assert gate.allows(0.9) is True
    assert gate.allows(0.5) is False


def test_confidence_gate_raise_on_block():
    gate = ConfidenceGate(threshold=0.8, raise_on_block=True)
    with pytest.raises(RCANGateError) as exc_info:
        gate.check(0.5)
    assert exc_info.value.gate_type == "confidence"
    assert exc_info.value.value == 0.5
    assert exc_info.value.threshold == 0.8


def test_confidence_gate_action_filter_skip():
    gate = ConfidenceGate(threshold=0.9, action_type="move_forward")
    # Different action — gate is skipped
    assert gate.check(0.1, action_type="speak") == GateResult.PASS


def test_confidence_gate_action_filter_applies():
    gate = ConfidenceGate(threshold=0.9, action_type="move_forward")
    assert gate.check(0.5, action_type="move_forward") == GateResult.BLOCK


def test_confidence_gate_invalid_threshold():
    with pytest.raises(ValueError):
        ConfidenceGate(threshold=1.5)


def test_confidence_gate_repr():
    gate = ConfidenceGate(threshold=0.8)
    assert "0.8" in repr(gate)


# ---------------------------------------------------------------------------
# HiTLGate
# ---------------------------------------------------------------------------


def test_hitl_gate_no_fn_blocks():
    gate = HiTLGate()
    assert gate.check("move_forward") == GateResult.BLOCK


def test_hitl_gate_approve():
    gate = HiTLGate(approval_fn=lambda action, params, conf: True)
    assert gate.check("move_forward") == GateResult.PASS


def test_hitl_gate_deny():
    gate = HiTLGate(approval_fn=lambda action, params, conf: False)
    assert gate.check("move_forward") == GateResult.BLOCK


def test_hitl_gate_required_below_skips_high_confidence():
    gate = HiTLGate(
        approval_fn=lambda a, p, c: True,
        required_below=0.7,
    )
    # High confidence — HiTL not needed
    assert gate.needs_approval("move", confidence=0.9) is False


def test_hitl_gate_required_below_triggers():
    gate = HiTLGate(
        approval_fn=lambda a, p, c: True,
        required_below=0.7,
    )
    assert gate.needs_approval("move", confidence=0.5) is True


def test_hitl_gate_error_in_fn_blocks():
    def bad_fn(action, params, conf):
        raise RuntimeError("approval system down")

    gate = HiTLGate(approval_fn=bad_fn)
    # Should block gracefully, not raise
    assert gate.check("move_forward") == GateResult.BLOCK


def test_hitl_gate_allows():
    gate = HiTLGate(approval_fn=lambda a, p, c: True)
    assert gate.allows("move_forward") is True
