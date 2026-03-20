"""Tests for rcan.qos — Quality of Service / Delivery Guarantees (GAP-11)."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from rcan.qos import QoSLevel, QoSManager, make_estop_with_qos
from rcan.exceptions import QoSAckTimeoutError, SafetyHaltError
from rcan.message import RCANMessage

TARGET = "rcan://registry.rcan.dev/acme/arm/v1/unit-001"


def make_msg(cmd="move_forward", qos=0, **kwargs) -> RCANMessage:
    return RCANMessage(cmd=cmd, target=TARGET, qos=qos, **kwargs)


class TestQoSLevel:
    def test_values(self):
        assert QoSLevel.FIRE_AND_FORGET == 0
        assert QoSLevel.ACKNOWLEDGED == 1
        assert QoSLevel.EXACTLY_ONCE == 2

    def test_is_int_enum(self):
        assert int(QoSLevel.FIRE_AND_FORGET) == 0


class TestQoSManager:
    def test_init_defaults(self):
        mgr = QoSManager()
        assert mgr.ack_timeout_s == 5.0
        assert mgr.max_retries == 3

    def test_fire_and_forget_calls_send(self):
        mgr = QoSManager()
        msg = make_msg(qos=0)
        send_fn = MagicMock()
        result = mgr.send_with_ack(msg, send_fn)
        send_fn.assert_called_once_with(msg)
        assert result is True

    def test_acknowledged_success_on_ack(self):
        """QoS 1: send, then receive ACK → success."""
        mgr = QoSManager(ack_timeout_s=0.5, max_retries=2)
        msg = make_msg(qos=1)

        def send_fn(m):
            # Simulate ACK received immediately
            mgr.record_ack(m.msg_id)

        result = mgr.send_with_ack(msg, send_fn)
        assert result is True

    def test_acknowledged_timeout_raises(self):
        """QoS 1: no ACK within timeout → QoSAckTimeoutError."""
        mgr = QoSManager(ack_timeout_s=0.05, max_retries=1)
        msg = make_msg(qos=1)
        send_fn = MagicMock()  # does not record ACK

        with pytest.raises(QoSAckTimeoutError):
            mgr.send_with_ack(msg, send_fn)

    def test_exactly_once_commit_success(self):
        """QoS 2: send, ACK, then COMMIT → success."""
        mgr = QoSManager(ack_timeout_s=0.5, max_retries=1)
        msg = make_msg(qos=2)

        def send_fn(m):
            mgr.record_ack(m.msg_id)
            mgr.record_commit(m.msg_id)

        result = mgr.send_with_ack(msg, send_fn)
        assert result is True

    def test_estop_timeout_raises_safety_halt(self):
        """ESTOP ACK timeout must raise SafetyHaltError, not QoSAckTimeoutError."""
        mgr = QoSManager(ack_timeout_s=0.05, max_retries=0)
        msg = make_msg(cmd="ESTOP", qos=2)
        send_fn = MagicMock()

        with pytest.raises(SafetyHaltError):
            mgr.send_with_ack(msg, send_fn)

    def test_pending_count(self):
        mgr = QoSManager(ack_timeout_s=10.0, max_retries=0)
        assert mgr.pending_count() == 0

    def test_record_ack_unknown_msg_id(self):
        """Recording ACK for unknown msg_id should not raise."""
        mgr = QoSManager()
        mgr.record_ack("nonexistent-id")  # should not raise

    def test_record_commit_unknown_msg_id(self):
        mgr = QoSManager()
        mgr.record_commit("nonexistent-id")  # should not raise


class TestMakeEstopWithQoS:
    def test_estop_has_qos_2(self):
        msg = make_estop_with_qos(
            ruri=TARGET, reason="Test emergency stop"
        )
        assert msg.qos == int(QoSLevel.EXACTLY_ONCE)

    def test_estop_cmd(self):
        msg = make_estop_with_qos(ruri=TARGET, reason="Test")
        assert msg.cmd == "ESTOP"

    def test_estop_is_rcan_message(self):
        msg = make_estop_with_qos(ruri=TARGET, reason="Test")
        assert isinstance(msg, RCANMessage)


class TestMessageTypeAdditions:
    def test_command_nack_in_message_type(self):
        from rcan.message import MessageType
        assert hasattr(MessageType, "COMMAND_NACK")
        assert MessageType.COMMAND_NACK == 18

    def test_command_ack_in_message_type(self):
        from rcan.message import MessageType
        assert hasattr(MessageType, "COMMAND_ACK")
        assert MessageType.COMMAND_ACK == 17
