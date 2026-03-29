"""Tests for rcan.offline — Offline Operation Mode (GAP-06)."""

from __future__ import annotations

import time

from rcan.message import RCANMessage
from rcan.offline import OfflineModeManager, OfflineStatus

TARGET = "rcan://registry.rcan.dev/acme/arm/v1/unit-001"
OWNER_A = "user://alice"
OWNER_B = "user://bob"


def make_msg(cmd="move_forward") -> RCANMessage:
    return RCANMessage(cmd=cmd, target=TARGET)


class TestOfflineStatus:
    def test_online_status(self):
        status = OfflineStatus(is_offline=False)
        assert status.is_offline is False
        assert status.elapsed_offline_s == 0.0

    def test_offline_status(self):
        since = time.time() - 100
        status = OfflineStatus(
            is_offline=True, offline_since=since, grace_remaining_s=3500
        )
        assert status.is_offline is True
        assert status.elapsed_offline_s >= 100

    def test_to_dict(self):
        status = OfflineStatus(is_offline=False)
        d = status.to_dict()
        assert "is_offline" in d
        assert "grace_remaining_s" in d


class TestOfflineModeManager:
    def test_online_by_default(self):
        mgr = OfflineModeManager()
        assert mgr.is_offline is False

    def test_go_offline(self):
        mgr = OfflineModeManager()
        mgr.go_offline()
        assert mgr.is_offline is True

    def test_go_online(self):
        mgr = OfflineModeManager()
        mgr.go_offline()
        mgr.go_online()
        assert mgr.is_offline is False

    def test_online_commands_always_allowed(self):
        mgr = OfflineModeManager()
        msg = make_msg()
        allowed, reason = mgr.can_accept_command(msg, local_network=True)
        assert allowed is True

    def test_estop_always_allowed_offline(self):
        """ESTOP must be allowed even when offline (P66 invariant)."""
        mgr = OfflineModeManager()
        mgr.go_offline()
        msg = make_msg(cmd="ESTOP")
        allowed, reason = mgr.can_accept_command(msg, local_network=True)
        assert allowed is True

    def test_stop_always_allowed_offline(self):
        mgr = OfflineModeManager()
        mgr.go_offline()
        msg = make_msg(cmd="stop")
        allowed, reason = mgr.can_accept_command(msg, local_network=True)
        assert allowed is True

    def test_remote_command_blocked_offline(self):
        """Non-local commands are blocked when offline."""
        mgr = OfflineModeManager()
        mgr.go_offline()
        msg = make_msg()
        allowed, reason = mgr.can_accept_command(msg, local_network=False)
        assert allowed is False

    def test_same_owner_local_allowed(self):
        mgr = OfflineModeManager()
        mgr.register_owner(OWNER_A)
        mgr.go_offline()
        msg = make_msg()
        allowed, reason = mgr.can_accept_command(
            msg,
            local_network=True,
            sender_owner_id=OWNER_A,
            robot_owner_id=OWNER_A,
        )
        assert allowed is True

    def test_cross_owner_within_grace_allowed(self):
        mgr = OfflineModeManager(cross_owner_grace_s=3600)
        mgr.register_owner(OWNER_B)
        mgr.go_offline()
        msg = make_msg()
        allowed, reason = mgr.can_accept_command(
            msg,
            local_network=True,
            sender_owner_id=OWNER_B,
            robot_owner_id=OWNER_A,
        )
        assert allowed is True

    def test_cross_owner_past_grace_blocked(self):
        mgr = OfflineModeManager(cross_owner_grace_s=0)
        mgr.register_owner(OWNER_B)
        mgr.go_offline()
        msg = make_msg()
        allowed, reason = mgr.can_accept_command(
            msg,
            local_network=True,
            sender_owner_id=OWNER_B,
            robot_owner_id=OWNER_A,
        )
        assert allowed is False
        assert "grace" in reason.lower() or "blocked" in reason.lower()

    def test_new_principal_blocked_offline(self):
        """New principals (not pre-registered) are blocked when offline."""
        mgr = OfflineModeManager()
        mgr.go_offline()
        # OWNER_UNKNOWN was never registered
        msg = make_msg()
        allowed, reason = mgr.can_accept_command(
            msg,
            local_network=True,
            sender_owner_id="user://unknown",
            robot_owner_id=OWNER_A,
        )
        assert allowed is False
        assert "principal" in reason.lower() or "authorized" in reason.lower()

    def test_get_status_online(self):
        mgr = OfflineModeManager()
        status = mgr.get_status()
        assert status.is_offline is False

    def test_get_status_offline(self):
        mgr = OfflineModeManager()
        mgr.go_offline()
        status = mgr.get_status()
        assert status.is_offline is True
        assert status.offline_since is not None
