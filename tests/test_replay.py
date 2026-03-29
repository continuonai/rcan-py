"""Tests for rcan.replay — Replay Attack Prevention (GAP-03)."""

from __future__ import annotations

import time
import uuid

from rcan.message import RCANMessage
from rcan.replay import ReplayCache, validate_replay

TARGET = "rcan://registry.rcan.dev/acme/arm/v1/unit-001"


def make_msg(cmd="move_forward", **kwargs) -> RCANMessage:
    return RCANMessage(cmd=cmd, target=TARGET, **kwargs)


# ---------------------------------------------------------------------------
# ReplayCache basics
# ---------------------------------------------------------------------------


class TestReplayCacheBasics:
    def test_fresh_message_allowed(self):
        cache = ReplayCache(window_s=30)
        allowed, reason = cache.check_and_record(
            msg_id=str(uuid.uuid4()),
            timestamp=time.time(),
        )
        assert allowed is True
        assert reason == ""

    def test_duplicate_msg_id_rejected(self):
        cache = ReplayCache(window_s=30)
        msg_id = str(uuid.uuid4())
        allowed1, _ = cache.check_and_record(msg_id=msg_id, timestamp=time.time())
        allowed2, reason2 = cache.check_and_record(msg_id=msg_id, timestamp=time.time())
        assert allowed1 is True
        assert allowed2 is False
        assert "Duplicate" in reason2

    def test_stale_timestamp_rejected(self):
        cache = ReplayCache(window_s=30)
        stale_ts = time.time() - 31  # 31 seconds ago
        allowed, reason = cache.check_and_record(
            msg_id=str(uuid.uuid4()),
            timestamp=stale_ts,
        )
        assert allowed is False
        assert "31" in reason or "old" in reason.lower()

    def test_exactly_at_window_boundary_rejected(self):
        cache = ReplayCache(window_s=30)
        # Exactly at window boundary + 1s
        old_ts = time.time() - 31
        allowed, _ = cache.check_and_record(
            msg_id=str(uuid.uuid4()),
            timestamp=old_ts,
        )
        assert allowed is False

    def test_future_timestamp_rejected(self):
        cache = ReplayCache(window_s=30)
        future_ts = time.time() + 10  # 10 seconds in future
        allowed, reason = cache.check_and_record(
            msg_id=str(uuid.uuid4()),
            timestamp=future_ts,
        )
        assert allowed is False
        assert "future" in reason.lower()

    def test_invalid_timestamp_rejected(self):
        cache = ReplayCache()
        allowed, reason = cache.check_and_record(
            msg_id=str(uuid.uuid4()),
            timestamp="not-a-number",
        )
        assert allowed is False


# ---------------------------------------------------------------------------
# Safety message window
# ---------------------------------------------------------------------------


class TestSafetyWindow:
    def test_safety_message_uses_10s_window(self):
        """Safety messages must enforce 10s window even if config says 30s."""
        cache = ReplayCache(window_s=30)
        # 11 seconds ago — within 30s window but outside 10s safety window
        ts = time.time() - 11
        allowed, reason = cache.check_and_record(
            msg_id=str(uuid.uuid4()),
            timestamp=ts,
            is_safety=True,
        )
        assert allowed is False

    def test_safety_message_fresh_allowed(self):
        cache = ReplayCache(window_s=30)
        ts = time.time() - 5  # 5 seconds ago — within 10s safety window
        allowed, _ = cache.check_and_record(
            msg_id=str(uuid.uuid4()),
            timestamp=ts,
            is_safety=True,
        )
        assert allowed is True

    def test_non_safety_11s_old_allowed(self):
        """Non-safety messages use the full window."""
        cache = ReplayCache(window_s=30)
        ts = time.time() - 11
        allowed, _ = cache.check_and_record(
            msg_id=str(uuid.uuid4()),
            timestamp=ts,
            is_safety=False,
        )
        assert allowed is True


# ---------------------------------------------------------------------------
# Cache size and eviction
# ---------------------------------------------------------------------------


class TestCacheEviction:
    def test_overflow_evicts_oldest(self):
        cache = ReplayCache(window_s=300, max_size=5)
        # Fill the cache
        for i in range(5):
            cache.check_and_record(msg_id=f"msg-{i}", timestamp=time.time())
        assert cache._seen.__len__() <= 5

        # Adding one more evicts the oldest
        cache.check_and_record(msg_id="msg-new", timestamp=time.time())
        assert len(cache._order) <= 5


# ---------------------------------------------------------------------------
# validate_replay function
# ---------------------------------------------------------------------------


class TestValidateReplay:
    def test_fresh_message_allowed(self):
        cache = ReplayCache()
        msg = make_msg()
        allowed, reason = validate_replay(msg, cache)
        assert allowed is True

    def test_duplicate_message_rejected(self):
        cache = ReplayCache()
        msg = make_msg()
        validate_replay(msg, cache)  # first time
        allowed, reason = validate_replay(msg, cache)  # replay
        assert allowed is False

    def test_estop_fresh_allowed(self):
        """Fresh ESTOP must be accepted — P66 invariant."""
        cache = ReplayCache()
        msg = make_msg(cmd="ESTOP")
        allowed, _ = validate_replay(msg, cache)
        assert allowed is True

    def test_estop_duplicate_rejected(self):
        """Even ESTOP should not be replayed (duplicate msg_id)."""
        cache = ReplayCache()
        msg = make_msg(cmd="ESTOP")
        validate_replay(msg, cache)
        allowed, reason = validate_replay(msg, cache)
        assert allowed is False


# ---------------------------------------------------------------------------
# Window configuration
# ---------------------------------------------------------------------------


class TestWindowConfig:
    def test_custom_window_respected(self):
        cache = ReplayCache(window_s=60)
        ts = time.time() - 45  # within 60s window
        allowed, _ = cache.check_and_record(
            msg_id=str(uuid.uuid4()),
            timestamp=ts,
        )
        assert allowed is True

    def test_window_clamped_to_max(self):
        """window_s > 300 should be clamped."""
        cache = ReplayCache(window_s=9999)
        assert cache.window_s == 300

    def test_window_clamped_to_min(self):
        """window_s < 5 should be clamped."""
        cache = ReplayCache(window_s=1)
        assert cache.window_s == 5
