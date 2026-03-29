"""
rcan.replay — Replay Attack Prevention (GAP-03).

Implements a sliding-window seen-set for msg_id values, rejecting duplicate
or stale messages. Applied BEFORE signature verification to prevent
replay-storm DoS attacks.

Spec: §8.3 — Replay Attack Prevention
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from rcan.exceptions import ReplayAttackError

if TYPE_CHECKING:
    from rcan.message import RCANMessage

logger = logging.getLogger(__name__)

# Safety message type code (SAFETY = 6 per canonical table)
_SAFETY_MESSAGE_TYPE = 6

# Maximum replay window for safety messages (§8.3)
_SAFETY_MAX_WINDOW_S = 10

# Default replay window
_DEFAULT_WINDOW_S = 30

# Default max cache size
_DEFAULT_MAX_SIZE = 10_000


@dataclass
class _CacheEntry:
    """Entry stored in the replay cache."""

    msg_id: str
    recorded_at: float  # monotonic time when first seen


class ReplayCache:
    """Sliding-window seen-set for msg_id values.

    Rejects messages where:
    - The ``timestamp`` is older than ``window_s`` seconds, OR
    - The ``msg_id`` has already been seen within the window.

    Safety messages enforce a max 10-second window regardless of config.

    Args:
        window_s:  Replay window in seconds (default 30; range 5–300).
        max_size:  Maximum number of entries to keep (default 10 000).
                   When full, the oldest entries are evicted.
    """

    def __init__(
        self, window_s: int = _DEFAULT_WINDOW_S, max_size: int = _DEFAULT_MAX_SIZE
    ) -> None:
        self.window_s = max(5, min(300, window_s))
        self.max_size = max(1, max_size)
        # msg_id -> monotonic time of first receipt
        self._seen: dict[str, float] = {}
        # ordered insertion list for eviction
        self._order: list[str] = []

    def _effective_window(self, is_safety: bool = False) -> int:
        """Return the effective window, capped at 10s for safety messages."""
        if is_safety:
            return min(self.window_s, _SAFETY_MAX_WINDOW_S)
        return self.window_s

    def _evict_expired(self, now: float, window_s: int) -> None:
        """Remove entries that have fallen outside the window."""
        cutoff = now - window_s
        while self._order and self._seen.get(self._order[0], now) < cutoff:
            old_id = self._order.pop(0)
            self._seen.pop(old_id, None)

    def _evict_overflow(self) -> None:
        """Evict oldest entries if cache is over capacity."""
        while len(self._order) > self.max_size:
            old_id = self._order.pop(0)
            self._seen.pop(old_id, None)

    def check_and_record(
        self,
        msg_id: str,
        timestamp: str | float,
        is_safety: bool = False,
    ) -> tuple[bool, str]:
        """Check whether a message is allowed and record it if so.

        Checks:
        1. ``timestamp`` is within the replay window (not stale).
        2. ``msg_id`` has not been seen before within the window.

        If both checks pass, the msg_id is recorded and the message is allowed.

        Args:
            msg_id:    Unique message identifier.
            timestamp: Unix timestamp of the message (float or ISO string).
            is_safety: True for safety-class messages (window capped to 10s).

        Returns:
            ``(allowed: bool, reason: str)`` — reason is empty if allowed.
        """
        now = time.time()
        mono_now = time.monotonic()
        window = self._effective_window(is_safety)

        # Parse timestamp
        try:
            ts = float(timestamp)
        except (ValueError, TypeError):
            return False, f"Cannot parse timestamp: {timestamp!r}"

        # Check staleness
        age = now - ts
        if age > window:
            logger.warning(
                "Replay rejected: msg_id=%s timestamp=%s age=%.1fs window=%ds",
                msg_id,
                timestamp,
                age,
                window,
            )
            return False, f"Message timestamp is {age:.1f}s old (window={window}s)"

        # Also reject future messages (generous 5s tolerance for clock skew)
        if ts > now + 5:
            return False, f"Message timestamp is in the future: {ts!r}"

        # Evict stale entries before checking seen-set
        self._evict_expired(mono_now, window)

        # Check for duplicate
        if msg_id in self._seen:
            logger.warning("Replay rejected: duplicate msg_id=%s", msg_id)
            return False, f"Duplicate msg_id: {msg_id!r}"

        # Record
        self._seen[msg_id] = mono_now
        self._order.append(msg_id)
        self._evict_overflow()

        return True, ""


def validate_replay(
    message: "RCANMessage",
    cache: ReplayCache,
) -> tuple[bool, str]:
    """Validate a message against the replay cache.

    This should be called BEFORE signature verification.

    ESTOP messages (safety_event == ESTOP or is_safety_message context) are
    never blocked when their timestamp is fresh — only stale/duplicate ESTOPs
    are rejected. This preserves the P66 ESTOP invariant.

    Args:
        message: The :class:`~rcan.message.RCANMessage` to validate.
        cache:   The :class:`ReplayCache` for this receiver.

    Returns:
        ``(allowed: bool, reason: str)``
    """
    # Heuristic: treat as safety message if cmd contains "estop" or "stop"
    # or if message has qos >= 1 (safety messages require QoS ≥ 1 in v1.5)
    is_safety = (
        "estop" in message.cmd.lower()
        or "stop" in message.cmd.lower()
        or message.qos >= 1
    )

    return cache.check_and_record(
        msg_id=message.msg_id,
        timestamp=message.timestamp,
        is_safety=is_safety,
    )


__all__ = ["ReplayCache", "validate_replay", "ReplayAttackError"]
