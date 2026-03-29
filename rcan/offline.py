"""
rcan.offline — Offline Operation Mode (GAP-06).

When the RCAN registry is unreachable, robots must continue to accept
owner-level commands from the local network while blocking cross-owner
commands after a configurable grace period.

Spec: §14 — Offline Operation Mode
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Default cross-owner grace period (1 hour)
DEFAULT_CROSS_OWNER_GRACE_S = 3600

# Default max offline period before quarantine (24 hours)
DEFAULT_OFFLINE_GRACE_S = 86400


@dataclass
class OfflineStatus:
    """Describes the robot's current offline state.

    Attributes:
        is_offline:         True if registry is currently unreachable.
        offline_since:      Unix timestamp when offline mode began (None if online).
        grace_remaining_s:  Seconds until cross-owner commands are blocked.
    """

    is_offline: bool
    offline_since: Optional[float] = None
    grace_remaining_s: float = DEFAULT_CROSS_OWNER_GRACE_S

    @property
    def elapsed_offline_s(self) -> float:
        """Seconds since going offline."""
        if not self.is_offline or self.offline_since is None:
            return 0.0
        return time.time() - self.offline_since

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_offline": self.is_offline,
            "offline_since": self.offline_since,
            "grace_remaining_s": self.grace_remaining_s,
            "elapsed_offline_s": self.elapsed_offline_s,
        }


class OfflineModeManager:
    """Manages offline operation policy for an RCAN robot.

    When offline:
    - ESTOP is ALWAYS accepted (P66 invariant).
    - Same-network, same-owner commands accepted within grace period.
    - Cross-owner commands blocked after cross_owner_grace_s.
    - New principals blocked entirely.

    Args:
        cross_owner_grace_s: Seconds before cross-owner commands are blocked.
        offline_grace_s:     Seconds before quarantine mode is entered.
    """

    def __init__(
        self,
        cross_owner_grace_s: float = DEFAULT_CROSS_OWNER_GRACE_S,
        offline_grace_s: float = DEFAULT_OFFLINE_GRACE_S,
    ) -> None:
        self.cross_owner_grace_s = cross_owner_grace_s
        self.offline_grace_s = offline_grace_s
        self._offline_since: Optional[float] = None
        self._known_owners: set[str] = set()

    @property
    def is_offline(self) -> bool:
        return self._offline_since is not None

    def go_offline(self) -> None:
        """Mark the robot as offline (registry unreachable)."""
        if self._offline_since is None:
            self._offline_since = time.time()
            logger.warning(
                "OfflineModeManager: entering offline mode at %s",
                self._offline_since,
            )

    def go_online(self) -> None:
        """Mark the robot as back online."""
        if self._offline_since is not None:
            elapsed = time.time() - self._offline_since
            logger.info("OfflineModeManager: back online after %.1f seconds", elapsed)
            self._offline_since = None

    def register_owner(self, owner_id: str) -> None:
        """Register a known owner (pre-cached from online state)."""
        self._known_owners.add(owner_id)

    def get_status(self) -> OfflineStatus:
        """Return current offline status."""
        if not self.is_offline:
            return OfflineStatus(
                is_offline=False, grace_remaining_s=self.cross_owner_grace_s
            )

        elapsed = time.time() - self._offline_since  # type: ignore[operator]
        grace_remaining = max(0.0, self.cross_owner_grace_s - elapsed)
        return OfflineStatus(
            is_offline=True,
            offline_since=self._offline_since,
            grace_remaining_s=grace_remaining,
        )

    def can_accept_command(
        self,
        msg: Any,
        offline_status: Optional[OfflineStatus] = None,
        local_network: bool = True,
        sender_owner_id: Optional[str] = None,
        robot_owner_id: Optional[str] = None,
    ) -> tuple[bool, str]:
        """Determine whether a command should be accepted in offline mode.

        Rules:
        1. ESTOP is ALWAYS allowed (P66 invariant), regardless of offline state.
        2. If online: always allowed (no offline restrictions).
        3. If offline and local_network=False: blocked.
        4. If offline, local_network=True, and same owner: allowed.
        5. If offline, local_network=True, cross-owner, and within grace: allowed.
        6. If offline, local_network=True, cross-owner, and past grace: blocked.
        7. New/unknown principals are blocked when offline.

        Args:
            msg:              :class:`~rcan.message.RCANMessage` to evaluate.
            offline_status:   Current offline status (fetched if None).
            local_network:    True if sender is on the local network.
            sender_owner_id:  Owner ID of the sending principal.
            robot_owner_id:   Owner ID of this robot.

        Returns:
            ``(allowed: bool, reason: str)``
        """
        cmd = getattr(msg, "cmd", "").lower()

        # P66 invariant: ESTOP is NEVER blocked
        if "estop" in cmd or cmd == "stop":
            return True, "ESTOP/STOP always allowed (P66 invariant)"

        status = offline_status if offline_status is not None else self.get_status()

        if not status.is_offline:
            return True, "Online — no restrictions"

        if not local_network:
            return False, "Offline: only local-network commands accepted"

        # Same owner check
        is_same_owner = (
            sender_owner_id is not None
            and robot_owner_id is not None
            and sender_owner_id == robot_owner_id
        )

        # New principal check (not seen before going offline)
        if sender_owner_id and sender_owner_id not in self._known_owners:
            return False, (
                f"Offline: new principal {sender_owner_id!r} not pre-authorized"
            )

        if is_same_owner:
            return True, "Offline: same-owner local command accepted"

        # Cross-owner: check grace period
        if status.grace_remaining_s > 0:
            return True, (
                f"Offline: cross-owner accepted within grace period "
                f"({status.grace_remaining_s:.0f}s remaining)"
            )

        return False, (
            f"Offline: cross-owner commands blocked after grace period "
            f"({self.cross_owner_grace_s}s). Robot in quarantine mode."
        )


__all__ = [
    "OfflineModeManager",
    "OfflineStatus",
]
