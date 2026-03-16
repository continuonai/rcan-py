"""
rcan.qos — Quality of Service / Delivery Guarantees (GAP-11).

Defines QoS levels and a QoSManager for at-least-once and exactly-once
message delivery. Safety messages MUST use QoS ≥ 1; ESTOP MUST use QoS 2.

Spec: §5.3 — Quality of Service
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Optional

from rcan.exceptions import QoSAckTimeoutError, SafetyHaltError

logger = logging.getLogger(__name__)


class QoSLevel(IntEnum):
    """Quality of Service delivery levels.

    - FIRE_AND_FORGET (0): No acknowledgement required. Use for TELEOP streams.
    - ACKNOWLEDGED (1): At-least-once; sender retries until COMMAND_ACK received.
    - EXACTLY_ONCE (2): Two-phase commit (COMMAND_ACK + COMMAND_COMMIT). ESTOP MUST use this.
    """

    FIRE_AND_FORGET = 0
    ACKNOWLEDGED = 1
    EXACTLY_ONCE = 2


@dataclass
class _PendingMessage:
    """Tracks a message awaiting acknowledgement."""

    msg_id: str
    message: Any  # RCANMessage
    send_fn: Callable
    sent_at: float
    retries: int = 0
    acked: bool = False
    committed: bool = False


class QoSManager:
    """Manages QoS delivery guarantees for outbound messages.

    Tracks pending acknowledgements, handles retries with exponential backoff,
    and triggers safety halts when ESTOP ACKs are not received.

    Args:
        ack_timeout_s: Seconds to wait for COMMAND_ACK (default 5.0).
        max_retries:   Maximum number of retry attempts (default 3).
    """

    def __init__(
        self,
        ack_timeout_s: float = 5.0,
        max_retries: int = 3,
    ) -> None:
        self.ack_timeout_s = ack_timeout_s
        self.max_retries = max_retries
        self._pending: dict[str, _PendingMessage] = {}

    def send_with_ack(
        self,
        message: Any,
        send_fn: Callable[[Any], None],
    ) -> bool:
        """Send a message and wait for acknowledgement (blocking retry loop).

        For QoS 1 (ACKNOWLEDGED): retries up to max_retries with exponential backoff.
        For QoS 2 (EXACTLY_ONCE): additionally waits for COMMAND_COMMIT.

        Args:
            message: :class:`~rcan.message.RCANMessage` to send.
            send_fn: Callable that transmits the message (e.g. HTTP POST).

        Returns:
            True if acknowledged within timeout and retries.

        Raises:
            QoSAckTimeoutError: If max retries exhausted without ACK.
            SafetyHaltError:    If ESTOP ACK times out (triggers safety halt).
        """
        qos = getattr(message, "qos", QoSLevel.FIRE_AND_FORGET)
        if qos == QoSLevel.FIRE_AND_FORGET:
            send_fn(message)
            return True

        is_estop = "estop" in getattr(message, "cmd", "").lower()
        pending = _PendingMessage(
            msg_id=message.msg_id,
            message=message,
            send_fn=send_fn,
            sent_at=time.monotonic(),
        )
        self._pending[message.msg_id] = pending

        # Retry loop with exponential backoff
        backoff = 0.1  # 100ms initial
        for attempt in range(self.max_retries + 1):
            logger.debug(
                "QoS send attempt=%d msg_id=%s qos=%d",
                attempt,
                message.msg_id,
                qos,
            )
            try:
                send_fn(message)
            except Exception as exc:
                logger.warning("QoS send failed on attempt %d: %s", attempt, exc)

            # Wait for ACK
            deadline = time.monotonic() + self.ack_timeout_s
            while time.monotonic() < deadline:
                if pending.acked:
                    logger.debug("ACK received for msg_id=%s", message.msg_id)
                    if qos == QoSLevel.EXACTLY_ONCE:
                        # Wait for COMMIT
                        if pending.committed:
                            self._pending.pop(message.msg_id, None)
                            return True
                        # else keep waiting
                    else:
                        self._pending.pop(message.msg_id, None)
                        return True
                time.sleep(0.05)

            if attempt < self.max_retries:
                logger.warning(
                    "ACK timeout for msg_id=%s (attempt %d/%d), retrying in %.2fs",
                    message.msg_id,
                    attempt + 1,
                    self.max_retries,
                    backoff,
                )
                time.sleep(backoff)
                backoff = min(backoff * 2, 5.0)
            else:
                # Max retries exhausted
                self._pending.pop(message.msg_id, None)
                if is_estop:
                    logger.critical(
                        "ESTOP ACK timeout after %d retries — triggering safety halt",
                        self.max_retries,
                    )
                    raise SafetyHaltError(
                        f"ESTOP delivery unconfirmed after {self.max_retries} retries. "
                        "Triggering local safety halt."
                    )
                raise QoSAckTimeoutError(
                    f"No ACK received for msg_id={message.msg_id!r} "
                    f"after {self.max_retries} retries."
                )

        return False

    def record_ack(self, msg_id: str) -> None:
        """Record receipt of a COMMAND_ACK for the given msg_id."""
        if msg_id in self._pending:
            self._pending[msg_id].acked = True
            logger.debug("ACK recorded for msg_id=%s", msg_id)

    def record_commit(self, msg_id: str) -> None:
        """Record receipt of a COMMAND_COMMIT for the given msg_id (QoS 2)."""
        if msg_id in self._pending:
            self._pending[msg_id].committed = True
            logger.debug("COMMIT recorded for msg_id=%s", msg_id)

    def pending_count(self) -> int:
        """Return number of messages awaiting acknowledgement."""
        return len(self._pending)


def make_estop_with_qos(ruri: str, reason: str) -> Any:
    """Create an ESTOP RCANMessage with QoS=EXACTLY_ONCE enforced.

    Overrides the safety.make_estop_message with a proper RCANMessage
    that carries QoS=2 for reliable delivery.

    Args:
        ruri:   Target robot RURI.
        reason: Human-readable reason for ESTOP.

    Returns:
        :class:`~rcan.message.RCANMessage` with qos=2.
    """
    from rcan.message import RCANMessage

    return RCANMessage(
        cmd="ESTOP",
        target=ruri,
        params={"reason": reason, "safety_event": "ESTOP"},
        qos=int(QoSLevel.EXACTLY_ONCE),
    )


__all__ = [
    "QoSLevel",
    "QoSManager",
    "make_estop_with_qos",
]
