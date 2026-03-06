"""
RCAN Safety Gates — ConfidenceGate and HiTLGate.

Gates are the software equivalent of hardware end stops: hard limits that
operate independently of whether the model got it right.

Spec: https://rcan.dev/spec#section-16
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from rcan.exceptions import RCANGateError


class GateResult(Enum):
    """Outcome of a safety gate check."""
    PASS = "pass"
    BLOCK = "block"
    PENDING = "pending"  # Awaiting HiTL approval


@dataclass
class ConfidenceGate:
    """
    Block actions below a minimum AI confidence threshold.

    The gate doesn't trust the model — that's the point. Even if the model
    is right 99.99% of the time, the gate is for the 0.01%.

    Example:
        gate = ConfidenceGate(threshold=0.8)
        result = gate.check(confidence=0.91)  # GateResult.PASS
        result = gate.check(confidence=0.65)  # GateResult.BLOCK

    Args:
        threshold:      Minimum confidence to pass [0.0–1.0].
        action_type:    Optional: only apply gate to this action type.
        raise_on_block: If True, raises RCANGateError instead of returning BLOCK.
    """

    threshold: float = 0.7
    action_type: str | None = None
    raise_on_block: bool = False

    def __post_init__(self) -> None:
        if not (0.0 <= self.threshold <= 1.0):
            raise ValueError(f"threshold must be in [0.0, 1.0], got {self.threshold}")

    def check(
        self,
        confidence: float,
        action_type: str | None = None,
    ) -> GateResult:
        """
        Check whether the given confidence passes the gate.

        Args:
            confidence:  AI inference confidence [0.0–1.0].
            action_type: Action being checked (used for action_type filtering).

        Returns:
            :class:`GateResult`.PASS or .BLOCK

        Raises:
            RCANGateError: If ``raise_on_block=True`` and confidence is below threshold.
        """
        # If gate is scoped to a specific action, skip for others
        if self.action_type is not None and action_type is not None:
            if action_type != self.action_type:
                return GateResult.PASS

        if confidence >= self.threshold:
            return GateResult.PASS

        if self.raise_on_block:
            raise RCANGateError(
                f"Confidence {confidence:.3f} below threshold {self.threshold:.3f}",
                gate_type="confidence",
                value=confidence,
                threshold=self.threshold,
            )
        return GateResult.BLOCK

    def allows(self, confidence: float, action_type: str | None = None) -> bool:
        """Convenience bool wrapper around :meth:`check`."""
        return self.check(confidence, action_type) == GateResult.PASS

    def __repr__(self) -> str:
        return f"ConfidenceGate(threshold={self.threshold}, action_type={self.action_type!r})"


@dataclass
class HiTLGate:
    """
    Human-in-the-Loop gate — require explicit human approval before executing.

    The gate calls an ``approval_fn`` and blocks until approval is received
    or the timeout expires.

    Example (synchronous):
        def my_approval(action, params, confidence):
            print(f"Approve {action} with confidence {confidence}? [y/N]")
            return input().strip().lower() == 'y'

        gate = HiTLGate(approval_fn=my_approval, timeout_s=30)
        result = gate.check("move_forward", {"distance_m": 2.0}, confidence=0.85)

    Args:
        approval_fn:    Callable(action, params, confidence) → bool.
                        Called synchronously; for async use see RCANClient.
        timeout_s:      Seconds to wait for approval before blocking (default 30).
        required_above: Confidence threshold ABOVE which HiTL is required.
                        Set to None to always require HiTL.
        required_below: Confidence threshold BELOW which HiTL is required.
                        Set to None to skip this check.
        raise_on_timeout: Raise RCANGateError on timeout instead of blocking.
    """

    approval_fn: Callable[[str, dict, float | None], bool] | None = None
    timeout_s: float = 30.0
    required_above: float | None = None   # e.g. 0.95 → require HiTL for very high confidence (sanity check)
    required_below: float | None = None   # e.g. 0.7 → require HiTL when confidence is low
    raise_on_timeout: bool = False

    def needs_approval(
        self, action: str, confidence: float | None = None
    ) -> bool:
        """
        Return True if this action/confidence combination requires HiTL approval.
        """
        if self.required_above is None and self.required_below is None:
            return True  # Always require HiTL
        if confidence is None:
            return True  # No confidence info → require review

        needs = False
        if self.required_below is not None and confidence < self.required_below:
            needs = True
        if self.required_above is not None and confidence > self.required_above:
            needs = True
        return needs

    def check(
        self,
        action: str,
        params: dict | None = None,
        confidence: float | None = None,
    ) -> GateResult:
        """
        Check whether this action is approved by a human.

        Returns:
            GateResult.PASS if approved, .BLOCK if denied or timed out.
        """
        if not self.needs_approval(action, confidence):
            return GateResult.PASS

        if self.approval_fn is None:
            # No approval function configured — block by default
            return GateResult.BLOCK

        start = time.monotonic()
        try:
            approved = self.approval_fn(action, params or {}, confidence)
            elapsed = time.monotonic() - start
            if elapsed > self.timeout_s:
                if self.raise_on_timeout:
                    raise RCANGateError(
                        f"HiTL approval timed out after {self.timeout_s}s",
                        gate_type="hitl",
                    )
                return GateResult.BLOCK
            return GateResult.PASS if approved else GateResult.BLOCK
        except RCANGateError:
            raise
        except Exception:
            return GateResult.BLOCK  # Any error in approval_fn → block

    def allows(
        self, action: str, params: dict | None = None, confidence: float | None = None
    ) -> bool:
        """Convenience bool wrapper."""
        return self.check(action, params, confidence) == GateResult.PASS

    def __repr__(self) -> str:
        return (
            f"HiTLGate(required_below={self.required_below}, "
            f"required_above={self.required_above}, timeout_s={self.timeout_s})"
        )
