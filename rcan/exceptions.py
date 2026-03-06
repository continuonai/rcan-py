"""RCAN exception hierarchy."""

from __future__ import annotations


class RCANError(Exception):
    """Base exception for all RCAN errors."""


class RCANAddressError(RCANError):
    """Invalid or unresolvable Robot URI."""


class RCANValidationError(RCANError):
    """RCAN message failed schema validation."""


class RCANGateError(RCANError):
    """Action blocked by a safety gate (confidence or HiTL)."""

    def __init__(self, message: str, gate_type: str = "unknown", value: float | None = None, threshold: float | None = None):
        super().__init__(message)
        self.gate_type = gate_type
        self.value = value
        self.threshold = threshold


class RCANSignatureError(RCANError):
    """RCAN message signature is missing, invalid, or from an untrusted key."""


class RCANRegistryError(RCANError):
    """Error communicating with the RCAN robot registry."""


class RCANTimeoutError(RCANError):
    """Command timed out waiting for a response or HiTL approval."""
