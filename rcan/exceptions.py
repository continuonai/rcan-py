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

    def __init__(
        self,
        message: str,
        gate_type: str = "unknown",
        value: float | None = None,
        threshold: float | None = None,
    ):
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


class RCANNodeError(RCANError):
    """Error communicating with an RCAN distributed registry node."""


# ---------------------------------------------------------------------------
# v1.5 additions
# ---------------------------------------------------------------------------


class VersionIncompatibleError(RCANError):
    """Incoming message MAJOR version does not match receiver's MAJOR version."""


class ReplayAttackError(RCANError):
    """Message rejected as a replay (duplicate msg_id or stale timestamp)."""


class ClockDriftError(RCANError):
    """System clock is not synchronized or exceeds allowed drift tolerance."""


class DelegationChainExceededError(RCANError):
    """Delegation chain depth exceeds the maximum allowed (4 hops)."""


class DelegationVerificationError(RCANError):
    """A delegation hop signature failed verification."""


class QoSAckTimeoutError(RCANError):
    """QoS acknowledgement timed out after max retries."""


class SafetyHaltError(RCANError):
    """A safety halt was triggered (e.g. ESTOP ACK timeout)."""


class ConfigAuthorizationError(RCANError):
    """Config update requires elevated role (creator) for safety overrides."""


class ConfigHashMismatchError(RCANError):
    """Config payload hash does not match declared config_hash."""


class RevocationError(RCANError):
    """A robot's identity has been revoked or suspended."""


class ConsentError(RCANError):
    """Consent is missing, expired, or invalid."""


__all__ = [
    "RCANError",
    "RCANAddressError",
    "RCANValidationError",
    "RCANGateError",
    "RCANSignatureError",
    "RCANRegistryError",
    "RCANTimeoutError",
    "RCANNodeError",
    # v1.5
    "VersionIncompatibleError",
    "ReplayAttackError",
    "ClockDriftError",
    "DelegationChainExceededError",
    "DelegationVerificationError",
    "QoSAckTimeoutError",
    "SafetyHaltError",
    "ConfigAuthorizationError",
    "ConfigHashMismatchError",
    "RevocationError",
    "ConsentError",
]
