"""
rcan.version — single source of truth for the RCAN spec version.

All modules that need the current spec version MUST import from here.
Do NOT hardcode version strings anywhere else.

Spec: https://rcan.dev/spec#section-3-5
"""

from __future__ import annotations

# RCAN specification version this SDK implements.
# Follows MAJOR.MINOR semantic versioning.
# Receivers MUST accept messages from same MAJOR, lower-or-equal MINOR.
SPEC_VERSION: str = "1.5"

# Supported v1.5 feature flags (VERSION_NEGOTIATION protocol)
SUPPORTED_FEATURES: frozenset[str] = frozenset(
    {
        "VERSION_NEGOTIATION",
        "REPLAY_PREVENTION",
        "CLOCK_SYNC",
        "CLOUD_RELAY_IDENTITY",
        "QOS_DELIVERY",
        "CONFIG_UPDATE",
        "KEY_ROTATION",
        "CONSENT_WIRE",
        "ROBOT_REVOCATION",
        "TRAINING_CONSENT",
        "DELEGATION_CHAIN",
        "OFFLINE_OPERATION",
        "FLEET_BROADCAST",
        "OBSERVER_MODE",
        "PHYSICAL_PRESENCE",
        "FAULT_REPORTING",
        "AUDIT_EXPORT",
    }
)

__all__ = ["SPEC_VERSION", "SUPPORTED_FEATURES"]
