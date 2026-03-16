"""
rcan.config_update — CONFIG_UPDATE Protocol (GAP-07).

Defines the payload schema for config update messages and validates that
safety parameter changes require elevated creator-level authorization.

Spec: §9.2 — CONFIG_UPDATE Wire Protocol
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from rcan.exceptions import ConfigAuthorizationError, ConfigHashMismatchError, RCANValidationError

logger = logging.getLogger(__name__)

# Fields that require safety scope (creator JWT) to modify
_DANGEROUS_FIELDS: frozenset[str] = frozenset(
    {
        "brain.provider",
        "safety.max_linear_speed_mps",
        "safety.emergency_stop_distance",
        "safety.watchdog_timeout",
        "safety.proximity_threshold",
    }
)

# Prefix-based dangerous fields (any field under "safety.*")
_DANGEROUS_PREFIXES: tuple[str, ...] = ("safety.",)


def _is_dangerous_field(key: str) -> bool:
    """Return True if *key* requires safety scope to modify."""
    if key in _DANGEROUS_FIELDS:
        return True
    return any(key.startswith(prefix) for prefix in _DANGEROUS_PREFIXES)


@dataclass
class ConfigUpdateMessage:
    """Payload for a CONFIG_UPDATE message (MessageType.CONFIG = 5).

    Attributes:
        config_diff:     Dict of key→value changes to apply.
        scope:           Authorization scope required (e.g. ``"operator"``).
        rollback_config: Previous config snapshot for rollback.
        config_hash:     SHA-256 hex digest of the canonical config_diff JSON.
        config_version:  Semver of the new config (e.g. ``"1.2.0"``).
        diff_only:       True if payload is a diff; False if full config.
        requires_restart: True if the change requires a robot restart.
        safety_overrides: True if safety parameters are being changed.
    """

    config_diff: dict[str, Any]
    scope: str
    rollback_config: dict[str, Any]
    config_hash: str = ""
    config_version: str = "1.0.0"
    diff_only: bool = True
    requires_restart: bool = False
    safety_overrides: bool = False

    def __post_init__(self) -> None:
        # Auto-compute config_hash if not provided
        if not self.config_hash:
            self.config_hash = hash_config_payload(self.config_diff)
        # Auto-detect safety_overrides
        if not self.safety_overrides:
            self.safety_overrides = any(
                _is_dangerous_field(k) for k in self.config_diff
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "config_diff": self.config_diff,
            "scope": self.scope,
            "rollback_config": self.rollback_config,
            "config_hash": self.config_hash,
            "config_version": self.config_version,
            "diff_only": self.diff_only,
            "requires_restart": self.requires_restart,
            "safety_overrides": self.safety_overrides,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConfigUpdateMessage":
        return cls(
            config_diff=data.get("config_diff", {}),
            scope=data.get("scope", "operator"),
            rollback_config=data.get("rollback_config", {}),
            config_hash=data.get("config_hash", ""),
            config_version=data.get("config_version", "1.0.0"),
            diff_only=data.get("diff_only", True),
            requires_restart=data.get("requires_restart", False),
            safety_overrides=data.get("safety_overrides", False),
        )


def hash_config_payload(config_diff: dict[str, Any]) -> str:
    """Compute SHA-256 of the canonical (sorted) JSON of *config_diff*.

    Args:
        config_diff: Dict of config changes.

    Returns:
        Hex digest string (64 chars).
    """
    canonical = json.dumps(config_diff, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def make_config_update(
    diff: dict[str, Any],
    scope: str,
    rollback: dict[str, Any],
    config_version: str = "1.0.0",
    requires_restart: bool = False,
) -> "RCANMessage":  # type: ignore[name-defined]
    """Build an RCAN CONFIG_UPDATE message.

    Args:
        diff:            Key→value changes to apply.
        scope:           Authorization scope required (``"operator"`` or ``"creator"``).
        rollback:        Previous config snapshot for rollback.
        config_version:  Semver of new config.
        requires_restart: True if restart is needed.

    Returns:
        :class:`~rcan.message.RCANMessage` with CONFIG type.

    Raises:
        ConfigAuthorizationError: If diff contains safety fields but scope
                                  is not ``"creator"``.
    """
    from rcan.message import RCANMessage

    # Validate scope for dangerous fields
    safety_fields = [k for k in diff if _is_dangerous_field(k)]
    if safety_fields and scope != "creator":
        raise ConfigAuthorizationError(
            f"Safety parameter changes {safety_fields!r} require scope='creator', "
            f"got scope={scope!r}"
        )

    config_msg = ConfigUpdateMessage(
        config_diff=diff,
        scope=scope,
        rollback_config=rollback,
        config_version=config_version,
        requires_restart=requires_restart,
    )

    return RCANMessage(
        cmd="config_update",
        target="rcan://rcan.dev/system/config/v1/self",
        params=config_msg.to_dict(),
    )


def validate_config_update(msg: Any) -> tuple[bool, str]:
    """Validate a CONFIG_UPDATE RCANMessage.

    Checks:
    - Payload has required fields (config_diff, scope, rollback_config).
    - config_hash matches computed hash of config_diff.
    - Safety fields require scope=='creator'.

    Args:
        msg: :class:`~rcan.message.RCANMessage` with CONFIG command.

    Returns:
        ``(valid: bool, reason: str)`` — reason empty if valid.
    """
    params = getattr(msg, "params", {})

    if "config_diff" not in params:
        return False, "Missing 'config_diff' in config update payload"
    if "scope" not in params:
        return False, "Missing 'scope' in config update payload"
    if "rollback_config" not in params:
        return False, "Missing 'rollback_config' in config update payload"

    config_diff = params["config_diff"]
    scope = params.get("scope", "")
    declared_hash = params.get("config_hash", "")

    # Verify config_hash
    if declared_hash:
        expected_hash = hash_config_payload(config_diff)
        if declared_hash != expected_hash:
            return False, (
                f"config_hash mismatch: declared={declared_hash[:16]}…, "
                f"computed={expected_hash[:16]}…"
            )

    # Check safety scope
    safety_fields = [k for k in config_diff if _is_dangerous_field(k)]
    if safety_fields and scope != "creator":
        return False, (
            f"Safety parameter changes {safety_fields!r} require scope='creator', "
            f"got scope={scope!r}"
        )

    return True, ""


__all__ = [
    "ConfigUpdateMessage",
    "make_config_update",
    "validate_config_update",
    "hash_config_payload",
]
