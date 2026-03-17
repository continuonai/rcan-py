"""
rcan.identity — Human Identity Verification and Level of Assurance (GAP-14).

Provides LoA (Level of Assurance) definitions, JWT claim parsing, scope
validation, and configurable LoA policies.

Default policy: all LoA = 1 (backward compatible with v1.5).
Recommended production policy: control ≥ 2, safety ≥ 3.

Spec: §14 — Human Identity Verification
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Optional

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Level of Assurance
# ---------------------------------------------------------------------------


class LevelOfAssurance(IntEnum):
    """RCAN Level of Assurance (LoA) for human identity.

    Levels:
        ANONYMOUS (1):       No identity verification. Backward-compatible default.
        EMAIL_VERIFIED (2):  Email address verified (e.g. magic link, OAuth).
        HARDWARE_TOKEN (3):  Hardware security key (FIDO2/WebAuthn, YubiKey, etc.).
    """

    ANONYMOUS = 1
    EMAIL_VERIFIED = 2
    HARDWARE_TOKEN = 3


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class IdentityRecord:
    """Verified identity record for a human principal.

    Attributes:
        sub:                  Subject identifier (e.g. user UUID or email hash).
        registry_url:         Registry that issued this identity.
        loa:                  Level of assurance for this identity.
        registry_tier:        Tier of the issuing registry (e.g. ``"authoritative"``).
        fido2_credential_id:  FIDO2 credential ID (required for LoA 3).
        verified_at:          ISO-8601 timestamp of the most recent verification.
    """

    sub: str
    registry_url: str
    loa: LevelOfAssurance
    registry_tier: str
    verified_at: str
    fido2_credential_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "sub": self.sub,
            "registry_url": self.registry_url,
            "loa": int(self.loa),
            "registry_tier": self.registry_tier,
            "verified_at": self.verified_at,
        }
        if self.fido2_credential_id is not None:
            d["fido2_credential_id"] = self.fido2_credential_id
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IdentityRecord":
        return cls(
            sub=data["sub"],
            registry_url=data["registry_url"],
            loa=LevelOfAssurance(int(data.get("loa", 1))),
            registry_tier=data.get("registry_tier", "community"),
            verified_at=data.get("verified_at", ""),
            fido2_credential_id=data.get("fido2_credential_id"),
        )


# ---------------------------------------------------------------------------
# LoA Policy
# ---------------------------------------------------------------------------


@dataclass
class LoaPolicy:
    """Minimum LoA requirements per RCAN command scope.

    All fields default to 1 (ANONYMOUS) for backward compatibility.
    The recommended production policy raises control to 2 and safety to 3.

    Attributes:
        min_loa_for_discover: Minimum LoA for scope ``"discover"``.
        min_loa_for_status:   Minimum LoA for scope ``"status"``.
        min_loa_for_chat:     Minimum LoA for scope ``"chat"``.
        min_loa_for_control:  Minimum LoA for scope ``"control"`` / ``"teleop"``.
        min_loa_for_safety:   Minimum LoA for scope ``"safety"`` / ESTOP commands.
    """

    min_loa_for_discover: int = 1
    min_loa_for_status: int = 1
    min_loa_for_chat: int = 1
    min_loa_for_control: int = 1
    min_loa_for_safety: int = 1


# Default: all LoA = 1 (backward compatible)
DEFAULT_LOA_POLICY: LoaPolicy = LoaPolicy(1, 1, 1, 1, 1)

# Recommended production: control ≥ 2, safety ≥ 3
PRODUCTION_LOA_POLICY: LoaPolicy = LoaPolicy(1, 1, 1, 2, 3)


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------


def extract_loa_from_jwt(token: str) -> LevelOfAssurance:
    """Parse an RCAN JWT (without signature verification) and read the ``loa`` claim.

    Args:
        token: Raw JWT string (``header.payload.signature``).

    Returns:
        :class:`LevelOfAssurance` from the ``loa`` claim, or
        ``LevelOfAssurance.ANONYMOUS`` if the claim is absent or the token
        cannot be parsed.
    """
    try:
        parts = token.split(".")
        if len(parts) < 2:
            log.debug("extract_loa_from_jwt: invalid JWT structure (< 2 parts)")
            return LevelOfAssurance.ANONYMOUS

        payload_b64 = parts[1]
        # Restore base64 padding
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding

        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        raw_loa = payload.get("loa")
        if raw_loa is None:
            log.debug("extract_loa_from_jwt: no loa claim; defaulting to ANONYMOUS")
            return LevelOfAssurance.ANONYMOUS

        loa_int = int(raw_loa)
        return LevelOfAssurance(loa_int)
    except Exception as exc:  # noqa: BLE001
        log.debug("extract_loa_from_jwt: failed to extract loa (%s); defaulting to ANONYMOUS", exc)
        return LevelOfAssurance.ANONYMOUS


# ---------------------------------------------------------------------------
# Scope validation
# ---------------------------------------------------------------------------

# Canonical scope-to-policy-field mapping
_SCOPE_FIELD_MAP: dict[str, str] = {
    "discover": "min_loa_for_discover",
    "status": "min_loa_for_status",
    "chat": "min_loa_for_chat",
    "control": "min_loa_for_control",
    "teleop": "min_loa_for_control",
    "operator": "min_loa_for_control",
    "safety": "min_loa_for_safety",
    "estop": "min_loa_for_safety",
    "fleet": "min_loa_for_control",
    "observer": "min_loa_for_status",
    "training_data": "min_loa_for_control",
}


def validate_loa_for_scope(
    loa: LevelOfAssurance,
    scope: str,
    min_loa_overrides: Optional[dict[str, int]] = None,
    policy: Optional[LoaPolicy] = None,
) -> tuple[bool, str]:
    """Check whether *loa* meets the minimum requirement for *scope*.

    Args:
        loa:               Caller's :class:`LevelOfAssurance`.
        scope:             RCAN scope string (e.g. ``"control"``, ``"safety"``).
        min_loa_overrides: Optional per-scope override dict
                           (e.g. ``{"control": 3, "safety": 3}``).
        policy:            :class:`LoaPolicy` to use (defaults to
                           :data:`DEFAULT_LOA_POLICY`).

    Returns:
        ``(True, "")`` if LoA meets requirement,
        ``(False, reason)`` otherwise.
    """
    if policy is None:
        policy = DEFAULT_LOA_POLICY

    # Check override first
    if min_loa_overrides and scope in min_loa_overrides:
        required = min_loa_overrides[scope]
    else:
        # Look up in policy
        scope_lower = scope.lower()
        field_name = _SCOPE_FIELD_MAP.get(scope_lower)
        if field_name is not None:
            required = getattr(policy, field_name)
        else:
            # Unknown scope — apply control-level minimum as safe default
            required = policy.min_loa_for_control
            log.debug(
                "validate_loa_for_scope: unknown scope %r; applying control-level minimum (%d)",
                scope,
                required,
            )

    loa_int = int(loa)
    if loa_int >= required:
        return True, ""
    return False, (
        f"Scope {scope!r} requires LoA ≥ {required} "
        f"(LevelOfAssurance.{LevelOfAssurance(required).name}), "
        f"but caller has LoA {loa_int} "
        f"(LevelOfAssurance.{loa.name})"
    )


__all__ = [
    "LevelOfAssurance",
    "IdentityRecord",
    "LoaPolicy",
    "DEFAULT_LOA_POLICY",
    "PRODUCTION_LOA_POLICY",
    "extract_loa_from_jwt",
    "validate_loa_for_scope",
]
