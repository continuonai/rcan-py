"""
rcan.identity — RCAN v2.1 Role-Based Access Control and Identity.

Defines the seven-level role hierarchy (§2), JWT claim parsing, scope
validation, and M2M authorization helpers.

Roles (v2.1):
    GUEST        (1) — read-only, anonymous
    OPERATOR     (2) — operational control
    CONTRIBUTOR  (3) — idle compute donation scope (maps to level 2.5 in JWT)
    ADMIN        (4) — configuration, user management
    M2M_PEER     (5) — robot-to-robot; issued by ADMIN
    CREATOR      (6) — full hardware/software control
    M2M_TRUSTED  (7) — fleet orchestration; RRF-issued only (JWT level 6)

Note: JWT ``rcan_role`` level values are 1–6; Python enum values are 1–7
(CONTRIBUTOR occupies position 3 internally, maps to JWT level 2.5 via
the ``ROLE_TO_JWT_LEVEL`` table).

Spec: §2 — Role-Based Access Control
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Role enum  (v2.1)
# ---------------------------------------------------------------------------


class Role(IntEnum):
    """RCAN v2.1 role hierarchy.

    Integer values are internal ordering only. Use :data:`ROLE_TO_JWT_LEVEL`
    and :func:`role_from_jwt_level` to map to/from JWT ``rcan_role`` level values.

    Levels (JWT):
        GUEST        → 1
        OPERATOR     → 2
        CONTRIBUTOR  → 2 (scoped subset; JWT claim uses fractional 2.5 string)
        ADMIN        → 3
        M2M_PEER     → 4
        CREATOR      → 5
        M2M_TRUSTED  → 6  (RRF-issued only)
    """

    GUEST       = 1
    OPERATOR    = 2
    CONTRIBUTOR = 3   # JWT level 2.5 — scoped to fleet.contribute only
    ADMIN       = 4   # JWT level 3
    M2M_PEER    = 5   # JWT level 4 — authorized by ADMIN
    CREATOR     = 6   # JWT level 5 — full hardware control
    M2M_TRUSTED = 7   # JWT level 6 — RRF-issued, fleet orchestration


# Map Role → JWT ``rcan_role`` level (float to accommodate 2.5)
ROLE_TO_JWT_LEVEL: dict[Role, float] = {
    Role.GUEST:       1.0,
    Role.OPERATOR:    2.0,
    Role.CONTRIBUTOR: 2.5,
    Role.ADMIN:       3.0,
    Role.M2M_PEER:    4.0,
    Role.CREATOR:     5.0,
    Role.M2M_TRUSTED: 6.0,
}

_JWT_LEVEL_TO_ROLE: dict[float, Role] = {v: k for k, v in ROLE_TO_JWT_LEVEL.items()}


def role_from_jwt_level(level: float) -> Optional[Role]:
    """Return the :class:`Role` for a JWT ``rcan_role`` numeric level."""
    return _JWT_LEVEL_TO_ROLE.get(float(level))


# ---------------------------------------------------------------------------
# Backward-compatible LoA alias
# ---------------------------------------------------------------------------

# v1.x code imported LevelOfAssurance. Keep a shim so existing callsites
# continue to work during migration; remove in v3.0.
LevelOfAssurance = Role  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Scopes  (v2.1)
# ---------------------------------------------------------------------------

#: Minimum role required per scope.
SCOPE_MIN_ROLE: dict[str, Role] = {
    "status":        Role.GUEST,
    "discover":      Role.GUEST,
    "chat":          Role.GUEST,
    "observer":      Role.GUEST,
    "contribute":    Role.CONTRIBUTOR,
    "control":       Role.OPERATOR,
    "teleop":        Role.OPERATOR,
    "training":      Role.ADMIN,
    "training_data": Role.ADMIN,
    "config":        Role.ADMIN,
    "authority":     Role.ADMIN,
    "admin":         Role.CREATOR,
    "safety":        Role.CREATOR,
    "estop":         Role.CREATOR,
    "fleet.trusted": Role.M2M_TRUSTED,
}


# ---------------------------------------------------------------------------
# Identity record
# ---------------------------------------------------------------------------


@dataclass
class IdentityRecord:
    """Verified identity record for a principal (human or machine).

    Attributes:
        sub:          Subject identifier (UUID, RRN, or orchestrator id).
        role:         RCAN v2.1 :class:`Role`.
        registry_url: Registry that issued this identity.
        scopes:       Granted scopes from JWT.
        verified_at:  ISO-8601 timestamp of most recent verification.
        peer_rrn:     For M2M_PEER tokens — the authorized peer's RRN.
        fleet_rrns:   For M2M_TRUSTED tokens — explicit fleet allowlist.
        is_m2m:       True when the principal is a machine (M2M_PEER or M2M_TRUSTED).
    """

    sub: str
    role: Role
    registry_url: str = ""
    scopes: list[str] = field(default_factory=list)
    verified_at: str = ""
    peer_rrn: Optional[str] = None
    fleet_rrns: list[str] = field(default_factory=list)

    @property
    def is_m2m(self) -> bool:
        return self.role in (Role.M2M_PEER, Role.M2M_TRUSTED)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "sub": self.sub,
            "rcan_role": ROLE_TO_JWT_LEVEL[self.role],
            "registry_url": self.registry_url,
            "scopes": self.scopes,
            "verified_at": self.verified_at,
        }
        if self.peer_rrn:
            d["peer_rrn"] = self.peer_rrn
        if self.fleet_rrns:
            d["fleet_rrns"] = self.fleet_rrns
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IdentityRecord":
        raw_level = float(data.get("rcan_role", 1.0))
        role = role_from_jwt_level(raw_level) or Role.GUEST
        return cls(
            sub=data.get("sub", ""),
            role=role,
            registry_url=data.get("registry_url", ""),
            scopes=list(data.get("scopes", data.get("rcan_scopes", []))),
            verified_at=data.get("verified_at", ""),
            peer_rrn=data.get("peer_rrn"),
            fleet_rrns=list(data.get("fleet_rrns", [])),
        )


# ---------------------------------------------------------------------------
# LoA Policy  (v2.1 — scope-based)
# ---------------------------------------------------------------------------


@dataclass
class LoaPolicy:
    """Minimum :class:`Role` requirements per RCAN scope.

    Defaults to GUEST (1) everywhere for backward compatibility.
    Production deployments should raise control to OPERATOR (2) and
    safety/admin to CREATOR (6).
    """

    min_role_for_discover: Role = Role.GUEST
    min_role_for_status:   Role = Role.GUEST
    min_role_for_chat:     Role = Role.GUEST
    min_role_for_control:  Role = Role.GUEST
    min_role_for_safety:   Role = Role.GUEST


DEFAULT_LOA_POLICY: LoaPolicy = LoaPolicy()

PRODUCTION_LOA_POLICY: LoaPolicy = LoaPolicy(
    min_role_for_discover=Role.GUEST,
    min_role_for_status=Role.GUEST,
    min_role_for_chat=Role.GUEST,
    min_role_for_control=Role.OPERATOR,
    min_role_for_safety=Role.CREATOR,
)


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------


def extract_role_from_jwt(token: str) -> Role:
    """Parse an RCAN v2.1 JWT and return the ``rcan_role`` claim as a :class:`Role`.

    Falls back to :attr:`Role.GUEST` when the claim is absent or the token
    cannot be parsed.
    """
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return Role.GUEST

        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding

        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        # v2.1 JWT uses rcan_role (float level)
        raw = payload.get("rcan_role")
        if raw is not None:
            role = role_from_jwt_level(float(raw))
            if role is not None:
                return role

        # v1.x fallback: loa claim (integer)
        loa = payload.get("loa")
        if loa is not None:
            role = role_from_jwt_level(float(int(loa)))
            if role is not None:
                return role

        return Role.GUEST
    except Exception as exc:  # noqa: BLE001
        log.debug("extract_role_from_jwt: failed (%s); defaulting to GUEST", exc)
        return Role.GUEST


# Backward-compat alias
extract_loa_from_jwt = extract_role_from_jwt


def extract_identity_from_jwt(token: str) -> IdentityRecord:
    """Parse an RCAN v2.1 JWT and return an :class:`IdentityRecord`.

    Does NOT verify the JWT signature. Use castor.auth or rcan.m2m for
    verified parsing.
    """
    try:
        parts = token.split(".")
        payload_b64 = parts[1] if len(parts) >= 2 else ""
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return IdentityRecord.from_dict(payload)
    except Exception as exc:  # noqa: BLE001
        log.debug("extract_identity_from_jwt: failed (%s)", exc)
        return IdentityRecord(sub="", role=Role.GUEST)


# ---------------------------------------------------------------------------
# Scope validation
# ---------------------------------------------------------------------------


def validate_role_for_scope(
    role: Role,
    scope: str,
    policy: Optional[LoaPolicy] = None,
) -> tuple[bool, str]:
    """Check whether *role* meets the minimum requirement for *scope*.

    Returns:
        ``(True, "")`` on success, ``(False, reason)`` on failure.
    """
    required = SCOPE_MIN_ROLE.get(scope.lower())
    if required is None:
        # Unknown scope — apply OPERATOR as a safe default
        required = Role.OPERATOR
        log.debug("validate_role_for_scope: unknown scope %r; applying OPERATOR minimum", scope)

    if role >= required:
        return True, ""
    return False, (
        f"Scope {scope!r} requires {required.name} (level {ROLE_TO_JWT_LEVEL[required]}), "
        f"but caller has {role.name} (level {ROLE_TO_JWT_LEVEL[role]})"
    )


# Backward-compat alias
def validate_loa_for_scope(
    loa: Role,
    scope: str,
    min_loa_overrides: Optional[dict[str, int]] = None,
    policy: Optional[LoaPolicy] = None,
) -> tuple[bool, str]:
    return validate_role_for_scope(loa, scope, policy)


__all__ = [
    "Role",
    "LevelOfAssurance",
    "ROLE_TO_JWT_LEVEL",
    "role_from_jwt_level",
    "SCOPE_MIN_ROLE",
    "IdentityRecord",
    "LoaPolicy",
    "DEFAULT_LOA_POLICY",
    "PRODUCTION_LOA_POLICY",
    "extract_role_from_jwt",
    "extract_loa_from_jwt",
    "extract_identity_from_jwt",
    "validate_role_for_scope",
    "validate_loa_for_scope",
]
