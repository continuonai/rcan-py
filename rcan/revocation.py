"""
rcan.revocation — Robot Identity Revocation (GAP-02).

Provides TTL-cached revocation status checks and a broadcast message
type for revoking robot identities.

Spec: §13 — Robot Identity Revocation
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal, Optional

from rcan.exceptions import RevocationError

logger = logging.getLogger(__name__)

# Default TTL for cached revocation status (1 hour)
DEFAULT_TTL_S = 3600

# Valid status values
RevocationStatusValue = Literal["active", "revoked", "suspended"]


@dataclass
class RevocationStatus:
    """Revocation status of a robot identity.

    Attributes:
        rrn:        Robot Registry Number.
        status:     ``"active"``, ``"revoked"``, or ``"suspended"``.
        revoked_at: Unix timestamp of revocation (None if active).
        reason:     Human-readable reason for revocation.
        authority:  Identity of the revoking authority (e.g. registry URL).
    """

    rrn: str
    status: RevocationStatusValue = "active"
    revoked_at: Optional[float] = None
    reason: str = ""
    authority: str = ""

    @property
    def is_active(self) -> bool:
        return self.status == "active"

    @property
    def is_revoked(self) -> bool:
        return self.status == "revoked"

    @property
    def is_suspended(self) -> bool:
        return self.status == "suspended"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rrn": self.rrn,
            "status": self.status,
            "revoked_at": self.revoked_at,
            "reason": self.reason,
            "authority": self.authority,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RevocationStatus":
        return cls(
            rrn=data.get("rrn", ""),
            status=data.get("status", "active"),  # type: ignore[arg-type]
            revoked_at=data.get("revoked_at"),
            reason=data.get("reason", ""),
            authority=data.get("authority", ""),
        )


@dataclass
class _CacheEntry:
    status: RevocationStatus
    cached_at: float
    ttl_s: float


class RevocationCache:
    """TTL cache for robot revocation status.

    Robots check their revocation status on startup and cache results.
    The default TTL is 1 hour — after expiry, status is re-fetched.

    Args:
        ttl_s: Cache entry lifetime in seconds (default 3600).
    """

    def __init__(self, ttl_s: float = DEFAULT_TTL_S) -> None:
        self.ttl_s = ttl_s
        self._cache: dict[str, _CacheEntry] = {}

    def get(self, rrn: str) -> Optional[RevocationStatus]:
        """Return cached status for *rrn*, or None if not cached / expired."""
        entry = self._cache.get(rrn)
        if entry is None:
            return None
        if time.time() - entry.cached_at > entry.ttl_s:
            del self._cache[rrn]
            return None
        return entry.status

    def set(self, status: RevocationStatus) -> None:
        """Cache a revocation status."""
        self._cache[status.rrn] = _CacheEntry(
            status=status,
            cached_at=time.time(),
            ttl_s=self.ttl_s,
        )

    def invalidate(self, rrn: str) -> None:
        """Remove cached status for *rrn* (e.g. after receiving revocation broadcast)."""
        self._cache.pop(rrn, None)

    def size(self) -> int:
        return len(self._cache)


def check_revocation(rrn: str, registry_url: str) -> RevocationStatus:
    """Fetch revocation status for *rrn* from the registry.

    Makes an HTTP GET to ``{registry_url}/api/v1/robots/{rrn}/revocation-status``.
    Falls back to an ``active`` status if the registry is unreachable (offline
    mode must handle staleness separately).

    Args:
        rrn:          Robot Registry Number.
        registry_url: Base URL of the RCAN registry.

    Returns:
        :class:`RevocationStatus`.
    """
    try:
        import urllib.request
        import json

        url = f"{registry_url.rstrip('/')}/api/v1/robots/{rrn}/revocation-status"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return RevocationStatus.from_dict({**data, "rrn": rrn})
    except Exception as exc:
        logger.warning(
            "Revocation check for %s failed (registry=%s): %s — assuming active",
            rrn,
            registry_url,
            exc,
        )
        return RevocationStatus(rrn=rrn, status="active")


def make_revocation_broadcast(
    rrn: str,
    reason: str,
    authority: str = "",
    target_uri: str = "rcan://rcan.dev/system/broadcast/v1/local",
) -> Any:
    """Build a ROBOT_REVOCATION broadcast RCANMessage.

    Peers receiving this message MUST invalidate all cached consent and
    public key material for the revoked RRN.

    Args:
        rrn:        RRN of the revoked robot.
        reason:     Human-readable reason for revocation.
        authority:  Identity of the revoking authority.
        target_uri: Broadcast target.

    Returns:
        :class:`~rcan.message.RCANMessage` with ROBOT_REVOCATION command.
    """
    from rcan.message import RCANMessage

    status = RevocationStatus(
        rrn=rrn,
        status="revoked",
        revoked_at=time.time(),
        reason=reason,
        authority=authority,
    )

    return RCANMessage(
        cmd="ROBOT_REVOCATION",
        target=target_uri,
        params={
            **status.to_dict(),
            "broadcast_id": str(uuid.uuid4()),
        },
    )


__all__ = [
    "RevocationStatus",
    "RevocationCache",
    "check_revocation",
    "make_revocation_broadcast",
]
