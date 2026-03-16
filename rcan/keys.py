"""
rcan.keys — Key Rotation (GAP-09).

Provides KeyStore for managing multiple signing keys with expiry/revocation,
and helpers for broadcasting key rotation events.

Spec: §8.6 — Key Lifecycle and Rotation
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Maximum key validity (365 days in seconds)
MAX_KEY_VALIDITY_S = 365 * 24 * 3600

# Default key overlap window during rotation (1 hour)
DEFAULT_OVERLAP_S = 3600


@dataclass
class KeyRotationMessage:
    """Payload for a KEY_ROTATION broadcast message.

    Attributes:
        new_public_key: PEM-encoded or base64 public key string.
        old_key_id:     key_id of the key being rotated out.
        overlap_s:      Seconds the old key remains valid after rotation.
        rotation_id:    Unique identifier for this rotation event.
        rotated_at:     Unix timestamp of the rotation.
    """

    new_public_key: str
    old_key_id: str
    overlap_s: int = DEFAULT_OVERLAP_S
    rotation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    rotated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "new_public_key": self.new_public_key,
            "old_key_id": self.old_key_id,
            "overlap_s": self.overlap_s,
            "rotation_id": self.rotation_id,
            "rotated_at": self.rotated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "KeyRotationMessage":
        return cls(
            new_public_key=data["new_public_key"],
            old_key_id=data.get("old_key_id", ""),
            overlap_s=data.get("overlap_s", DEFAULT_OVERLAP_S),
            rotation_id=data.get("rotation_id", str(uuid.uuid4())),
            rotated_at=data.get("rotated_at", time.time()),
        )


@dataclass
class _KeyEntry:
    """Internal key store entry."""

    key_id: str
    public_key: str  # PEM or base64
    valid_from: float
    valid_until: float
    revoked_at: Optional[float] = None

    @property
    def is_valid(self) -> bool:
        now = time.time()
        if self.revoked_at is not None:
            return False
        return self.valid_from <= now <= self.valid_until

    @property
    def is_expired(self) -> bool:
        return time.time() > self.valid_until


class KeyStore:
    """In-memory store for signing key history with expiry and revocation.

    Maps key_id → (public_key, valid_from, valid_until). Supports multiple
    simultaneously valid keys to allow smooth rotation overlap.

    Example::

        store = KeyStore()
        store.add_key("kid1", public_key_pem, valid_for_s=3600)
        entry = store.get_valid_key("kid1")
    """

    def __init__(self) -> None:
        self._keys: dict[str, _KeyEntry] = {}

    def add_key(
        self,
        key_id: str,
        public_key: str,
        valid_for_s: int = MAX_KEY_VALIDITY_S,
        valid_from: Optional[float] = None,
    ) -> None:
        """Add a new key to the store.

        Args:
            key_id:     Unique key identifier (e.g. 8-char hex from public key hash).
            public_key: PEM-encoded or base64 public key string.
            valid_for_s: Validity duration in seconds (max 365 days).
            valid_from:  Start time (defaults to now).
        """
        valid_for_s = min(valid_for_s, MAX_KEY_VALIDITY_S)
        now = time.time()
        start = valid_from if valid_from is not None else now
        entry = _KeyEntry(
            key_id=key_id,
            public_key=public_key,
            valid_from=start,
            valid_until=start + valid_for_s,
        )
        self._keys[key_id] = entry
        logger.info(
            "KeyStore: added key_id=%s valid_until=%s",
            key_id,
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(entry.valid_until)),
        )

    def expire_key(self, key_id: str, expire_at: Optional[float] = None) -> None:
        """Set an expiry time on a key (for graceful rotation).

        Args:
            key_id:    Key to expire.
            expire_at: Expiry timestamp (defaults to now).
        """
        entry = self._keys.get(key_id)
        if entry is None:
            logger.warning("KeyStore: expire_key: key_id=%s not found", key_id)
            return
        entry.valid_until = expire_at if expire_at is not None else time.time()
        logger.info("KeyStore: key_id=%s set to expire at %s", key_id, entry.valid_until)

    def revoke_key(self, key_id: str) -> None:
        """Immediately revoke a key.

        Args:
            key_id: Key to revoke.
        """
        entry = self._keys.get(key_id)
        if entry is None:
            logger.warning("KeyStore: revoke_key: key_id=%s not found", key_id)
            return
        entry.revoked_at = time.time()
        logger.warning("KeyStore: key_id=%s REVOKED", key_id)

    def get_valid_key(self, key_id: str) -> Optional[_KeyEntry]:
        """Return the entry for *key_id* if currently valid, else None."""
        entry = self._keys.get(key_id)
        if entry is None:
            return None
        return entry if entry.is_valid else None

    def all_valid_keys(self) -> list[_KeyEntry]:
        """Return all currently valid (not expired, not revoked) keys."""
        return [e for e in self._keys.values() if e.is_valid]

    def to_jwks(self) -> dict[str, Any]:
        """Export all keys as a minimal JWKS-like dict.

        Returns:
            Dict with ``keys`` list per RFC 7517.
        """
        keys = []
        for entry in self._keys.values():
            k: dict[str, Any] = {
                "kid": entry.key_id,
                "alg": "EdDSA",
                "use": "sig",
                "exp": int(entry.valid_until),
                "nbf": int(entry.valid_from),
                "key": entry.public_key,
            }
            if entry.revoked_at is not None:
                k["revoked_at"] = int(entry.revoked_at)
            keys.append(k)
        return {"keys": keys}


def make_key_rotation_message(
    new_public_key: str,
    old_key_id: str,
    overlap_s: int = DEFAULT_OVERLAP_S,
    target: str = "rcan://rcan.dev/system/broadcast/v1/local",
) -> Any:
    """Build an RCAN KEY_ROTATION message for broadcasting key rotation.

    Args:
        new_public_key: PEM or base64 public key string.
        old_key_id:     key_id being rotated out.
        overlap_s:      How long the old key remains accepted (default 1h).
        target:         Broadcast target URI.

    Returns:
        :class:`~rcan.message.RCANMessage` with KEY_ROTATION command.
    """
    from rcan.message import RCANMessage

    rotation = KeyRotationMessage(
        new_public_key=new_public_key,
        old_key_id=old_key_id,
        overlap_s=overlap_s,
    )

    return RCANMessage(
        cmd="KEY_ROTATION",
        target=target,
        params=rotation.to_dict(),
    )


__all__ = [
    "KeyRotationMessage",
    "KeyStore",
    "make_key_rotation_message",
]
