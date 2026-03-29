"""
rcan.envelope — RCAN v2.2 envelope types.

Provides the DelegationHop and MediaChunk dataclasses introduced in the
v2.2 specification for post-quantum and attestation envelope fields.

Spec: https://rcan.dev/spec/v2.2
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any


@dataclass
class DelegationHop:
    """A single hop in a v2.2 delegation chain.

    Attributes:
        robot_rrn:   Robot Resource Name of the delegating robot.
        scope:       Scope being delegated (e.g. ``"operator"``).
        issued_at:   ISO-8601 issuance timestamp.
        expires_at:  ISO-8601 expiry timestamp.
        sig:         Optional ML-DSA-65 or Ed25519 signature (base64url).
    """

    robot_rrn: str
    scope: str
    issued_at: str
    expires_at: str
    sig: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "robot_rrn": self.robot_rrn,
            "scope": self.scope,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "sig": self.sig,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DelegationHop":
        return cls(
            robot_rrn=data["robot_rrn"],
            scope=data["scope"],
            issued_at=data["issued_at"],
            expires_at=data["expires_at"],
            sig=data.get("sig", ""),
        )


@dataclass
class MediaChunk:
    """An inline or by-reference media attachment for v2.2 messages.

    Attributes:
        chunk_id:     Unique identifier for this chunk.
        mime_type:    MIME type of the media (e.g. ``"image/jpeg"``).
        size_bytes:   Size of the media in bytes.
        hash_sha256:  Expected SHA-256 hex digest prefixed with ``"sha256:"``.
        data:         Inline data (plain text / base64 encoded by the caller).
        ref_url:      URL to fetch the media from when not inline.
    """

    chunk_id: str
    mime_type: str
    size_bytes: int
    hash_sha256: str
    data: str = ""
    ref_url: str = ""

    def verify_hash(self) -> None:
        """Verify that *data* matches *hash_sha256*.

        Raises:
            ValueError: If the computed hash does not match.
        """
        actual = "sha256:" + hashlib.sha256(self.data.encode()).hexdigest()
        if actual != self.hash_sha256:
            raise ValueError(
                f"MediaChunk hash mismatch: expected {self.hash_sha256}, got {actual}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "mime_type": self.mime_type,
            "size_bytes": self.size_bytes,
            "hash_sha256": self.hash_sha256,
            "data": self.data,
            "ref_url": self.ref_url,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MediaChunk":
        return cls(
            chunk_id=data["chunk_id"],
            mime_type=data["mime_type"],
            size_bytes=data["size_bytes"],
            hash_sha256=data["hash_sha256"],
            data=data.get("data", ""),
            ref_url=data.get("ref_url", ""),
        )


__all__ = [
    "DelegationHop",
    "MediaChunk",
]
