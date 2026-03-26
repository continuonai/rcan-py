"""
rcan.firmware — RCAN v2.1 Firmware Manifest generation and verification.

Every RCAN v2.1 robot MUST publish a signed firmware manifest at:
    {ruri}/.well-known/rcan-firmware-manifest.json

The manifest is Ed25519-signed by the manufacturer's key registered in the RRF.
The SHA-256 hash of the canonical manifest JSON is carried in every message
envelope as ``firmware_hash`` (field 13).

Spec: §11 — Firmware Manifests
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger(__name__)

# Well-known endpoint path
FIRMWARE_MANIFEST_PATH = "/.well-known/rcan-firmware-manifest.json"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class FirmwareComponent:
    """A single component entry in the firmware manifest.

    Attributes:
        name:    Component name (e.g. ``"brain-runtime"``).
        version: Semantic version string.
        hash:    SHA-256 hash prefixed with ``"sha256:"``.
    """

    name: str
    version: str
    hash: str  # "sha256:<hex>"

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "version": self.version, "hash": self.hash}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FirmwareComponent":
        return cls(
            name=data["name"],
            version=data["version"],
            hash=data["hash"],
        )


@dataclass
class FirmwareManifest:
    """RCAN v2.1 firmware manifest.

    Attributes:
        rrn:              Robot Registration Number.
        firmware_version: Semver or CalVer version string.
        build_hash:       SHA-256 of the full firmware bundle (``"sha256:<hex>"``).
        components:       Per-component name/version/hash records.
        signed_at:        UTC ISO-8601 timestamp when the manifest was signed.
        signature:        Ed25519 signature over canonical JSON (base64url).
                          Empty string when unsigned (not yet signed).
    """

    rrn: str
    firmware_version: str
    build_hash: str
    components: list[FirmwareComponent] = field(default_factory=list)
    signed_at: str = ""
    signature: str = ""

    # ----------------------------------------------------------------
    # Canonical JSON (deterministic, for signing)
    # ----------------------------------------------------------------

    def canonical_dict(self) -> dict[str, Any]:
        """Return the manifest as a dict WITHOUT the ``signature`` field, sorted."""
        return {
            "attestation_ref": "",  # placeholder; receivers ignore this
            "build_hash": self.build_hash,
            "components": [c.to_dict() for c in self.components],
            "firmware_version": self.firmware_version,
            "rrn": self.rrn,
            "signed_at": self.signed_at,
        }

    def canonical_json(self) -> bytes:
        """Return canonical JSON bytes (sorted keys, no trailing whitespace)."""
        return json.dumps(
            self.canonical_dict(), separators=(",", ":"), sort_keys=True
        ).encode()

    # ----------------------------------------------------------------
    # Hash helper
    # ----------------------------------------------------------------

    def compute_build_hash(self) -> str:
        """Compute SHA-256 over canonical JSON and return ``"sha256:<hex>"``."""
        digest = hashlib.sha256(self.canonical_json()).hexdigest()
        return f"sha256:{digest}"

    # ----------------------------------------------------------------
    # Serialization
    # ----------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        d = self.canonical_dict()
        if self.signature:
            d["signature"] = self.signature
        return d

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FirmwareManifest":
        components = [FirmwareComponent.from_dict(c) for c in data.get("components", [])]
        return cls(
            rrn=data["rrn"],
            firmware_version=data["firmware_version"],
            build_hash=data["build_hash"],
            components=components,
            signed_at=data.get("signed_at", ""),
            signature=data.get("signature", ""),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "FirmwareManifest":
        return cls.from_dict(json.loads(json_str))


# ---------------------------------------------------------------------------
# Signing / Verification
# ---------------------------------------------------------------------------


def sign_manifest(manifest: FirmwareManifest, private_key_bytes: bytes) -> FirmwareManifest:
    """Sign *manifest* with an Ed25519 private key.

    Sets ``signed_at`` to the current UTC time and ``signature`` to the
    base64url-encoded Ed25519 signature over the canonical JSON.

    Args:
        manifest:          The manifest to sign (mutated in place AND returned).
        private_key_bytes: 32-byte Ed25519 private key seed.

    Returns:
        The signed manifest (same object).

    Raises:
        ImportError: If ``cryptography`` package is not installed.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise ImportError(
            "Install 'cryptography' to sign firmware manifests: pip install cryptography"
        ) from exc

    manifest.signed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    sig_bytes = private_key.sign(manifest.canonical_json())
    manifest.signature = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()
    return manifest


def verify_manifest(manifest: FirmwareManifest, public_key_bytes: bytes) -> bool:
    """Verify the Ed25519 signature on *manifest*.

    Args:
        manifest:         The manifest to verify.
        public_key_bytes: 32-byte Ed25519 public key.

    Returns:
        True if the signature is valid.

    Raises:
        FirmwareIntegrityError: If the signature is invalid or missing.
        ImportError: If ``cryptography`` package is not installed.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:
        raise ImportError(
            "Install 'cryptography' to verify firmware manifests: pip install cryptography"
        ) from exc

    if not manifest.signature:
        raise FirmwareIntegrityError("Manifest has no signature")

    try:
        sig_bytes = base64.urlsafe_b64decode(manifest.signature + "==")
        pub_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub_key.verify(sig_bytes, manifest.canonical_json())
        return True
    except InvalidSignature as exc:
        raise FirmwareIntegrityError(
            f"Firmware manifest signature verification failed for RRN {manifest.rrn!r}"
        ) from exc
    except Exception as exc:
        raise FirmwareIntegrityError(f"Manifest verification error: {exc}") from exc


def firmware_hash_from_manifest(manifest: FirmwareManifest) -> str:
    """Return the ``firmware_hash`` envelope value for this manifest.

    This is the SHA-256 of the canonical JSON (NOT the ``build_hash`` field,
    which is the hash of the firmware bundle itself). The envelope field
    lets receivers cross-check that the manifest they fetched matches what
    the sender declared.
    """
    return f"sha256:{hashlib.sha256(manifest.canonical_json()).hexdigest()}"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class FirmwareIntegrityError(Exception):
    """Raised when firmware manifest signature verification fails.

    Callers MUST emit ``FAULT_REPORT (26)`` with
    ``fault_code: "FIRMWARE_INTEGRITY_FAILURE"`` when this is raised.
    """


__all__ = [
    "FIRMWARE_MANIFEST_PATH",
    "FirmwareComponent",
    "FirmwareManifest",
    "FirmwareIntegrityError",
    "sign_manifest",
    "verify_manifest",
    "firmware_hash_from_manifest",
]
