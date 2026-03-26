"""
rcan.sbom — RCAN v2.1 Software Bill of Materials (SBOM) generation.

Every RCAN v2.1 robot MUST publish a CycloneDX v1.5+ SBOM at:
    {ruri}/.well-known/rcan-sbom.json

The SBOM includes RCAN-specific extensions under the ``x-rcan-extensions``
key. The ``attestation_ref`` envelope field (field 14) points to this
endpoint or to the RRF-hosted countersigned version.

Spec: §12 — Supply Chain Attestation
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger(__name__)

SBOM_PATH = "/.well-known/rcan-sbom.json"
CYCLONEDX_SPEC_VERSION = "1.5"
BOM_FORMAT = "CycloneDX"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class SBOMComponent:
    """A CycloneDX component entry.

    Attributes:
        type:    CycloneDX component type (e.g. ``"library"``, ``"device"``).
        name:    Component name.
        version: Component version string.
        hashes:  List of ``{"alg": "SHA-256", "content": "<hex>"}`` dicts.
        purl:    Package URL (e.g. ``"pkg:pypi/rcan@1.1.0"``).
    """

    name: str
    version: str
    type: str = "library"
    hashes: list[dict[str, str]] = field(default_factory=list)
    purl: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": self.type,
            "name": self.name,
            "version": self.version,
        }
        if self.hashes:
            d["hashes"] = self.hashes
        if self.purl:
            d["purl"] = self.purl
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SBOMComponent":
        return cls(
            type=data.get("type", "library"),
            name=data["name"],
            version=data["version"],
            hashes=data.get("hashes", []),
            purl=data.get("purl"),
        )


@dataclass
class RCANSBOMExtensions:
    """RCAN-specific extensions for the CycloneDX SBOM.

    Attributes:
        rrn:                  Robot Registration Number.
        firmware_hash:        Links SBOM to firmware manifest build_hash.
        attestation_signed_at: UTC timestamp when RRF countersignature was issued.
        rrf_countersignature: Ed25519 signature by RRF root key (L5 only).
    """

    rrn: str
    firmware_hash: str
    attestation_signed_at: str = ""
    rrf_countersignature: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "rrn": self.rrn,
            "firmware_hash": self.firmware_hash,
            "attestation_signed_at": self.attestation_signed_at,
        }
        if self.rrf_countersignature:
            d["rrf_countersignature"] = self.rrf_countersignature
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RCANSBOMExtensions":
        return cls(
            rrn=data["rrn"],
            firmware_hash=data["firmware_hash"],
            attestation_signed_at=data.get("attestation_signed_at", ""),
            rrf_countersignature=data.get("rrf_countersignature"),
        )


@dataclass
class RCANBOM:
    """RCAN v2.1 CycloneDX Software Bill of Materials.

    Attributes:
        rrn:         Robot Registration Number (used in metadata component).
        version_str: The robot firmware/software version.
        components:  List of :class:`SBOMComponent` entries.
        extensions:  RCAN extensions (``x-rcan-extensions`` block).
        timestamp:   BOM generation timestamp (UTC ISO-8601). Auto-set if empty.
        bom_version: CycloneDX BOM version counter (increment on each update).
    """

    rrn: str
    version_str: str
    components: list[SBOMComponent] = field(default_factory=list)
    extensions: Optional[RCANSBOMExtensions] = None
    timestamp: str = ""
    bom_version: int = 1

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ----------------------------------------------------------------
    # Serialization
    # ----------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "bomFormat": BOM_FORMAT,
            "specVersion": CYCLONEDX_SPEC_VERSION,
            "version": self.bom_version,
            "metadata": {
                "timestamp": self.timestamp,
                "component": {
                    "type": "device",
                    "name": self.rrn,
                    "version": self.version_str,
                },
            },
            "components": [c.to_dict() for c in self.components],
        }
        if self.extensions:
            d["x-rcan-extensions"] = self.extensions.to_dict()
        return d

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RCANBOM":
        meta = data.get("metadata", {})
        meta_comp = meta.get("component", {})
        components = [SBOMComponent.from_dict(c) for c in data.get("components", [])]
        ext_data = data.get("x-rcan-extensions")
        extensions = RCANSBOMExtensions.from_dict(ext_data) if ext_data else None
        return cls(
            rrn=meta_comp.get("name", ""),
            version_str=meta_comp.get("version", ""),
            components=components,
            extensions=extensions,
            timestamp=meta.get("timestamp", ""),
            bom_version=data.get("version", 1),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "RCANBOM":
        return cls.from_dict(json.loads(json_str))

    # ----------------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------------

    def set_rcan_extensions(
        self,
        firmware_hash: str,
        rrf_countersignature: Optional[str] = None,
    ) -> "RCANBOM":
        """Set or update the RCAN extensions block. Returns self for chaining."""
        self.extensions = RCANSBOMExtensions(
            rrn=self.rrn,
            firmware_hash=firmware_hash,
            attestation_signed_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            rrf_countersignature=rrf_countersignature,
        )
        return self

    def validate(self) -> list[str]:
        """Return a list of validation errors (empty list = valid)."""
        errors: list[str] = []
        if not self.rrn:
            errors.append("rrn is required")
        if not self.version_str:
            errors.append("version_str is required")
        if self.extensions is None:
            errors.append("x-rcan-extensions block is required (set_rcan_extensions())")
        elif not self.extensions.firmware_hash:
            errors.append("x-rcan-extensions.firmware_hash is required")
        return errors


__all__ = [
    "SBOM_PATH",
    "CYCLONEDX_SPEC_VERSION",
    "BOM_FORMAT",
    "SBOMComponent",
    "RCANSBOMExtensions",
    "RCANBOM",
]
