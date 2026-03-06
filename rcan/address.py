"""
RCAN Robot URI — globally unique, resolvable robot addresses.

Format:
    rcan://<registry>/<manufacturer>/<model>/<version>/<device-id>

Examples:
    rcan://registry.rcan.dev/acme/robotarm/v2/unit-001
    rcan://registry.rcan.dev/continuonai/continuonbot/v1/pi5-lab-01

Spec: https://rcan.dev/spec#section-2
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from rcan.exceptions import RCANAddressError


# Allowed characters in URI path segments
_SEGMENT_RE = re.compile(r"^[a-zA-Z0-9._\-]+$")
_URI_RE = re.compile(
    r"^rcan://(?P<registry>[^/]+)/(?P<manufacturer>[^/]+)/(?P<model>[^/]+)"
    r"/(?P<version>[^/]+)/(?P<device_id>[^/]+)/?$"
)


@dataclass(frozen=True, slots=True)
class RobotURI:
    """
    An immutable, validated RCAN Robot URI.

    Attributes:
        registry:     Registry hostname (e.g. ``registry.rcan.dev``)
        manufacturer: Manufacturer slug (e.g. ``acme``)
        model:        Model slug (e.g. ``robotarm``)
        version:      Hardware/firmware version (e.g. ``v2``)
        device_id:    Per-unit identifier (e.g. ``unit-001``)
    """

    registry: str
    manufacturer: str
    model: str
    version: str
    device_id: str

    DEFAULT_REGISTRY: ClassVar[str] = "registry.rcan.dev"

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def parse(cls, uri: str) -> "RobotURI":
        """
        Parse a RCAN URI string into a :class:`RobotURI`.

        Raises:
            RCANAddressError: If the URI is malformed.
        """
        uri = uri.strip()
        match = _URI_RE.match(uri)
        if not match:
            raise RCANAddressError(
                f"Invalid RCAN URI: {uri!r}. "
                "Expected format: rcan://<registry>/<manufacturer>/<model>/<version>/<device-id>"
            )
        parts = match.groupdict()
        for field, value in parts.items():
            if not _SEGMENT_RE.match(value):
                raise RCANAddressError(
                    f"Invalid character in URI segment {field!r}: {value!r}"
                )
        return cls(**parts)

    @classmethod
    def build(
        cls,
        manufacturer: str,
        model: str,
        version: str,
        device_id: str,
        registry: str | None = None,
    ) -> "RobotURI":
        """
        Construct a :class:`RobotURI` from components.

        Args:
            manufacturer: Manufacturer slug (lowercase, hyphens ok).
            model:        Model slug.
            version:      Version string (e.g. ``v2`` or ``1.0.0``).
            device_id:    Per-unit identifier.
            registry:     Registry hostname. Defaults to ``registry.rcan.dev``.

        Raises:
            RCANAddressError: If any component contains invalid characters.
        """
        reg = registry or cls.DEFAULT_REGISTRY
        uri = f"rcan://{reg}/{manufacturer}/{model}/{version}/{device_id}"
        return cls.parse(uri)

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def __str__(self) -> str:
        return f"rcan://{self.registry}/{self.manufacturer}/{self.model}/{self.version}/{self.device_id}"

    def __repr__(self) -> str:
        return f"RobotURI({str(self)!r})"

    @property
    def registry_url(self) -> str:
        """HTTPS URL for this robot in the registry."""
        return f"https://{self.registry}/registry/{self.manufacturer}/{self.model}/{self.version}/{self.device_id}"

    @property
    def namespace(self) -> str:
        """Manufacturer/model namespace (without version or device)."""
        return f"{self.manufacturer}/{self.model}"

    def with_device(self, device_id: str) -> "RobotURI":
        """Return a new URI with a different device_id (same namespace)."""
        return RobotURI(
            registry=self.registry,
            manufacturer=self.manufacturer,
            model=self.model,
            version=self.version,
            device_id=device_id,
        )
