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

    # ------------------------------------------------------------------
    # v2.1 — Signed RURI
    # ------------------------------------------------------------------

    @property
    def path(self) -> str:
        """The signable path component (without scheme, without query string)."""
        return f"{self.registry}/{self.manufacturer}/{self.model}/{self.version}/{self.device_id}"

    def sign(self, private_key_bytes: bytes) -> str:
        """Return a signed RURI string (``rcan://...?sig=<base64url>``).

        The signature is an Ed25519 signature over the UTF-8 encoded path
        (no scheme, no query string). Required at L2+ conformance.

        Args:
            private_key_bytes: 32-byte Ed25519 private key seed.

        Returns:
            Signed RURI string including ``?sig=<base64url>``.

        Raises:
            ImportError: If ``cryptography`` package is not installed.
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
        except ImportError as exc:
            raise ImportError(
                "Install 'cryptography' to sign RURIs: pip install cryptography"
            ) from exc

        import base64

        private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        sig_bytes = private_key.sign(self.path.encode())
        sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()
        return f"{self}?sig={sig_b64}"

    def verify_sig(self, sig_b64: str, public_key_bytes: bytes) -> bool:
        """Verify an RURI signature.

        Args:
            sig_b64:          Base64url-encoded Ed25519 signature (from ``?sig=``).
            public_key_bytes: 32-byte Ed25519 public key.

        Returns:
            True if valid.

        Raises:
            RCANAddressError: If the signature is invalid.
            ImportError: If ``cryptography`` is not installed.
        """
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
        except ImportError as exc:
            raise ImportError(
                "Install 'cryptography' to verify RURIs: pip install cryptography"
            ) from exc

        import base64

        try:
            sig_bytes = base64.urlsafe_b64decode(sig_b64 + "==")
            pub_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pub_key.verify(sig_bytes, self.path.encode())
            return True
        except InvalidSignature as exc:
            raise RCANAddressError(f"RURI_SIGNATURE_INVALID for {self!r}") from exc

    def sign_pqc(self, keypair: "MlDsaKeyPair") -> str:
        """Return a signed RURI string using ML-DSA-65 (``?pqc_sig=<base64url>``).

        The signature covers the UTF-8 encoded path (no scheme, no query
        string), identical to :meth:`sign` but using ML-DSA-65 instead of
        Ed25519.

        Args:
            keypair: :class:`~rcan.crypto.MlDsaKeyPair` with private key.

        Returns:
            Signed RURI string including ``?pqc_sig=<base64url>``.

        Raises:
            RCANSignatureError: If *keypair* has no private key.
            ImportError:        If dilithium-py is not installed.
        """
        import base64

        from rcan.crypto import MlDsaKeyPair, sign_ml_dsa  # noqa: F401 (type check)

        sig_bytes = sign_ml_dsa(keypair, self.path.encode())
        sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()
        return f"{self}?pqc_sig={sig_b64}"

    def verify_sig_pqc(self, pqc_sig_b64: str, keypair: "MlDsaKeyPair") -> bool:
        """Verify an ML-DSA-65 RURI signature.

        Args:
            pqc_sig_b64: Base64url-encoded ML-DSA-65 signature (from ``?pqc_sig=``).
            keypair:     :class:`~rcan.crypto.MlDsaKeyPair` (public key only is
                         sufficient).

        Returns:
            True if valid.

        Raises:
            RCANAddressError: If the signature is invalid.
            ImportError:      If dilithium-py is not installed.
        """
        import base64

        from rcan.crypto import MlDsaKeyPair, verify_ml_dsa  # noqa: F401

        try:
            sig_bytes = base64.urlsafe_b64decode(pqc_sig_b64 + "==")
            verify_ml_dsa(keypair.public_key_bytes, self.path.encode(), sig_bytes)
            return True
        except Exception as exc:
            from rcan.exceptions import RCANSignatureError

            if isinstance(exc, RCANSignatureError):
                raise RCANAddressError(
                    f"RURI_PQC_SIGNATURE_INVALID for {self!r}"
                ) from exc
            raise

    @classmethod
    def parse_signed(cls, uri: str) -> tuple["RobotURI", str | None]:
        """Parse a (possibly signed) RURI string.

        Returns:
            ``(RobotURI, sig_b64)`` where ``sig_b64`` is None if unsigned.
        """
        sig: str | None = None
        base_uri = uri
        if "?sig=" in uri:
            base_uri, _, sig_part = uri.partition("?sig=")
            sig = sig_part.split("&")[0] if sig_part else None
        return cls.parse(base_uri), sig
