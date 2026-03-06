"""
RCAN Message Signing — Ed25519 key pairs and message authentication.

Signs RCAN commands with Ed25519 so robots can verify that commands
came from a trusted operator and haven't been tampered with.

Requires the ``cryptography`` optional dependency:
    pip install rcan[crypto]

Example:
    from rcan.signing import KeyPair, sign_message, verify_message
    from rcan import RCANMessage, RobotURI

    # Operator generates a key pair once
    keypair = KeyPair.generate()
    keypair.save_private("~/.rcan/operator.pem")
    # Share keypair.public_pem with the robot

    # Sign outbound commands
    msg = RCANMessage(cmd="move_forward", target=uri, params={"distance_m": 1.0})
    signed = sign_message(msg, keypair)

    # Robot verifies
    trusted = [KeyPair.from_public_pem(operator_pub_pem)]
    verify_message(signed, trusted)  # raises RCANSignatureError if invalid

Spec: https://rcan.dev/spec#section-8
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rcan.exceptions import RCANSignatureError


def _require_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, PrivateFormat, NoEncryption,
            load_pem_private_key, load_pem_public_key,
        )
        return True
    except ImportError:
        raise ImportError(
            "Ed25519 signing requires the 'cryptography' package. "
            "Install with: pip install rcan[crypto]"
        )


@dataclass
class KeyPair:
    """
    An Ed25519 key pair for signing RCAN messages.

    Attributes:
        key_id:      Short identifier derived from the public key (8 hex chars).
        public_pem:  PEM-encoded public key (safe to share with robots).
        _private_key: Raw private key object (never serialized in repr).
    """

    key_id: str
    public_pem: bytes
    _private_key: Any = None  # Ed25519PrivateKey

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def generate(cls) -> "KeyPair":
        """
        Generate a new Ed25519 key pair.

        Returns:
            New :class:`KeyPair` with a fresh private key.

        Raises:
            ImportError: If the ``cryptography`` package is not installed.
        """
        _require_crypto()
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat,
        )
        private_key = Ed25519PrivateKey.generate()
        pub_bytes = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        key_id = _key_id_from_pem(pub_bytes)
        return cls(key_id=key_id, public_pem=pub_bytes, _private_key=private_key)

    @classmethod
    def from_private_pem(cls, pem: bytes | str) -> "KeyPair":
        """
        Load a key pair from a PEM-encoded private key.

        Args:
            pem: PEM bytes or str.

        Raises:
            RCANSignatureError: If the PEM is invalid.
        """
        _require_crypto()
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key, Encoding, PublicFormat,
        )
        try:
            if isinstance(pem, str):
                pem = pem.encode()
            private_key = load_pem_private_key(pem, password=None)
            pub_bytes = private_key.public_key().public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            )
            return cls(
                key_id=_key_id_from_pem(pub_bytes),
                public_pem=pub_bytes,
                _private_key=private_key,
            )
        except Exception as e:
            raise RCANSignatureError(f"Failed to load private key: {e}") from e

    @classmethod
    def from_public_pem(cls, pem: bytes | str) -> "KeyPair":
        """
        Load a public-only key pair from a PEM-encoded public key.

        Public-only keys can verify signatures but not sign messages.

        Args:
            pem: PEM bytes or str.
        """
        _require_crypto()
        if isinstance(pem, str):
            pem = pem.encode()
        key_id = _key_id_from_pem(pem)
        return cls(key_id=key_id, public_pem=pem, _private_key=None)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_private(self, path: str | Path) -> None:
        """
        Save the private key to a PEM file (mode 0600).

        Args:
            path: File path. ``~`` is expanded.

        Raises:
            RCANSignatureError: If this is a public-only key pair.
        """
        if self._private_key is None:
            raise RCANSignatureError("Cannot save private key: this is a public-only KeyPair")
        _require_crypto()
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, NoEncryption
        )
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        pem = self._private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        path.write_bytes(pem)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def save_public(self, path: str | Path) -> None:
        """Save the public key to a PEM file."""
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.public_pem)

    @classmethod
    def load(cls, private_path: str | Path) -> "KeyPair":
        """Load a key pair from a private key PEM file."""
        path = Path(private_path).expanduser()
        return cls.from_private_pem(path.read_bytes())

    @classmethod
    def load_public(cls, public_path: str | Path) -> "KeyPair":
        """Load a public-only key pair from a public key PEM file."""
        path = Path(public_path).expanduser()
        return cls.from_public_pem(path.read_bytes())

    # ------------------------------------------------------------------
    # Signing / Verification
    # ------------------------------------------------------------------

    def sign_bytes(self, data: bytes) -> bytes:
        """
        Sign raw bytes with the private key.

        Returns:
            Raw Ed25519 signature bytes (64 bytes).

        Raises:
            RCANSignatureError: If this is a public-only key pair.
        """
        if self._private_key is None:
            raise RCANSignatureError("Cannot sign: private key not available")
        return self._private_key.sign(data)

    def verify_bytes(self, data: bytes, signature: bytes) -> None:
        """
        Verify a signature over raw bytes.

        Raises:
            RCANSignatureError: If the signature is invalid.
        """
        _require_crypto()
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.exceptions import InvalidSignature
        try:
            pub_key = load_pem_public_key(self.public_pem)
            pub_key.verify(signature, data)
        except InvalidSignature as e:
            raise RCANSignatureError(f"Signature verification failed: {e}") from e
        except Exception as e:
            raise RCANSignatureError(f"Verification error: {e}") from e

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def has_private_key(self) -> bool:
        return self._private_key is not None

    def __repr__(self) -> str:
        mode = "private+public" if self.has_private_key else "public-only"
        return f"KeyPair(key_id={self.key_id!r}, {mode})"


# ---------------------------------------------------------------------------
# Message-level sign / verify
# ---------------------------------------------------------------------------


def sign_message(msg: Any, keypair: "KeyPair") -> Any:
    """
    Sign an :class:`~rcan.RCANMessage` with an Ed25519 key pair.

    The signature covers the canonical message payload (cmd, target, params,
    timestamp, msg_id) sorted for stability. The ``sig`` field is added to the
    message in-place and the message is returned.

    Args:
        msg:     :class:`~rcan.RCANMessage` to sign.
        keypair: Key pair with private key available.

    Returns:
        The same message object with ``signature`` set.

    Raises:
        RCANSignatureError: If the keypair has no private key.
    """
    payload = _canonical_message_bytes(msg)
    raw_sig = keypair.sign_bytes(payload)
    sig_b64 = base64.urlsafe_b64encode(raw_sig).decode()
    msg.signature = {
        "alg": "ed25519",
        "kid": keypair.key_id,
        "value": sig_b64,
    }
    return msg


def verify_message(msg: Any, trusted_keys: list["KeyPair"]) -> None:
    """
    Verify the signature on an :class:`~rcan.RCANMessage`.

    Args:
        msg:          Message with a ``signature`` field.
        trusted_keys: List of trusted public :class:`KeyPair` objects.

    Raises:
        RCANSignatureError: If signature is missing, key_id unknown, or
                            signature is cryptographically invalid.
    """
    if not msg.signature:
        raise RCANSignatureError("Message is unsigned — signature field missing")

    sig_dict = msg.signature
    kid = sig_dict.get("kid")
    alg = sig_dict.get("alg", "")
    sig_value = sig_dict.get("value", "")

    if alg != "ed25519":
        raise RCANSignatureError(f"Unsupported signature algorithm: {alg!r}")

    # Find key by key_id
    matched = next((k for k in trusted_keys if k.key_id == kid), None)
    if matched is None:
        raise RCANSignatureError(
            f"No trusted key with kid={kid!r}. "
            f"Known kids: {[k.key_id for k in trusted_keys]}"
        )

    try:
        raw_sig = base64.urlsafe_b64decode(sig_value + "==")
    except Exception as e:
        raise RCANSignatureError(f"Invalid base64 signature: {e}") from e

    payload = _canonical_message_bytes(msg)
    matched.verify_bytes(payload, raw_sig)


def _canonical_message_bytes(msg: Any) -> bytes:
    """Return the canonical bytes to sign for a message (stable, sorted JSON)."""
    payload = {
        "rcan": msg.rcan,
        "msg_id": msg.msg_id,
        "timestamp": msg.timestamp,
        "cmd": msg.cmd,
        "target": str(msg.target),
        "params": msg.params,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _key_id_from_pem(pub_pem: bytes) -> str:
    """Derive an 8-char hex key ID from a public key PEM."""
    return hashlib.sha256(pub_pem).hexdigest()[:8]
