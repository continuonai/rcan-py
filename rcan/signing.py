"""
RCAN Message Signing — ML-DSA-65 (NIST FIPS 204).

RCAN v2.2: Ed25519 is fully deprecated. ML-DSA-65 (CRYSTALS-Dilithium) is
the ONLY signing algorithm. All messages MUST carry a ``sig`` block with
``alg: "ml-dsa-65"``.

Requires dilithium-py:
    pip install rcan[pq]

Example:
    from rcan.signing import MLDSAKeyPair, sign_message, verify_message
    from rcan import RCANMessage, RobotURI

    # Generate key pair once (at boot)
    kp = MLDSAKeyPair.generate()
    kp.save("~/.rcan/operator.key")

    # Sign outbound messages
    msg = RCANMessage(cmd="move_forward", target=uri, params={"distance_m": 1.0})
    signed = sign_message(msg, kp)
    # signed.signature = { alg: "ml-dsa-65", kid: "...", value: "..." }

    # Verify
    pub = MLDSAKeyPair.from_public_bytes(kp.public_key)
    verify_message(signed, [pub])  # raises RCANSignatureError if invalid

Spec: https://rcan.dev/spec/v2.2#section-7-2
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

# ---------------------------------------------------------------------------
# ML-DSA-65 (FIPS 204) — the only signing algorithm
# ---------------------------------------------------------------------------


def _require_mldsa() -> Any:
    """Return the ML_DSA_65 class or raise ImportError."""
    try:
        from dilithium_py.ml_dsa import ML_DSA_65  # type: ignore[import]

        return ML_DSA_65
    except ImportError as e:
        raise ImportError(
            "ML-DSA-65 signing requires the 'dilithium-py' package. "
            "Install with: pip install rcan[pq]"
        ) from e


@dataclass
class MLDSAKeyPair:
    """
    An ML-DSA-65 (CRYSTALS-Dilithium, FIPS 204) key pair.

    This is the ONLY signing key type in RCAN v2.2+. Ed25519 is deprecated.

    Key sizes:
        Public key:   1952 bytes
        Private key:  4032 bytes
        Signature:    3309 bytes

    Attributes:
        key_id:      Short identifier derived from SHA-256 of the public key (8 hex chars).
        public_key:  Raw public key bytes (1952 bytes).
        _secret_key: Raw private key bytes (4032 bytes, never logged/repr'd).
    """

    key_id: str
    public_key: bytes
    _secret_key: bytes | None = None

    @classmethod
    def generate(cls) -> "MLDSAKeyPair":
        """Generate a new ML-DSA-65 key pair."""
        ML_DSA_65 = _require_mldsa()
        pk, sk = ML_DSA_65.keygen()
        kid = hashlib.sha256(pk).hexdigest()[:8]
        return cls(key_id=kid, public_key=pk, _secret_key=sk)

    @classmethod
    def from_public_bytes(cls, public_key: bytes) -> "MLDSAKeyPair":
        """Load a public-only key pair (verify-only)."""
        kid = hashlib.sha256(public_key).hexdigest()[:8]
        return cls(key_id=kid, public_key=public_key, _secret_key=None)

    def save(self, path: str | Path) -> None:
        """
        Save the key pair to a binary file (mode 0600).

        Format: 4-byte magic ``b'MLDS'``, 2-byte pk_len (big-endian),
        public key bytes, then private key bytes.
        """
        if self._secret_key is None:
            raise RCANSignatureError(
                "Cannot save: public-only MLDSAKeyPair has no private key"
            )
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        pk_len = len(self.public_key).to_bytes(2, "big")
        path.write_bytes(b"MLDS" + pk_len + self.public_key + self._secret_key)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def save_public(self, path: str | Path) -> None:
        """Save only the public key bytes to a file."""
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.public_key)

    @classmethod
    def load(cls, path: str | Path) -> "MLDSAKeyPair":
        """Load an ML-DSA-65 key pair from a file saved by :meth:`save`."""
        data = Path(path).expanduser().read_bytes()
        if data[:4] != b"MLDS":
            raise RCANSignatureError(
                "Not a valid MLDSAKeyPair file (missing MLDS magic)"
            )
        pk_len = int.from_bytes(data[4:6], "big")
        pk = data[6 : 6 + pk_len]
        sk = data[6 + pk_len :]
        kid = hashlib.sha256(pk).hexdigest()[:8]
        return cls(key_id=kid, public_key=pk, _secret_key=sk)

    @classmethod
    def load_public(cls, path: str | Path) -> "MLDSAKeyPair":
        """Load a public-only key pair from a raw public key file."""
        pk = Path(path).expanduser().read_bytes()
        return cls.from_public_bytes(pk)

    def sign_bytes(self, data: bytes) -> bytes:
        """Sign raw bytes; returns ML-DSA-65 signature (~3309 bytes)."""
        if self._secret_key is None:
            raise RCANSignatureError("Cannot sign: private key not available")
        ML_DSA_65 = _require_mldsa()
        return ML_DSA_65.sign(self._secret_key, data)

    def verify_bytes(self, data: bytes, signature: bytes) -> None:
        """
        Verify an ML-DSA-65 signature over raw bytes.

        Raises:
            RCANSignatureError: If the signature is invalid.
        """
        ML_DSA_65 = _require_mldsa()
        try:
            ok = ML_DSA_65.verify(self.public_key, data, signature)
        except Exception as e:
            raise RCANSignatureError(f"ML-DSA verification error: {e}") from e
        if not ok:
            raise RCANSignatureError("ML-DSA-65 signature verification failed")

    @property
    def has_private_key(self) -> bool:
        return self._secret_key is not None

    def __repr__(self) -> str:
        mode = "private+public" if self.has_private_key else "public-only"
        return f"MLDSAKeyPair(key_id={self.key_id!r}, alg=ML-DSA-65, {mode})"


# ---------------------------------------------------------------------------
# Message-level sign / verify
# ---------------------------------------------------------------------------


def sign_message(msg: Any, keypair: "MLDSAKeyPair") -> Any:
    """
    Sign an :class:`~rcan.RCANMessage` with ML-DSA-65 (FIPS 204).

    Sets ``msg.signature`` to a dict with ``alg: "ml-dsa-65"``, ``kid``, and ``value``.
    Ed25519 is not used — ML-DSA-65 is the only signing algorithm in RCAN v2.2+.

    Args:
        msg:     :class:`~rcan.RCANMessage` to sign.
        keypair: :class:`MLDSAKeyPair` with private key available.

    Returns:
        The same message with ``signature`` set.

    Raises:
        RCANSignatureError: If the keypair has no private key.
    """
    payload = _canonical_message_bytes(msg)
    raw_sig = keypair.sign_bytes(payload)
    msg.signature = {
        "alg": "ml-dsa-65",
        "kid": keypair.key_id,
        "value": base64.urlsafe_b64encode(raw_sig).decode(),
    }
    # Clear any leftover pq_sig from hybrid period
    if hasattr(msg, "pq_sig"):
        msg.pq_sig = None
    return msg


def verify_message(
    msg: Any,
    trusted_keys: "list[MLDSAKeyPair]",
) -> None:
    """
    Verify the ML-DSA-65 signature on an :class:`~rcan.RCANMessage`.

    Args:
        msg:          Message with a ``signature`` field (alg: ml-dsa-65).
        trusted_keys: Trusted ML-DSA-65 public :class:`MLDSAKeyPair` objects.

    Raises:
        RCANSignatureError: If signature is missing, alg unsupported, key unknown,
                            or signature cryptographically invalid.
    """
    if not msg.signature:
        raise RCANSignatureError("Message is unsigned — signature field missing")

    sig_dict = msg.signature
    alg = sig_dict.get("alg", "")
    kid = sig_dict.get("kid")
    sig_value = sig_dict.get("value", "")

    if alg != "ml-dsa-65":
        raise RCANSignatureError(
            f"Unsupported signature algorithm: {alg!r}. "
            "RCAN v2.2 requires ml-dsa-65 (Ed25519 is deprecated)."
        )

    matched = next((k for k in trusted_keys if k.key_id == kid), None)
    if matched is None:
        raise RCANSignatureError(
            f"No trusted ML-DSA-65 key with kid={kid!r}. "
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


# ---------------------------------------------------------------------------
# Legacy KeyPair stub — raises on use, guides migration
# ---------------------------------------------------------------------------


class KeyPair:
    """
    DEPRECATED — Ed25519 KeyPair has been removed in RCAN v2.2.

    Use :class:`MLDSAKeyPair` instead.

    Raises:
        DeprecationWarning on construction.
    """

    def __init__(self, *args, **kwargs):
        raise DeprecationWarning(
            "Ed25519 KeyPair is deprecated in RCAN v2.2. "
            "Use MLDSAKeyPair (ML-DSA-65, FIPS 204). "
            "See https://rcan.dev/spec/v2.2#section-7-2"
        )

    @classmethod
    def generate(cls) -> "MLDSAKeyPair":
        """Redirects to MLDSAKeyPair.generate()."""
        import warnings

        warnings.warn(
            "KeyPair.generate() is deprecated — use MLDSAKeyPair.generate()",
            DeprecationWarning,
            stacklevel=2,
        )
        return MLDSAKeyPair.generate()
