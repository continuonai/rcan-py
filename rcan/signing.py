"""
RCAN Message Signing — Ed25519 key pairs and post-quantum ML-DSA hybrid.

Signs RCAN commands so robots can verify that commands came from a trusted
operator and haven't been tampered with.

RCAN v2.2 introduces hybrid signing: messages carry BOTH an Ed25519 signature
(``sig`` field, backward-compatible) and an ML-DSA-65 signature (``pq_sig``
field, NIST FIPS 204, quantum-resistant).  New robots verify both; legacy
robots verify only Ed25519 until the Ed25519 sunset (2029).

Requires the ``cryptography`` optional dependency:
    pip install rcan[crypto]

For PQ signing also install dilithium-py:
    pip install dilithium-py

Example:
    from rcan.signing import KeyPair, MLDSAKeyPair, sign_message, verify_message
    from rcan import RCANMessage, RobotURI

    # Operator generates key pairs once
    ed_kp  = KeyPair.generate()
    pq_kp  = MLDSAKeyPair.generate()
    ed_kp.save_private("~/.rcan/operator.pem")
    pq_kp.save("~/.rcan/operator_pq.key")

    # Sign outbound commands (hybrid: Ed25519 + ML-DSA-65)
    msg = RCANMessage(cmd="move_forward", target=uri, params={"distance_m": 1.0})
    signed = sign_message(msg, ed_kp, pq_keypair=pq_kp)

    # Robot verifies (hybrid: both sigs checked when pq_trusted provided)
    trusted = [KeyPair.from_public_pem(operator_pub_pem)]
    pq_trusted = [MLDSAKeyPair.from_public_bytes(pq_pub_bytes)]
    verify_message(signed, trusted, pq_trusted_keys=pq_trusted)

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


# ---------------------------------------------------------------------------
# ML-DSA (FIPS 204) — post-quantum signing
# ---------------------------------------------------------------------------


def _require_mldsa() -> Any:
    """Return the ML_DSA_65 class or raise ImportError."""
    try:
        from dilithium_py.ml_dsa import ML_DSA_65  # type: ignore[import]

        return ML_DSA_65
    except ImportError as e:
        raise ImportError(
            "ML-DSA signing requires the 'dilithium-py' package. "
            "Install with: pip install dilithium-py"
        ) from e


@dataclass
class MLDSAKeyPair:
    """
    An ML-DSA-65 (CRYSTALS-Dilithium, FIPS 204) key pair for post-quantum signing.

    Key sizes:
        Public key:   1952 bytes
        Private key:  4032 bytes
        Signature:    3309 bytes

    Attributes:
        key_id:      Short identifier derived from SHA-256 of the public key.
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
            raise RCANSignatureError("Cannot save: public-only MLDSAKeyPair has no private key")
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
            raise RCANSignatureError("Not a valid MLDSAKeyPair file (missing MLDS magic)")
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
            raise RCANSignatureError("ML-DSA signature verification failed")

    @property
    def has_private_key(self) -> bool:
        return self._secret_key is not None

    def __repr__(self) -> str:
        mode = "private+public" if self.has_private_key else "public-only"
        return f"MLDSAKeyPair(key_id={self.key_id!r}, alg=ML-DSA-65, {mode})"


# ---------------------------------------------------------------------------
# Hybrid sign / verify (updated for v2.2)
# ---------------------------------------------------------------------------


def sign_message(
    msg: Any,
    keypair: "KeyPair",
    pq_keypair: "MLDSAKeyPair | None" = None,
) -> Any:
    """
    Sign an :class:`~rcan.RCANMessage` with Ed25519 (and optionally ML-DSA-65).

    In RCAN v2.2+ hybrid mode, pass both ``keypair`` (Ed25519) and
    ``pq_keypair`` (ML-DSA-65).  The message will carry two signatures:

    - ``sig`` — Ed25519 signature dict (backward-compatible with v2.1)
    - ``pq_sig`` — ML-DSA-65 signature dict (new in v2.2, field 17)

    Args:
        msg:        :class:`~rcan.RCANMessage` to sign.
        keypair:    Ed25519 key pair with private key available.
        pq_keypair: ML-DSA-65 key pair (optional; enables hybrid mode).

    Returns:
        The same message object with ``signature`` and optionally ``pq_sig`` set.
    """
    payload = _canonical_message_bytes(msg)

    # Ed25519 signature (always present)
    raw_sig = keypair.sign_bytes(payload)
    msg.signature = {
        "alg": "ed25519",
        "kid": keypair.key_id,
        "value": base64.urlsafe_b64encode(raw_sig).decode(),
    }

    # ML-DSA-65 signature (v2.2 hybrid)
    if pq_keypair is not None:
        pq_raw = pq_keypair.sign_bytes(payload)
        msg.pq_sig = {
            "alg": "ml-dsa-65",
            "kid": pq_keypair.key_id,
            "value": base64.urlsafe_b64encode(pq_raw).decode(),
        }
    else:
        msg.pq_sig = None

    return msg


def verify_message(
    msg: Any,
    trusted_keys: "list[KeyPair]",
    pq_trusted_keys: "list[MLDSAKeyPair] | None" = None,
    require_pq: bool = False,
) -> None:
    """
    Verify signatures on an :class:`~rcan.RCANMessage`.

    In hybrid mode (v2.2), verifies Ed25519 signature AND ML-DSA-65 signature
    when ``pq_trusted_keys`` is provided.

    Args:
        msg:             Message with a ``signature`` field.
        trusted_keys:    Trusted Ed25519 public :class:`KeyPair` objects.
        pq_trusted_keys: Trusted ML-DSA-65 :class:`MLDSAKeyPair` objects (optional).
        require_pq:      If True, raise if ``pq_sig`` is absent or invalid.
                         Default False for backward compat with v2.1 messages.

    Raises:
        RCANSignatureError: If any checked signature is missing, unknown, or invalid.
    """
    if not msg.signature:
        raise RCANSignatureError("Message is unsigned — signature field missing")

    payload = _canonical_message_bytes(msg)

    # --- Ed25519 verification (always required) ---
    sig_dict = msg.signature
    kid = sig_dict.get("kid")
    alg = sig_dict.get("alg", "")
    sig_value = sig_dict.get("value", "")

    if alg != "ed25519":
        raise RCANSignatureError(f"Unsupported Ed25519 signature algorithm: {alg!r}")

    matched = next((k for k in trusted_keys if k.key_id == kid), None)
    if matched is None:
        raise RCANSignatureError(
            f"No trusted key (Ed25519) with kid={kid!r}. "
            f"Known kids: {[k.key_id for k in trusted_keys]}"
        )
    try:
        raw_sig = base64.urlsafe_b64decode(sig_value + "==")
    except Exception as e:
        raise RCANSignatureError(f"Invalid base64 Ed25519 signature: {e}") from e
    matched.verify_bytes(payload, raw_sig)

    # --- ML-DSA-65 verification (v2.2 hybrid, optional unless require_pq) ---
    pq_sig_dict = getattr(msg, "pq_sig", None)
    if pq_trusted_keys or require_pq:
        if not pq_sig_dict:
            if require_pq:
                raise RCANSignatureError("ML-DSA signature (pq_sig) required but missing")
            return  # pq_trusted_keys provided but message is pre-v2.2 — skip

        pq_kid = pq_sig_dict.get("kid")
        pq_alg = pq_sig_dict.get("alg", "")
        pq_value = pq_sig_dict.get("value", "")

        if pq_alg != "ml-dsa-65":
            raise RCANSignatureError(f"Unsupported PQ signature algorithm: {pq_alg!r}")

        pq_matched = next(
            (k for k in (pq_trusted_keys or []) if k.key_id == pq_kid), None
        )
        if pq_matched is None:
            raise RCANSignatureError(
                f"No trusted ML-DSA key with kid={pq_kid!r}. "
                f"Known kids: {[k.key_id for k in (pq_trusted_keys or [])]}"
            )
        try:
            pq_raw = base64.urlsafe_b64decode(pq_value + "==")
        except Exception as e:
            raise RCANSignatureError(f"Invalid base64 ML-DSA signature: {e}") from e
        pq_matched.verify_bytes(payload, pq_raw)
