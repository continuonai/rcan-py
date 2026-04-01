"""
rcan.crypto — Post-Quantum Cryptography primitives (ML-DSA-65).

Provides ML-DSA-65 (CRYSTALS-Dilithium, NIST FIPS 204) key generation,
signing, and verification, plus hybrid Ed25519+ML-DSA-65 support and
JWK encoding for public key exchange.

Requires dilithium-py (already a dependency for rcan[pq]):
    pip install rcan[pq]

Example::

    from rcan.crypto import generate_ml_dsa_keypair, sign_ml_dsa, verify_ml_dsa

    kp = generate_ml_dsa_keypair()
    sig = sign_ml_dsa(kp, b"hello")
    verify_ml_dsa(kp.public_key_bytes, b"hello", sig)

Spec: https://rcan.dev/spec/v2.2#section-7-2
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from rcan.exceptions import RCANSignatureError

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ML_DSA_ALG = "ml-dsa-65"
HYBRID_ALG = "hybrid-ed25519-ml-dsa-65"

# ML-DSA-65 key/signature sizes
ML_DSA_PK_BYTES = 1952
ML_DSA_SK_BYTES = 4032
ML_DSA_SIG_BYTES = 3309


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _require_mldsa() -> Any:
    """Return the ML_DSA_65 class or raise ImportError."""
    try:
        from dilithium_py.ml_dsa import ML_DSA_65  # type: ignore[import]

        return ML_DSA_65
    except ImportError as exc:
        raise ImportError(
            "ML-DSA-65 requires the 'dilithium-py' package. "
            "Install with: pip install rcan[pq]"
        ) from exc


def _require_ed25519() -> Any:
    """Return Ed25519PrivateKey module or raise ImportError."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        return ed25519
    except ImportError as exc:
        raise ImportError(
            "Ed25519 hybrid signing requires the 'cryptography' package. "
            "Install with: pip install cryptography"
        ) from exc


# ---------------------------------------------------------------------------
# MlDsaKeyPair
# ---------------------------------------------------------------------------


@dataclass
class MlDsaKeyPair:
    """
    An ML-DSA-65 (CRYSTALS-Dilithium, FIPS 204) key pair.

    Attributes:
        key_id:          8-char hex derived from SHA-256 of public key.
        public_key_bytes: Raw public key bytes (1952 bytes).
        _secret_key:     Raw private key bytes (4032 bytes). None for verify-only.
    """

    key_id: str
    public_key_bytes: bytes
    _secret_key: bytes | None = field(default=None, repr=False)

    @property
    def has_private_key(self) -> bool:
        return self._secret_key is not None

    def __repr__(self) -> str:
        mode = "private+public" if self.has_private_key else "public-only"
        return f"MlDsaKeyPair(key_id={self.key_id!r}, alg={ML_DSA_ALG!r}, {mode})"


# ---------------------------------------------------------------------------
# HybridSignature
# ---------------------------------------------------------------------------


@dataclass
class HybridSignature:
    """
    Combined Ed25519 + ML-DSA-65 signature.

    Both signatures cover the same message bytes. Verification requires
    both to pass.

    Attributes:
        ed25519_sig:  Ed25519 signature bytes (64 bytes).
        ml_dsa_sig:   ML-DSA-65 signature bytes (3309 bytes).
        kid:          Key ID (derived from ML-DSA-65 public key).
    """

    ed25519_sig: bytes
    ml_dsa_sig: bytes
    kid: str

    def to_dict(self) -> dict[str, str]:
        return {
            "alg": HYBRID_ALG,
            "kid": self.kid,
            "ed25519": base64.urlsafe_b64encode(self.ed25519_sig).rstrip(b"=").decode(),
            "ml_dsa": base64.urlsafe_b64encode(self.ml_dsa_sig).rstrip(b"=").decode(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "HybridSignature":
        alg = d.get("alg", "")
        if alg != HYBRID_ALG:
            raise RCANSignatureError(
                f"Expected alg={HYBRID_ALG!r}, got {alg!r}"
            )
        try:
            ed_sig = base64.urlsafe_b64decode(d["ed25519"] + "==")
            ml_sig = base64.urlsafe_b64decode(d["ml_dsa"] + "==")
        except (KeyError, Exception) as exc:
            raise RCANSignatureError(f"Invalid hybrid signature dict: {exc}") from exc
        return cls(ed25519_sig=ed_sig, ml_dsa_sig=ml_sig, kid=d.get("kid", ""))


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def generate_ml_dsa_keypair() -> MlDsaKeyPair:
    """Generate a new ML-DSA-65 key pair.

    Returns:
        :class:`MlDsaKeyPair` with both private and public key.

    Raises:
        ImportError: If dilithium-py is not installed.
    """
    ML_DSA_65 = _require_mldsa()
    pk, sk = ML_DSA_65.keygen()
    kid = hashlib.sha256(pk).hexdigest()[:8]
    return MlDsaKeyPair(key_id=kid, public_key_bytes=pk, _secret_key=sk)


# ---------------------------------------------------------------------------
# ML-DSA-65 sign / verify
# ---------------------------------------------------------------------------


def sign_ml_dsa(keypair: MlDsaKeyPair, message: bytes) -> bytes:
    """Sign *message* with ML-DSA-65.

    Args:
        keypair: :class:`MlDsaKeyPair` with private key available.
        message: Raw bytes to sign.

    Returns:
        ML-DSA-65 signature bytes (~3309 bytes).

    Raises:
        RCANSignatureError: If the keypair has no private key.
        ImportError:        If dilithium-py is not installed.
    """
    if keypair._secret_key is None:
        raise RCANSignatureError("Cannot sign: private key not available")
    ML_DSA_65 = _require_mldsa()
    return ML_DSA_65.sign(keypair._secret_key, message)


def verify_ml_dsa(public_key_bytes: bytes, message: bytes, signature: bytes) -> None:
    """Verify an ML-DSA-65 signature.

    Args:
        public_key_bytes: Raw ML-DSA-65 public key (1952 bytes).
        message:          The signed message bytes.
        signature:        ML-DSA-65 signature bytes (~3309 bytes).

    Raises:
        RCANSignatureError: If the signature is invalid.
        ImportError:        If dilithium-py is not installed.
    """
    ML_DSA_65 = _require_mldsa()
    try:
        ok = ML_DSA_65.verify(public_key_bytes, message, signature)
    except Exception as exc:
        raise RCANSignatureError(f"ML-DSA-65 verification error: {exc}") from exc
    if not ok:
        raise RCANSignatureError("ML-DSA-65 signature verification failed")


# ---------------------------------------------------------------------------
# Hybrid Ed25519 + ML-DSA-65 sign / verify
# ---------------------------------------------------------------------------


def sign_hybrid(
    ml_dsa_keypair: MlDsaKeyPair,
    ed25519_private_key_bytes: bytes,
    message: bytes,
) -> HybridSignature:
    """Sign *message* with both Ed25519 and ML-DSA-65.

    Both signatures cover the same *message* bytes. The hybrid scheme
    provides defence-in-depth: compromising one algorithm does not break
    the other.

    Args:
        ml_dsa_keypair:           :class:`MlDsaKeyPair` with private key.
        ed25519_private_key_bytes: 32-byte Ed25519 private key seed.
        message:                   Raw bytes to sign.

    Returns:
        :class:`HybridSignature`.

    Raises:
        RCANSignatureError: If either keypair has no private key.
        ImportError:        If dilithium-py or cryptography is not installed.
    """
    ed25519 = _require_ed25519()

    ed_private = ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_private_key_bytes)
    ed_sig = ed_private.sign(message)

    ml_sig = sign_ml_dsa(ml_dsa_keypair, message)

    return HybridSignature(
        ed25519_sig=ed_sig,
        ml_dsa_sig=ml_sig,
        kid=ml_dsa_keypair.key_id,
    )


def verify_hybrid(
    ml_dsa_public_key_bytes: bytes,
    ed25519_public_key_bytes: bytes,
    message: bytes,
    hybrid_sig: HybridSignature,
) -> None:
    """Verify a :class:`HybridSignature` over *message*.

    Both Ed25519 and ML-DSA-65 signatures must be valid.

    Args:
        ml_dsa_public_key_bytes:   Raw ML-DSA-65 public key (1952 bytes).
        ed25519_public_key_bytes:  32-byte Ed25519 public key.
        message:                   The signed message bytes.
        hybrid_sig:                :class:`HybridSignature` to verify.

    Raises:
        RCANSignatureError: If either signature is invalid.
        ImportError:        If dilithium-py or cryptography is not installed.
    """
    ed25519 = _require_ed25519()

    # Verify Ed25519
    try:
        from cryptography.exceptions import InvalidSignature

        ed_pub = ed25519.Ed25519PublicKey.from_public_bytes(ed25519_public_key_bytes)
        ed_pub.verify(hybrid_sig.ed25519_sig, message)
    except InvalidSignature as exc:
        raise RCANSignatureError("Hybrid: Ed25519 signature verification failed") from exc
    except Exception as exc:
        raise RCANSignatureError(f"Hybrid: Ed25519 verification error: {exc}") from exc

    # Verify ML-DSA-65
    verify_ml_dsa(ml_dsa_public_key_bytes, message, hybrid_sig.ml_dsa_sig)


# ---------------------------------------------------------------------------
# JWK encoding / decoding for ML-DSA-65 public keys
# ---------------------------------------------------------------------------


def encode_public_key_jwk(keypair: MlDsaKeyPair) -> dict[str, str]:
    """Encode an ML-DSA-65 public key as a JWK-like dict.

    Uses the ``OKP`` key type with ``crv: ML-DSA-65`` as specified in
    draft-ietf-cose-dilithium.

    Args:
        keypair: :class:`MlDsaKeyPair` (public key only is sufficient).

    Returns:
        Dict with ``kty``, ``crv``, ``x``, and ``kid`` fields.
    """
    x = base64.urlsafe_b64encode(keypair.public_key_bytes).rstrip(b"=").decode()
    return {
        "kty": "OKP",
        "crv": "ML-DSA-65",
        "x": x,
        "kid": keypair.key_id,
        "use": "sig",
        "alg": ML_DSA_ALG,
    }


def decode_public_key_jwk(jwk: dict[str, Any]) -> MlDsaKeyPair:
    """Decode an ML-DSA-65 JWK dict into a public-only :class:`MlDsaKeyPair`.

    Args:
        jwk: Dict as produced by :func:`encode_public_key_jwk`.

    Returns:
        Public-only :class:`MlDsaKeyPair`.

    Raises:
        RCANSignatureError: If the JWK is missing required fields or has
                            an unexpected key type/curve.
    """
    kty = jwk.get("kty")
    crv = jwk.get("crv")
    if kty != "OKP" or crv != "ML-DSA-65":
        raise RCANSignatureError(
            f"Expected OKP/ML-DSA-65 JWK, got kty={kty!r} crv={crv!r}"
        )
    x = jwk.get("x")
    if not x:
        raise RCANSignatureError("JWK missing 'x' field (public key)")
    try:
        pk_bytes = base64.urlsafe_b64decode(x + "==")
    except Exception as exc:
        raise RCANSignatureError(f"Invalid base64url in JWK 'x': {exc}") from exc

    kid = jwk.get("kid") or hashlib.sha256(pk_bytes).hexdigest()[:8]
    return MlDsaKeyPair(key_id=kid, public_key_bytes=pk_bytes, _secret_key=None)


__all__ = [
    "ML_DSA_ALG",
    "HYBRID_ALG",
    "ML_DSA_PK_BYTES",
    "ML_DSA_SK_BYTES",
    "ML_DSA_SIG_BYTES",
    "MlDsaKeyPair",
    "HybridSignature",
    "generate_ml_dsa_keypair",
    "sign_ml_dsa",
    "verify_ml_dsa",
    "sign_hybrid",
    "verify_hybrid",
    "encode_public_key_jwk",
    "decode_public_key_jwk",
]
