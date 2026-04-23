"""rcan.hybrid — Dict-level hybrid signing (ML-DSA-65 + Ed25519).

This module provides a dict-in / dict-out contract for RCAN registration
bodies and other wire payloads. It wraps the low-level bytes primitives
in :mod:`rcan.crypto` with the canonical JSON serialization in
:mod:`rcan.encoding`.

Wire format produced by :func:`sign_body`::

    {
        ...body...,
        "pq_signing_pub": "<base64 ML-DSA-65 public key>",
        "pq_kid":         "<first 8 hex of sha256(ml_dsa_pub)>",
        "sig": {
            "ml_dsa":      "<base64 ML-DSA-65 signature>",
            "ed25519":     "<base64 Ed25519 signature>",
            "ed25519_pub": "<base64 Ed25519 public key>",
        },
    }

The signature is over ``canonical_json({**body, pq_signing_pub, pq_kid})``.
:func:`verify_body` strips only ``sig`` before re-canonicalizing, so the
signed bytes are reconstructed exactly.

This shape is wire-compatible with RobotRegistryFoundation's
``functions/v2/*/register.ts`` endpoints.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Any

from rcan.crypto import HybridSignature, MlDsaKeyPair, sign_hybrid, verify_hybrid
from rcan.encoding import canonical_json
from rcan.exceptions import RCANSignatureError

__all__ = ["sign_body", "verify_body"]


def _kid_from_pub(ml_dsa_pub: bytes) -> str:
    """First 8 hex chars of sha256(ml_dsa_pub). Stable per-key identifier."""
    return hashlib.sha256(ml_dsa_pub).hexdigest()[:8]


def sign_body(
    keypair: MlDsaKeyPair,
    body: dict[str, Any],
    *,
    ed25519_secret: bytes,
    ed25519_public: bytes,
) -> dict[str, Any]:
    """Sign ``body`` with a hybrid ML-DSA-65 + Ed25519 signature.

    Adds three top-level fields to a copy of ``body``:
    ``pq_signing_pub`` (base64 of ``keypair.public_key_bytes``),
    ``pq_kid`` (first 8 hex of sha256(pq_signing_pub)), and ``sig``
    (dict with ``ml_dsa``, ``ed25519``, ``ed25519_pub``, all base64).

    The signed message is ``canonical_json({**body, pq_signing_pub,
    pq_kid})``. :func:`verify_body` reconstructs that exact byte sequence.

    Args:
        keypair: ML-DSA-65 keypair. Must have ``_secret_key`` populated.
        body: Wire body to sign. Caller retains ownership; a copy is returned.
        ed25519_secret: 32 bytes, raw Ed25519 private key.
        ed25519_public: 32 bytes, raw Ed25519 public key.

    Returns:
        A new dict.

    Raises:
        RCANSignatureError: If ML-DSA signing fails.
    """
    pq_pub_b64 = base64.b64encode(keypair.public_key_bytes).decode("ascii")
    pq_kid = _kid_from_pub(keypair.public_key_bytes)
    body_with_ids = {**body, "pq_signing_pub": pq_pub_b64, "pq_kid": pq_kid}
    message = canonical_json(body_with_ids)
    hs = sign_hybrid(keypair, ed25519_secret, message)
    return {
        **body_with_ids,
        "sig": {
            "ml_dsa": base64.b64encode(hs.ml_dsa_sig).decode("ascii"),
            "ed25519": base64.b64encode(hs.ed25519_sig).decode("ascii"),
            "ed25519_pub": base64.b64encode(ed25519_public).decode("ascii"),
        },
    }


def verify_body(signed: dict[str, Any], pq_signing_pub: bytes) -> bool:
    """Verify a :func:`sign_body` payload.

    Strips the ``sig`` field, canonicalizes the remainder, hybrid-verifies
    against the passed public key.

    Returns:
        ``True`` if both signatures verify. ``False`` on any verification
        failure, malformed input, or missing required fields.
    """
    try:
        sig = signed.get("sig")
        if not sig or not isinstance(sig, dict):
            return False
        for k in ("ml_dsa", "ed25519", "ed25519_pub"):
            if k not in sig or not isinstance(sig[k], str):
                return False
        if not signed.get("pq_signing_pub"):
            return False
        rest = {k: v for k, v in signed.items() if k != "sig"}
        message = canonical_json(rest)
        verify_hybrid(
            ml_dsa_public_key_bytes=pq_signing_pub,
            ed25519_public_key_bytes=base64.b64decode(sig["ed25519_pub"]),
            message=message,
            hybrid_sig=HybridSignature(
                ml_dsa_sig=base64.b64decode(sig["ml_dsa"]),
                ed25519_sig=base64.b64decode(sig["ed25519"]),
                kid=signed.get("pq_kid", ""),
            ),
        )
        return True
    except (RCANSignatureError, KeyError, ValueError, binascii.Error):
        return False
