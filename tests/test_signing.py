"""
Tests for RCAN v2.2 ML-DSA-65 signing.

Ed25519 (KeyPair) is deprecated. MLDSAKeyPair is the only signing class.
All tests use sign_message(msg, mldsa_kp) and verify_message(msg, [pub]).
"""

from __future__ import annotations

import pytest

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,  # noqa: F401
    )

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

from rcan import RCANMessage, RobotURI
from rcan.exceptions import RCANSignatureError
from rcan.signing import MLDSAKeyPair, sign_message, verify_message

URI = RobotURI.parse("rcan://rrf.rcan.dev/test/robot/v1/unit-001")


def make_msg() -> RCANMessage:
    return RCANMessage(cmd="move_forward", target=URI, params={"distance_m": 1.0})


# ---------------------------------------------------------------------------
# Sign
# ---------------------------------------------------------------------------


def test_sign_message_sets_signature():
    kp = MLDSAKeyPair.generate()
    msg = make_msg()
    signed = sign_message(msg, kp)
    assert signed.signature is not None
    assert signed.signature["alg"] == "ml-dsa-65"
    assert signed.signature["kid"] == kp.key_id
    assert signed.signature["value"]


def test_sign_message_clears_pq_sig():
    """pq_sig from hybrid period should be cleared on fresh sign."""
    kp = MLDSAKeyPair.generate()
    msg = make_msg()
    msg.pq_sig = {"alg": "ml-dsa-65", "kid": "old", "value": "oldsig"}  # type: ignore[attr-defined]
    sign_message(msg, kp)
    assert getattr(msg, "pq_sig", None) is None


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


def test_verify_message_valid():
    kp = MLDSAKeyPair.generate()
    msg = make_msg()
    sign_message(msg, kp)
    pub = MLDSAKeyPair.from_public_bytes(kp.public_key)
    verify_message(msg, [pub])  # no exception


def test_verify_message_wrong_key():
    kp1 = MLDSAKeyPair.generate()
    kp2 = MLDSAKeyPair.generate()
    msg = make_msg()
    sign_message(msg, kp1)
    pub_wrong = MLDSAKeyPair.from_public_bytes(kp2.public_key)
    with pytest.raises(RCANSignatureError, match="No trusted"):
        verify_message(msg, [pub_wrong])


def test_verify_message_tampered_payload():
    kp = MLDSAKeyPair.generate()
    msg = make_msg()
    sign_message(msg, kp)
    msg.params = {"distance_m": 999.0}
    pub = MLDSAKeyPair.from_public_bytes(kp.public_key)
    with pytest.raises(RCANSignatureError):
        verify_message(msg, [pub])


def test_verify_unsigned_message():
    msg = make_msg()
    with pytest.raises(RCANSignatureError, match="unsigned"):
        verify_message(msg, [])


def test_verify_ed25519_sig_rejected():
    """Ed25519 signatures are rejected in RCAN v2.2."""
    msg = make_msg()
    msg.signature = {"alg": "ed25519", "kid": "abc", "value": "xxx"}
    kp = MLDSAKeyPair.generate()
    pub = MLDSAKeyPair.from_public_bytes(kp.public_key)
    with pytest.raises(RCANSignatureError, match="deprecated|ml-dsa-65"):
        verify_message(msg, [pub])


def test_verify_multiple_trusted_keys():
    kp1 = MLDSAKeyPair.generate()
    kp2 = MLDSAKeyPair.generate()
    msg = make_msg()
    sign_message(msg, kp2)
    trusted = [
        MLDSAKeyPair.from_public_bytes(kp1.public_key),
        MLDSAKeyPair.from_public_bytes(kp2.public_key),
    ]
    verify_message(msg, trusted)  # kp2 is in the list


# ---------------------------------------------------------------------------
# KeyPair deprecation
# ---------------------------------------------------------------------------


def test_keypair_deprecated():
    from rcan.signing import KeyPair

    with pytest.raises(DeprecationWarning):
        KeyPair()


def test_keypair_generate_redirects():
    import warnings

    from rcan.signing import KeyPair

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        kp = KeyPair.generate()
        assert any("deprecated" in str(warning.message).lower() for warning in w)
    assert isinstance(kp, MLDSAKeyPair)


# ---------------------------------------------------------------------------
# Key ID
# ---------------------------------------------------------------------------


def test_key_id_deterministic():
    kp = MLDSAKeyPair.generate()
    pub = MLDSAKeyPair.from_public_bytes(kp.public_key)
    assert pub.key_id == kp.key_id


def test_key_id_length():
    kp = MLDSAKeyPair.generate()
    assert len(kp.key_id) == 8
