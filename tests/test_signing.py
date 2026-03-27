"""Tests for rcan.signing — Ed25519 key pairs and message signing."""

from __future__ import annotations

import pytest

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

pytestmark = pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography package not installed")

from rcan.signing import KeyPair, MLDSAKeyPair, sign_message, verify_message, _key_id_from_pem
from rcan import RCANMessage, RobotURI
from rcan.exceptions import RCANSignatureError

TARGET = "rcan://registry.rcan.dev/acme/arm/v2/unit-001"


def make_msg(**kwargs):
    return RCANMessage(cmd="move_forward", target=TARGET, params={"distance_m": 1.0}, **kwargs)


# ---------------------------------------------------------------------------
# KeyPair generation
# ---------------------------------------------------------------------------


def test_generate_key_pair():
    kp = KeyPair.generate()
    assert kp.key_id
    assert len(kp.key_id) == 8
    assert kp.public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert kp.has_private_key is True


def test_two_keypairs_different():
    kp1 = KeyPair.generate()
    kp2 = KeyPair.generate()
    assert kp1.key_id != kp2.key_id
    assert kp1.public_pem != kp2.public_pem


def test_repr():
    kp = KeyPair.generate()
    assert "private+public" in repr(kp)


# ---------------------------------------------------------------------------
# PEM round-trip
# ---------------------------------------------------------------------------


def test_private_pem_roundtrip():
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, NoEncryption
    )
    kp = KeyPair.generate()
    pem = kp._private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    restored = KeyPair.from_private_pem(pem)
    assert restored.key_id == kp.key_id
    assert restored.public_pem == kp.public_pem
    assert restored.has_private_key is True


def test_public_only_keypair():
    kp = KeyPair.generate()
    pub_only = KeyPair.from_public_pem(kp.public_pem)
    assert pub_only.key_id == kp.key_id
    assert pub_only.has_private_key is False


def test_public_only_cannot_sign():
    kp = KeyPair.generate()
    pub_only = KeyPair.from_public_pem(kp.public_pem)
    with pytest.raises(RCANSignatureError, match="private key not available"):
        pub_only.sign_bytes(b"data")


def test_from_private_pem_invalid():
    with pytest.raises(RCANSignatureError):
        KeyPair.from_private_pem(b"not a valid pem")


# ---------------------------------------------------------------------------
# File save / load
# ---------------------------------------------------------------------------


def test_save_and_load_private(tmp_path):
    kp = KeyPair.generate()
    path = tmp_path / "operator.pem"
    kp.save_private(path)
    assert path.exists()
    loaded = KeyPair.load(path)
    assert loaded.key_id == kp.key_id
    assert loaded.has_private_key is True


def test_save_and_load_public(tmp_path):
    kp = KeyPair.generate()
    path = tmp_path / "operator.pub"
    kp.save_public(path)
    loaded = KeyPair.load_public(path)
    assert loaded.key_id == kp.key_id
    assert loaded.has_private_key is False


def test_save_private_public_only_raises():
    kp = KeyPair.generate()
    pub_only = KeyPair.from_public_pem(kp.public_pem)
    with pytest.raises(RCANSignatureError, match="public-only"):
        pub_only.save_private("/tmp/shouldnotexist.pem")


# ---------------------------------------------------------------------------
# sign_message / verify_message
# ---------------------------------------------------------------------------


def test_sign_message_sets_signature():
    kp = KeyPair.generate()
    msg = make_msg()
    signed = sign_message(msg, kp)
    assert signed.signature is not None
    assert signed.signature["alg"] == "ed25519"
    assert signed.signature["kid"] == kp.key_id
    assert signed.signature["value"]


def test_verify_message_valid():
    kp = KeyPair.generate()
    pq_kp = MLDSAKeyPair.generate()
    msg = make_msg()
    sign_message(msg, kp, pq_keypair=pq_kp)
    trusted = [KeyPair.from_public_pem(kp.public_pem)]
    pq_trusted = [MLDSAKeyPair.from_public_bytes(pq_kp.public_key)]
    verify_message(msg, trusted, pq_trusted_keys=pq_trusted)  # should not raise


def test_verify_message_wrong_key():
    kp1 = KeyPair.generate()
    kp2 = KeyPair.generate()
    msg = make_msg()
    sign_message(msg, kp1)
    trusted = [KeyPair.from_public_pem(kp2.public_pem)]
    with pytest.raises(RCANSignatureError, match="No trusted key"):
        verify_message(msg, trusted)


def test_verify_message_tampered_payload():
    kp = KeyPair.generate()
    pq_kp = MLDSAKeyPair.generate()
    msg = make_msg()
    sign_message(msg, kp, pq_keypair=pq_kp)
    # Tamper with params after signing
    msg.params = {"distance_m": 999.0}
    trusted = [KeyPair.from_public_pem(kp.public_pem)]
    pq_trusted = [MLDSAKeyPair.from_public_bytes(pq_kp.public_key)]
    with pytest.raises(RCANSignatureError, match="[Ss]ignature"):
        verify_message(msg, trusted, pq_trusted_keys=pq_trusted)


def test_verify_unsigned_message():
    msg = make_msg()  # no signature
    with pytest.raises(RCANSignatureError, match="unsigned"):
        verify_message(msg, [])


def test_verify_unsupported_algorithm():
    msg = make_msg()
    msg.signature = {"alg": "rsa", "kid": "abc", "value": "xxx"}
    with pytest.raises(RCANSignatureError, match="Unsupported"):
        verify_message(msg, [])


def test_multiple_trusted_keys():
    kp1 = KeyPair.generate()
    kp2 = KeyPair.generate()
    pq_kp = MLDSAKeyPair.generate()
    msg = make_msg()
    sign_message(msg, kp2, pq_keypair=pq_kp)
    trusted = [
        KeyPair.from_public_pem(kp1.public_pem),
        KeyPair.from_public_pem(kp2.public_pem),
    ]
    pq_trusted = [MLDSAKeyPair.from_public_bytes(pq_kp.public_key)]
    verify_message(msg, trusted, pq_trusted_keys=pq_trusted)  # should pass (kp2 is in list)


# ---------------------------------------------------------------------------
# Key ID
# ---------------------------------------------------------------------------


def test_key_id_deterministic():
    kp = KeyPair.generate()
    assert _key_id_from_pem(kp.public_pem) == kp.key_id


def test_key_id_length():
    kp = KeyPair.generate()
    assert len(kp.key_id) == 8
