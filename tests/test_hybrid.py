"""Tests for rcan.hybrid — dict-level hybrid signing wrapper."""
from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from rcan.crypto import generate_ml_dsa_keypair
from rcan.exceptions import RCANSignatureError
from rcan.hybrid import sign_body, verify_body


@pytest.fixture
def mldsa_keypair():
    return generate_ml_dsa_keypair()


@pytest.fixture
def ed25519_keypair():
    sk = ed25519.Ed25519PrivateKey.generate()
    sec = sk.private_bytes_raw()
    pub = sk.public_key().public_bytes_raw()
    return sec, pub


def test_sign_body_round_trip(mldsa_keypair, ed25519_keypair):
    ed_sec, ed_pub = ed25519_keypair
    body = {"rrn": "RRN-000000000042", "name": "test"}
    signed = sign_body(
        mldsa_keypair, body, ed25519_secret=ed_sec, ed25519_public=ed_pub
    )
    assert "pq_signing_pub" in signed
    assert "pq_kid" in signed
    assert "sig" in signed
    assert set(signed["sig"].keys()) == {"ml_dsa", "ed25519", "ed25519_pub"}
    assert all(isinstance(v, str) for v in signed["sig"].values())
    assert signed["rrn"] == "RRN-000000000042"
    assert signed["name"] == "test"
    assert verify_body(signed, base64.b64decode(signed["pq_signing_pub"])) is True


def test_verify_body_rejects_tampered_body(mldsa_keypair, ed25519_keypair):
    ed_sec, ed_pub = ed25519_keypair
    signed = sign_body(
        mldsa_keypair, {"name": "alice"}, ed25519_secret=ed_sec, ed25519_public=ed_pub
    )
    pq_pub = base64.b64decode(signed["pq_signing_pub"])
    signed["name"] = "mallory"
    assert verify_body(signed, pq_pub) is False


def test_verify_body_rejects_missing_sig():
    assert verify_body({"name": "alice"}, b"\x00" * 32) is False


def test_verify_body_rejects_missing_pq_signing_pub():
    assert verify_body({"sig": {"ml_dsa": "", "ed25519": "", "ed25519_pub": ""}}, b"\x00" * 32) is False


def test_verify_body_rejects_wrong_key(mldsa_keypair, ed25519_keypair):
    ed_sec, ed_pub = ed25519_keypair
    signed = sign_body(
        mldsa_keypair, {"name": "alice"}, ed25519_secret=ed_sec, ed25519_public=ed_pub
    )
    other_kp = generate_ml_dsa_keypair()
    assert verify_body(signed, other_kp.public_key_bytes) is False


def test_sign_body_preserves_body_keys(mldsa_keypair, ed25519_keypair):
    """sign_body returns a new dict containing ALL original body keys + signing fields."""
    ed_sec, ed_pub = ed25519_keypair
    body = {"a": 1, "b": {"nested": "value"}, "c": [1, 2, 3]}
    signed = sign_body(mldsa_keypair, body, ed25519_secret=ed_sec, ed25519_public=ed_pub)
    for k, v in body.items():
        assert signed[k] == v


def test_sign_body_pq_kid_is_first_8_hex_of_sha256(mldsa_keypair, ed25519_keypair):
    """pq_kid = first 8 hex chars of sha256(ml_dsa public key bytes)."""
    import hashlib

    ed_sec, ed_pub = ed25519_keypair
    signed = sign_body(
        mldsa_keypair, {"x": 1}, ed25519_secret=ed_sec, ed25519_public=ed_pub
    )
    expected_kid = hashlib.sha256(mldsa_keypair.public_key_bytes).hexdigest()[:8]
    assert signed["pq_kid"] == expected_kid
