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


# ---- regression: sign_body / verify_body asymmetry on `sig` placeholder ----
# Discovered 2026-04-27 — robot-md 1.2.2 emitters pass dataclass-asdict bodies
# that include `sig: {}` placeholder fields. sign_body in rcan-py 3.3.0 included
# that placeholder in the canonical bytes; verify_body strips `sig` before
# canonicalizing. The hashes diverged → every signed artifact failed verify.

def test_sign_body_strips_sig_placeholder(mldsa_keypair, ed25519_keypair):
    """Body containing `sig: {}` placeholder must produce a verifiable signature.

    This is the exact pattern robot-md FRIA/IFU/benchmarks/eu-register emit code
    creates via dataclasses.asdict(doc) on a dataclass with `sig: dict = {}`.
    """
    ed_sec, ed_pub = ed25519_keypair
    body_with_placeholder = {"hello": "world", "n": 42, "sig": {}}
    signed = sign_body(mldsa_keypair, body_with_placeholder, ed25519_secret=ed_sec, ed25519_public=ed_pub)
    assert verify_body(signed, base64.b64decode(signed["pq_signing_pub"])) is True


def test_sign_body_clean_body_unchanged(mldsa_keypair, ed25519_keypair):
    """Behavior on body without sig must be identical to pre-3.3.1 — verifies cleanly."""
    ed_sec, ed_pub = ed25519_keypair
    signed = sign_body(mldsa_keypair, {"hello": "world", "n": 42}, ed25519_secret=ed_sec, ed25519_public=ed_pub)
    assert verify_body(signed, base64.b64decode(signed["pq_signing_pub"])) is True


def test_sign_body_sig_content_irrelevant(mldsa_keypair, ed25519_keypair):
    """The content of an existing `sig` field in body must not affect verifiability.

    sign_body strips `sig` before canonicalizing, so {} vs {"garbage": "values"}
    in body both produce signatures that verify. (The signatures themselves may
    differ due to ML-DSA randomness — only verify success matters.)
    """
    ed_sec, ed_pub = ed25519_keypair
    s1 = sign_body(mldsa_keypair, {"x": 1, "sig": {}}, ed25519_secret=ed_sec, ed25519_public=ed_pub)
    s2 = sign_body(mldsa_keypair, {"x": 1, "sig": {"garbage": "values"}}, ed25519_secret=ed_sec, ed25519_public=ed_pub)
    s3 = sign_body(mldsa_keypair, {"x": 1}, ed25519_secret=ed_sec, ed25519_public=ed_pub)
    assert verify_body(s1, base64.b64decode(s1["pq_signing_pub"])) is True
    assert verify_body(s2, base64.b64decode(s2["pq_signing_pub"])) is True
    assert verify_body(s3, base64.b64decode(s3["pq_signing_pub"])) is True
