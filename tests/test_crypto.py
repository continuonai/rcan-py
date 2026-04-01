"""
Tests for rcan.crypto — ML-DSA-65 PQC primitives (issue #47).
"""

from __future__ import annotations

import base64

import pytest

from rcan.crypto import (
    HYBRID_ALG,
    ML_DSA_ALG,
    ML_DSA_PK_BYTES,
    ML_DSA_SIG_BYTES,
    ML_DSA_SK_BYTES,
    HybridSignature,
    MlDsaKeyPair,
    decode_public_key_jwk,
    encode_public_key_jwk,
    generate_ml_dsa_keypair,
    sign_hybrid,
    sign_ml_dsa,
    verify_hybrid,
    verify_ml_dsa,
)
from rcan.exceptions import RCANSignatureError

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def kp() -> MlDsaKeyPair:
    return generate_ml_dsa_keypair()


@pytest.fixture(scope="module")
def ed25519_keys():
    """Return (private_bytes, public_bytes) for Ed25519 test keys."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes_raw()
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv_bytes, pub_bytes


# ---------------------------------------------------------------------------
# MlDsaKeyPair
# ---------------------------------------------------------------------------


class TestMlDsaKeyPair:
    def test_generate_sizes(self, kp):
        assert len(kp.public_key_bytes) == ML_DSA_PK_BYTES
        assert kp._secret_key is not None
        assert len(kp._secret_key) == ML_DSA_SK_BYTES
        assert len(kp.key_id) == 8

    def test_has_private_key_true(self, kp):
        assert kp.has_private_key is True

    def test_has_private_key_false(self, kp):
        pub = MlDsaKeyPair(
            key_id=kp.key_id, public_key_bytes=kp.public_key_bytes, _secret_key=None
        )
        assert pub.has_private_key is False

    def test_repr_private(self, kp):
        r = repr(kp)
        assert "MlDsaKeyPair" in r
        assert "private+public" in r
        assert ML_DSA_ALG in r

    def test_repr_public_only(self, kp):
        pub = MlDsaKeyPair(
            key_id=kp.key_id, public_key_bytes=kp.public_key_bytes, _secret_key=None
        )
        assert "public-only" in repr(pub)

    def test_key_id_deterministic(self, kp):
        import hashlib

        expected = hashlib.sha256(kp.public_key_bytes).hexdigest()[:8]
        assert kp.key_id == expected

    def test_different_keys_different_ids(self):
        kp1 = generate_ml_dsa_keypair()
        kp2 = generate_ml_dsa_keypair()
        assert kp1.key_id != kp2.key_id


# ---------------------------------------------------------------------------
# sign_ml_dsa / verify_ml_dsa
# ---------------------------------------------------------------------------


class TestSignVerifyMlDsa:
    def test_sign_returns_correct_size(self, kp):
        sig = sign_ml_dsa(kp, b"hello")
        assert len(sig) == ML_DSA_SIG_BYTES

    def test_verify_valid(self, kp):
        msg = b"rcan pqc test"
        sig = sign_ml_dsa(kp, msg)
        verify_ml_dsa(kp.public_key_bytes, msg, sig)  # should not raise

    def test_verify_wrong_message(self, kp):
        sig = sign_ml_dsa(kp, b"original")
        with pytest.raises(RCANSignatureError):
            verify_ml_dsa(kp.public_key_bytes, b"tampered", sig)

    def test_verify_wrong_key(self, kp):
        sig = sign_ml_dsa(kp, b"data")
        other = generate_ml_dsa_keypair()
        with pytest.raises(RCANSignatureError):
            verify_ml_dsa(other.public_key_bytes, b"data", sig)

    def test_verify_corrupted_sig(self, kp):
        sig = bytearray(sign_ml_dsa(kp, b"data"))
        sig[0] ^= 0xFF
        with pytest.raises(RCANSignatureError):
            verify_ml_dsa(kp.public_key_bytes, b"data", bytes(sig))

    def test_sign_no_private_key_raises(self, kp):
        pub_only = MlDsaKeyPair(
            key_id=kp.key_id, public_key_bytes=kp.public_key_bytes, _secret_key=None
        )
        with pytest.raises(RCANSignatureError, match="private key"):
            sign_ml_dsa(pub_only, b"data")

    def test_empty_message(self, kp):
        sig = sign_ml_dsa(kp, b"")
        verify_ml_dsa(kp.public_key_bytes, b"", sig)

    def test_large_message(self, kp):
        msg = b"x" * 100_000
        sig = sign_ml_dsa(kp, msg)
        verify_ml_dsa(kp.public_key_bytes, msg, sig)


# ---------------------------------------------------------------------------
# HybridSignature
# ---------------------------------------------------------------------------


class TestHybridSignature:
    def test_to_dict_roundtrip(self, kp, ed25519_keys):
        priv_bytes, pub_bytes = ed25519_keys
        hs = sign_hybrid(kp, priv_bytes, b"test msg")
        d = hs.to_dict()
        assert d["alg"] == HYBRID_ALG
        assert d["kid"] == kp.key_id
        hs2 = HybridSignature.from_dict(d)
        assert hs2.ed25519_sig == hs.ed25519_sig
        assert hs2.ml_dsa_sig == hs.ml_dsa_sig

    def test_from_dict_wrong_alg(self):
        d = {"alg": "wrong", "kid": "abc", "ed25519": "AAAA", "ml_dsa": "AAAA"}
        with pytest.raises(RCANSignatureError, match="alg"):
            HybridSignature.from_dict(d)

    def test_from_dict_missing_field(self):
        d = {"alg": HYBRID_ALG, "kid": "abc"}
        with pytest.raises(RCANSignatureError):
            HybridSignature.from_dict(d)


# ---------------------------------------------------------------------------
# sign_hybrid / verify_hybrid
# ---------------------------------------------------------------------------


class TestSignVerifyHybrid:
    def test_verify_valid(self, kp, ed25519_keys):
        priv_bytes, pub_bytes = ed25519_keys
        msg = b"hybrid test"
        hs = sign_hybrid(kp, priv_bytes, msg)
        verify_hybrid(kp.public_key_bytes, pub_bytes, msg, hs)

    def test_wrong_message(self, kp, ed25519_keys):
        priv_bytes, pub_bytes = ed25519_keys
        hs = sign_hybrid(kp, priv_bytes, b"original")
        with pytest.raises(RCANSignatureError):
            verify_hybrid(kp.public_key_bytes, pub_bytes, b"tampered", hs)

    def test_wrong_ed25519_key(self, kp, ed25519_keys):
        priv_bytes, pub_bytes = ed25519_keys
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        other_priv = Ed25519PrivateKey.generate()
        other_pub = other_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        hs = sign_hybrid(kp, priv_bytes, b"data")
        with pytest.raises(RCANSignatureError, match="Ed25519"):
            verify_hybrid(kp.public_key_bytes, other_pub, b"data", hs)

    def test_wrong_ml_dsa_key(self, kp, ed25519_keys):
        priv_bytes, pub_bytes = ed25519_keys
        other_kp = generate_ml_dsa_keypair()
        hs = sign_hybrid(kp, priv_bytes, b"data")
        with pytest.raises(RCANSignatureError):
            verify_hybrid(other_kp.public_key_bytes, pub_bytes, b"data", hs)

    def test_kid_matches_ml_dsa_keypair(self, kp, ed25519_keys):
        priv_bytes, _ = ed25519_keys
        hs = sign_hybrid(kp, priv_bytes, b"kid test")
        assert hs.kid == kp.key_id


# ---------------------------------------------------------------------------
# JWK encode / decode
# ---------------------------------------------------------------------------


class TestJwk:
    def test_encode_fields(self, kp):
        jwk = encode_public_key_jwk(kp)
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "ML-DSA-65"
        assert jwk["use"] == "sig"
        assert jwk["alg"] == ML_DSA_ALG
        assert jwk["kid"] == kp.key_id
        assert "x" in jwk

    def test_roundtrip(self, kp):
        jwk = encode_public_key_jwk(kp)
        recovered = decode_public_key_jwk(jwk)
        assert recovered.public_key_bytes == kp.public_key_bytes
        assert recovered.key_id == kp.key_id
        assert not recovered.has_private_key

    def test_decode_wrong_kty(self, kp):
        jwk = encode_public_key_jwk(kp)
        jwk["kty"] = "RSA"
        with pytest.raises(RCANSignatureError, match="OKP"):
            decode_public_key_jwk(jwk)

    def test_decode_wrong_crv(self, kp):
        jwk = encode_public_key_jwk(kp)
        jwk["crv"] = "Ed25519"
        with pytest.raises(RCANSignatureError, match="ML-DSA-65"):
            decode_public_key_jwk(jwk)

    def test_decode_missing_x(self, kp):
        jwk = {"kty": "OKP", "crv": "ML-DSA-65", "kid": kp.key_id}
        with pytest.raises(RCANSignatureError, match="'x'"):
            decode_public_key_jwk(jwk)

    def test_x_is_base64url_no_padding(self, kp):
        jwk = encode_public_key_jwk(kp)
        assert "=" not in jwk["x"]

    def test_decoded_key_can_verify(self, kp):
        jwk = encode_public_key_jwk(kp)
        pub = decode_public_key_jwk(jwk)
        msg = b"verify after jwk roundtrip"
        sig = sign_ml_dsa(kp, msg)
        verify_ml_dsa(pub.public_key_bytes, msg, sig)

    def test_kid_inferred_when_missing(self, kp):
        import hashlib

        jwk = encode_public_key_jwk(kp)
        del jwk["kid"]
        recovered = decode_public_key_jwk(jwk)
        expected_kid = hashlib.sha256(kp.public_key_bytes).hexdigest()[:8]
        assert recovered.key_id == expected_kid


# ---------------------------------------------------------------------------
# RobotURI.sign_pqc / verify_sig_pqc integration
# ---------------------------------------------------------------------------


class TestRobotUriPqc:
    URI = "rcan://registry.rcan.dev/acme/robotarm/v2/unit-001"

    def test_sign_pqc_contains_param(self, kp):
        from rcan.address import RobotURI

        uri = RobotURI.parse(self.URI)
        signed = uri.sign_pqc(kp)
        assert "?pqc_sig=" in signed

    def test_verify_sig_pqc_valid(self, kp):
        from rcan.address import RobotURI

        uri = RobotURI.parse(self.URI)
        signed = uri.sign_pqc(kp)
        _, _, pqc_sig = signed.partition("?pqc_sig=")
        assert uri.verify_sig_pqc(pqc_sig, kp) is True

    def test_verify_sig_pqc_wrong_key(self, kp):
        from rcan.address import RobotURI
        from rcan.exceptions import RCANAddressError

        uri = RobotURI.parse(self.URI)
        signed = uri.sign_pqc(kp)
        _, _, pqc_sig = signed.partition("?pqc_sig=")
        other_kp = generate_ml_dsa_keypair()
        with pytest.raises(RCANAddressError, match="PQC_SIGNATURE_INVALID"):
            uri.verify_sig_pqc(pqc_sig, other_kp)

    def test_sign_pqc_no_private_key_raises(self, kp):
        from rcan.address import RobotURI
        from rcan.exceptions import RCANSignatureError

        uri = RobotURI.parse(self.URI)
        pub_only = MlDsaKeyPair(
            key_id=kp.key_id, public_key_bytes=kp.public_key_bytes, _secret_key=None
        )
        with pytest.raises(RCANSignatureError):
            uri.sign_pqc(pub_only)


# ---------------------------------------------------------------------------
# sign_m2m_pqc / verify_m2m_pqc integration
# ---------------------------------------------------------------------------


class TestM2MPqc:
    def test_sign_adds_pqc_sig(self, kp):
        from rcan.m2m import sign_m2m_pqc

        payload = {"sub": "robot-001", "iss": "rrf.rcan.dev", "exp": 9999999999}
        result = sign_m2m_pqc(payload, kp)
        assert "pqc_sig" in result
        assert isinstance(result["pqc_sig"], str)

    def test_verify_valid(self, kp):
        from rcan.m2m import sign_m2m_pqc, verify_m2m_pqc

        payload = {"sub": "robot-001", "iss": "rrf.rcan.dev", "exp": 9999999999}
        sign_m2m_pqc(payload, kp)
        verify_m2m_pqc(payload, kp.public_key_bytes)  # should not raise

    def test_verify_wrong_key(self, kp):
        from rcan.m2m import M2MAuthError, sign_m2m_pqc, verify_m2m_pqc

        payload = {"sub": "robot-001", "iss": "rrf.rcan.dev", "exp": 9999999999}
        sign_m2m_pqc(payload, kp)
        other = generate_ml_dsa_keypair()
        with pytest.raises(M2MAuthError):
            verify_m2m_pqc(payload, other.public_key_bytes)

    def test_verify_missing_sig_field(self, kp):
        from rcan.m2m import M2MAuthError, verify_m2m_pqc

        payload = {"sub": "robot-001"}
        with pytest.raises(M2MAuthError, match="pqc_sig"):
            verify_m2m_pqc(payload, kp.public_key_bytes)

    def test_custom_sig_field(self, kp):
        from rcan.m2m import sign_m2m_pqc, verify_m2m_pqc

        payload = {"sub": "robot-001", "exp": 9999999999}
        sign_m2m_pqc(payload, kp, sig_field="rrf_pqc_sig")
        assert "rrf_pqc_sig" in payload
        verify_m2m_pqc(payload, kp.public_key_bytes, sig_field="rrf_pqc_sig")

    def test_payload_mutation_breaks_sig(self, kp):
        from rcan.m2m import M2MAuthError, sign_m2m_pqc, verify_m2m_pqc

        payload = {"sub": "robot-001", "exp": 9999999999}
        sign_m2m_pqc(payload, kp)
        payload["sub"] = "attacker-999"  # tamper after signing
        with pytest.raises(M2MAuthError):
            verify_m2m_pqc(payload, kp.public_key_bytes)

    def test_sign_modifies_payload_in_place(self, kp):
        from rcan.m2m import sign_m2m_pqc

        payload = {"sub": "x", "exp": 1}
        result = sign_m2m_pqc(payload, kp)
        assert result is payload
        assert "pqc_sig" in payload
