"""
Tests for RCAN v2.2 ML-DSA-65 signing (formerly PQ hybrid tests).

Ed25519 is deprecated. This file tests MLDSAKeyPair directly.
sign_message / verify_message now use only ML-DSA-65.
"""

from __future__ import annotations

import base64
import tempfile

import pytest

from rcan import RCANMessage, RobotURI
from rcan.exceptions import RCANSignatureError
from rcan.signing import MLDSAKeyPair, sign_message, verify_message

URI = RobotURI.parse("rcan://rrf.rcan.dev/test/robot/v1/unit-001")


@pytest.fixture(scope="module")
def kp() -> MLDSAKeyPair:
    return MLDSAKeyPair.generate()


def _msg() -> RCANMessage:
    return RCANMessage(cmd="test_cmd", target=URI, params={"x": 1})


class TestMLDSAKeyPair:
    def test_generate(self):
        kp = MLDSAKeyPair.generate()
        assert len(kp.public_key) == 1952
        assert kp._secret_key is not None
        assert len(kp._secret_key) == 4032
        assert len(kp.key_id) == 8

    def test_sign_verify_bytes(self, kp):
        data = b"hello rcan v2.2"
        sig = kp.sign_bytes(data)
        assert len(sig) == 3309
        kp.verify_bytes(data, sig)

    def test_verify_tampered(self, kp):
        data = b"original"
        sig = kp.sign_bytes(data)
        with pytest.raises(RCANSignatureError):
            kp.verify_bytes(b"tampered", sig)

    def test_public_only_cannot_sign(self):
        kp = MLDSAKeyPair.generate()
        pub = MLDSAKeyPair.from_public_bytes(kp.public_key)
        with pytest.raises(RCANSignatureError):
            pub.sign_bytes(b"data")

    def test_repr(self, kp):
        r = repr(kp)
        assert "ML-DSA-65" in r
        assert "private+public" in r

    def test_save_load_roundtrip(self, kp):
        with tempfile.NamedTemporaryFile(suffix=".key", delete=False) as f:
            path = f.name
        kp.save(path)
        loaded = MLDSAKeyPair.load(path)
        assert loaded.public_key == kp.public_key
        assert loaded._secret_key == kp._secret_key
        data = b"roundtrip"
        loaded.verify_bytes(data, loaded.sign_bytes(data))

    def test_save_public_load_public(self, kp):
        with tempfile.NamedTemporaryFile(suffix=".pub", delete=False) as f:
            path = f.name
        kp.save_public(path)
        pub = MLDSAKeyPair.load_public(path)
        assert pub.public_key == kp.public_key
        assert not pub.has_private_key

    def test_save_without_private_raises(self):
        pub = MLDSAKeyPair.from_public_bytes(b"\x00" * 1952)
        with tempfile.NamedTemporaryFile(suffix=".key") as f:
            with pytest.raises(RCANSignatureError):
                pub.save(f.name)

    def test_load_invalid_magic(self):
        with tempfile.NamedTemporaryFile(suffix=".key", delete=False) as f:
            f.write(b"XXXX" + b"\x00" * 100)
            path = f.name
        with pytest.raises(RCANSignatureError, match="magic"):
            MLDSAKeyPair.load(path)


class TestSignVerify:
    def test_sign_sets_ml_dsa_alg(self, kp):
        msg = _msg()
        signed = sign_message(msg, kp)
        assert signed.signature["alg"] == "ml-dsa-65"

    def test_verify_valid(self, kp):
        msg = _msg()
        sign_message(msg, kp)
        pub = MLDSAKeyPair.from_public_bytes(kp.public_key)
        verify_message(msg, [pub])

    def test_verify_wrong_key(self, kp):
        msg = _msg()
        sign_message(msg, kp)
        other = MLDSAKeyPair.generate()
        with pytest.raises(RCANSignatureError, match="No trusted"):
            verify_message(msg, [MLDSAKeyPair.from_public_bytes(other.public_key)])

    def test_tampered_sig(self, kp):
        msg = _msg()
        sign_message(msg, kp)
        orig = base64.urlsafe_b64decode(msg.signature["value"] + "==")
        corrupted = bytearray(orig)
        corrupted[0] ^= 0xFF
        msg.signature["value"] = base64.urlsafe_b64encode(bytes(corrupted)).decode()
        pub = MLDSAKeyPair.from_public_bytes(kp.public_key)
        with pytest.raises(RCANSignatureError):
            verify_message(msg, [pub])

    def test_ed25519_sig_rejected(self, kp):
        msg = _msg()
        msg.signature = {"alg": "ed25519", "kid": kp.key_id, "value": "xxx"}
        pub = MLDSAKeyPair.from_public_bytes(kp.public_key)
        with pytest.raises(RCANSignatureError, match="deprecated|ml-dsa-65"):
            verify_message(msg, [pub])


class TestMessageRoundTrip:
    def test_signature_survives_round_trip(self, kp):
        msg = _msg()
        sign_message(msg, kp)
        d = msg.to_dict()
        assert d["sig"]["alg"] == "ml-dsa-65"
        restored = RCANMessage.from_dict(d)
        assert restored.signature["alg"] == "ml-dsa-65"
        assert restored.signature["value"] == msg.signature["value"]

    def test_verify_after_round_trip(self, kp):
        msg = _msg()
        sign_message(msg, kp)
        restored = RCANMessage.from_dict(msg.to_dict())
        pub = MLDSAKeyPair.from_public_bytes(kp.public_key)
        verify_message(restored, [pub])
