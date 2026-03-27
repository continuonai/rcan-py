"""
Tests for RCAN v2.2 post-quantum hybrid signing.

Covers:
  - MLDSAKeyPair generation, save/load, sign/verify
  - Hybrid sign_message() and verify_message() (Ed25519 + ML-DSA-65)
  - Backward compat: v2.1 messages (no pq_sig) still verify with Ed25519-only path
  - require_pq enforcement
  - RCANMessage pq_sig round-trip (to_dict / from_dict)
  - Error paths: wrong key, tampered payload, missing pq_sig with require_pq
"""

from __future__ import annotations

import base64
import tempfile
from pathlib import Path

import pytest

from rcan import RCANMessage, RobotURI
from rcan.exceptions import RCANSignatureError
from rcan.signing import KeyPair, MLDSAKeyPair, sign_message, verify_message


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

URI = RobotURI.parse("rcan://rrf.rcan.dev/test/robot/v1/unit-001")


@pytest.fixture(scope="module")
def ed_kp() -> KeyPair:
    return KeyPair.generate()


@pytest.fixture(scope="module")
def pq_kp() -> MLDSAKeyPair:
    return MLDSAKeyPair.generate()


def _msg() -> RCANMessage:
    return RCANMessage(cmd="test_cmd", target=URI, params={"x": 1})


# ---------------------------------------------------------------------------
# MLDSAKeyPair unit tests
# ---------------------------------------------------------------------------


class TestMLDSAKeyPair:
    def test_generate(self):
        kp = MLDSAKeyPair.generate()
        assert len(kp.public_key) == 1952
        assert kp._secret_key is not None
        assert len(kp._secret_key) == 4032
        assert len(kp.key_id) == 8

    def test_sign_verify_bytes(self, pq_kp):
        data = b"hello rcan v2.2"
        sig = pq_kp.sign_bytes(data)
        assert len(sig) == 3309
        pq_kp.verify_bytes(data, sig)  # no exception = pass

    def test_verify_tampered(self, pq_kp):
        data = b"original"
        sig = pq_kp.sign_bytes(data)
        with pytest.raises(RCANSignatureError):
            pq_kp.verify_bytes(b"tampered", sig)

    def test_public_only_cannot_sign(self):
        kp = MLDSAKeyPair.generate()
        pub_only = MLDSAKeyPair.from_public_bytes(kp.public_key)
        with pytest.raises(RCANSignatureError):
            pub_only.sign_bytes(b"data")

    def test_repr(self, pq_kp):
        r = repr(pq_kp)
        assert "ML-DSA-65" in r
        assert "private+public" in r

    def test_save_load_roundtrip(self, pq_kp):
        with tempfile.NamedTemporaryFile(suffix=".key", delete=False) as f:
            path = f.name
        pq_kp.save(path)
        loaded = MLDSAKeyPair.load(path)
        assert loaded.public_key == pq_kp.public_key
        assert loaded._secret_key == pq_kp._secret_key
        assert loaded.key_id == pq_kp.key_id
        # Verify still works after round-trip
        data = b"roundtrip test"
        sig = loaded.sign_bytes(data)
        loaded.verify_bytes(data, sig)

    def test_save_public_load_public(self, pq_kp):
        with tempfile.NamedTemporaryFile(suffix=".pub", delete=False) as f:
            path = f.name
        pq_kp.save_public(path)
        pub_only = MLDSAKeyPair.load_public(path)
        assert pub_only.public_key == pq_kp.public_key
        assert not pub_only.has_private_key

    def test_save_without_private_raises(self):
        pub_only = MLDSAKeyPair.from_public_bytes(b"\x00" * 1952)
        with tempfile.NamedTemporaryFile(suffix=".key") as f:
            with pytest.raises(RCANSignatureError):
                pub_only.save(f.name)

    def test_load_invalid_magic(self):
        with tempfile.NamedTemporaryFile(suffix=".key", delete=False) as f:
            f.write(b"XXXX" + b"\x00" * 100)
            path = f.name
        with pytest.raises(RCANSignatureError, match="magic"):
            MLDSAKeyPair.load(path)


# ---------------------------------------------------------------------------
# Hybrid sign_message / verify_message
# ---------------------------------------------------------------------------


class TestHybridSigning:
    def test_hybrid_sign_sets_both_sigs(self, ed_kp, pq_kp):
        msg = _msg()
        signed = sign_message(msg, ed_kp, pq_keypair=pq_kp)
        assert signed.signature is not None
        assert signed.signature["alg"] == "ed25519"
        assert signed.pq_sig is not None
        assert signed.pq_sig["alg"] == "ml-dsa-65"

    def test_ed_only_sign_no_pq_sig(self, ed_kp):
        msg = _msg()
        signed = sign_message(msg, ed_kp)
        assert signed.signature is not None
        assert signed.pq_sig is None

    def test_hybrid_verify_both_valid(self, ed_kp, pq_kp):
        msg = _msg()
        sign_message(msg, ed_kp, pq_keypair=pq_kp)
        pub_ed = KeyPair.from_public_pem(ed_kp.public_pem)
        pub_pq = MLDSAKeyPair.from_public_bytes(pq_kp.public_key)
        verify_message(msg, [pub_ed], pq_trusted_keys=[pub_pq])  # no exception

    def test_ed_only_verify_legacy_compat(self, ed_kp):
        """Ed25519-only messages still verify with require_pq=False (legacy v2.1 compat)."""
        msg = _msg()
        sign_message(msg, ed_kp)
        pub_ed = KeyPair.from_public_pem(ed_kp.public_pem)
        verify_message(msg, [pub_ed], require_pq=False)  # explicit legacy compat

    def test_hybrid_msg_pq_trusted_no_pq_sig_skips(self, ed_kp, pq_kp):
        """v2.1 message (no pq_sig) — accepted only with require_pq=False (legacy compat)."""
        msg = _msg()
        sign_message(msg, ed_kp)  # Ed25519 only
        pub_ed = KeyPair.from_public_pem(ed_kp.public_pem)
        pub_pq = MLDSAKeyPair.from_public_bytes(pq_kp.public_key)
        verify_message(msg, [pub_ed], pq_trusted_keys=[pub_pq], require_pq=False)  # explicit compat

    def test_require_pq_raises_when_absent(self, ed_kp):
        msg = _msg()
        sign_message(msg, ed_kp)  # no pq_sig
        pub_ed = KeyPair.from_public_pem(ed_kp.public_pem)
        with pytest.raises(RCANSignatureError, match="pq_sig.*required"):
            verify_message(msg, [pub_ed], require_pq=True)

    def test_require_pq_passes_when_present(self, ed_kp, pq_kp):
        msg = _msg()
        sign_message(msg, ed_kp, pq_keypair=pq_kp)
        pub_ed = KeyPair.from_public_pem(ed_kp.public_pem)
        pub_pq = MLDSAKeyPair.from_public_bytes(pq_kp.public_key)
        verify_message(msg, [pub_ed], pq_trusted_keys=[pub_pq], require_pq=True)

    def test_tampered_pq_sig_raises(self, ed_kp, pq_kp):
        msg = _msg()
        sign_message(msg, ed_kp, pq_keypair=pq_kp)
        # Corrupt pq_sig value
        orig = base64.urlsafe_b64decode(msg.pq_sig["value"] + "==")
        corrupted = bytearray(orig)
        corrupted[0] ^= 0xFF
        msg.pq_sig["value"] = base64.urlsafe_b64encode(bytes(corrupted)).decode()
        pub_ed = KeyPair.from_public_pem(ed_kp.public_pem)
        pub_pq = MLDSAKeyPair.from_public_bytes(pq_kp.public_key)
        with pytest.raises(RCANSignatureError):
            verify_message(msg, [pub_ed], pq_trusted_keys=[pub_pq])

    def test_wrong_pq_key_raises(self, ed_kp, pq_kp):
        msg = _msg()
        sign_message(msg, ed_kp, pq_keypair=pq_kp)
        pub_ed = KeyPair.from_public_pem(ed_kp.public_pem)
        other_pq = MLDSAKeyPair.generate()
        pub_pq_wrong = MLDSAKeyPair.from_public_bytes(other_pq.public_key)
        with pytest.raises(RCANSignatureError, match="kid"):
            verify_message(msg, [pub_ed], pq_trusted_keys=[pub_pq_wrong])

    def test_unsupported_pq_alg_raises(self, ed_kp, pq_kp):
        msg = _msg()
        sign_message(msg, ed_kp, pq_keypair=pq_kp)
        msg.pq_sig["alg"] = "slh-dsa-sha2-128s"  # not yet supported
        pub_ed = KeyPair.from_public_pem(ed_kp.public_pem)
        pub_pq = MLDSAKeyPair.from_public_bytes(pq_kp.public_key)
        with pytest.raises(RCANSignatureError, match="Unsupported PQ"):
            verify_message(msg, [pub_ed], pq_trusted_keys=[pub_pq])


# ---------------------------------------------------------------------------
# RCANMessage round-trip (to_dict / from_dict)
# ---------------------------------------------------------------------------


class TestMessageRoundTrip:
    def test_pq_sig_survives_round_trip(self, ed_kp, pq_kp):
        msg = _msg()
        sign_message(msg, ed_kp, pq_keypair=pq_kp)
        d = msg.to_dict()
        assert "pq_sig" in d
        assert d["pq_sig"]["alg"] == "ml-dsa-65"
        restored = RCANMessage.from_dict(d)
        assert restored.pq_sig is not None
        assert restored.pq_sig["alg"] == "ml-dsa-65"
        assert restored.pq_sig["value"] == msg.pq_sig["value"]

    def test_no_pq_sig_absent_from_dict(self, ed_kp):
        msg = _msg()
        sign_message(msg, ed_kp)
        d = msg.to_dict()
        assert "pq_sig" not in d

    def test_pq_sig_verify_after_round_trip(self, ed_kp, pq_kp):
        msg = _msg()
        sign_message(msg, ed_kp, pq_keypair=pq_kp)
        restored = RCANMessage.from_dict(msg.to_dict())
        pub_ed = KeyPair.from_public_pem(ed_kp.public_pem)
        pub_pq = MLDSAKeyPair.from_public_bytes(pq_kp.public_key)
        verify_message(restored, [pub_ed], pq_trusted_keys=[pub_pq])
