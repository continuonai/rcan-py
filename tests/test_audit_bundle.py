"""Tests for rcan.audit_bundle — construct + verify."""

from __future__ import annotations

import base64
import json

from rcan.audit_bundle import (
    Artifact,
    AuditBundle,
    BundleVerificationResult,
    Signature,
    VerifyMode,
    canonical_json,
    hash_robot_md,
    verify_bundle,
)


def test_canonical_json_is_deterministic():
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert canonical_json({"a": [3, 1, 2]}) == b'{"a":[3,1,2]}'
    assert canonical_json({"a": "héllo"}) == '{"a":"héllo"}'.encode("utf-8")


def test_canonical_json_excludes_signature_field():
    obj = {"a": 1, "signature": {"kid": "x", "alg": "Ed25519", "sig": "abc"}}
    canon = canonical_json(obj, exclude="signature")
    assert b"signature" not in canon


def test_canonical_json_normalizes_whole_number_floats():
    """Ensures the audit-bundle canonical_json shares the rcan-ts parity fix."""
    assert canonical_json({"x": 50.0}) == b'{"x":50}'


def test_construct_minimal_bundle():
    bundle = AuditBundle.new(
        rrn="RRN-000000000002",
        robot_md_sha256="a" * 64,
        artifacts=[],
    )
    payload = bundle.to_dict()
    assert payload["schema_version"] == "1.0"
    assert payload["rrn"] == "RRN-000000000002"
    assert payload["bundle_id"].startswith("bundle_")
    assert "signed_at" in payload


def test_hash_robot_md_is_sha256_hex():
    digest = hash_robot_md(b"# ROBOT\nname: bob\n")
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_verify_bundle_aggregator_trust_mode_with_valid_signature():
    """A bundle signed correctly verifies in AGGREGATOR_TRUST mode."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    bundle_json = _build_signed_bundle(priv, kid="test-kid")
    pubkey_pem = _pubkey_pem(priv)

    result = verify_bundle(
        bundle_json,
        mode=VerifyMode.AGGREGATOR_TRUST,
        kid_to_pem={"test-kid": pubkey_pem},
    )
    assert result.bundle_signature_ok is True
    assert result.all_ok is True


def test_verify_bundle_rejects_tampered_payload():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    bundle_json = _build_signed_bundle(priv, kid="test-kid")
    bundle_json = bundle_json.replace("RRN-000000000002", "RRN-000000000099")
    pubkey_pem = _pubkey_pem(priv)

    result = verify_bundle(
        bundle_json,
        mode=VerifyMode.AGGREGATOR_TRUST,
        kid_to_pem={"test-kid": pubkey_pem},
    )
    assert result.bundle_signature_ok is False


def test_verify_bundle_strict_mode_checks_inner_artifacts():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    bundle_priv = Ed25519PrivateKey.generate()
    artifact_priv = Ed25519PrivateKey.generate()

    artifact = _build_signed_artifact(artifact_priv, kid="art-kid")
    bundle_json = _build_signed_bundle(
        bundle_priv, kid="bundle-kid", artifacts=[artifact]
    )

    kid_to_pem = {
        "bundle-kid": _pubkey_pem(bundle_priv),
        "art-kid": _pubkey_pem(artifact_priv),
    }
    result = verify_bundle(bundle_json, mode=VerifyMode.STRICT, kid_to_pem=kid_to_pem)
    assert result.bundle_signature_ok is True
    assert len(result.artifact_results) == 1
    assert result.artifact_results[0].ok is True
    assert result.all_ok is True


def test_verify_bundle_strict_rejects_tampered_artifact():
    """STRICT must catch a tampered inner artifact even when the outer
    bundle signature is still valid."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    bundle_priv = Ed25519PrivateKey.generate()
    artifact_priv = Ed25519PrivateKey.generate()

    artifact = _build_signed_artifact(artifact_priv, kid="art-kid")
    bundle_json_str = _build_signed_bundle(
        bundle_priv, kid="bundle-kid", artifacts=[artifact]
    )

    bundle_dict = json.loads(bundle_json_str)
    bundle_dict["artifacts"][0]["payload"]["pass"] = 999
    tampered_json = json.dumps(bundle_dict)

    kid_to_pem = {
        "bundle-kid": _pubkey_pem(bundle_priv),
        "art-kid": _pubkey_pem(artifact_priv),
    }
    result = verify_bundle(tampered_json, mode=VerifyMode.STRICT, kid_to_pem=kid_to_pem)

    assert result.all_ok is False
    assert len(result.artifact_results) == 1
    assert result.artifact_results[0].ok is False
    assert "did not verify" in result.artifact_results[0].reason


def test_verify_bundle_kid_resolver_callable():
    """kid_to_pem may be a callable, not just a dict."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    bundle_json = _build_signed_bundle(priv, kid="cb-kid")
    pubkey_pem = _pubkey_pem(priv)

    def resolver(kid: str) -> bytes | None:
        return pubkey_pem if kid == "cb-kid" else None

    result = verify_bundle(
        bundle_json, mode=VerifyMode.AGGREGATOR_TRUST, kid_to_pem=resolver
    )
    assert result.bundle_signature_ok is True


def test_verify_bundle_missing_signature_returns_false():
    bundle = AuditBundle.new(
        rrn="RRN-000000000002",
        robot_md_sha256="a" * 64,
        artifacts=[],
    )
    payload = bundle.to_dict()
    result = verify_bundle(
        json.dumps(payload),
        mode=VerifyMode.AGGREGATOR_TRUST,
        kid_to_pem={},
    )
    assert isinstance(result, BundleVerificationResult)
    assert result.bundle_signature_ok is False
    assert result.all_ok is False


def _build_signed_bundle(priv, *, kid: str, artifacts=None) -> str:
    bundle = AuditBundle.new(
        rrn="RRN-000000000002",
        robot_md_sha256="a" * 64,
        artifacts=artifacts or [],
    )
    payload = bundle.to_dict()
    canon = canonical_json(payload, exclude="bundle_signature")
    sig = priv.sign(canon)
    payload["bundle_signature"] = {
        "kid": kid,
        "alg": "Ed25519",
        "sig": base64.b64encode(sig).decode("ascii"),
    }
    return json.dumps(payload)


def _build_signed_artifact(priv, *, kid: str) -> Artifact:
    body = {
        "artifact_type": "cert-gateway-authority",
        "schema_version": "1.0",
        "produced_at": "2026-05-03T19:00:00+00:00",
        "payload": {"pass": 4, "fail": 0},
    }
    canon = canonical_json(body, exclude="artifact_signature")
    sig = priv.sign(canon)
    return Artifact(
        artifact_type=body["artifact_type"],
        schema_version=body["schema_version"],
        produced_at=body["produced_at"],
        payload=body["payload"],
        artifact_signature=Signature(
            kid=kid,
            alg="Ed25519",
            sig=base64.b64encode(sig).decode("ascii"),
        ),
    )


def _pubkey_pem(priv) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
