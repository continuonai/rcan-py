"""Audit-bundle v1.0 — construction + verification helpers.

Implements the nested-signature envelope from rcan-spec
``schemas/audit-bundle-v1.json``. Reuses :func:`rcan.encoding.canonical_json`
for cross-language byte parity (the ``exclude`` kwarg drops the signature
field before serializing the pre-image).

Verification requires the ``[crypto]`` extra::

    pip install rcan[crypto]

Construction (``AuditBundle.new`` / ``Artifact`` / ``Signature`` /
:func:`canonical_json` / :func:`hash_robot_md`) has no third-party
dependencies — it works on a base ``rcan`` install.
"""

from __future__ import annotations

import enum
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Union

from rcan.encoding import canonical_json

__all__ = [
    "SCHEMA_VERSION",
    "Signature",
    "Artifact",
    "AuditBundle",
    "VerifyMode",
    "ArtifactVerificationResult",
    "BundleVerificationResult",
    "verify_bundle",
    "canonical_json",
    "hash_robot_md",
]

SCHEMA_VERSION = "1.0"

KidResolver = Union[dict[str, bytes], Callable[[str], bytes | None]]


@dataclass
class Signature:
    kid: str
    alg: str  # always "Ed25519" in v1.0
    sig: str  # base64

    def to_dict(self) -> dict:
        return {"kid": self.kid, "alg": self.alg, "sig": self.sig}


@dataclass
class Artifact:
    artifact_type: str
    schema_version: str
    produced_at: str
    payload: dict
    artifact_signature: Signature

    def to_dict(self) -> dict:
        return {
            "artifact_type": self.artifact_type,
            "schema_version": self.schema_version,
            "produced_at": self.produced_at,
            "payload": self.payload,
            "artifact_signature": self.artifact_signature.to_dict(),
        }


@dataclass
class AuditBundle:
    bundle_id: str
    rrn: str
    robot_md_sha256: str
    signed_at: str
    matrix_version: str = "1.0"
    matrix_signed_at: str | None = None
    operator: dict | None = None
    artifacts: list[Artifact] = field(default_factory=list)
    bundle_signature: Signature | None = None

    @classmethod
    def new(
        cls,
        *,
        rrn: str,
        robot_md_sha256: str,
        artifacts: list[Artifact],
        operator: dict | None = None,
        matrix_signed_at: str | None = None,
    ) -> "AuditBundle":
        return cls(
            bundle_id="bundle_" + secrets.token_hex(16),
            rrn=rrn,
            robot_md_sha256=robot_md_sha256,
            signed_at=datetime.now(tz=timezone.utc).isoformat(),
            matrix_signed_at=matrix_signed_at,
            operator=operator,
            artifacts=artifacts,
        )

    def to_dict(self) -> dict:
        out: dict = {
            "schema_version": SCHEMA_VERSION,
            "bundle_id": self.bundle_id,
            "rrn": self.rrn,
            "robot_md_sha256": self.robot_md_sha256,
            "signed_at": self.signed_at,
            "matrix_version": self.matrix_version,
            "artifacts": [a.to_dict() for a in self.artifacts],
        }
        if self.matrix_signed_at:
            out["matrix_signed_at"] = self.matrix_signed_at
        if self.operator:
            out["operator"] = self.operator
        if self.bundle_signature:
            out["bundle_signature"] = self.bundle_signature.to_dict()
        return out


class VerifyMode(enum.Enum):
    STRICT = "strict"  # verify every inner artifact + bundle
    AGGREGATOR_TRUST = "aggregator_trust"  # verify only the outer bundle signature


@dataclass
class ArtifactVerificationResult:
    artifact_type: str
    kid: str
    ok: bool
    reason: str


@dataclass
class BundleVerificationResult:
    bundle_signature_ok: bool
    artifact_results: list[ArtifactVerificationResult]
    all_ok: bool


def verify_bundle(
    bundle_json: str,
    *,
    mode: VerifyMode,
    kid_to_pem: KidResolver,
) -> BundleVerificationResult:
    """Verify a bundle. ``kid_to_pem`` resolves a kid to its PEM public key.

    Accepts either a dict ``{kid: pem_bytes}`` or a callable
    ``(kid) -> pem_bytes | None``. Requires the ``[crypto]`` extra.
    """
    data = json.loads(bundle_json)
    bundle_sig = data.get("bundle_signature")
    if not bundle_sig:
        return BundleVerificationResult(
            bundle_signature_ok=False,
            artifact_results=[],
            all_ok=False,
        )

    bundle_ok = _verify_signature(
        canonical_json(data, exclude="bundle_signature"),
        bundle_sig,
        kid_to_pem,
    )

    artifact_results: list[ArtifactVerificationResult] = []
    if mode == VerifyMode.STRICT:
        for art in data.get("artifacts", []):
            sig = art.get("artifact_signature")
            ok = _verify_signature(
                canonical_json(art, exclude="artifact_signature"),
                sig,
                kid_to_pem,
            )
            artifact_results.append(
                ArtifactVerificationResult(
                    artifact_type=art.get("artifact_type", "(unknown)"),
                    kid=sig["kid"] if sig else "(none)",
                    ok=ok,
                    reason="ok" if ok else "signature did not verify",
                )
            )

    all_ok = bundle_ok and all(r.ok for r in artifact_results)
    return BundleVerificationResult(
        bundle_signature_ok=bundle_ok,
        artifact_results=artifact_results,
        all_ok=all_ok,
    )


def _verify_signature(
    message: bytes, sig_obj: dict | None, kid_to_pem: KidResolver
) -> bool:
    try:
        import base64

        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "rcan.audit_bundle.verify_bundle requires the [crypto] extra: "
            "pip install rcan[crypto]"
        ) from exc

    if sig_obj is None:
        return False
    kid = sig_obj.get("kid")
    if kid is None:
        return False
    if isinstance(kid_to_pem, dict):
        pem = kid_to_pem.get(kid)
    else:
        pem = kid_to_pem(kid)
    if pem is None:
        return False
    try:
        pub = serialization.load_pem_public_key(pem)
    except ValueError:
        return False
    if not isinstance(pub, Ed25519PublicKey):
        return False
    try:
        pub.verify(base64.b64decode(sig_obj["sig"]), message)
    except (InvalidSignature, KeyError, ValueError):
        return False
    return True


def hash_robot_md(content: bytes) -> str:
    """Compute the ``robot_md_sha256`` field for a given ROBOT.md body."""
    return hashlib.sha256(content).hexdigest()
