"""
rcan.m2m — RCAN v2.1 Machine-to-Machine Authorization.

Implements M2M_PEER and M2M_TRUSTED token parsing and verification.

M2M_PEER (level 4):
    Authorized by a human ADMIN or CREATOR for robot-to-robot communication.
    Token is signed by the authorizing robot's private key.

M2M_TRUSTED (level 6):
    Issued exclusively by the Robot Registry Foundation (RRF) root key.
    Enables cross-fleet orchestration. Requires multi-owner consent.
    Hard limits: 24 h max TTL, explicit fleet_rrns allowlist, no self-issuance.

Spec: §2.8 — M2M_PEER Authorization
      §2.9 — M2M_TRUSTED Fleet Orchestration
"""

from __future__ import annotations

import base64
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

log = logging.getLogger(__name__)

# RRF public key endpoint (Ed25519)
RRF_ROOT_PUBKEY_URL = "https://api.rrf.rcan.dev/.well-known/rrf-root-pubkey.pem"
# RRF revocation list endpoint
RRF_REVOCATION_URL = "https://api.rrf.rcan.dev/v2/revocations"
# Revocation cache TTL (seconds) — MUST be ≤ 60 per spec
RRF_REVOCATION_CACHE_TTL = 55
# Pubkey cache TTL (seconds)
RRF_PUBKEY_CACHE_TTL = 3600

# Required JWT issuer for M2M_TRUSTED tokens
M2M_TRUSTED_ISSUER = "rrf.rcan.dev"


# ---------------------------------------------------------------------------
# Claims dataclasses
# ---------------------------------------------------------------------------


@dataclass
class M2MPeerClaims:
    """Parsed claims from an M2M_PEER JWT.

    Attributes:
        sub:        Subject RRN of the peer robot.
        peer_rrn:   The robot RRN the peer is authorized to command.
        scopes:     Authorized scopes for this M2M session.
        exp:        Unix expiry timestamp.
        iss:        Issuing robot RRN (the ADMIN that granted this token).
        raw:        Raw decoded payload dict.
    """

    sub: str
    peer_rrn: str
    scopes: list[str]
    exp: int
    iss: str
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        return time.time() > self.exp

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "M2MPeerClaims":
        return cls(
            sub=payload.get("sub", ""),
            peer_rrn=payload.get("peer_rrn", ""),
            scopes=list(payload.get("rcan_scopes", payload.get("scopes", []))),
            exp=int(payload.get("exp", 0)),
            iss=payload.get("iss", ""),
            raw=payload,
        )


@dataclass
class M2MTrustedClaims:
    """Parsed claims from an M2M_TRUSTED JWT (RRF-issued).

    Attributes:
        sub:        Orchestrator identifier (NOT a robot RRN).
        fleet_rrns: Explicit allowlist of robots this token may command.
        scopes:     Must include ``"fleet.trusted"``.
        exp:        Unix expiry timestamp (max 24 h from issuance).
        iss:        Must be ``"rrf.rcan.dev"``.
        rrf_sig:    RRF Ed25519 signature over claims (base64url).
        raw:        Raw decoded payload dict.
    """

    sub: str
    fleet_rrns: list[str]
    scopes: list[str]
    exp: int
    iss: str
    rrf_sig: str
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        return time.time() > self.exp

    def authorizes_rrn(self, rrn: str) -> bool:
        """True if this token authorizes commanding *rrn*."""
        return rrn in self.fleet_rrns

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "M2MTrustedClaims":
        return cls(
            sub=payload.get("sub", ""),
            fleet_rrns=list(payload.get("fleet_rrns", [])),
            scopes=list(payload.get("rcan_scopes", payload.get("scopes", []))),
            exp=int(payload.get("exp", 0)),
            iss=payload.get("iss", ""),
            rrf_sig=payload.get("rrf_sig", ""),
            raw=payload,
        )


# ---------------------------------------------------------------------------
# JWT parsing helper
# ---------------------------------------------------------------------------


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        raise M2MAuthError("Invalid JWT structure")
    payload_b64 = parts[1]
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    return json.loads(base64.urlsafe_b64decode(payload_b64))


# ---------------------------------------------------------------------------
# M2M_PEER verification
# ---------------------------------------------------------------------------


def parse_m2m_peer_token(token: str) -> M2MPeerClaims:
    """Parse an M2M_PEER JWT without signature verification.

    For full verification (signature check), use ``verify_m2m_peer_token``.
    """
    payload = _decode_jwt_payload(token)
    claims = M2MPeerClaims.from_payload(payload)
    if claims.is_expired:
        raise M2MAuthError(f"M2M_PEER token expired for sub={claims.sub!r}")
    if not claims.peer_rrn:
        raise M2MAuthError("M2M_PEER token missing peer_rrn claim")
    return claims


# ---------------------------------------------------------------------------
# M2M_TRUSTED verification
# ---------------------------------------------------------------------------

# Module-level caches (thread-safe)
_rrf_pubkey_cache: Optional[bytes] = None
_rrf_pubkey_fetched_at: float = 0.0
_rrf_revocation_cache: set[str] = set()
_rrf_revocation_fetched_at: float = 0.0
_cache_lock = threading.Lock()


def _fetch_rrf_pubkey() -> bytes:
    """Fetch the RRF root Ed25519 public key (cached for 1 h)."""
    global _rrf_pubkey_cache, _rrf_pubkey_fetched_at

    with _cache_lock:
        if (
            _rrf_pubkey_cache
            and (time.time() - _rrf_pubkey_fetched_at) < RRF_PUBKEY_CACHE_TTL
        ):
            return _rrf_pubkey_cache

    try:
        import urllib.request

        with urllib.request.urlopen(RRF_ROOT_PUBKEY_URL, timeout=5) as resp:
            pem_data = resp.read()
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        pub_key_obj = load_pem_public_key(pem_data)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if not isinstance(pub_key_obj, Ed25519PublicKey):
            raise M2MAuthError("RRF root key is not an Ed25519 key")
        raw_bytes = pub_key_obj.public_bytes(
            encoding=__import__(
                "cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]
            ).Encoding.Raw,
            format=__import__(
                "cryptography.hazmat.primitives.serialization",
                fromlist=["PublicFormat"],
            ).PublicFormat.Raw,
        )
        with _cache_lock:
            _rrf_pubkey_cache = raw_bytes
            _rrf_pubkey_fetched_at = time.time()
        return raw_bytes
    except Exception as exc:
        raise M2MAuthError(f"Failed to fetch RRF root public key: {exc}") from exc


def _fetch_rrf_revocations() -> set[str]:
    """Fetch the RRF revocation list (cached for ≤ 55 s)."""
    global _rrf_revocation_cache, _rrf_revocation_fetched_at

    with _cache_lock:
        if (time.time() - _rrf_revocation_fetched_at) < RRF_REVOCATION_CACHE_TTL:
            return _rrf_revocation_cache

    try:
        import urllib.request

        with urllib.request.urlopen(RRF_REVOCATION_URL, timeout=5) as resp:
            data = json.loads(resp.read())
        revoked: set[str] = set(data.get("revoked_orchestrators", []))
        revoked |= set(data.get("revoked_jtis", []))
        with _cache_lock:
            _rrf_revocation_cache = revoked
            _rrf_revocation_fetched_at = time.time()
        return revoked
    except Exception as exc:
        log.warning("Failed to fetch RRF revocation list: %s — using cached list", exc)
        with _cache_lock:
            return _rrf_revocation_cache


def verify_m2m_trusted_token(
    token: str,
    target_rrn: str,
    *,
    skip_revocation_check: bool = False,
    rrf_pubkey_override: Optional[bytes] = None,
) -> M2MTrustedClaims:
    """Verify an M2M_TRUSTED JWT token against the RRF root key.

    Performs all required checks per RCAN v2.1 §2.9:

    1. JWT structure and payload parsing
    2. Issuer MUST be ``"rrf.rcan.dev"``
    3. ``fleet.trusted`` scope MUST be present
    4. Token MUST NOT be expired
    5. Ed25519 signature verified against RRF root public key
    6. Revocation list checked (unless ``skip_revocation_check=True``)
    7. ``target_rrn`` MUST be in ``fleet_rrns``

    Args:
        token:                 Raw JWT string.
        target_rrn:            The RRN of the robot being commanded.
        skip_revocation_check: Skip the RRF revocation list check (testing only).
        rrf_pubkey_override:   Override RRF public key for testing.

    Returns:
        Verified :class:`M2MTrustedClaims`.

    Raises:
        M2MAuthError: On any verification failure.
        ImportError: If ``cryptography`` package is not installed.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise ImportError(
            "Install 'cryptography' for M2M_TRUSTED verification: pip install cryptography"
        ) from exc

    payload = _decode_jwt_payload(token)
    claims = M2MTrustedClaims.from_payload(payload)

    # 1. Issuer check
    if claims.iss != M2M_TRUSTED_ISSUER:
        raise M2MAuthError(
            f"M2M_TRUSTED token issuer must be {M2M_TRUSTED_ISSUER!r}, got {claims.iss!r}"
        )

    # 2. Scope check
    if "fleet.trusted" not in claims.scopes:
        raise M2MAuthError("M2M_TRUSTED token missing required 'fleet.trusted' scope")

    # 3. Expiry check
    if claims.is_expired:
        raise M2MAuthError(f"M2M_TRUSTED token expired (sub={claims.sub!r})")

    # 4. Signature verification
    if not claims.rrf_sig:
        raise M2MAuthError("M2M_TRUSTED token missing rrf_sig claim")

    pub_key_bytes = rrf_pubkey_override or _fetch_rrf_pubkey()
    try:
        sig_bytes = base64.urlsafe_b64decode(claims.rrf_sig + "==")
        # Signature is over the canonical JSON of the payload (without rrf_sig)
        payload_for_verify = {k: v for k, v in payload.items() if k != "rrf_sig"}
        canonical = json.dumps(
            payload_for_verify, separators=(",", ":"), sort_keys=True
        ).encode()
        pub_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
        pub_key.verify(sig_bytes, canonical)
    except InvalidSignature as exc:
        raise M2MAuthError(
            "M2M_TRUSTED token RRF signature verification failed"
        ) from exc
    except Exception as exc:
        raise M2MAuthError(f"M2M_TRUSTED signature check error: {exc}") from exc

    # 5. Revocation check
    if not skip_revocation_check:
        revoked = _fetch_rrf_revocations()
        if claims.sub in revoked:
            raise M2MAuthError(
                f"M2M_TRUSTED orchestrator {claims.sub!r} is on the RRF revocation list"
            )
        jti = payload.get("jti")
        if jti and jti in revoked:
            raise M2MAuthError(f"M2M_TRUSTED token JTI {jti!r} has been revoked")

    # 6. fleet_rrns allowlist
    if not claims.authorizes_rrn(target_rrn):
        raise M2MAuthError(
            f"M2M_TRUSTED token does not authorize commanding {target_rrn!r}. "
            f"Authorized fleet: {claims.fleet_rrns!r}"
        )

    return claims


# ---------------------------------------------------------------------------
# RRF Revocation Poller
# ---------------------------------------------------------------------------


class RRFRevocationPoller:
    """Background thread that polls the RRF revocation list while M2M_TRUSTED
    sessions are active.

    Usage::

        poller = RRFRevocationPoller()
        poller.register_session("orchestrator:fleet-brain")
        # ... session active ...
        poller.unregister_session("orchestrator:fleet-brain")
        poller.stop()
    """

    def __init__(self, interval: float = RRF_REVOCATION_CACHE_TTL) -> None:
        self._interval = interval
        self._active_sessions: set[str] = set()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def register_session(self, orchestrator_sub: str) -> None:
        with self._lock:
            self._active_sessions.add(orchestrator_sub)
        self._ensure_running()

    def unregister_session(self, orchestrator_sub: str) -> None:
        with self._lock:
            self._active_sessions.discard(orchestrator_sub)

    @property
    def has_active_sessions(self) -> bool:
        with self._lock:
            return bool(self._active_sessions)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def _ensure_running(self) -> None:
        if self._thread is None or not self._thread.is_alive():
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run, daemon=True, name="rrf-revocation-poller"
            )
            self._thread.start()

    def _run(self) -> None:
        log.debug("RRFRevocationPoller: started")
        while not self._stop_event.wait(self._interval):
            if not self.has_active_sessions:
                log.debug("RRFRevocationPoller: no active sessions — stopping")
                break
            try:
                _fetch_rrf_revocations()
            except Exception as exc:
                log.warning("RRFRevocationPoller: poll failed: %s", exc)
        log.debug("RRFRevocationPoller: stopped")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class M2MAuthError(Exception):
    """Raised when M2M token verification fails."""


def sign_m2m_pqc(
    payload: "dict[str, Any]",
    keypair: "MlDsaKeyPair",
    *,
    sig_field: str = "pqc_sig",
) -> "dict[str, Any]":
    """Sign an M2M JWT payload dict with ML-DSA-65.

    Computes an ML-DSA-65 signature over the canonical JSON of *payload*
    (all fields except *sig_field*, sorted keys, no extra whitespace) and
    adds it as ``payload[sig_field]`` (base64url, no padding).

    This is the PQC analogue of the Ed25519 ``rrf_sig`` field used by
    ``M2M_TRUSTED`` tokens.  Both fields can coexist during the transition
    period.

    Args:
        payload:   JWT claims dict (modified in-place and returned).
        keypair:   :class:`~rcan.crypto.MlDsaKeyPair` with private key.
        sig_field: Name of the field to store the signature (default: ``"pqc_sig"``).

    Returns:
        The *payload* dict with *sig_field* added/updated.

    Raises:
        RCANSignatureError: If *keypair* has no private key.
        ImportError:        If dilithium-py is not installed.
    """
    from rcan.crypto import MlDsaKeyPair, sign_ml_dsa  # noqa: F401

    canonical_payload = {k: v for k, v in payload.items() if k != sig_field}
    canonical = json.dumps(
        canonical_payload, separators=(",", ":"), sort_keys=True
    ).encode()
    raw_sig = sign_ml_dsa(keypair, canonical)
    payload[sig_field] = base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()
    return payload


def verify_m2m_pqc(
    payload: "dict[str, Any]",
    public_key_bytes: bytes,
    *,
    sig_field: str = "pqc_sig",
) -> None:
    """Verify an ML-DSA-65 M2M payload signature.

    Verifies the ML-DSA-65 signature stored in ``payload[sig_field]`` over
    the canonical JSON of *payload* (excluding *sig_field* itself).

    Args:
        payload:          JWT claims dict containing *sig_field*.
        public_key_bytes: Raw ML-DSA-65 public key bytes (1952 bytes).
        sig_field:        Name of the signature field (default: ``"pqc_sig"``).

    Raises:
        M2MAuthError: If the signature is missing or invalid.
        ImportError:  If dilithium-py is not installed.
    """
    from rcan.crypto import verify_ml_dsa

    sig_b64 = payload.get(sig_field)
    if not sig_b64:
        raise M2MAuthError(f"M2M payload missing '{sig_field}' field")

    canonical_payload = {k: v for k, v in payload.items() if k != sig_field}
    canonical = json.dumps(
        canonical_payload, separators=(",", ":"), sort_keys=True
    ).encode()

    try:
        sig_bytes = base64.urlsafe_b64decode(sig_b64 + "==")
        verify_ml_dsa(public_key_bytes, canonical, sig_bytes)
    except Exception as exc:
        raise M2MAuthError(
            f"M2M ML-DSA-65 signature verification failed: {exc}"
        ) from exc


__all__ = [
    "M2MPeerClaims",
    "M2MTrustedClaims",
    "M2MAuthError",
    "M2M_TRUSTED_ISSUER",
    "parse_m2m_peer_token",
    "verify_m2m_trusted_token",
    "sign_m2m_pqc",
    "verify_m2m_pqc",
    "RRFRevocationPoller",
]
