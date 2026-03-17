"""Tests for rcan.identity — Human Identity Verification (GAP-14)."""

from __future__ import annotations

import base64
import json
import time

import pytest

from rcan.identity import (
    DEFAULT_LOA_POLICY,
    PRODUCTION_LOA_POLICY,
    IdentityRecord,
    LevelOfAssurance,
    LoaPolicy,
    extract_loa_from_jwt,
    validate_loa_for_scope,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_jwt(payload: dict) -> str:
    """Build a minimal unsigned JWT for testing."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "EdDSA", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload_b64}.fakesig"


# ---------------------------------------------------------------------------
# LevelOfAssurance
# ---------------------------------------------------------------------------


class TestLevelOfAssurance:
    def test_values(self):
        assert LevelOfAssurance.ANONYMOUS == 1
        assert LevelOfAssurance.EMAIL_VERIFIED == 2
        assert LevelOfAssurance.HARDWARE_TOKEN == 3

    def test_is_int_enum(self):
        assert int(LevelOfAssurance.ANONYMOUS) == 1
        assert int(LevelOfAssurance.EMAIL_VERIFIED) == 2

    def test_comparison(self):
        assert LevelOfAssurance.HARDWARE_TOKEN > LevelOfAssurance.EMAIL_VERIFIED
        assert LevelOfAssurance.EMAIL_VERIFIED > LevelOfAssurance.ANONYMOUS

    def test_from_int(self):
        assert LevelOfAssurance(1) == LevelOfAssurance.ANONYMOUS
        assert LevelOfAssurance(2) == LevelOfAssurance.EMAIL_VERIFIED
        assert LevelOfAssurance(3) == LevelOfAssurance.HARDWARE_TOKEN


# ---------------------------------------------------------------------------
# IdentityRecord
# ---------------------------------------------------------------------------


class TestIdentityRecord:
    def test_construction(self):
        record = IdentityRecord(
            sub="user-123",
            registry_url="https://registry.example.com",
            loa=LevelOfAssurance.EMAIL_VERIFIED,
            registry_tier="authoritative",
            verified_at="2026-01-01T00:00:00Z",
        )
        assert record.sub == "user-123"
        assert record.loa == LevelOfAssurance.EMAIL_VERIFIED
        assert record.fido2_credential_id is None

    def test_with_fido2(self):
        record = IdentityRecord(
            sub="user-456",
            registry_url="https://registry.example.com",
            loa=LevelOfAssurance.HARDWARE_TOKEN,
            registry_tier="authoritative",
            verified_at="2026-01-01T00:00:00Z",
            fido2_credential_id="cred-abc123",
        )
        assert record.fido2_credential_id == "cred-abc123"

    def test_to_dict_roundtrip(self):
        record = IdentityRecord(
            sub="user-789",
            registry_url="https://registry.example.com",
            loa=LevelOfAssurance.HARDWARE_TOKEN,
            registry_tier="root",
            verified_at="2026-03-01T10:00:00Z",
            fido2_credential_id="cred-xyz",
        )
        d = record.to_dict()
        r2 = IdentityRecord.from_dict(d)
        assert r2.sub == record.sub
        assert r2.loa == record.loa
        assert r2.fido2_credential_id == record.fido2_credential_id

    def test_loa_stored_as_int_in_dict(self):
        record = IdentityRecord(
            sub="u1",
            registry_url="https://r.example.com",
            loa=LevelOfAssurance.EMAIL_VERIFIED,
            registry_tier="community",
            verified_at="2026-01-01T00:00:00Z",
        )
        d = record.to_dict()
        assert d["loa"] == 2


# ---------------------------------------------------------------------------
# LoaPolicy
# ---------------------------------------------------------------------------


class TestLoaPolicy:
    def test_default_policy_all_1(self):
        assert DEFAULT_LOA_POLICY.min_loa_for_discover == 1
        assert DEFAULT_LOA_POLICY.min_loa_for_status == 1
        assert DEFAULT_LOA_POLICY.min_loa_for_chat == 1
        assert DEFAULT_LOA_POLICY.min_loa_for_control == 1
        assert DEFAULT_LOA_POLICY.min_loa_for_safety == 1

    def test_production_policy_values(self):
        assert PRODUCTION_LOA_POLICY.min_loa_for_discover == 1
        assert PRODUCTION_LOA_POLICY.min_loa_for_status == 1
        assert PRODUCTION_LOA_POLICY.min_loa_for_chat == 1
        assert PRODUCTION_LOA_POLICY.min_loa_for_control == 2
        assert PRODUCTION_LOA_POLICY.min_loa_for_safety == 3

    def test_custom_policy(self):
        policy = LoaPolicy(
            min_loa_for_discover=1,
            min_loa_for_status=1,
            min_loa_for_chat=1,
            min_loa_for_control=3,
            min_loa_for_safety=3,
        )
        assert policy.min_loa_for_control == 3


# ---------------------------------------------------------------------------
# extract_loa_from_jwt
# ---------------------------------------------------------------------------


class TestExtractLoaFromJwt:
    def test_loa_1_anonymous(self):
        token = make_jwt({"sub": "user", "loa": 1, "exp": time.time() + 3600})
        loa = extract_loa_from_jwt(token)
        assert loa == LevelOfAssurance.ANONYMOUS

    def test_loa_2_email_verified(self):
        token = make_jwt({"sub": "user", "loa": 2, "exp": time.time() + 3600})
        loa = extract_loa_from_jwt(token)
        assert loa == LevelOfAssurance.EMAIL_VERIFIED

    def test_loa_3_hardware_token(self):
        token = make_jwt({"sub": "user", "loa": 3, "exp": time.time() + 3600})
        loa = extract_loa_from_jwt(token)
        assert loa == LevelOfAssurance.HARDWARE_TOKEN

    def test_missing_loa_defaults_to_anonymous(self):
        """Missing loa claim → ANONYMOUS (backward compatible)."""
        token = make_jwt({"sub": "user", "exp": time.time() + 3600})
        loa = extract_loa_from_jwt(token)
        assert loa == LevelOfAssurance.ANONYMOUS

    def test_invalid_token_defaults_to_anonymous(self):
        """Malformed JWT → ANONYMOUS (graceful degradation)."""
        loa = extract_loa_from_jwt("not.a.jwt")
        assert loa == LevelOfAssurance.ANONYMOUS

    def test_empty_token_defaults_to_anonymous(self):
        loa = extract_loa_from_jwt("")
        assert loa == LevelOfAssurance.ANONYMOUS

    def test_one_part_token(self):
        loa = extract_loa_from_jwt("onlyone")
        assert loa == LevelOfAssurance.ANONYMOUS

    def test_bad_base64_defaults_to_anonymous(self):
        loa = extract_loa_from_jwt("header.!!! invalid base64 !!!.sig")
        assert loa == LevelOfAssurance.ANONYMOUS

    def test_loa_string_coerced_to_int(self):
        """Some JWTs may store loa as a string "2"."""
        token = make_jwt({"sub": "user", "loa": "2"})
        loa = extract_loa_from_jwt(token)
        assert loa == LevelOfAssurance.EMAIL_VERIFIED


# ---------------------------------------------------------------------------
# validate_loa_for_scope
# ---------------------------------------------------------------------------


class TestValidateLaoForScope:
    # --- Default policy (all LoA = 1) ---

    def test_anonymous_passes_all_scopes_default_policy(self):
        for scope in ["discover", "status", "chat", "control", "safety"]:
            valid, reason = validate_loa_for_scope(LevelOfAssurance.ANONYMOUS, scope)
            assert valid, f"Expected scope={scope} to pass with default policy, got reason={reason}"

    def test_higher_loa_always_passes(self):
        for loa in LevelOfAssurance:
            valid, _ = validate_loa_for_scope(loa, "control")
            assert valid

    # --- Production policy ---

    def test_control_requires_loa2_production(self):
        valid, reason = validate_loa_for_scope(
            LevelOfAssurance.ANONYMOUS,
            "control",
            policy=PRODUCTION_LOA_POLICY,
        )
        assert not valid
        assert "2" in reason or "loa" in reason.lower()

    def test_control_loa2_passes_production(self):
        valid, _ = validate_loa_for_scope(
            LevelOfAssurance.EMAIL_VERIFIED,
            "control",
            policy=PRODUCTION_LOA_POLICY,
        )
        assert valid

    def test_safety_requires_loa3_production(self):
        valid, reason = validate_loa_for_scope(
            LevelOfAssurance.EMAIL_VERIFIED,
            "safety",
            policy=PRODUCTION_LOA_POLICY,
        )
        assert not valid
        assert "3" in reason or "loa" in reason.lower()

    def test_safety_loa3_passes_production(self):
        valid, _ = validate_loa_for_scope(
            LevelOfAssurance.HARDWARE_TOKEN,
            "safety",
            policy=PRODUCTION_LOA_POLICY,
        )
        assert valid

    def test_discover_loa1_passes_production(self):
        valid, _ = validate_loa_for_scope(
            LevelOfAssurance.ANONYMOUS,
            "discover",
            policy=PRODUCTION_LOA_POLICY,
        )
        assert valid

    def test_status_loa1_passes_production(self):
        valid, _ = validate_loa_for_scope(
            LevelOfAssurance.ANONYMOUS,
            "status",
            policy=PRODUCTION_LOA_POLICY,
        )
        assert valid

    # --- Scope aliases ---

    def test_teleop_maps_to_control(self):
        valid, _ = validate_loa_for_scope(
            LevelOfAssurance.ANONYMOUS,
            "teleop",
            policy=PRODUCTION_LOA_POLICY,
        )
        # teleop maps to control (requires LoA 2 in production)
        assert not valid

    def test_estop_maps_to_safety(self):
        valid, _ = validate_loa_for_scope(
            LevelOfAssurance.EMAIL_VERIFIED,
            "estop",
            policy=PRODUCTION_LOA_POLICY,
        )
        # estop maps to safety (requires LoA 3)
        assert not valid

    def test_observer_maps_to_status(self):
        valid, _ = validate_loa_for_scope(
            LevelOfAssurance.ANONYMOUS,
            "observer",
            policy=PRODUCTION_LOA_POLICY,
        )
        assert valid

    # --- min_loa_overrides ---

    def test_override_increases_requirement(self):
        """Override can increase control requirement beyond production policy."""
        valid, reason = validate_loa_for_scope(
            LevelOfAssurance.EMAIL_VERIFIED,
            "control",
            min_loa_overrides={"control": 3},
            policy=PRODUCTION_LOA_POLICY,
        )
        assert not valid
        assert "3" in reason or "loa" in reason.lower()

    def test_override_decreases_requirement(self):
        """Override can relax safety requirement (not recommended, but possible)."""
        valid, _ = validate_loa_for_scope(
            LevelOfAssurance.ANONYMOUS,
            "safety",
            min_loa_overrides={"safety": 1},
            policy=PRODUCTION_LOA_POLICY,
        )
        assert valid

    def test_override_takes_precedence_over_policy(self):
        """min_loa_overrides dict wins over policy value."""
        valid, _ = validate_loa_for_scope(
            LevelOfAssurance.EMAIL_VERIFIED,
            "control",
            min_loa_overrides={"control": 2},  # matches LoA
            policy=PRODUCTION_LOA_POLICY,
        )
        assert valid

    def test_unknown_scope_uses_control_default(self):
        """Unknown scopes apply control-level minimum as safe default."""
        valid, _ = validate_loa_for_scope(
            LevelOfAssurance.ANONYMOUS,
            "custom_unknown_scope",
            policy=PRODUCTION_LOA_POLICY,
        )
        # Production policy: control ≥ 2 → ANONYMOUS (1) should fail
        assert not valid

    def test_reason_empty_on_success(self):
        valid, reason = validate_loa_for_scope(
            LevelOfAssurance.EMAIL_VERIFIED, "control"
        )
        assert valid
        assert reason == ""

    def test_reason_contains_scope_on_failure(self):
        _, reason = validate_loa_for_scope(
            LevelOfAssurance.ANONYMOUS,
            "safety",
            policy=PRODUCTION_LOA_POLICY,
        )
        assert "safety" in reason.lower()

    # --- Backward compatibility ---

    def test_backward_compat_default_policy_allows_all(self):
        """Default policy (all LoA=1) must not break any existing LoA=1 callers."""
        for scope in ["discover", "status", "chat", "control", "safety", "teleop", "estop"]:
            valid, _ = validate_loa_for_scope(LevelOfAssurance.ANONYMOUS, scope)
            assert valid, f"scope={scope} should pass with DEFAULT_LOA_POLICY"
