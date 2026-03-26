"""Tests for rcan.identity — RCAN v2.1 RBAC (§2)."""

from __future__ import annotations

import base64
import json
import time

import pytest

from rcan.identity import (
    DEFAULT_LOA_POLICY,
    PRODUCTION_LOA_POLICY,
    ROLE_TO_JWT_LEVEL,
    SCOPE_MIN_ROLE,
    IdentityRecord,
    LevelOfAssurance,
    LoaPolicy,
    Role,
    extract_identity_from_jwt,
    extract_loa_from_jwt,
    extract_role_from_jwt,
    role_from_jwt_level,
    validate_loa_for_scope,
    validate_role_for_scope,
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
# Role enum
# ---------------------------------------------------------------------------


class TestRole:
    def test_values(self):
        assert Role.GUEST == 1
        assert Role.OPERATOR == 2
        assert Role.CONTRIBUTOR == 3
        assert Role.ADMIN == 4
        assert Role.M2M_PEER == 5
        assert Role.CREATOR == 6
        assert Role.M2M_TRUSTED == 7

    def test_ordering(self):
        assert Role.GUEST < Role.OPERATOR < Role.CONTRIBUTOR
        assert Role.CONTRIBUTOR < Role.ADMIN < Role.M2M_PEER
        assert Role.M2M_PEER < Role.CREATOR < Role.M2M_TRUSTED

    def test_is_m2m(self):
        record = IdentityRecord(sub="robot", role=Role.M2M_PEER)
        assert record.is_m2m is True
        record2 = IdentityRecord(sub="robot", role=Role.M2M_TRUSTED)
        assert record2.is_m2m is True
        record3 = IdentityRecord(sub="human", role=Role.CREATOR)
        assert record3.is_m2m is False

    def test_backward_compat_alias(self):
        """LevelOfAssurance must be an alias for Role."""
        assert LevelOfAssurance is Role


# ---------------------------------------------------------------------------
# JWT level mapping
# ---------------------------------------------------------------------------


class TestRoleJwtLevelMapping:
    def test_all_roles_have_jwt_levels(self):
        for role in Role:
            assert role in ROLE_TO_JWT_LEVEL, f"Role.{role.name} missing from ROLE_TO_JWT_LEVEL"

    def test_jwt_levels(self):
        assert ROLE_TO_JWT_LEVEL[Role.GUEST] == 1.0
        assert ROLE_TO_JWT_LEVEL[Role.OPERATOR] == 2.0
        assert ROLE_TO_JWT_LEVEL[Role.CONTRIBUTOR] == 2.5
        assert ROLE_TO_JWT_LEVEL[Role.ADMIN] == 3.0
        assert ROLE_TO_JWT_LEVEL[Role.M2M_PEER] == 4.0
        assert ROLE_TO_JWT_LEVEL[Role.CREATOR] == 5.0
        assert ROLE_TO_JWT_LEVEL[Role.M2M_TRUSTED] == 6.0

    def test_role_from_jwt_level(self):
        assert role_from_jwt_level(1.0) == Role.GUEST
        assert role_from_jwt_level(2.0) == Role.OPERATOR
        assert role_from_jwt_level(2.5) == Role.CONTRIBUTOR
        assert role_from_jwt_level(3.0) == Role.ADMIN
        assert role_from_jwt_level(4.0) == Role.M2M_PEER
        assert role_from_jwt_level(5.0) == Role.CREATOR
        assert role_from_jwt_level(6.0) == Role.M2M_TRUSTED

    def test_role_from_jwt_level_unknown(self):
        assert role_from_jwt_level(99.0) is None
        assert role_from_jwt_level(0.0) is None


# ---------------------------------------------------------------------------
# IdentityRecord
# ---------------------------------------------------------------------------


class TestIdentityRecord:
    def test_construction(self):
        record = IdentityRecord(
            sub="user-123",
            role=Role.ADMIN,
            registry_url="https://registry.example.com",
            scopes=["config", "status"],
            verified_at="2026-01-01T00:00:00Z",
        )
        assert record.sub == "user-123"
        assert record.role == Role.ADMIN
        assert "config" in record.scopes

    def test_m2m_peer_record(self):
        record = IdentityRecord(
            sub="RRN-000000000005",
            role=Role.M2M_PEER,
            peer_rrn="RRN-000000000001",
            scopes=["control", "status"],
        )
        assert record.is_m2m is True
        assert record.peer_rrn == "RRN-000000000001"

    def test_m2m_trusted_record(self):
        record = IdentityRecord(
            sub="orchestrator:fleet-brain",
            role=Role.M2M_TRUSTED,
            fleet_rrns=["RRN-000000000001", "RRN-000000000005"],
            scopes=["fleet.trusted"],
        )
        assert record.is_m2m is True
        assert len(record.fleet_rrns) == 2

    def test_to_dict_roundtrip(self):
        record = IdentityRecord(
            sub="user-789",
            role=Role.CREATOR,
            registry_url="https://registry.example.com",
            scopes=["admin"],
            verified_at="2026-03-01T10:00:00Z",
        )
        d = record.to_dict()
        assert d["rcan_role"] == 5.0  # CREATOR → JWT level 5
        r2 = IdentityRecord.from_dict(d)
        assert r2.sub == record.sub
        assert r2.role == record.role

    def test_from_dict_v1x_loa_fallback(self):
        """from_dict must handle old v1.x 'loa' integer claims."""
        # v1.x tokens used loa: 1 (ANONYMOUS), 2, 3
        data = {"sub": "old-user", "loa": 1}
        record = IdentityRecord.from_dict(data)
        # loa=1 → JWT level 1.0 → Role.GUEST
        assert record.role == Role.GUEST


# ---------------------------------------------------------------------------
# extract_role_from_jwt
# ---------------------------------------------------------------------------


class TestExtractRoleFromJwt:
    def test_guest_from_rcan_role_1(self):
        token = make_jwt({"sub": "u", "rcan_role": 1, "exp": time.time() + 3600})
        assert extract_role_from_jwt(token) == Role.GUEST

    def test_operator_from_rcan_role_2(self):
        token = make_jwt({"sub": "u", "rcan_role": 2})
        assert extract_role_from_jwt(token) == Role.OPERATOR

    def test_contributor_from_rcan_role_2_5(self):
        token = make_jwt({"sub": "u", "rcan_role": 2.5})
        assert extract_role_from_jwt(token) == Role.CONTRIBUTOR

    def test_admin_from_rcan_role_3(self):
        token = make_jwt({"sub": "u", "rcan_role": 3})
        assert extract_role_from_jwt(token) == Role.ADMIN

    def test_m2m_peer_from_rcan_role_4(self):
        token = make_jwt({"sub": "u", "rcan_role": 4})
        assert extract_role_from_jwt(token) == Role.M2M_PEER

    def test_creator_from_rcan_role_5(self):
        token = make_jwt({"sub": "u", "rcan_role": 5})
        assert extract_role_from_jwt(token) == Role.CREATOR

    def test_m2m_trusted_from_rcan_role_6(self):
        token = make_jwt({"sub": "u", "rcan_role": 6})
        assert extract_role_from_jwt(token) == Role.M2M_TRUSTED

    def test_v1x_loa_fallback(self):
        """Old v1.x tokens with 'loa' claim should parse to nearest Role."""
        token = make_jwt({"sub": "u", "loa": 1})
        assert extract_role_from_jwt(token) == Role.GUEST

    def test_missing_claim_defaults_to_guest(self):
        token = make_jwt({"sub": "u", "exp": time.time() + 3600})
        assert extract_role_from_jwt(token) == Role.GUEST

    def test_invalid_token_defaults_to_guest(self):
        assert extract_role_from_jwt("not.a.jwt") == Role.GUEST

    def test_backward_compat_alias(self):
        """extract_loa_from_jwt must still work."""
        token = make_jwt({"sub": "u", "rcan_role": 3})
        assert extract_loa_from_jwt(token) == Role.ADMIN

    def test_extract_identity_from_jwt(self):
        token = make_jwt({
            "sub": "RRN-000000000005",
            "rcan_role": 4,
            "rcan_scopes": ["control", "status"],
            "peer_rrn": "RRN-000000000001",
        })
        identity = extract_identity_from_jwt(token)
        assert identity.sub == "RRN-000000000005"
        assert identity.role == Role.M2M_PEER
        assert "control" in identity.scopes
        assert identity.peer_rrn == "RRN-000000000001"


# ---------------------------------------------------------------------------
# validate_role_for_scope
# ---------------------------------------------------------------------------


class TestValidateRoleForScope:
    def test_guest_passes_status(self):
        ok, reason = validate_role_for_scope(Role.GUEST, "status")
        assert ok
        assert reason == ""

    def test_guest_fails_control(self):
        ok, reason = validate_role_for_scope(Role.GUEST, "control")
        assert not ok
        assert "OPERATOR" in reason or "control" in reason.lower()

    def test_operator_passes_control(self):
        ok, _ = validate_role_for_scope(Role.OPERATOR, "control")
        assert ok

    def test_contributor_passes_contribute(self):
        ok, _ = validate_role_for_scope(Role.CONTRIBUTOR, "contribute")
        assert ok

    def test_operator_fails_config(self):
        ok, _ = validate_role_for_scope(Role.OPERATOR, "config")
        assert not ok

    def test_admin_passes_config(self):
        ok, _ = validate_role_for_scope(Role.ADMIN, "config")
        assert ok

    def test_creator_passes_admin(self):
        ok, _ = validate_role_for_scope(Role.CREATOR, "admin")
        assert ok

    def test_m2m_peer_passes_control(self):
        ok, _ = validate_role_for_scope(Role.M2M_PEER, "control")
        assert ok

    def test_m2m_trusted_passes_fleet_trusted(self):
        ok, _ = validate_role_for_scope(Role.M2M_TRUSTED, "fleet.trusted")
        assert ok

    def test_creator_fails_fleet_trusted(self):
        ok, _ = validate_role_for_scope(Role.CREATOR, "fleet.trusted")
        assert not ok

    def test_unknown_scope_applies_operator_minimum(self):
        ok, _ = validate_role_for_scope(Role.GUEST, "custom_unknown_scope")
        assert not ok

    def test_backward_compat_validate_loa_for_scope(self):
        """validate_loa_for_scope alias must still work."""
        ok, _ = validate_loa_for_scope(Role.ADMIN, "config")
        assert ok

    def test_all_scopes_have_min_role(self):
        """Every scope in SCOPE_MIN_ROLE must be satisfied by M2M_TRUSTED (highest role)."""
        for scope in SCOPE_MIN_ROLE:
            ok, reason = validate_role_for_scope(Role.M2M_TRUSTED, scope)
            assert ok, f"M2M_TRUSTED should pass scope {scope!r}: {reason}"


# ---------------------------------------------------------------------------
# LoaPolicy
# ---------------------------------------------------------------------------


class TestLoaPolicy:
    def test_default_policy_all_guest(self):
        p = DEFAULT_LOA_POLICY
        assert p.min_role_for_discover == Role.GUEST
        assert p.min_role_for_control == Role.GUEST
        assert p.min_role_for_safety == Role.GUEST

    def test_production_policy(self):
        p = PRODUCTION_LOA_POLICY
        assert p.min_role_for_discover == Role.GUEST
        assert p.min_role_for_control == Role.OPERATOR
        assert p.min_role_for_safety == Role.CREATOR

    def test_custom_policy(self):
        p = LoaPolicy(min_role_for_control=Role.ADMIN, min_role_for_safety=Role.CREATOR)
        assert p.min_role_for_control == Role.ADMIN
