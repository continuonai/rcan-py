"""Tests for rcan.validate — message, config, URI, and audit chain validation."""

from __future__ import annotations

import json
import os


from rcan.validate import (
    RRN_RE,
    RRN_DELEGATED_RE,
    RRN_ANY_RE,
    validate_uri,
    validate_message,
    validate_config,
    validate_audit_chain,
    ValidationResult,
)


# ---------------------------------------------------------------------------
# RRN regex pattern tests (Part 1 — address space expansion)
# ---------------------------------------------------------------------------


class TestRRNPatterns:
    """RRN format: RRN-{8–16 digits}  or  RRN-{PREFIX}-{8–16 digits}."""

    # ---- Root RRN (RRN_RE) ----

    def test_rrn_re_8_digits_legacy(self):
        """8-digit root RRNs remain valid (backward compat)."""
        assert RRN_RE.match("RRN-12345678")

    def test_rrn_re_12_digits(self):
        """12-digit root RRN — recommended new format."""
        assert RRN_RE.match("RRN-000000000001")

    def test_rrn_re_16_digits(self):
        """16-digit root RRN — maximum sequence length."""
        assert RRN_RE.match("RRN-0000000000000001")

    def test_rrn_re_7_digits_invalid(self):
        """7-digit sequences are too short."""
        assert not RRN_RE.match("RRN-1234567")

    def test_rrn_re_17_digits_invalid(self):
        """17-digit sequences exceed max."""
        assert not RRN_RE.match("RRN-00000000000000001")

    # ---- Delegated RRN (RRN_DELEGATED_RE) ----

    def test_delegated_re_8_digit_legacy(self):
        """Legacy 8-digit delegated RRNs remain valid."""
        assert RRN_DELEGATED_RE.match("RRN-BD-12345678")

    def test_delegated_re_12_digits(self):
        """12-digit delegated RRN."""
        assert RRN_DELEGATED_RE.match("RRN-BD-000000000001")

    def test_delegated_re_alphanumeric_prefix(self):
        """Alphanumeric prefix (new format)."""
        assert RRN_DELEGATED_RE.match("RRN-BD1-000000000001")

    def test_delegated_re_8char_prefix_16_digits(self):
        """Maximum prefix length (8 chars) with 16-digit sequence."""
        assert RRN_DELEGATED_RE.match("RRN-BDABCDEF-0000000000000001")

    def test_delegated_re_7_digits_invalid(self):
        """7-digit sequences are too short."""
        assert not RRN_DELEGATED_RE.match("RRN-BD-1234567")

    def test_delegated_re_9char_prefix_invalid(self):
        """9-character prefixes are too long."""
        assert not RRN_DELEGATED_RE.match("RRN-TOOLONGPR-00000001")

    def test_delegated_re_1char_prefix_invalid(self):
        """1-character prefixes are too short."""
        assert not RRN_DELEGATED_RE.match("RRN-B-00000001")

    # ---- Combined (RRN_ANY_RE) ----

    def test_any_re_root_8_digits(self):
        assert RRN_ANY_RE.match("RRN-12345678")

    def test_any_re_root_12_digits(self):
        assert RRN_ANY_RE.match("RRN-000000000001")

    def test_any_re_delegated_8_digits(self):
        assert RRN_ANY_RE.match("RRN-BD-12345678")

    def test_any_re_delegated_12_digits(self):
        assert RRN_ANY_RE.match("RRN-BD-000000000001")

    def test_any_re_alphanumeric_prefix(self):
        assert RRN_ANY_RE.match("RRN-BD1-000000000001")

    def test_any_re_8char_prefix_16_digits(self):
        assert RRN_ANY_RE.match("RRN-BDABCDEF-0000000000000001")

    def test_any_re_7_digits_invalid(self):
        assert not RRN_ANY_RE.match("RRN-BD-1234567")

    def test_any_re_9char_prefix_invalid(self):
        assert not RRN_ANY_RE.match("RRN-TOOLONGPREFIX-00000001")


# ---------------------------------------------------------------------------
# URI validation
# ---------------------------------------------------------------------------


def test_validate_uri_valid():
    result = validate_uri("rcan://registry.rcan.dev/acme/arm/v2/unit-001")
    assert result.ok
    assert not result.issues
    assert any("acme" in i for i in result.info)


def test_validate_uri_invalid():
    result = validate_uri("http://not-a-rcan-uri")
    assert not result.ok
    assert result.issues


def test_validate_uri_too_short():
    result = validate_uri("rcan://registry.rcan.dev/acme/arm")
    assert not result.ok


# ---------------------------------------------------------------------------
# Message validation
# ---------------------------------------------------------------------------


VALID_MSG = {
    "rcan": "2.1.0",
    "cmd": "move_forward",
    "target": "rcan://registry.rcan.dev/acme/arm/v2/unit-001",
    "params": {"distance_m": 1.0},
    "confidence": 0.91,
}


def test_validate_message_valid():
    result = validate_message(VALID_MSG)
    assert result.ok
    assert not result.issues


def test_validate_message_json_string():
    result = validate_message(json.dumps(VALID_MSG))
    assert result.ok


def test_validate_message_missing_cmd():
    msg = dict(VALID_MSG)
    del msg["cmd"]
    result = validate_message(msg)
    assert not result.ok
    assert any("cmd" in i for i in result.issues)


def test_validate_message_missing_target():
    msg = dict(VALID_MSG)
    del msg["target"]
    result = validate_message(msg)
    assert not result.ok


def test_validate_message_missing_rcan():
    msg = dict(VALID_MSG)
    del msg["rcan"]
    result = validate_message(msg)
    assert not result.ok


def test_validate_message_invalid_json():
    result = validate_message("not json at all {{{")
    assert not result.ok


def test_validate_message_no_confidence_warns():
    msg = {k: v for k, v in VALID_MSG.items() if k != "confidence"}
    result = validate_message(msg)
    assert result.ok  # valid, but...
    assert any("confidence" in w.lower() for w in result.warnings)


def test_validate_message_no_signature_warns():
    result = validate_message(VALID_MSG)
    assert any("unsigned" in w.lower() for w in result.warnings)


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


VALID_CONFIG = {
    "rcan_version": "2.1.0",
    "metadata": {
        "manufacturer": "acme",
        "model": "robotarm",
        "version": "v2",
        "device_id": "unit-001",
        "rrn": "RRN-000000000042",  # 12-digit recommended format
    },
    "agent": {
        "provider": "ollama",
        "model": "qwen2.5:7b",
        "confidence_gates": [{"threshold": 0.8}],
    },
    "rcan_protocol": {
        "jwt_auth": {"enabled": True},
    },
}


def test_validate_config_valid():
    result = validate_config(VALID_CONFIG)
    assert not result.issues  # no errors (warnings ok)


def test_validate_config_missing_manufacturer():
    cfg = json.loads(json.dumps(VALID_CONFIG))
    del cfg["metadata"]["manufacturer"]
    result = validate_config(cfg)
    assert not result.ok
    assert any("manufacturer" in i for i in result.issues)


def test_validate_config_missing_model():
    cfg = json.loads(json.dumps(VALID_CONFIG))
    del cfg["metadata"]["model"]
    result = validate_config(cfg)
    assert not result.ok


def test_validate_config_file(tmp_path):
    import yaml

    config_file = tmp_path / "robot.rcan.yaml"
    config_file.write_text(yaml.dump(VALID_CONFIG))
    result = validate_config(str(config_file))
    assert not result.issues


def test_validate_config_file_not_found():
    result = validate_config("/nonexistent/path/robot.rcan.yaml")
    assert not result.ok


def test_validate_config_no_rrn_warns():
    cfg = json.loads(json.dumps(VALID_CONFIG))
    del cfg["metadata"]["rrn"]
    result = validate_config(cfg)
    assert any("register" in w.lower() or "rrn" in w.lower() for w in result.warnings)


# ---------------------------------------------------------------------------
# Audit chain validation
# ---------------------------------------------------------------------------


def test_validate_audit_chain_valid(tmp_path):
    from rcan.audit import AuditChain
    from rcan import CommitmentRecord

    chain_path = tmp_path / "audit.jsonl"
    chain = AuditChain(secret="test-secret")
    chain.append(CommitmentRecord(action="move_forward", robot_uri="rcan://r/a/b/v1/x"))
    chain.append(CommitmentRecord(action="stop", robot_uri="rcan://r/a/b/v1/x"))
    chain_path.write_text(chain.to_jsonl())

    os.environ["OPENCASTOR_COMMITMENT_SECRET"] = "test-secret"
    try:
        result = validate_audit_chain(str(chain_path))
    finally:
        del os.environ["OPENCASTOR_COMMITMENT_SECRET"]

    assert result.ok
    assert any("2 records" in i for i in result.info)


def test_validate_audit_chain_empty(tmp_path):
    chain_path = tmp_path / "empty.jsonl"
    chain_path.write_text("")
    result = validate_audit_chain(str(chain_path))
    # Empty is a warning, not a failure
    assert result.ok or any("empty" in w.lower() for w in result.warnings)


def test_validate_audit_chain_not_found():
    result = validate_audit_chain("/nonexistent/audit.jsonl")
    assert not result.ok


def test_validate_audit_chain_tampered(tmp_path):
    from rcan.audit import AuditChain
    from rcan import CommitmentRecord

    chain_path = tmp_path / "audit.jsonl"
    chain = AuditChain(secret="test-secret")
    chain.append(CommitmentRecord(action="move_forward", robot_uri="rcan://r/a/b/v1/x"))

    # Write tampered record
    records = chain.to_jsonl().strip().splitlines()
    data = json.loads(records[0])
    data["action"] = "self_destruct"
    chain_path.write_text(json.dumps(data) + "\n")

    os.environ["OPENCASTOR_COMMITMENT_SECRET"] = "test-secret"
    try:
        result = validate_audit_chain(str(chain_path))
    finally:
        del os.environ["OPENCASTOR_COMMITMENT_SECRET"]

    assert not result.ok


# ---------------------------------------------------------------------------
# ValidationResult helpers
# ---------------------------------------------------------------------------


def test_validation_result_fail():
    r = ValidationResult()
    r.fail("something broke")
    assert not r.ok
    assert "something broke" in r.issues


def test_validation_result_warn():
    r = ValidationResult()
    r.warn("use TLS")
    assert r.ok  # warnings don't fail
    assert "use TLS" in r.warnings


# ---------------------------------------------------------------------------
# OpenCastor RCANMessage format tests
# ---------------------------------------------------------------------------


class TestValidateMessageOpenCastorFormat:
    """validate_message() should accept OpenCastor's RCANMessage envelope."""

    def test_opencastor_format_int_type(self):
        """OpenCastor format with integer type accepted."""
        msg = {
            "type": 3,
            "source": "rcan://local/bob",
            "target": "rcan://local/alex",
            "payload": {"request": "status"},
            "priority": 1,
            "message_id": "test-123",
            "timestamp": "2026-03-14T00:00:00Z",
        }
        result = validate_message(msg)
        assert result.ok, f"Expected ok, got issues: {result.issues}"

    def test_opencastor_format_string_type(self):
        """OpenCastor format with string type (enum name) accepted."""
        msg = {
            "type": "STATUS",
            "source": "rcan://local/bob",
            "target": "rcan://local/alex",
            "payload": {},
        }
        result = validate_message(msg)
        assert result.ok, f"Expected ok, got issues: {result.issues}"

    def test_opencastor_format_source_ruri_alias(self):
        """source_ruri is accepted as an alias for source."""
        msg = {
            "type": 3,
            "source_ruri": "rcan://local/bob",
            "target_ruri": "rcan://local/alex",
            "payload": {},
        }
        result = validate_message(msg)
        assert result.ok, f"Expected ok, got issues: {result.issues}"

    def test_opencastor_format_missing_source_fails(self):
        """Missing source (and source_ruri) should fail."""
        msg = {
            "type": 3,
            "target": "rcan://local/alex",
            "payload": {},
        }
        result = validate_message(msg)
        assert not result.ok
        assert any("source" in i for i in result.issues)

    def test_opencastor_format_missing_target_fails(self):
        """Missing target (and target_ruri) should fail."""
        msg = {
            "type": 3,
            "source": "rcan://local/bob",
            "payload": {},
        }
        result = validate_message(msg)
        assert not result.ok
        assert any("target" in i for i in result.issues)

    def test_opencastor_format_missing_type_falls_back_to_wire(self):
        """Message without 'type' is treated as wire format (needs rcan/cmd/target)."""
        msg = {
            "source": "rcan://local/bob",
            "target": "rcan://local/alex",
            "payload": {},
        }
        result = validate_message(msg)
        # Wire format requires rcan + cmd — should fail
        assert not result.ok

    def test_classic_wire_format_still_works(self):
        """Classic wire format {rcan, cmd, target} continues to pass."""
        msg = {
            "rcan": "2.1.0",
            "cmd": "stop",
            "target": "rcan://rcan.dev/acme/arm/v1/unit-001",
        }
        result = validate_message(msg)
        assert result.ok, f"Expected ok, got issues: {result.issues}"

    def test_transparency_message_type(self):
        """MessageType 18 (TRANSPARENCY) accepted in OpenCastor format."""
        msg = {
            "type": 18,
            "source": "rcan://local/robot01",
            "target": "rcan://local/human-display",
            "payload": {
                "ai_system": True,
                "model_family": "claude-sonnet",
                "operator": "example-company",
                "capabilities": ["navigation", "speech"],
                "limitations": ["cannot lift > 2kg"],
                "contact": "safety@example.com",
                "rcan_version": "2.1.0",
                "p66_conformance_pct": 87,
                "audit_enabled": True,
            },
        }
        result = validate_message(msg)
        assert result.ok, f"Expected ok, got issues: {result.issues}"
