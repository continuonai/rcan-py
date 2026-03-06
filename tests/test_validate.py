"""Tests for rcan.validate — message, config, URI, and audit chain validation."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from rcan.validate import (
    validate_uri,
    validate_message,
    validate_config,
    validate_audit_chain,
    ValidationResult,
)


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
    "rcan": "1.2",
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
    "rcan_version": "1.2",
    "metadata": {
        "manufacturer": "acme",
        "model": "robotarm",
        "version": "v2",
        "rrn": "RRN-00000042",
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
