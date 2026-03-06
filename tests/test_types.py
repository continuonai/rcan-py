"""Tests for rcan.types TypedDict definitions."""
from __future__ import annotations

import pytest
from rcan.types import RCANMetadata, RCANAgentConfig, RCANConfig, RCANMessageEnvelope
from rcan.validate import validate_config


# ---------------------------------------------------------------------------
# TypedDict import / usage
# ---------------------------------------------------------------------------

def test_rcan_metadata_typed():
    meta: RCANMetadata = {"manufacturer": "acme", "model": "arm", "version": "v1", "device_id": "unit-1"}
    assert meta["manufacturer"] == "acme"


def test_rcan_agent_config_typed():
    agent: RCANAgentConfig = {"provider": "ollama", "model": "qwen2.5:7b", "temperature": 0.7}
    assert agent["provider"] == "ollama"


def test_rcan_config_typed():
    cfg: RCANConfig = {
        "rcan_version": "1.2",
        "metadata": {"manufacturer": "acme", "model": "arm", "device_id": "u1"},
        "agent": {"provider": "ollama"},
    }
    assert cfg["rcan_version"] == "1.2"


def test_rcan_message_envelope_typed():
    env: RCANMessageEnvelope = {
        "cmd": "move",
        "target": "rcan://registry.rcan.dev/acme/arm/v1/unit-001",
        "rcan_version": "1.2",
        "confidence": 0.92,
        "timestamp_ns": 1709900000000000000,
    }
    assert env["cmd"] == "move"
    assert env["confidence"] == 0.92


# ---------------------------------------------------------------------------
# Validate config — required key checks
# ---------------------------------------------------------------------------

def test_validate_config_missing_rcan_version():
    cfg = {
        "metadata": {"manufacturer": "acme", "model": "arm", "device_id": "u1"},
        "agent": {"provider": "ollama"},
    }
    result = validate_config(cfg)
    assert not result.ok
    assert any("rcan_version" in i for i in result.issues)


def test_validate_config_missing_agent():
    cfg = {
        "rcan_version": "1.2",
        "metadata": {"manufacturer": "acme", "model": "arm", "device_id": "u1"},
    }
    result = validate_config(cfg)
    assert not result.ok
    assert any("agent" in i for i in result.issues)


def test_validate_config_bad_rcan_version_format():
    cfg = {
        "rcan_version": "v1.2.0",
        "metadata": {"manufacturer": "acme", "model": "arm", "device_id": "u1"},
        "agent": {},
    }
    result = validate_config(cfg)
    assert not result.ok
    assert any("rcan_version" in i for i in result.issues)


def test_validate_config_missing_device_id():
    cfg = {
        "rcan_version": "1.2",
        "metadata": {"manufacturer": "acme", "model": "arm"},
        "agent": {},
    }
    result = validate_config(cfg)
    assert not result.ok
    assert any("device_id" in i for i in result.issues)


def test_validate_config_robot_name_backwards_compat():
    """robot_name is acceptable as a backwards-compat alias for device_id."""
    cfg = {
        "rcan_version": "1.2",
        "metadata": {"manufacturer": "acme", "model": "arm", "robot_name": "my-robot"},
        "agent": {},
    }
    result = validate_config(cfg)
    # Should not fail on device_id check
    assert not any("device_id" in i for i in result.issues)


# ---------------------------------------------------------------------------
# rcan package-level imports
# ---------------------------------------------------------------------------

def test_rcan_types_importable_from_package():
    from rcan import RCANConfig, RCANMetadata, RCANAgentConfig, RCANMessageEnvelope
    assert RCANConfig is not None
    assert RCANMetadata is not None
