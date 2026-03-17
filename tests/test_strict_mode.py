"""Tests for rcan-validate config --strict mode (Issue #18)."""

import tempfile
import os

from rcan.validate import validate_config

# Minimal valid L1/L2/L3 config — passes without strict
FULL_CONFIG = {
    "rcan_version": "1.6",
    "metadata": {
        "manufacturer": "Acme",
        "model": "AcmeBot",
        "version": "1.0",
        "device_id": "acme-001",
    },
    "agent": {
        "confidence_gates": [{"threshold": 0.8}],
        "hitl_gates": [{"action": "move"}],
        "commitment_chain": {"enabled": True},
    },
    "rcan_protocol": {
        "jwt_auth": {"enabled": True},
    },
}

# Config with wrong spec version
WRONG_VERSION_CONFIG = {**FULL_CONFIG, "rcan_version": "1.0"}

# Config that generates warnings (missing optional but warned fields)
WARN_CONFIG = {
    "rcan_version": "1.6",
    "metadata": {
        "manufacturer": "Acme",
        "model": "AcmeBot",
        "device_id": "acme-001",
        # missing 'version' → warns
    },
    "agent": {},  # missing confidence_gates, hitl_gates, commitment_chain → warns
}


def _write_yaml(cfg: dict) -> str:
    """Write a config dict to a temp YAML file, return path."""
    import yaml

    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as f:
        yaml.dump(cfg, f)
    return path


def test_strict_promotes_warnings_to_errors():
    """Strict mode must promote warnings to errors."""
    path = _write_yaml(WARN_CONFIG)
    try:
        # Non-strict: warnings only, ok=True
        result_normal = validate_config(path, fetch_schema=False)
        assert result_normal.warnings, "Expected warnings in non-strict mode"

        # Strict: warnings become failures
        result_strict = validate_config(path, fetch_schema=False, strict=True)
        assert not result_strict.ok, "Expected strict mode to fail due to warnings"
        # Warnings should be cleared (promoted to issues)
        assert not result_strict.warnings, "Warnings should be promoted to issues"
    finally:
        os.unlink(path)


def test_strict_rejects_wrong_spec_version():
    """Strict mode should fail if rcan_version != current spec version."""
    path = _write_yaml(WRONG_VERSION_CONFIG)
    try:
        result = validate_config(path, fetch_schema=False, strict=True)
        assert not result.ok
        combined = " ".join(result.issues)
        assert "1.2" in combined or "strict" in combined
    finally:
        os.unlink(path)


def test_strict_accepts_current_spec_version():
    """Strict mode should not fail on spec version when it matches."""
    path = _write_yaml(FULL_CONFIG)
    try:
        # We patch schema fetch to return None to avoid network dependency
        from unittest.mock import patch

        with patch("rcan.validate._fetch_canonical_schema", return_value=None):
            result = validate_config(path, strict=True)
        # If warnings exist they'll become errors; FULL_CONFIG is designed to be clean
        # The only failure here would be schema unavailability turned into error in strict
        # We're interested in spec version NOT causing a failure
        spec_failures = [
            i for i in result.issues if "rcan_version" in i and "strict" in i
        ]
        assert not spec_failures, f"Spec version falsely flagged: {spec_failures}"
    finally:
        os.unlink(path)


def test_strict_validates_rrn_format_in_device_id():
    """Strict mode should validate device_id that starts with RRN-."""
    bad_rrn_config = {
        **FULL_CONFIG,
        "metadata": {
            **FULL_CONFIG["metadata"],
            "device_id": "RRN-BADFORMAT",  # starts with RRN- but invalid
        },
    }
    path = _write_yaml(bad_rrn_config)
    try:
        from unittest.mock import patch

        with patch("rcan.validate._fetch_canonical_schema", return_value=None):
            result = validate_config(path, strict=True)
        combined = " ".join(result.issues)
        assert not result.ok
        assert "RRN" in combined or "device_id" in combined
    finally:
        os.unlink(path)


def test_strict_valid_rrn_device_id_passes():
    """A valid RRN in device_id should not trigger strict RRN check."""
    valid_rrn_config = {
        **FULL_CONFIG,
        "metadata": {
            **FULL_CONFIG["metadata"],
            "device_id": "RRN-000000000001",
        },
    }
    path = _write_yaml(valid_rrn_config)
    try:
        from unittest.mock import patch

        with patch("rcan.validate._fetch_canonical_schema", return_value=None):
            result = validate_config(path, strict=True)
        rrn_failures = [i for i in result.issues if "device_id" in i and "RRN" in i]
        assert not rrn_failures, f"Valid RRN falsely flagged: {rrn_failures}"
    finally:
        os.unlink(path)


def test_no_schema_flag_ignored_in_strict():
    """In strict mode, fetch_schema=False is overridden (schema always fetched)."""
    # We verify that validate_config is called with effective schema fetch = True in strict
    from unittest.mock import patch

    path = _write_yaml(FULL_CONFIG)
    try:
        fetched = []

        def fake_fetch(name):
            fetched.append(name)
            return None  # simulate unavailable but don't error in this variant

        with patch("rcan.validate._fetch_canonical_schema", side_effect=fake_fetch):
            # Even with fetch_schema=False, strict overrides
            validate_config(path, fetch_schema=False, strict=True)

        assert fetched, "Schema fetch should have been attempted in strict mode"
    finally:
        os.unlink(path)
