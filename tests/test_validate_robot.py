"""Tests for rcan-validate robot <rrn> subcommand (Issue #17)."""

from unittest.mock import patch, MagicMock

from rcan.validate import validate_robot
from rcan.exceptions import RCANNodeError


VALID_RECORD = {
    "record": {
        "name": "AcmeBot 2000",
        "manufacturer": "Acme Corp",
        "model": "AB-2000",
        "rcan_version": "1.2",
        "verification_tier": "verified",
    },
    "resolved_by": "rcan.dev",
}

MISSING_FIELDS_RECORD = {
    "record": {
        "name": "Partial Bot",
        # missing manufacturer, model, rcan_version
        "verification_tier": "community",
    },
    "resolved_by": "rcan.dev",
}


def _make_mock_client(return_value):
    mock = MagicMock()
    mock.resolve.return_value = return_value
    return mock


@patch("rcan.validate._fetch_canonical_schema", return_value=None)
@patch("rcan.node.NodeClient")
def test_valid_robot_record_passes(MockNodeClient, mock_schema):
    """A fully populated robot record should produce a PASS result."""
    MockNodeClient.return_value = _make_mock_client(VALID_RECORD)
    result = validate_robot("RRN-000000000001")
    assert result.ok, f"Expected PASS but got issues: {result.issues}"
    assert not result.issues


@patch("rcan.validate._fetch_canonical_schema", return_value=None)
@patch("rcan.node.NodeClient")
def test_missing_fields_fails(MockNodeClient, mock_schema):
    """A record missing required fields should produce FAIL results."""
    MockNodeClient.return_value = _make_mock_client(MISSING_FIELDS_RECORD)
    result = validate_robot("RRN-000000000001")
    assert not result.ok
    combined = " ".join(result.issues)
    assert "manufacturer" in combined
    assert "model" in combined
    assert "rcan_version" in combined


@patch("rcan.validate._fetch_canonical_schema", return_value=None)
@patch("rcan.node.NodeClient")
def test_invalid_rrn_format_fails(MockNodeClient, mock_schema):
    """An invalid RRN format should fail validation."""
    MockNodeClient.return_value = _make_mock_client(VALID_RECORD)
    result = validate_robot("INVALID-RRN")
    assert not result.ok
    assert any("RRN" in issue or "format" in issue.lower() for issue in result.issues)


@patch("rcan.validate._fetch_canonical_schema", return_value=None)
@patch("rcan.node.NodeClient")
def test_node_error_fails(MockNodeClient, mock_schema):
    """A RCANNodeError should produce a FAIL result."""
    mock_client = MagicMock()
    mock_client.resolve.side_effect = RCANNodeError("not found")
    MockNodeClient.return_value = mock_client
    result = validate_robot("RRN-000000000001")
    assert not result.ok
    assert any(
        "fetch" in issue.lower() or "not found" in issue.lower()
        for issue in result.issues
    )


@patch("rcan.validate._fetch_canonical_schema", return_value=None)
@patch("rcan.node.NodeClient")
def test_delegated_rrn_format_valid(MockNodeClient, mock_schema):
    """Delegated RRN (with prefix) should be recognised as valid format."""
    MockNodeClient.return_value = _make_mock_client(VALID_RECORD)
    result = validate_robot("RRN-BD-000000000001")
    # The format check should pass
    assert any("format valid" in msg for msg in result.info), result.info
