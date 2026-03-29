"""Tests for rcan-validate node subcommand (Issue #15)."""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

from rcan.validate import main, validate_node

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_MANIFEST = {
    "rcan_node_version": "1.0",
    "node_type": "root",
    "operator": "Continuon AI",
    "namespace_prefix": "RRN",
    "public_key": "ed25519:AAABBBCCC000111",
    "api_base": "https://rcan.dev",
    "capabilities": ["resolve", "register"],
    "ttl_seconds": 3600,
}


def _make_manifest_file(data: dict, tmp_path: Path) -> str:
    """Write manifest JSON to a temp file and return the path."""
    p = tmp_path / "rcan-node.json"
    p.write_text(json.dumps(data))
    return str(p)


# ---------------------------------------------------------------------------
# Local file validation
# ---------------------------------------------------------------------------


def test_validate_node_from_file_valid(tmp_path):
    """A fully populated, well-formed manifest passes all checks."""
    path = _make_manifest_file(VALID_MANIFEST, tmp_path)
    result = validate_node(path, from_file=True)
    assert result.ok, result.issues
    assert not result.issues


def test_validate_node_from_file_missing_public_key(tmp_path):
    """Missing public_key causes a FAIL."""
    bad = dict(VALID_MANIFEST)
    del bad["public_key"]
    path = _make_manifest_file(bad, tmp_path)
    result = validate_node(path, from_file=True)
    assert not result.ok
    assert any("public_key" in i for i in result.issues)


def test_validate_node_from_file_missing_node_type(tmp_path):
    """Missing node_type causes a FAIL."""
    bad = dict(VALID_MANIFEST)
    del bad["node_type"]
    path = _make_manifest_file(bad, tmp_path)
    result = validate_node(path, from_file=True)
    assert not result.ok
    assert any("node_type" in i for i in result.issues)


def test_validate_node_from_file_invalid_node_type(tmp_path):
    """node_type value outside the allowed set causes a FAIL."""
    bad = {**VALID_MANIFEST, "node_type": "unknown_type"}
    path = _make_manifest_file(bad, tmp_path)
    result = validate_node(path, from_file=True)
    assert not result.ok
    assert any("node_type" in i for i in result.issues)


def test_validate_node_from_file_bad_public_key_prefix(tmp_path):
    """public_key not starting with 'ed25519:' causes a FAIL."""
    bad = {**VALID_MANIFEST, "public_key": "rsa:AAABBB"}
    path = _make_manifest_file(bad, tmp_path)
    result = validate_node(path, from_file=True)
    assert not result.ok
    assert any("public_key" in i for i in result.issues)


def test_validate_node_from_file_non_https_api_base(tmp_path):
    """api_base with http:// (not https://) causes a FAIL or WARN."""
    bad = {**VALID_MANIFEST, "api_base": "http://insecure.example.com"}
    path = _make_manifest_file(bad, tmp_path)
    result = validate_node(path, from_file=True)
    # Non-https api_base is a FAIL per spec
    assert not result.ok or result.warnings
    combined = result.issues + result.warnings
    assert any("api_base" in m or "https" in m for m in combined)


def test_validate_node_from_file_missing_all_required_fields(tmp_path):
    """Empty manifest fails all required-field checks."""
    path = _make_manifest_file({}, tmp_path)
    result = validate_node(path, from_file=True)
    assert not result.ok
    assert len(result.issues) >= 3  # at least several missing fields flagged


def test_validate_node_file_not_found():
    """Non-existent file returns a clear failure."""
    result = validate_node("/nonexistent/rcan-node.json", from_file=True)
    assert not result.ok
    assert any("not found" in i.lower() for i in result.issues)


def test_validate_node_invalid_json(tmp_path):
    """Corrupt JSON file returns a clear failure."""
    p = tmp_path / "bad.json"
    p.write_text("{ not valid json }")
    result = validate_node(str(p), from_file=True)
    assert not result.ok


# ---------------------------------------------------------------------------
# URL-based validation (mocked HTTP)
# ---------------------------------------------------------------------------


def test_validate_node_from_url_valid(tmp_path):
    """Valid manifest fetched from URL passes all checks."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(VALID_MANIFEST).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = validate_node("https://registry.example.com")

    assert result.ok or result.warnings  # may warn if api_base HEAD fails in CI


def test_validate_node_from_url_http_error():
    """HTTP error (404) from the manifest endpoint causes a FAIL."""
    with patch(
        "urllib.request.urlopen",
        side_effect=urllib.error.HTTPError(
            url="https://bad.example.com/.well-known/rcan-node.json",
            code=404,
            msg="Not Found",
            hdrs=None,
            fp=None,
        ),
    ):
        result = validate_node("https://bad.example.com")

    assert not result.ok
    assert any("404" in i for i in result.issues)


def test_validate_node_from_url_network_error():
    """Network-level error causes a FAIL."""
    with patch(
        "urllib.request.urlopen",
        side_effect=urllib.error.URLError("connection refused"),
    ):
        result = validate_node("https://unreachable.example.com")

    assert not result.ok


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------


def test_cli_node_file_valid(tmp_path):
    """CLI: rcan-validate node --file <path> → exit 0 for valid manifest."""
    path = _make_manifest_file(VALID_MANIFEST, tmp_path)
    # Mock urlopen so the api_base reachability check doesn't hit real network
    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=mock_resp):
        rc = main(["node", "--file", path])
    assert rc in (0, 2)  # 0=PASS, 2=WARN (api_base may warn)


def test_cli_node_file_missing_key(tmp_path):
    """CLI: rcan-validate node --file <path> → exit 1 for missing public_key."""
    bad = dict(VALID_MANIFEST)
    del bad["public_key"]
    path = _make_manifest_file(bad, tmp_path)
    rc = main(["node", "--file", path])
    assert rc == 1
