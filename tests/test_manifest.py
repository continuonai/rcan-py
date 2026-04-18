"""Tests for rcan.from_manifest — ROBOT.md cross-link."""

from __future__ import annotations

from pathlib import Path

import pytest

from rcan import ManifestInfo, from_manifest


BOB = """---
rcan_version: "3.0"
metadata:
  robot_name: bob
  manufacturer: acme
  model: so-arm101
  version: "1.0"
  device_id: bob-001
  rrn: RRN-000000000003
  rcan_uri: rcan://rcan.dev/acme/so-arm101/1-0/bob-001
physics:
  type: arm
  dof: 6
drivers:
  - id: arm
    protocol: feetech
    port: /dev/ttyACM0
capabilities:
  - arm.pick
safety:
  estop:
    software: true
    response_ms: 100
network:
  rrf_endpoint: https://rcan.dev
  port: 8001
  signing_alg: pqc-hybrid-v1
---

# bob

## Identity
A test arm.

## What bob Can Do
Pick.

## Safety Gates
E-stop.
"""


def _write(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "ROBOT.md"
    p.write_text(content)
    return p


def test_from_manifest_returns_manifest_info(tmp_path):
    p = _write(tmp_path, BOB)
    info = from_manifest(p)
    assert isinstance(info, ManifestInfo)
    assert info.rrn == "RRN-000000000003"
    assert info.rcan_uri == "rcan://rcan.dev/acme/so-arm101/1-0/bob-001"
    assert info.endpoint == "https://rcan.dev"
    assert info.signing_alg == "pqc-hybrid-v1"
    assert info.robot_name == "bob"
    assert info.rcan_version == "3.0"
    assert info.public_resolver == "https://rcan.dev/r/RRN-000000000003"


def test_from_manifest_unregistered_robot_has_none_rrn(tmp_path):
    content = BOB.replace("  rrn: RRN-000000000003\n", "")
    content = content.replace(
        "  rcan_uri: rcan://rcan.dev/acme/so-arm101/1-0/bob-001\n", ""
    )
    p = _write(tmp_path, content)
    info = from_manifest(p)
    assert info.rrn is None
    assert info.rcan_uri is None
    assert info.public_resolver is None
    assert info.robot_name == "bob"


def test_from_manifest_frontmatter_full_dict(tmp_path):
    # Callers that want fields beyond the shortcut set can dig into .frontmatter.
    p = _write(tmp_path, BOB)
    info = from_manifest(p)
    assert info.frontmatter["physics"]["dof"] == 6
    assert info.frontmatter["capabilities"] == ["arm.pick"]


def test_from_manifest_accepts_string_path(tmp_path):
    p = _write(tmp_path, BOB)
    info = from_manifest(str(p))
    assert info.rrn == "RRN-000000000003"


def test_from_manifest_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        from_manifest(tmp_path / "nope.ROBOT.md")


def test_from_manifest_missing_frontmatter_raises(tmp_path):
    p = tmp_path / "ROBOT.md"
    p.write_text("# just markdown, no frontmatter\n")
    with pytest.raises(ValueError, match="'---'"):
        from_manifest(p)


def test_from_manifest_unterminated_frontmatter_raises(tmp_path):
    p = tmp_path / "ROBOT.md"
    p.write_text("---\nmetadata:\n  robot_name: bob\n# body, no closing fence\n")
    with pytest.raises(ValueError, match="unterminated"):
        from_manifest(p)


def test_from_manifest_scalar_frontmatter_raises(tmp_path):
    p = tmp_path / "ROBOT.md"
    p.write_text("---\njust-a-scalar\n---\n# body\n")
    with pytest.raises(ValueError, match="YAML mapping"):
        from_manifest(p)
