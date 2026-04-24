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


# --- v3.2: agent.runtimes[] normalization + validation ---

import warnings


def test_normalize_agent_flat_form_emits_deprecation_warning():
    """Flat agent.provider/model form should emit DeprecationWarning and normalize
    to a single-entry runtimes[] internally (rcan-spec v3.2)."""
    from rcan.manifest import _normalize_agent

    flat_agent = {
        "provider": "anthropic",
        "model": "claude-sonnet-4-6",
        "latency_budget_ms": 200,
        "safety_stop": True,
    }
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        runtimes = _normalize_agent(flat_agent)
    assert len(caught) == 1
    assert issubclass(caught[0].category, DeprecationWarning)
    assert "flat agent" in str(caught[0].message).lower()
    assert len(runtimes) == 1
    entry = runtimes[0]
    assert entry["default"] is True
    assert entry["models"][0]["provider"] == "anthropic"
    assert entry["models"][0]["model"] == "claude-sonnet-4-6"
    assert entry["latency_budget_ms"] == 200
    assert entry["safety_stop"] is True


def test_normalize_agent_runtimes_form_no_warning():
    """Structured agent.runtimes[] form returned as-is, no DeprecationWarning."""
    from rcan.manifest import _normalize_agent

    structured_agent = {
        "runtimes": [
            {
                "id": "robot-md",
                "harness": "claude-code",
                "default": True,
                "models": [{"provider": "anthropic", "model": "claude-sonnet-4-6", "role": "primary"}],
            },
            {
                "id": "opencastor",
                "harness": "castor-default",
                "models": [{"provider": "anthropic", "model": "claude-sonnet-4-6", "role": "primary"}],
            },
        ],
    }
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        runtimes = _normalize_agent(structured_agent)
    assert len(caught) == 0
    assert runtimes == structured_agent["runtimes"]


def test_normalize_agent_both_forms_raises():
    """Presence of BOTH flat keys and runtimes[] is ambiguous and must raise."""
    from rcan.manifest import _normalize_agent

    mixed = {
        "provider": "anthropic",
        "model": "claude-sonnet-4-6",
        "runtimes": [{"id": "robot-md", "harness": "claude-code", "default": True}],
    }
    with pytest.raises(ValueError, match="both flat.*and runtimes"):
        _normalize_agent(mixed)


def test_normalize_agent_none_returns_none():
    """No agent block → None (not an empty list)."""
    from rcan.manifest import _normalize_agent

    assert _normalize_agent(None) is None
    assert _normalize_agent({}) is None


def test_validate_agent_runtimes_single_entry_default_optional():
    """When runtimes[] has exactly one entry, default is optional."""
    from rcan.manifest import _validate_agent_runtimes

    errors = _validate_agent_runtimes(
        [{"id": "robot-md", "harness": "claude-code"}]
    )
    assert errors == []


def test_validate_agent_runtimes_multiple_entries_require_exactly_one_default():
    """When runtimes[] has 2+ entries, exactly one MUST be default: true."""
    from rcan.manifest import _validate_agent_runtimes

    no_default = [
        {"id": "robot-md", "harness": "claude-code"},
        {"id": "opencastor", "harness": "castor-default"},
    ]
    errors = _validate_agent_runtimes(no_default)
    assert any("exactly one" in e for e in errors)

    two_defaults = [
        {"id": "robot-md", "harness": "claude-code", "default": True},
        {"id": "opencastor", "harness": "castor-default", "default": True},
    ]
    errors = _validate_agent_runtimes(two_defaults)
    assert any("exactly one" in e for e in errors)

    ok = [
        {"id": "robot-md", "harness": "claude-code", "default": True},
        {"id": "opencastor", "harness": "castor-default"},
    ]
    assert _validate_agent_runtimes(ok) == []


def test_validate_agent_runtimes_requires_id_and_harness():
    """Every entry MUST have id + harness."""
    from rcan.manifest import _validate_agent_runtimes

    missing_harness = [{"id": "robot-md"}]
    errors = _validate_agent_runtimes(missing_harness)
    assert any("harness" in e for e in errors)

    missing_id = [{"harness": "claude-code"}]
    errors = _validate_agent_runtimes(missing_id)
    assert any("id" in e for e in errors)


def test_validate_agent_runtimes_unknown_fields_allowed():
    """Unknown per-entry fields are preserved (runtime-specific pass-through)."""
    from rcan.manifest import _validate_agent_runtimes

    with_extras = [
        {
            "id": "opencastor",
            "harness": "castor-default",
            "recipes": ["pick-place-basic"],
            "custom_key": {"nested": "value"},
        }
    ]
    assert _validate_agent_runtimes(with_extras) == []


RUNTIMES_MANIFEST = """---
rcan_version: "3.2"
metadata:
  robot_name: bob
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
agent:
  runtimes:
    - id: robot-md
      harness: claude-code
      default: true
      models:
        - provider: anthropic
          model: claude-sonnet-4-6
          role: primary
    - id: opencastor
      harness: castor-default
      models:
        - provider: anthropic
          model: claude-sonnet-4-6
          role: primary
      recipes: [pick-place-basic]
network:
  rrf_endpoint: https://rcan.dev
---

# Bob
"""


def test_from_manifest_populates_agent_runtimes(tmp_path: Path):
    """from_manifest should populate ManifestInfo.agent_runtimes when runtimes[] present."""
    f = tmp_path / "ROBOT.md"
    f.write_text(RUNTIMES_MANIFEST)
    info = from_manifest(f)
    assert info.agent_runtimes is not None
    assert len(info.agent_runtimes) == 2
    assert info.agent_runtimes[0]["id"] == "robot-md"
    assert info.agent_runtimes[0]["default"] is True
    assert info.agent_runtimes[1]["id"] == "opencastor"
