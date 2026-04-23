"""Tests for rcan.compliance — RCAN v3.0 compliance dataclasses."""

import pytest

from rcan.compliance import (
    EuRegisterEntry,
    FriaConformance,
    FriaDocument,
    FriaSigningKey,
    InstructionsForUse,
    PostMarketIncident,
    SafetyBenchmark,
)


def test_fria_signing_key_fields():
    key = FriaSigningKey(alg="ml-dsa-65", kid="key-001", public_key="AAAA")
    assert key.alg == "ml-dsa-65"
    assert key.kid == "key-001"
    assert key.public_key == "AAAA"


def test_fria_signing_key_frozen():
    key = FriaSigningKey(alg="ml-dsa-65", kid="key-001", public_key="AAAA")
    with pytest.raises(Exception):
        key.alg = "ed25519"  # type: ignore[misc]


def test_fria_conformance_field_names():
    c = FriaConformance(score=92.5, pass_count=24, warn_count=1, fail_count=0)
    assert c.score == 92.5
    assert c.pass_count == 24
    assert c.warn_count == 1
    assert c.fail_count == 0


def _make_signing_key() -> FriaSigningKey:
    return FriaSigningKey(alg="ml-dsa-65", kid="key-001", public_key="AAAA")


def _make_sig() -> dict:
    return {"alg": "ml-dsa-65", "kid": "key-001", "value": "BBBB"}


def test_fria_document_required_fields():
    doc = FriaDocument(
        schema="rcan-fria-v1",
        generated_at="2026-04-12T09:00:00.000Z",
        system={"rrn": "RRN-000000000001", "robot_name": "bot", "rcan_version": "3.0"},
        deployment={"annex_iii_basis": "safety_component", "prerequisite_waived": False},
        signing_key=_make_signing_key(),
        sig=_make_sig(),
    )
    assert doc.schema == "rcan-fria-v1"
    assert doc.conformance is None


def test_fria_document_with_conformance():
    conformance = FriaConformance(score=90.0, pass_count=22, warn_count=2, fail_count=0)
    doc = FriaDocument(
        schema="rcan-fria-v1",
        generated_at="2026-04-12T09:00:00.000Z",
        system={"rrn": "RRN-000000000001", "robot_name": "bot", "rcan_version": "3.0"},
        deployment={"annex_iii_basis": "safety_component", "prerequisite_waived": False},
        signing_key=_make_signing_key(),
        sig=_make_sig(),
        conformance=conformance,
    )
    assert doc.conformance is not None
    assert doc.conformance.pass_count == 22


def test_fria_document_frozen():
    doc = FriaDocument(
        schema="rcan-fria-v1",
        generated_at="2026-04-12T09:00:00.000Z",
        system={},
        deployment={},
        signing_key=_make_signing_key(),
        sig=_make_sig(),
    )
    with pytest.raises(Exception):
        doc.schema = "wrong"  # type: ignore[misc]


def test_safety_benchmark_fields():
    sb = SafetyBenchmark(
        protocol="rcan-sbp-v1",
        score=87.3,
        pass_count=19,
        fail_count=2,
        run_at="2026-04-12T08:00:00.000Z",
        rrn="RRN-000000000001",
    )
    assert sb.protocol == "rcan-sbp-v1"
    assert sb.score == 87.3
    assert sb.fail_count == 2
    assert sb.rrn == "RRN-000000000001"


def test_instructions_for_use_fields():
    ifu = InstructionsForUse(
        rrn="RRN-000000000001",
        robot_name="bot",
        intended_use="indoor navigation",
        operating_environment="warehouse",
        contraindications=("wet floors", "outdoor use"),
        version="1.0",
        issued_at="2026-04-12T09:00:00.000Z",
    )
    assert ifu.rrn == "RRN-000000000001"
    assert len(ifu.contraindications) == 2
    assert "wet floors" in ifu.contraindications


def test_instructions_for_use_contraindications_immutable():
    ifu = InstructionsForUse(
        rrn="RRN-000000000001",
        robot_name="bot",
        intended_use="indoor navigation",
        operating_environment="warehouse",
        contraindications=("wet floors",),
        version="1.0",
        issued_at="2026-04-12T09:00:00.000Z",
    )
    assert isinstance(ifu.contraindications, tuple)
    # tuples do not support append — verifies immutability
    assert not hasattr(ifu.contraindications, "append")


def test_post_market_incident_fields():
    inc = PostMarketIncident(
        rrn="RRN-000000000001",
        incident_id="INC-001",
        severity="high",
        description="Collision with obstacle",
        occurred_at="2026-04-10T14:00:00.000Z",
        reported_at="2026-04-10T15:00:00.000Z",
        status="open",
    )
    assert inc.severity == "high"
    assert inc.status == "open"


def test_eu_register_entry_fields():
    entry = EuRegisterEntry(
        rrn="RRN-000000000001",
        robot_name="bot",
        manufacturer="acme",
        annex_iii_basis="safety_component",
        fria_submitted_at="2026-04-12T09:00:00.000Z",
        compliance_status="compliant",
        registered_at="2026-04-12T09:05:00.000Z",
    )
    assert entry.compliance_status == "compliant"
    assert entry.fria_submitted_at is not None


def test_eu_register_entry_no_fria():
    entry = EuRegisterEntry(
        rrn="RRN-000000000001",
        robot_name="bot",
        manufacturer="acme",
        annex_iii_basis="safety_component",
        fria_submitted_at=None,
        compliance_status="no_fria",
        registered_at="2026-04-12T09:05:00.000Z",
    )
    assert entry.fria_submitted_at is None
    assert entry.compliance_status == "no_fria"


def test_post_market_incident_frozen():
    inc = PostMarketIncident(
        rrn="RRN-000000000001",
        incident_id="INC-001",
        severity="low",
        description="Minor sensor anomaly",
        occurred_at="2026-04-12T10:00:00.000Z",
        reported_at="2026-04-12T10:05:00.000Z",
        status="open",
    )
    with pytest.raises(Exception):
        inc.status = "resolved"  # type: ignore[misc]


def test_fria_document_not_hashable():
    """FriaDocument is not hashable because system/deployment/sig are plain dicts."""
    doc = FriaDocument(
        schema="rcan-fria-v1",
        generated_at="2026-04-12T09:00:00.000Z",
        system={"rrn": "RRN-000000000001"},
        deployment={"annex_iii_basis": "safety_component"},
        signing_key=FriaSigningKey(alg="ml-dsa-65", kid="k", public_key="A"),
        sig={"alg": "ml-dsa-65", "kid": "k", "value": "B"},
    )
    with pytest.raises(TypeError):
        hash(doc)


# ----- v3.1 compliance builder tests (§23, §24) -----

from rcan.compliance import build_ifu, build_safety_benchmark


def test_build_safety_benchmark_envelope_shape():
    """Returns rcan-safety-benchmark-v1 envelope around passed-in path stats."""
    results = {
        "estop": {
            "min_ms": 0.1, "mean_ms": 0.2, "p95_ms": 0.3,
            "p99_ms": 0.4, "max_ms": 0.5, "pass": True,
        },
        "bounds_check": {
            "min_ms": 0.1, "mean_ms": 0.2, "p95_ms": 0.3,
            "p99_ms": 0.4, "max_ms": 0.5, "pass": True,
        },
    }
    out = build_safety_benchmark(
        rrn="RRN-000000000042",
        manifest_path="/path/to/ROBOT.md",
        iterations=20,
        thresholds_ms={"estop": 100.0, "bounds_check": 5.0},
        results=results,
    )
    assert out["schema"] == "rcan-safety-benchmark-v1"
    assert out["rrn"] == "RRN-000000000042"
    assert out["manifest_path"] == "/path/to/ROBOT.md"
    assert out["iterations"] == 20
    assert out["thresholds_ms"] == {"estop": 100.0, "bounds_check": 5.0}
    assert out["paths"] == results


def test_build_safety_benchmark_empty_results_ok():
    """Empty results are valid (e.g., mid-implementation partial run)."""
    out = build_safety_benchmark(
        rrn="RRN-000000000001",
        manifest_path="/x.md",
        iterations=1,
        thresholds_ms={},
        results={},
    )
    assert out["paths"] == {}
    assert out["schema"] == "rcan-safety-benchmark-v1"


def test_build_ifu_envelope_shape():
    """Returns rcan-ifu-v1 envelope with Art. 13(3) sections."""
    sections = {
        "provider_identity": {
            "manufacturer": "ACME Robotics",
            "author": "test@acme.com",
        },
        "intended_purpose": "Pick-and-place",
        "capabilities": ["arm.pick", "arm.place"],
        "safety_limits": {"payload_kg": 0.5},
    }
    out = build_ifu(
        rrn="RRN-000000000042",
        manifest_path="/robot/ROBOT.md",
        sections=sections,
    )
    assert out["schema"] == "rcan-ifu-v1"
    assert out["rrn"] == "RRN-000000000042"
    assert out["manifest_path"] == "/robot/ROBOT.md"
    assert out["sections"] == sections


def test_build_ifu_includes_provider_identity():
    """provider_identity sub-section is preserved verbatim in the envelope."""
    out = build_ifu(
        rrn="RRN-000000000001",
        manifest_path="/x.md",
        sections={"provider_identity": {"manufacturer": "M", "author": "a@b"}},
    )
    assert out["sections"]["provider_identity"]["manufacturer"] == "M"


# ----- v3.1 compliance builder tests (§25, §26) -----

from rcan.compliance import build_eu_register_entry, build_incident_report


def test_build_incident_report_envelope_shape():
    incidents = [
        {
            "incident_id": "INC-0001",
            "date": "2026-04-20T10:00:00Z",
            "severity": "minor",
            "description": "grip slipped at 100g payload",
            "mitigation": "tightened gripper preload",
        }
    ]
    out = build_incident_report(
        rrn="RRN-000000000042",
        manifest_path="/x/ROBOT.md",
        incidents=incidents,
        generated_at="2026-04-23T12:00:00Z",
    )
    assert out["schema"] == "rcan-incidents-v1"
    assert out["rrn"] == "RRN-000000000042"
    assert out["manifest_path"] == "/x/ROBOT.md"
    assert out["generated_at"] == "2026-04-23T12:00:00Z"
    assert out["incidents"] == incidents
    assert out["count"] == 1


def test_build_incident_report_empty_incidents_ok():
    out = build_incident_report(
        rrn="RRN-000000000001",
        manifest_path="/x.md",
        incidents=[],
        generated_at="2026-04-23T12:00:00Z",
    )
    assert out["incidents"] == []
    assert out["count"] == 0


def test_build_eu_register_entry_envelope_shape():
    system = {
        "rrn": "RRN-000000000042",
        "name": "bob",
        "manufacturer": "ACME",
        "annex_iii_basis": "safety_component",
        "rcn_ids": ["RCN-000000000001"],
        "rmn": "RMN-000000000002",
    }
    out = build_eu_register_entry(
        rrn="RRN-000000000042",
        manifest_path="/x/ROBOT.md",
        fria_ref="file:./fria.pdf",
        system=system,
        submitted_at="2026-04-23T12:00:00Z",
    )
    assert out["schema"] == "rcan-eu-register-v1"
    assert out["rrn"] == "RRN-000000000042"
    assert out["manifest_path"] == "/x/ROBOT.md"
    assert out["fria_ref"] == "file:./fria.pdf"
    assert out["system"] == system
    assert out["submitted_at"] == "2026-04-23T12:00:00Z"
