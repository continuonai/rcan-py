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


# ----- v3.1 compliance builder tests (§23, §24, §25, §26) -----

from rcan.compliance import (
    ART13_COVERAGE,
    ART72_NOTE,
    CONFORMITY_STATUS_DECLARED,
    REPORTING_DEADLINES,
    SUBMISSION_INSTRUCTIONS,
    VALID_SEVERITIES,
    build_eu_register_entry,
    build_ifu,
    build_incident_report,
    build_safety_benchmark,
)


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
    thresholds = {"estop_p95_ms": 100.0, "bounds_check_p95_ms": 5.0}
    out = build_safety_benchmark(
        iterations=20,
        thresholds=thresholds,
        results=results,
        mode="synthetic",
        generated_at="2026-04-23T12:00:00.000000Z",
        overall_pass=True,
    )
    assert out["schema"] == "rcan-safety-benchmark-v1"
    assert out["generated_at"] == "2026-04-23T12:00:00.000000Z"
    assert out["mode"] == "synthetic"
    assert out["iterations"] == 20
    assert out["thresholds"] == thresholds
    assert out["results"] == results
    assert out["overall_pass"] is True


def test_build_safety_benchmark_empty_results_ok():
    """Empty results dict is valid (vacuous pass)."""
    out = build_safety_benchmark(
        iterations=20,
        thresholds={},
        results={},
        mode="synthetic",
        generated_at="2026-04-23T12:00:00.000000Z",
        overall_pass=True,
    )
    assert out["schema"] == "rcan-safety-benchmark-v1"
    assert out["results"] == {}
    assert out["overall_pass"] is True


def test_build_ifu_envelope_shape():
    """Returns rcan-ifu-v1 envelope with all 8 Art. 13(3) sections at top level."""
    out = build_ifu(
        provider_identity={"manufacturer": "ACME Robotics", "contact": "test@acme.com"},
        intended_purpose={"description": "Pick-and-place in warehouse"},
        capabilities_and_limitations={"max_payload_kg": 0.5, "reach_m": 0.6},
        accuracy_and_performance={"positioning_error_mm": 1.0},
        human_oversight_measures={"estop": True, "supervision_required": True},
        known_risks_and_misuse={"misuse_scenarios": ["unattended operation"]},
        expected_lifetime={"years": 5},
        maintenance_requirements={"interval_months": 6},
        generated_at="2026-04-23T12:00:00.000000Z",
    )
    assert out["schema"] == "rcan-ifu-v1"
    assert out["generated_at"] == "2026-04-23T12:00:00.000000Z"
    assert out["provider_identity"] == {"manufacturer": "ACME Robotics", "contact": "test@acme.com"}
    assert out["intended_purpose"] == {"description": "Pick-and-place in warehouse"}
    assert out["capabilities_and_limitations"] == {"max_payload_kg": 0.5, "reach_m": 0.6}
    assert out["accuracy_and_performance"] == {"positioning_error_mm": 1.0}
    assert out["human_oversight_measures"] == {"estop": True, "supervision_required": True}
    assert out["known_risks_and_misuse"] == {"misuse_scenarios": ["unattended operation"]}
    assert out["expected_lifetime"] == {"years": 5}
    assert out["maintenance_requirements"] == {"interval_months": 6}
    assert out["art13_coverage"] == list(ART13_COVERAGE)


def test_build_ifu_art13_coverage_matches_constant():
    """art13_coverage in output is list(ART13_COVERAGE)."""
    out = build_ifu(
        provider_identity={},
        intended_purpose={},
        capabilities_and_limitations={},
        accuracy_and_performance={},
        human_oversight_measures={},
        known_risks_and_misuse={},
        expected_lifetime={},
        maintenance_requirements={},
        generated_at="2026-04-23T12:00:00.000000Z",
    )
    assert out["art13_coverage"] == list(ART13_COVERAGE)
    assert len(out["art13_coverage"]) == 8


def test_build_incident_report_envelope_shape():
    """Returns rcan-incidents-v1 envelope with auto-computed counts and constants."""
    incidents = [
        {"severity": "life_health", "description": "arm collision", "occurred_at": "2026-04-20T10:00:00Z"},
        {"severity": "other", "description": "sensor drift", "occurred_at": "2026-04-21T09:00:00Z"},
    ]
    out = build_incident_report(
        rrn="RRN-000000000042",
        incidents=incidents,
        generated_at="2026-04-23T12:00:00Z",
    )
    assert out["schema"] == "rcan-incidents-v1"
    assert out["generated_at"] == "2026-04-23T12:00:00Z"
    assert out["rrn"] == "RRN-000000000042"
    assert out["total_incidents"] == 2
    assert out["incidents_by_severity"] == {"life_health": 1, "other": 1}
    assert out["reporting_deadlines"] == dict(REPORTING_DEADLINES)
    assert out["art72_note"] == ART72_NOTE
    assert out["incidents"] == incidents


def test_build_incident_report_empty_incidents_ok():
    """Zero incidents: total_incidents==0, both severity buckets zero."""
    out = build_incident_report(
        rrn="RRN-000000000001",
        incidents=[],
        generated_at="2026-04-23T12:00:00Z",
    )
    assert out["schema"] == "rcan-incidents-v1"
    assert out["total_incidents"] == 0
    assert out["incidents_by_severity"] == {"life_health": 0, "other": 0}
    assert out["incidents"] == []


def test_build_incident_report_unknown_severity_ignored():
    """Unknown severity still counts toward total_incidents but not by_severity."""
    out = build_incident_report(
        rrn="RRN-000000000001",
        incidents=[{"severity": "bogus", "description": "unknown"}],
        generated_at="2026-04-23T12:00:00Z",
    )
    assert out["total_incidents"] == 1
    assert out["incidents_by_severity"] == {"life_health": 0, "other": 0}


def test_build_eu_register_entry_envelope_shape():
    """Returns rcan-eu-register-v1 envelope with annex_iii_basis at top level."""
    provider = {"name": "ACME Robotics", "contact": "legal@acme.com"}
    system = {
        "rrn": "RRN-000000000042",
        "rrn_uri": "rcan://rrf.rcan.dev/RRN-000000000042",
        "robot_name": "bob",
        "rcan_version": "3.1.1",
        "opencastor_version": "2026.4.22.1",
        "rcn_ids": ["RCN-000000000001"],
        "rmn": "RMN-000000000002",
        "rhn_ids": [],
    }
    out = build_eu_register_entry(
        rmn="RMN-000000000002",
        fria_ref="fria-RRN-000000000042.json",
        provider=provider,
        system=system,
        annex_iii_basis="safety_component",
        generated_at="2026-04-23T12:00:00.000000Z",
    )
    assert out["schema"] == "rcan-eu-register-v1"
    assert out["generated_at"] == "2026-04-23T12:00:00.000000Z"
    assert out["rmn"] == "RMN-000000000002"
    assert out["fria_ref"] == "fria-RRN-000000000042.json"
    assert out["provider"] == provider
    assert out["system"] == system
    assert out["annex_iii_basis"] == "safety_component"
    assert out["conformity_status"] == CONFORMITY_STATUS_DECLARED
    assert out["submission_instructions"] == SUBMISSION_INSTRUCTIONS


def test_build_eu_register_entry_override_conformity_status():
    """conformity_status can be overridden from the default."""
    out = build_eu_register_entry(
        rmn="RMN-000000000002",
        fria_ref="fria.json",
        provider={"name": "X", "contact": "x@x.com"},
        system={"rrn": "RRN-000000000001"},
        annex_iii_basis="safety_component",
        generated_at="2026-04-23T12:00:00.000000Z",
        conformity_status="provisional",
    )
    assert out["conformity_status"] == "provisional"


def test_build_eu_register_entry_requires_rmn():
    """rmn is required as of rcan-spec v3.1 for per-model Art. 49 routing."""
    import pytest
    with pytest.raises(TypeError):
        build_eu_register_entry(  # type: ignore[call-arg]
            fria_ref="fria.json",
            provider={"name": "X", "contact": "x@x.com"},
            system={"rrn": "RRN-000000000001"},
            annex_iii_basis="safety_component",
            generated_at="2026-04-23T12:00:00.000000Z",
        )
