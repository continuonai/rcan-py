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
        contraindications=["wet floors", "outdoor use"],
        version="1.0",
        issued_at="2026-04-12T09:00:00.000Z",
    )
    assert ifu.rrn == "RRN-000000000001"
    assert len(ifu.contraindications) == 2
    assert "wet floors" in ifu.contraindications


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
