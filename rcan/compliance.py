"""
rcan.compliance — RCAN v3.0 compliance document types.

Dataclasses for the five compliance schemas introduced in RCAN v3.0
(aligned with EU AI Act Articles 9, 13, 49, 60, and 72):

  FriaDocument       — §22 Fundamental Rights Impact Assessment
  SafetyBenchmark    — §23 Safety Benchmark Protocol
  InstructionsForUse — §24 Instructions for Use
  PostMarketIncident — §25 Post-Market Monitoring Incident
  EuRegisterEntry    — §26 EU Register Submission

Spec: https://rcan.dev/spec/section-22
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FriaSigningKey:
    """ML-DSA-65 signing key reference attached to a FRIA document."""

    alg: str        # signing algorithm — always "ml-dsa-65" for rcan-fria-v1
    kid: str        # key identifier
    public_key: str # base64url-encoded public key


@dataclass(frozen=True)
class FriaConformance:
    """Conformance test summary embedded in a FRIA document.

    Field names use *_count suffixes to avoid collision with Python
    built-ins ``pass`` and ``fail``.
    """

    score: float      # 0–100 composite score
    pass_count: int   # number of passing checks
    warn_count: int   # number of warnings
    fail_count: int   # number of failing checks


@dataclass(frozen=True)
class FriaDocument:
    """rcan-fria-v1 Fundamental Rights Impact Assessment document.

    Corresponds to the JSON payload submitted to
    POST /api/v1/robots/:rrn/fria on the RRF registry.

    ``system``, ``deployment``, and ``sig`` are kept as plain dicts because the
    FRIA schema allows implementation-defined extra fields. As a consequence,
    ``FriaDocument`` instances are **not hashable** and cannot be used as dict
    keys or in sets.
    """

    schema: str                          # must be "rcan-fria-v1"
    generated_at: str                    # ISO-8601 timestamp
    system: dict                         # rrn, robot_name, rcan_version, …
    deployment: dict                     # annex_iii_basis, prerequisite_waived, …
    signing_key: FriaSigningKey
    sig: dict                            # alg, kid, value (base64url ML-DSA-65 sig)
    conformance: FriaConformance | None = None


@dataclass(frozen=True)
class SafetyBenchmark:
    """Safety Benchmark Protocol result (§23).

    Records the outcome of running the rcan-sbp benchmark suite
    against a robot at a specific point in time.
    """

    protocol: str    # benchmark protocol identifier, e.g. "rcan-sbp-v1"
    score: float     # 0–100 composite score
    pass_count: int
    fail_count: int
    run_at: str      # ISO-8601 timestamp of benchmark run
    rrn: str         # Robot Registry Number of the tested robot


@dataclass(frozen=True)
class InstructionsForUse:
    """Instructions for Use document (§24, EU AI Act Art. 13).

    Describes the intended deployment context and operational
    constraints for a specific robot.
    """

    rrn: str
    robot_name: str
    intended_use: str
    operating_environment: str
    contraindications: tuple[str, ...]  # conditions under which robot must not operate
    version: str                  # IFU document version, e.g. "1.0"
    issued_at: str                # ISO-8601 timestamp


@dataclass(frozen=True)
class PostMarketIncident:
    """Post-market monitoring incident report (§25, EU AI Act Art. 72).

    Captures a safety-relevant event after a robot has been deployed.
    """

    rrn: str
    incident_id: str
    severity: str     # "low" | "medium" | "high" | "critical"
    description: str
    occurred_at: str  # ISO-8601
    reported_at: str  # ISO-8601
    status: str       # "open" | "under_review" | "resolved"


@dataclass(frozen=True)
class EuRegisterEntry:
    """EU AI Act Article 49 / Article 60 register entry (§26).

    Summary record submitted to or retrieved from the EU register of
    high-risk AI systems. ``fria_submitted_at`` is None when no FRIA
    has been submitted yet (compliance_status == "no_fria").
    """

    rrn: str
    robot_name: str
    manufacturer: str
    annex_iii_basis: str
    fria_submitted_at: str | None  # ISO-8601, or None if no FRIA submitted
    compliance_status: str         # "compliant" | "provisional" | "non_compliant" | "no_fria"
    registered_at: str             # ISO-8601



# ----------------------------------------------------------------------
# v3.1 — Artifact builder functions (§23-26)
#
# These builders produce canonical envelope dicts ready to sign via
# rcan.hybrid.sign_body or post to a compliance registry endpoint. The
# measurement / filesystem / domain logic stays in the caller (robot-md);
# these builders only shape already-prepared input into the spec-defined
# wire format.
#
# 3.1.1 breaking change: the 3.1.0 envelopes did not match robot-md's
# actual shipped artifact shapes. 3.1.1 corrects this before any consumer
# adopted 3.1.0's builders. Downstream callers that relied on 3.1.0 will
# need to update their call sites — no compatibility shim is provided.
# ----------------------------------------------------------------------

SAFETY_BENCHMARK_SCHEMA = "rcan-safety-benchmark-v1"
IFU_SCHEMA = "rcan-ifu-v1"
INCIDENT_REPORT_SCHEMA = "rcan-incidents-v1"
EU_REGISTER_SCHEMA = "rcan-eu-register-v1"

# §24 Art. 13(3) — the 8 IFU sections EU AI Act mandates.
ART13_COVERAGE: tuple[str, ...] = (
    "provider_identity",
    "intended_purpose",
    "capabilities_and_limitations",
    "accuracy_and_performance",
    "human_oversight_measures",
    "known_risks_and_misuse",
    "expected_lifetime",
    "maintenance_requirements",
)

# §25 Art. 72 — post-market incident severities and their reporting deadlines.
VALID_SEVERITIES: tuple[str, ...] = ("life_health", "other")
REPORTING_DEADLINES: dict[str, str] = {
    "life_health": "15 days from incident timestamp",
    "other": "90 days from incident timestamp",
}
ART72_NOTE: str = (
    "Providers must report serious incidents to the relevant national "
    "authority within the applicable deadline per EU AI Act Art. 72."
)

# §26 Art. 49 — EU register submission defaults.
CONFORMITY_STATUS_DECLARED: str = "declared"
SUBMISSION_INSTRUCTIONS: str = (
    "Submit this package to the EU AI Act database at "
    "https://ec.europa.eu/digital-strategy/en/policies/european-ai-act. "
    "Include the referenced rcan-fria-v1 JSON as an attachment."
)


def build_safety_benchmark(
    *,
    iterations: int,
    thresholds: dict,
    results: dict,
    mode: str,
    generated_at: str,
    overall_pass: bool,
) -> dict:
    """Build an ``rcan-safety-benchmark-v1`` envelope (§23).

    Args:
        iterations: Number of samples per path.
        thresholds: Threshold dict keyed by ``{path}_p95_ms`` (caller
            supplies the suffix — robot-md's wire format bakes p95 into
            the key name).
        results: Path name → stats dict with min_ms / mean_ms / p95_ms /
            p99_ms / max_ms / pass. Caller measures and pre-rounds.
        mode: Run mode, e.g. "synthetic" or "hardware".
        generated_at: ISO 8601 UTC timestamp (caller generates).
        overall_pass: Whether every path passed its threshold.

    Returns:
        Dict conforming to §23 schema. Ready to serialize or sign.
    """
    return {
        "schema": SAFETY_BENCHMARK_SCHEMA,
        "generated_at": generated_at,
        "mode": mode,
        "iterations": iterations,
        "thresholds": thresholds,
        "results": results,
        "overall_pass": overall_pass,
    }


def build_ifu(
    *,
    provider_identity: dict,
    intended_purpose: dict,
    capabilities_and_limitations: dict,
    accuracy_and_performance: dict,
    human_oversight_measures: dict,
    known_risks_and_misuse: dict,
    expected_lifetime: dict,
    maintenance_requirements: dict,
    generated_at: str,
) -> dict:
    """Build an ``rcan-ifu-v1`` envelope (§24 — EU AI Act Art. 13(3) IFU).

    All 8 Art. 13(3) sections are required top-level dict fields. The
    builder emits ``art13_coverage`` automatically from ``ART13_COVERAGE``.

    Args:
        provider_identity: Art. 13(3)(a) provider identity block.
        intended_purpose: Art. 13(3)(b) intended purpose block.
        capabilities_and_limitations: Art. 13(3)(c).
        accuracy_and_performance: Art. 13(3)(d).
        human_oversight_measures: Art. 13(3)(e).
        known_risks_and_misuse: Art. 13(3)(f).
        expected_lifetime: Art. 13(3)(g).
        maintenance_requirements: Art. 13(3)(h).
        generated_at: ISO 8601 UTC timestamp.

    Returns:
        Dict conforming to §24 schema.
    """
    return {
        "schema": IFU_SCHEMA,
        "generated_at": generated_at,
        "art13_coverage": list(ART13_COVERAGE),
        "provider_identity": provider_identity,
        "intended_purpose": intended_purpose,
        "capabilities_and_limitations": capabilities_and_limitations,
        "accuracy_and_performance": accuracy_and_performance,
        "human_oversight_measures": human_oversight_measures,
        "known_risks_and_misuse": known_risks_and_misuse,
        "expected_lifetime": expected_lifetime,
        "maintenance_requirements": maintenance_requirements,
    }


def build_incident_report(
    *,
    rrn: str,
    incidents: list[dict],
    generated_at: str,
) -> dict:
    """Build an ``rcan-incidents-v1`` envelope (§25 — Art. 72 post-market).

    Auto-computes ``total_incidents`` and ``incidents_by_severity``.
    Unknown severities are silently ignored (mirrors robot-md behavior).

    Args:
        rrn: Robot Resource Name.
        incidents: List of incident entry dicts (each has ``severity``).
        generated_at: ISO 8601 UTC timestamp of report generation.

    Returns:
        Dict conforming to §25 schema with reporting deadlines and Art. 72
        note attached from module constants.
    """
    by_severity: dict[str, int] = dict.fromkeys(VALID_SEVERITIES, 0)
    for entry in incidents:
        sev = entry.get("severity")
        if sev in by_severity:
            by_severity[sev] += 1
    return {
        "schema": INCIDENT_REPORT_SCHEMA,
        "generated_at": generated_at,
        "rrn": rrn,
        "total_incidents": len(incidents),
        "incidents_by_severity": by_severity,
        "reporting_deadlines": dict(REPORTING_DEADLINES),
        "art72_note": ART72_NOTE,
        "incidents": list(incidents),
    }


def build_eu_register_entry(
    *,
    rmn: str,
    fria_ref: str,
    provider: dict,
    system: dict,
    annex_iii_basis: str,
    generated_at: str,
    conformity_status: str = CONFORMITY_STATUS_DECLARED,
    submission_instructions: str = SUBMISSION_INSTRUCTIONS,
) -> dict:
    """Build an ``rcan-eu-register-v1`` envelope (§26 — Art. 49 EU Register).

    Art. 49 registration is scoped per AI system (per model), not per
    individual robot. ``rmn`` identifies the model being registered;
    ``system.rrn`` records which specific robot produced the submission
    (provenance only).

    Args:
        rmn: Robot Model Number — the model registered under Art. 49.
            Format: ``RMN-XXXXXXXXXXXX`` (12 digits). Required as of
            rcan-spec v3.1.
        fria_ref: Basename of the signed rcan-fria-v1 JSON to attach.
        provider: Provider block — ``{name, contact}``.
        system: System block — ``{rrn, rrn_uri, robot_name, rcan_version,
            opencastor_version, rcn_ids, rmn, rhn_ids}``.
        annex_iii_basis: The Annex III high-risk category string.
        generated_at: ISO 8601 UTC timestamp.
        conformity_status: Defaults to "declared".
        submission_instructions: Defaults to the EU database blurb.

    Returns:
        Dict conforming to §26 v3.1 schema.
    """
    return {
        "schema": EU_REGISTER_SCHEMA,
        "generated_at": generated_at,
        "rmn": rmn,
        "fria_ref": fria_ref,
        "provider": provider,
        "system": system,
        "annex_iii_basis": annex_iii_basis,
        "conformity_status": conformity_status,
        "submission_instructions": submission_instructions,
    }


__all__ = [
    # v3.0 dataclasses
    "FriaSigningKey",
    "FriaConformance",
    "FriaDocument",
    "SafetyBenchmark",
    "InstructionsForUse",
    "PostMarketIncident",
    "EuRegisterEntry",
    # v3.1 schema constants
    "SAFETY_BENCHMARK_SCHEMA",
    "IFU_SCHEMA",
    "INCIDENT_REPORT_SCHEMA",
    "EU_REGISTER_SCHEMA",
    # v3.1 spec-domain constants
    "ART13_COVERAGE",
    "VALID_SEVERITIES",
    "REPORTING_DEADLINES",
    "ART72_NOTE",
    "CONFORMITY_STATUS_DECLARED",
    "SUBMISSION_INSTRUCTIONS",
    # v3.1 builders
    "build_safety_benchmark",
    "build_ifu",
    "build_incident_report",
    "build_eu_register_entry",
]
