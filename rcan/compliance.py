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
# v3.1 — Artifact builder functions (§22-26)
#
# These builders return canonical envelope dicts ready to be written to
# disk as artifacts, signed via rcan.hybrid.sign_body, or posted to a
# compliance registry endpoint. The measurement / filesystem / domain
# logic stays in the caller (robot-md); these builders only shape
# already-prepared input into the spec-defined envelopes.
# ----------------------------------------------------------------------

SAFETY_BENCHMARK_SCHEMA = "rcan-safety-benchmark-v1"
IFU_SCHEMA = "rcan-ifu-v1"
INCIDENT_REPORT_SCHEMA = "rcan-incidents-v1"
EU_REGISTER_SCHEMA = "rcan-eu-register-v1"


def build_safety_benchmark(
    *,
    rrn: str,
    manifest_path: str,
    iterations: int,
    thresholds_ms: dict,
    results: dict,
) -> dict:
    """Build an ``rcan-safety-benchmark-v1`` envelope (§23).

    Args:
        rrn: Robot Resource Name of the subject robot.
        manifest_path: Path to the ROBOT.md that was benchmarked.
        iterations: Number of samples per path.
        thresholds_ms: Path name → threshold milliseconds.
        results: Path name → stats dict with min_ms / mean_ms / p95_ms /
                 p99_ms / max_ms / pass. Caller measures and pre-rounds.

    Returns:
        Dict conforming to §23 schema. Ready to serialize or sign.
    """
    return {
        "schema": SAFETY_BENCHMARK_SCHEMA,
        "rrn": rrn,
        "manifest_path": manifest_path,
        "iterations": iterations,
        "thresholds_ms": thresholds_ms,
        "paths": results,
    }


def build_ifu(
    *,
    rrn: str,
    manifest_path: str,
    sections: dict,
) -> dict:
    """Build an ``rcan-ifu-v1`` envelope (§24 — EU AI Act Art. 13(3) IFU).

    Args:
        rrn: Robot Resource Name.
        manifest_path: Source ROBOT.md path.
        sections: All Art. 13(3) sections. Caller provides; builder does
                  not validate sub-structure (that's robot-md's job).

    Returns:
        Dict conforming to §24 schema.
    """
    return {
        "schema": IFU_SCHEMA,
        "rrn": rrn,
        "manifest_path": manifest_path,
        "sections": sections,
    }


def build_incident_report(
    *,
    rrn: str,
    manifest_path: str,
    incidents: list[dict],
    generated_at: str,
) -> dict:
    """Build an ``rcan-incidents-v1`` envelope (§25 — Art. 72 post-market).

    Args:
        rrn: Robot Resource Name.
        manifest_path: Source ROBOT.md path.
        incidents: List of incident dicts. Caller provides; builder does
                   not validate sub-structure.
        generated_at: ISO 8601 UTC timestamp of report generation.

    Returns:
        Dict conforming to §25 schema with a ``count`` field for quick
        consumer summaries.
    """
    return {
        "schema": INCIDENT_REPORT_SCHEMA,
        "rrn": rrn,
        "manifest_path": manifest_path,
        "generated_at": generated_at,
        "count": len(incidents),
        "incidents": incidents,
    }


def build_eu_register_entry(
    *,
    rrn: str,
    manifest_path: str,
    fria_ref: str,
    system: dict,
    submitted_at: str,
) -> dict:
    """Build an ``rcan-eu-register-v1`` envelope (§26 — Art. 49 EU Register).

    Args:
        rrn: Robot Resource Name.
        manifest_path: Source ROBOT.md path.
        fria_ref: URI reference to the FRIA artifact (file: or http URI).
        system: System-block dict (rrn, name, manufacturer, annex_iii_basis,
                optional rcn_ids / rmn / rhn_ids).
        submitted_at: ISO 8601 UTC timestamp of submission.

    Returns:
        Dict conforming to §26 schema.
    """
    return {
        "schema": EU_REGISTER_SCHEMA,
        "rrn": rrn,
        "manifest_path": manifest_path,
        "fria_ref": fria_ref,
        "submitted_at": submitted_at,
        "system": system,
    }


__all__ = [
    "FriaSigningKey",
    "FriaConformance",
    "FriaDocument",
    "SafetyBenchmark",
    "InstructionsForUse",
    "PostMarketIncident",
    "EuRegisterEntry",
    "SAFETY_BENCHMARK_SCHEMA",
    "IFU_SCHEMA",
    "INCIDENT_REPORT_SCHEMA",
    "EU_REGISTER_SCHEMA",
    "build_safety_benchmark",
    "build_ifu",
    "build_incident_report",
    "build_eu_register_entry",
]
