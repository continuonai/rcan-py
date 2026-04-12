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

    ``system`` and ``deployment`` are kept as plain dicts because the
    FRIA schema allows implementation-defined extra fields.
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
    contraindications: list[str]  # conditions under which robot must not operate
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


__all__ = [
    "FriaSigningKey",
    "FriaConformance",
    "FriaDocument",
    "SafetyBenchmark",
    "InstructionsForUse",
    "PostMarketIncident",
    "EuRegisterEntry",
]
