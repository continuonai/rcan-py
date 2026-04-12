# rcan-py v2.0.0 Design

**Date:** 2026-04-12
**Repo:** continuonai/rcan-py
**Status:** Approved — pending implementation plan

---

## Goal

Bump rcan-py to v2.0.0 aligned with RCAN spec v3.0. Add Python dataclasses for the five new compliance schemas (§22–§26) and enforce the REGISTRY_REGISTER breaking change (required `fria_ref` field).

---

## Architecture

Option A: single new `rcan/compliance.py` module + targeted changes to `rcan/message.py` and `rcan/__init__.py`.

```
rcan/
├── compliance.py      # new — FriaDocument, SafetyBenchmark, IFU, Incident, EuRegisterEntry
├── message.py         # modified — RegistryRegisterPayload TypedDict + make_registry_register()
└── __init__.py        # modified — version constants, new exports

tests/
└── test_compliance.py # new — instantiation + helper + version tests
```

No new dependencies. All new types use stdlib dataclasses + TypedDict.

---

## Section 1: Data Model (`rcan/compliance.py`)

All classes are `@dataclass(frozen=True)`. Field names avoid Python keywords (`pass_count`, `fail_count` instead of `pass`, `fail`).

```python
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class FriaSigningKey:
    alg: str          # "ml-dsa-65"
    kid: str
    public_key: str   # base64url-encoded public key

@dataclass(frozen=True)
class FriaConformance:
    score: float
    pass_count: int
    warn_count: int
    fail_count: int

@dataclass(frozen=True)
class FriaDocument:
    schema: str                        # "rcan-fria-v1"
    generated_at: str                  # ISO-8601
    system: dict                       # rrn, robot_name, rcan_version
    deployment: dict                   # annex_iii_basis, prerequisite_waived
    signing_key: FriaSigningKey
    sig: dict                          # alg, kid, value (base64url)
    conformance: FriaConformance | None = None

@dataclass(frozen=True)
class SafetyBenchmark:
    protocol: str     # e.g. "rcan-sbp-v1"
    score: float
    pass_count: int
    fail_count: int
    run_at: str       # ISO-8601
    rrn: str

@dataclass(frozen=True)
class InstructionsForUse:
    rrn: str
    robot_name: str
    intended_use: str
    operating_environment: str
    contraindications: list[str]
    version: str
    issued_at: str    # ISO-8601

@dataclass(frozen=True)
class PostMarketIncident:
    rrn: str
    incident_id: str
    severity: str     # "low" | "medium" | "high" | "critical"
    description: str
    occurred_at: str  # ISO-8601
    reported_at: str  # ISO-8601
    status: str       # "open" | "under_review" | "resolved"

@dataclass(frozen=True)
class EuRegisterEntry:
    rrn: str
    robot_name: str
    manufacturer: str
    annex_iii_basis: str
    fria_submitted_at: str | None
    compliance_status: str   # "compliant" | "provisional" | "non_compliant" | "no_fria"
    registered_at: str       # ISO-8601
```

---

## Section 2: Breaking Changes (`rcan/message.py`)

New `RegistryRegisterPayload` TypedDict documents the required `fria_ref` field introduced in RCAN v3.0:

```python
class RegistryRegisterPayload(TypedDict):
    rrn: str
    robot_name: str
    public_key: str           # base64url Ed25519 or ML-DSA-65
    verification_tier: str    # "community" | "verified" | "manufacturer" | "certified"
    fria_ref: str             # REQUIRED in RCAN v3.0
    metadata: dict
```

New helper function:

```python
def make_registry_register(
    rrn: str,
    robot_name: str,
    public_key: str,
    verification_tier: str,
    fria_ref: str,
    metadata: dict | None = None,
) -> RCANMessage:
    """Build a REGISTRY_REGISTER message. fria_ref is required in RCAN v3.0."""
    payload = RegistryRegisterPayload(
        rrn=rrn,
        robot_name=robot_name,
        public_key=public_key,
        verification_tier=verification_tier,
        fria_ref=fria_ref,
        metadata=metadata or {},
    )
    return RCANMessage(type=MessageType.REGISTRY_REGISTER, payload=dict(payload))
```

`RCANMessage` dataclass itself is unchanged — `payload` stays `dict`. No wire format changes.

---

## Section 3: Version Bump + Exports

**`pyproject.toml`:** `version = "2.0.0"`

**`rcan/__init__.py`:**
```python
__version__ = "2.0.0"
SPEC_VERSION = "3.0"

from rcan.compliance import (
    FriaSigningKey,
    FriaConformance,
    FriaDocument,
    SafetyBenchmark,
    InstructionsForUse,
    PostMarketIncident,
    EuRegisterEntry,
)
from rcan.message import (
    # ... all existing exports unchanged ...
    RegistryRegisterPayload,
    make_registry_register,
)
```

All existing exports are preserved. Only version constants change.

---

## Section 4: Testing (`tests/test_compliance.py`)

```python
# Dataclass instantiation
def test_fria_document_fields()
def test_fria_conformance_field_names()   # pass_count, fail_count avoid keyword collision
def test_safety_benchmark_fields()
def test_instructions_for_use_fields()
def test_post_market_incident_severity_values()
def test_eu_register_entry_compliance_status_values()

# make_registry_register helper
def test_make_registry_register_includes_fria_ref()
def test_make_registry_register_message_type()

# Version constants
def test_version_constants()   # __version__ == "2.0.0", SPEC_VERSION == "3.0"
```

Existing test suite is unchanged — no regressions expected.

---

## Out of Scope

- API client methods for the new RRF compliance endpoints (POST /fria, GET /fria, GET /compliance)
- CLI changes to `rcan-validate`
- rcan-ts SDK (Sub-project D)
- Flutter app (Sub-project E)
