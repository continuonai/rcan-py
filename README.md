# rcan-py

Python SDK for the [RCAN protocol](https://rcan.dev/spec/) — build robots that communicate securely, audit every action, and enforce safety gates locally.

[![PyPI version](https://img.shields.io/pypi/v/rcan.svg)](https://pypi.org/project/rcan/)
[![RCAN Spec](https://img.shields.io/badge/RCAN-v1.6-blue)](https://rcan.dev/spec/)
[![Tests](https://github.com/continuonai/rcan-py/actions/workflows/ci.yml/badge.svg)](https://github.com/continuonai/rcan-py/actions)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://pypi.org/project/rcan/)

## Install

```bash
pip install rcan==0.6.0
```

Optional extras:

```bash
pip install rcan[http]    # httpx for registry client
pip install rcan[crypto]  # cryptography for Ed25519 signing
pip install rcan[all]     # everything
```

## Quick Start

```python
from rcan import RobotURI, RCANMessage, ConfidenceGate
from rcan.audit import AuditChain, CommitmentRecord
from rcan.replay import ReplayCache
from rcan.qos import QoSLevel
from rcan.consent import ConsentRequest

# 1. Address a robot
uri = RobotURI.build(manufacturer="acme", model="arm", version="v2", device_id="unit-001")
# rcan://registry.rcan.dev/acme/arm/v2/unit-001

# 2. Gate on AI confidence before acting
gate = ConfidenceGate(threshold=0.8)
confidence = 0.91

if gate.allows(confidence):
    msg = RCANMessage(
        cmd="move_forward",
        target=uri,
        params={"distance_m": 1.0},
        confidence=confidence,
        model_identity="gemini-2.5-flash",
    )

# 3. Replay attack prevention — deduplicate incoming messages
cache = ReplayCache(window_seconds=300)
if cache.is_replay(msg.msg_id):
    raise ValueError("Replay attack detected")
cache.record(msg.msg_id)

# 4. Tamper-evident audit chain — every action sealed and linked
chain = AuditChain(secret="your-hmac-secret")
chain.append(CommitmentRecord(
    action="move_forward",
    robot_uri=str(uri),
    confidence=confidence,
    model_identity="gemini-2.5-flash",
    safety_approved=True,
))
chain.verify_all()  # raises if chain is tampered

# 5. Request human consent before a sensitive action
req = ConsentRequest(
    action="open_gripper",
    robot_uri=str(uri),
    requester="operator-alice",
    scope="control",
)
print(req.to_json())
```

## What's in v0.6.0

| Module | Description |
|---|---|
| `rcan.message` | Core `RCANMessage` envelope with all v1.6 fields |
| `rcan.address` | `RobotURI` — parse, build, and validate RCAN robot addresses |
| `rcan.audit` | `AuditChain` + `CommitmentRecord` — tamper-evident HMAC-chained logs |
| `rcan.gates` | `ConfidenceGate`, `HiTLGate` — safety gates for AI-driven actions |
| `rcan.replay` | `ReplayCache` — sliding-window replay attack prevention (GAP-03) |
| `rcan.clock` | `ClockSyncStatus` — NTP clock sync verification (GAP-04) |
| `rcan.qos` | `QoSLevel` — FIRE_AND_FORGET / ACKNOWLEDGED / EXACTLY_ONCE (GAP-11) |
| `rcan.consent` | Consent wire protocol — request/grant/deny (GAP-05) |
| `rcan.revocation` | Robot identity revocation with TTL cache (GAP-02) |
| `rcan.training_consent` | Training data consent, GDPR/EU AI Act Annex III §5 (GAP-10) |
| `rcan.delegation` | Command delegation chain, max 4 hops, Ed25519-signed (GAP-01) |
| `rcan.offline` | Offline operation mode — ESTOP always allowed (GAP-06) |
| `rcan.fault` | `FaultCode` structured fault taxonomy (GAP-20) |
| `rcan.federation` | Federated consent — cross-registry trust, DNS discovery (GAP-16) |
| `rcan.transport` | Constrained transports — compact CBOR, 32-byte ESTOP minimal, BLE (GAP-17) |
| `rcan.multimodal` | Multi-modal payloads — inline/ref media, streaming (GAP-18) |
| `rcan.identity` | Level of Assurance — LoA policies, JWT parsing (GAP-14) |
| `rcan.keys` | Key rotation with JWKS-compatible `KeyStore` (GAP-09) |
| `rcan.config_update` | `CONFIG_UPDATE` protocol with safety scope enforcement (GAP-07) |
| `rcan.node` | `NodeClient` — resolve RRNs across federated registry nodes (§17) |
| `rcan.validate` | L1/L2/L3 conformance validation for configs, messages, URIs |

## Protocol 66 Compliance

Protocol 66 is RCAN's safety layer. Key invariants enforced by this SDK:

- **ESTOP always delivered** — `QoSLevel.EXACTLY_ONCE`, never blocked by QoS downgrade
- **Local safety wins** — `offline` module enforces local limits even without cloud connectivity
- **Confidence gates run locally** — `ConfidenceGate` never makes a network call
- **Audit chain required** — `AuditChain.verify_all()` before executing any flagged command

```python
from rcan.offline import OfflineMode
from rcan.safety import SafetyInvariant

mode = OfflineMode()
mode.assert_estop_reachable()   # raises if ESTOP path is blocked
```

## CLI

```bash
# Validate a robot config (L1/L2/L3 conformance)
rcan-validate config myrobot.rcan.yaml

# Validate a RCAN message
rcan-validate message command.json

# Verify an audit chain
rcan-validate audit audit.jsonl

# Validate a Robot URI
rcan-validate uri 'rcan://registry.rcan.dev/acme/arm/v2/unit-001'

# Run all checks
rcan-validate all myrobot.rcan.yaml
```

## Spec Compliance

Implements [RCAN v1.6](https://rcan.dev/spec/) — 587 tests, 0 skipped.

Covered sections: §1 Robot URI · §2 RBAC · §3 Message Format · §5 Authentication · §5.3 QoS · §6 Safety Invariants · §8.3 Replay Prevention · §8.4 Clock Sync · §8.5 Sender Type · §8.6 Key Lifecycle · §8.7 Level of Assurance · §9 Capabilities · §11 Behavior Scripts · §12 Command Delegation · §13 Revocation · §14 Offline Mode · §16 AI Accountability · §17 Distributed Registry · §18 Federation · §19 Constrained Transport · §21 Registry Integration

## Ecosystem

| Package | Version | Purpose |
|---|---|---|
| **rcan-py** (this) | v0.6.0 | Python SDK |
| [rcan-ts](https://github.com/continuonai/rcan-ts) | v0.6.0 | TypeScript SDK |
| [rcan-spec](https://github.com/continuonai/rcan-spec) | v1.6.0 | Protocol spec |
| [ROBOT.md](https://robotmd.dev) | v0.1.0 | Robot self-declaration format — read by any agent at session start ([repo](https://github.com/RobotRegistryFoundation/robot-md)) |
| [OpenCastor](https://github.com/craigm26/OpenCastor) | v2026.3.17.1 | Robot runtime (reference impl) |
| [RRF](https://robotregistryfoundation.org) | v1.6.0 | Robot identity registry |
| [Fleet UI](https://app.opencastor.com) | live | Web fleet dashboard |
| [Docs](https://docs.opencastor.com) | live | Runtime reference, RCAN, API |

## Contributing

Issues and PRs welcome at [github.com/continuonai/rcan-py](https://github.com/continuonai/rcan-py).

Spec discussions: [github.com/continuonai/rcan-spec/issues](https://github.com/continuonai/rcan-spec/issues)

## License

MIT
