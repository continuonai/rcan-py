# rcan-py

Official Python SDK for the [RCAN Robot Communication Protocol](https://rcan.dev).

RCAN (Robot Communication and Addressing Network) is an open protocol for robot networking built from safety requirements outward. It provides globally unique robot addressing, authenticated command chains, forensic audit trails, and safety gates.

[![Spec](https://img.shields.io/badge/RCAN-v1.2-blue)](https://rcan.dev/spec)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://pypi.org/project/rcan)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## Install

```bash
pip install rcan
```

Optional extras:
```bash
pip install rcan[http]    # httpx for registry client
pip install rcan[crypto]  # cryptography for Ed25519 signing
pip install rcan[all]     # everything
```

## Quick Start

```python
from rcan import RobotURI, RCANMessage, ConfidenceGate, CommitmentRecord
from rcan.audit import AuditChain

# 1. Build a robot address
uri = RobotURI.build(
    manufacturer="acme",
    model="robotarm",
    version="v2",
    device_id="unit-001",
)
print(uri)  # rcan://registry.rcan.dev/acme/robotarm/v2/unit-001

# 2. Gate on AI confidence before sending a command
gate = ConfidenceGate(threshold=0.8)
confidence = 0.91  # from your AI model

if gate.allows(confidence):
    msg = RCANMessage(
        cmd="move_forward",
        target=uri,
        params={"distance_m": 1.0},
        confidence=confidence,
        model_identity="Qwen2.5-7B-Q4",
    )
    print(msg.to_json(indent=2))
else:
    print(f"Action blocked: confidence {confidence} below threshold {gate.threshold}")

# 3. Create a tamper-evident audit record
chain = AuditChain(secret="your-hmac-secret")
record = chain.append(CommitmentRecord(
    action="move_forward",
    robot_uri=str(uri),
    confidence=confidence,
    model_identity="Qwen2.5-7B-Q4",
    params={"distance_m": 1.0},
    safety_approved=True,
))
print(f"Commitment: {record.content_hash}")
print(f"Chain valid: {chain.verify_all()}")
```

## Core Concepts

### Robot URI

Every robot has a globally unique, resolvable URI:

```
rcan://<registry>/<manufacturer>/<model>/<version>/<device-id>
```

```python
from rcan import RobotURI

uri = RobotURI.parse("rcan://registry.rcan.dev/acme/arm/v2/unit-001")
uri.manufacturer  # "acme"
uri.registry_url  # "https://registry.rcan.dev/registry/acme/arm/v2/unit-001"

# Build from components
uri = RobotURI.build("acme", "arm", "v2", "unit-001")
```

### Safety Gates

Gates are the software equivalent of hardware end stops — hard limits that operate independently of whether the model got the inference right.

**ConfidenceGate** — block AI-driven actions below a confidence threshold:

```python
from rcan import ConfidenceGate, GateResult

gate = ConfidenceGate(threshold=0.8)
gate.check(0.91)  # GateResult.PASS
gate.check(0.65)  # GateResult.BLOCK

# Raise instead of returning BLOCK
gate = ConfidenceGate(threshold=0.8, raise_on_block=True)

# Scope to a specific action type
gate = ConfidenceGate(threshold=0.9, action_type="move_forward")
```

**HiTLGate** — require human approval before executing:

```python
from rcan import HiTLGate

def my_approval(action, params, confidence):
    print(f"Approve {action} (confidence={confidence})? [y/N]")
    return input().strip().lower() == "y"

gate = HiTLGate(
    approval_fn=my_approval,
    timeout_s=30,
    required_below=0.7,  # only require HiTL when confidence is low
)
gate.check("move_forward", params={"distance_m": 2.0}, confidence=0.65)
```

### Audit Trail

Every action can be sealed into a tamper-evident `CommitmentRecord`, chained so that altering any record breaks all subsequent hashes:

```python
from rcan import CommitmentRecord
from rcan.audit import AuditChain

chain = AuditChain(secret="your-secret")

# Append records — each is HMAC-sealed and linked to the previous
r1 = chain.append(CommitmentRecord(action="move_forward", robot_uri=str(uri)))
r2 = chain.append(CommitmentRecord(action="stop", robot_uri=str(uri)))

# Verify integrity of the entire chain
chain.verify_all()  # True

# Export as JSONL for storage
with open("audit.jsonl", "w") as f:
    f.write(chain.to_jsonl())
```

### RCAN Messages

```python
from rcan import RCANMessage

msg = RCANMessage(
    cmd="move_forward",
    target="rcan://registry.rcan.dev/acme/arm/v2/unit-001",
    params={"distance_m": 1.0},
    confidence=0.91,
    sender="operator-alice",
    scope="operator",
)

json_str = msg.to_json(indent=2)
restored = RCANMessage.from_json(json_str)
```

## Distributed Registry (NodeClient)

RCAN v1.2 §17 introduces a distributed registry network. `NodeClient` resolves RRNs from any node in the federation — root or delegated.

```python
from rcan import NodeClient

client = NodeClient()

# Discover which node is authoritative for an RRN
node = client.discover("RRN-BD-00000001")
print(node["node_type"])   # "authoritative"
print(node["operator"])    # "Boston Dynamics, Inc."

# Resolve a full robot record
robot = client.resolve("RRN-BD-00000001")
print(robot["robot_name"])  # "Atlas Unit 001"

# Use a custom root
client = NodeClient(root_url="https://rcan.dev")
```

**RRN Formats:**

| Format | Example | Description |
|--------|---------|-------------|
| Root (legacy, 8-digit) | `RRN-00000042` | Original format; still valid |
| Root (recommended, 12-digit) | `RRN-000000000042` | New registrations should use 12+ digits |
| Delegated | `RRN-BD-00000001` | Namespace-prefixed; authoritative node holds the record |

Prefix is 2–8 uppercase alphanumeric characters. Sequence is 8–16 digits (up to 10¹⁶ robots per namespace).

## Verification Tiers

Every registered robot has a verification tier. SDKs expose this in resolved records.

| Badge | Tier | Description |
|-------|------|-------------|
| ⬜ Community | Unverified | Self-registered; no identity check |
| 🟡 Verified | Email/domain verified | Manufacturer identity confirmed |
| 🔵 Partner | Official partner program | Signed partnership agreement |
| ✅ Certified | Third-party tested | Passed conformance test suite |

## Spec Compliance

This SDK implements [RCAN v1.2](https://rcan.dev/spec), including:
- §2 Robot Addressing (Robot URI)
- §3 Message format and serialization
- §16 AI Accountability Layer (confidence gate, HiTL gate, thought log)
- §17 Distributed Registry Node Protocol (NodeClient, RRN resolution)

## CLI

```bash
# Validate a RCAN config (L1/L2/L3 conformance)
rcan-validate config myrobot.rcan.yaml

# Watch for changes and re-validate
rcan-validate config myrobot.rcan.yaml --watch

# Validate a message
rcan-validate message command.json

# Verify an audit chain
rcan-validate audit audit.jsonl

# Validate a Robot URI
rcan-validate uri 'rcan://registry.rcan.dev/acme/arm/v2/unit-001'

# Validate a node manifest (fetches /.well-known/rcan-node.json)
rcan-validate node https://registry.example.com

# Validate a node manifest from a local file
rcan-validate node --file path/to/rcan-node.json

# Run all checks
rcan-validate all myrobot.rcan.yaml
```

## Swarm Safety

`NodeClient.resolve()` is the foundation of RCAN-based swarm safety. Before any robot accepts a command from a peer, it should verify the peer's identity and certification tier.

```python
from rcan import NodeClient, ConfidenceGate, CommitmentRecord
from rcan.audit import AuditChain

client = NodeClient()

# Resolve peer identity from the distributed registry (or stale cache if offline)
peer = client.resolve("RRN-BD-000000000042")
tier = peer['record'].get('verification_tier', 'community')

# Enforce minimum trust tier before accepting swarm commands
TRUSTED_TIERS = ('verified', 'certified', 'accredited')
if tier not in TRUSTED_TIERS:
    raise SecurityError(f"Peer robot not sufficiently verified: {tier}")

print(f"✅ Peer verified: {peer.get('robot_name', 'unknown')} [{tier}]")

# Gate on your own model's confidence before acting on the command
gate = ConfidenceGate(threshold=0.80)
my_confidence = 0.91  # from your AI model

if gate.allows(my_confidence):
    # Execute the task and log it to the commitment chain
    chain = AuditChain(secret="your-chain-secret")
    chain.append(CommitmentRecord(
        action="move_to_waypoint",
        robot_uri="rcan://registry.rcan.dev/acme/rover/v1/unit-007",
        confidence=my_confidence,
        model_identity="claude-sonnet-4-6",
        params={"waypoint": "zone-7", "authorized_by": "RRN-BD-000000000042"},
        safety_approved=True,
    ))
    print("📝 Action logged to commitment chain")
```

### RCAN-Swarm Safe checklist

| Requirement | rcan-py API |
|-------------|-------------|
| Valid RRN, verified tier | `NodeClient.resolve(rrn)` → `verification_tier` |
| Commitment chain enabled | `AuditChain` + `CommitmentRecord` |
| Confidence gate ≥ 0.7 | `ConfidenceGate(threshold=0.7)` |
| HITL gate for swarm commands | `HiTLGate(approval_fn=...)` |

> Full guide: [rcan.dev/use-cases/swarm/](https://rcan.dev/use-cases/swarm/)

## Ecosystem

| Package | Language | Install |
|---------|----------|---------|
| **rcan-py** (this) | Python 3.10+ | `pip install rcan` |
| [rcan-ts](https://github.com/continuonai/rcan-ts) | TypeScript / Node | `npm install @continuonai/rcan-ts` |
| [OpenCastor](https://github.com/craigm26/OpenCastor) | Python (robot runtime) | `curl -sL opencastor.com/install \| bash` |

## Links

- **Quickstart**: https://rcan.dev/quickstart
- **Spec**: https://rcan.dev/spec
- **Registry**: https://rcan.dev/registry
- **rcan-ts** (TypeScript SDK): https://github.com/continuonai/rcan-ts · [npm](https://www.npmjs.com/package/@continuonai/rcan)
- **OpenCastor** (Python robot runtime, RCAN reference implementation): https://github.com/craigm26/OpenCastor
- **OpenCastor Fleet UI** (Flutter web app for remote robot management): https://app.opencastor.com
- **Robot Registry Foundation** (global robot identity registry): https://robotregistryfoundation.org
- **GitHub**: https://github.com/continuonai/rcan-py
- **Issues**: https://github.com/continuonai/rcan-spec/issues

## License

MIT
