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

## Spec Compliance

This SDK implements [RCAN v1.2](https://rcan.dev/spec), including:
- §2 Robot Addressing (Robot URI)
- §3 Message format and serialization
- §16 AI Accountability Layer (confidence gate, HiTL gate, thought log)

## Links

- **Spec**: https://rcan.dev/spec
- **Registry**: https://rcan.dev/registry
- **GitHub**: https://github.com/continuonai/rcan-py
- **Issues**: https://github.com/continuonai/rcan-spec/issues

## License

MIT
