"""
rcan — Official Python SDK for the RCAN Robot Communication Protocol.

RCAN (Robot Communication and Addressing Network) is an open protocol for
robot networking built from safety requirements outward. This SDK provides
Python bindings for building RCAN-compliant robot systems.

Spec: https://rcan.dev/spec
Docs: https://rcan.dev/docs

Quick start:
    from rcan import RobotURI, RCANMessage, ConfidenceGate

    uri = RobotURI.parse("rcan://registry.rcan.dev/acme/arm/v1/unit-001")
    gate = ConfidenceGate(threshold=0.8)

    if gate.check(confidence=0.91):
        msg = RCANMessage(
            cmd="move_forward",
            target=uri,
            params={"distance_m": 1.0},
            confidence=0.91,
        )
        print(msg.to_json())
"""

from rcan.address import RobotURI
from rcan.audit import CommitmentRecord
from rcan.exceptions import (
    RCANError,
    RCANAddressError,
    RCANGateError,
    RCANRegistryError,
    RCANSignatureError,
    RCANTimeoutError,
    RCANValidationError,
)
from rcan.gates import ConfidenceGate, HiTLGate, GateResult
from rcan.message import RCANMessage, RCANResponse
from rcan.types import RCANConfig, RCANMetadata, RCANAgentConfig, RCANMessageEnvelope

__version__ = "0.1.1"
__spec_version__ = "1.2"

__all__ = [
    # Address
    "RobotURI",
    # Message
    "RCANMessage",
    "RCANResponse",
    # Audit
    "CommitmentRecord",
    # Gates
    "ConfidenceGate",
    "HiTLGate",
    "GateResult",
    # Exceptions
    "RCANError",
    "RCANAddressError",
    "RCANGateError",
    "RCANRegistryError",
    "RCANSignatureError",
    "RCANTimeoutError",
    "RCANValidationError",
    # Types
    "RCANConfig",
    "RCANMetadata",
    "RCANAgentConfig",
    "RCANMessageEnvelope",
    # Sub-modules (imported explicitly)
    # rcan.registry — RegistryClient (requires rcan[http])
    # rcan.signing  — KeyPair, sign_message, verify_message (requires rcan[crypto])
    # rcan.audit    — AuditChain
]
