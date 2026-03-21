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
    RCANNodeError,
    RCANRegistryError,
    RCANSignatureError,
    RCANTimeoutError,
    RCANValidationError,
    # v1.5 exceptions
    VersionIncompatibleError,
    ReplayAttackError,
    ClockDriftError,
    DelegationChainExceededError,
    DelegationVerificationError,
    QoSAckTimeoutError,
    SafetyHaltError,
    ConfigAuthorizationError,
    ConfigHashMismatchError,
    RevocationError,
    ConsentError,
    # v1.6 exceptions
    FederationError,
    IdentityError,
)
from rcan.gates import ConfidenceGate, HiTLGate, GateResult
from rcan.message import (
    RCANMessage,
    RCANResponse,
    MessageType,
    SenderType,
    make_cloud_relay_message,
    validate_version_compat,
)
from rcan.node import NodeClient
from rcan.types import RCANConfig, RCANMetadata, RCANAgentConfig, RCANMessageEnvelope
from rcan.version import SPEC_VERSION, SUPPORTED_FEATURES

# v1.5 modules — Replay Prevention (GAP-03)
from rcan.replay import ReplayCache, validate_replay

# v1.5 modules — Clock Synchronization (GAP-04)
from rcan.clock import ClockSyncStatus, check_clock_sync, assert_clock_synced

# v1.5 modules — QoS / Delivery Guarantees (GAP-11)
from rcan.qos import QoSLevel, QoSManager, make_estop_with_qos

# v1.5 modules — Config Update (GAP-07)
from rcan.config_update import (
    ConfigUpdateMessage,
    make_config_update,
    validate_config_update,
)

# v1.5 modules — Key Rotation (GAP-09)
from rcan.keys import KeyRotationMessage, KeyStore, make_key_rotation_message

# v1.5 modules — Consent Wire Protocol (GAP-05)
from rcan.consent import (
    ConsentRequestPayload,
    ConsentGrantPayload,
    ConsentDenyPayload,
    make_consent_request,
    make_consent_grant,
    make_consent_deny,
    validate_consent_message,
)

# v1.5 modules — Robot Identity Revocation (GAP-02)
from rcan.revocation import (
    RevocationStatus,
    RevocationCache,
    check_revocation,
    make_revocation_broadcast,
)

# v1.5 modules — Training Data Consent (GAP-10)
from rcan.training_consent import (
    DataCategory,
    TrainingConsentRequest,
    make_training_consent_request,
    make_training_consent_grant,
    make_training_consent_deny,
)

# v1.5 modules — Command Delegation Chain (GAP-01)
from rcan.delegation import (
    DelegationHop,
    add_delegation_hop,
    validate_delegation_chain,
)

# v1.5 modules — Offline Operation Mode (GAP-06)
from rcan.offline import OfflineModeManager, OfflineStatus

# v1.5 modules — Fault Reporting (GAP-20)
from rcan.fault import FaultCode, FaultReport, make_fault_report

# v1.6 modules — Federated Consent (GAP-16)
from rcan import federation
from rcan.federation import (
    RegistryTier,
    FederationSyncType,
    RegistryIdentity,
    FederationSyncPayload,
    TrustAnchorCache,
    make_federation_sync,
    validate_cross_registry_command,
)

# v1.6 modules — Constrained Transports (GAP-17)
from rcan import transport
from rcan.transport import (
    TransportEncoding,
    TransportNegotiation,
    TransportError,
    encode_compact,
    decode_compact,
    encode_minimal,
    decode_minimal,
    encode_ble_frame,
    decode_ble_frames,
    select_transport,
)

# v1.6 modules — Multi-Modal Payloads (GAP-18)
from rcan import multimodal
from rcan.multimodal import (
    MediaEncoding,
    MediaChunk,
    StreamChunk,
    MediaSizeError,
    add_media_inline,
    add_media_ref,
    validate_media_chunks,
    make_training_data_message,
    make_stream_chunk,
)

# v1.6 modules — Human Identity Verification (GAP-14)
from rcan import identity
from rcan.identity import (
    LevelOfAssurance,
    IdentityRecord,
    LoaPolicy,
    DEFAULT_LOA_POLICY,
    PRODUCTION_LOA_POLICY,
    extract_loa_from_jwt,
    validate_loa_for_scope,
)

__version__ = "0.7.0"
__spec_version__ = "1.9.0"

__all__ = [
    # Address
    "RobotURI",
    # Message
    "RCANMessage",
    "RCANResponse",
    "MessageType",
    "SenderType",
    "make_cloud_relay_message",
    "validate_version_compat",
    # Audit
    "CommitmentRecord",
    # Gates
    "ConfidenceGate",
    "HiTLGate",
    "GateResult",
    # Exceptions — original
    "RCANError",
    "RCANAddressError",
    "RCANGateError",
    "RCANNodeError",
    "RCANRegistryError",
    "RCANSignatureError",
    "RCANTimeoutError",
    "RCANValidationError",
    # Exceptions — v1.5
    "VersionIncompatibleError",
    "ReplayAttackError",
    "ClockDriftError",
    "DelegationChainExceededError",
    "DelegationVerificationError",
    "QoSAckTimeoutError",
    "SafetyHaltError",
    "ConfigAuthorizationError",
    "ConfigHashMismatchError",
    "RevocationError",
    "ConsentError",
    # Node federation
    "NodeClient",
    # Types
    "RCANConfig",
    "RCANMetadata",
    "RCANAgentConfig",
    "RCANMessageEnvelope",
    # Version
    "__version__",
    "SPEC_VERSION",
    "SUPPORTED_FEATURES",
    # v1.5 — Replay Prevention (GAP-03)
    "ReplayCache",
    "validate_replay",
    # v1.5 — Clock Sync (GAP-04)
    "ClockSyncStatus",
    "check_clock_sync",
    "assert_clock_synced",
    # v1.5 — QoS (GAP-11)
    "QoSLevel",
    "QoSManager",
    "make_estop_with_qos",
    # v1.5 — Config Update (GAP-07)
    "ConfigUpdateMessage",
    "make_config_update",
    "validate_config_update",
    # v1.5 — Key Rotation (GAP-09)
    "KeyRotationMessage",
    "KeyStore",
    "make_key_rotation_message",
    # v1.5 — Consent Wire Protocol (GAP-05)
    "ConsentRequestPayload",
    "ConsentGrantPayload",
    "ConsentDenyPayload",
    "make_consent_request",
    "make_consent_grant",
    "make_consent_deny",
    "validate_consent_message",
    # v1.5 — Robot Identity Revocation (GAP-02)
    "RevocationStatus",
    "RevocationCache",
    "check_revocation",
    "make_revocation_broadcast",
    # v1.5 — Training Data Consent (GAP-10)
    "DataCategory",
    "TrainingConsentRequest",
    "make_training_consent_request",
    "make_training_consent_grant",
    "make_training_consent_deny",
    # v1.5 — Command Delegation Chain (GAP-01)
    "DelegationHop",
    "add_delegation_hop",
    "validate_delegation_chain",
    # v1.5 — Offline Operation Mode (GAP-06)
    "OfflineModeManager",
    "OfflineStatus",
    # v1.5 — Fault Reporting (GAP-20)
    "FaultCode",
    "FaultReport",
    "make_fault_report",
    # v1.6 — Federated Consent (GAP-16)
    "federation",
    "RegistryTier",
    "FederationSyncType",
    "RegistryIdentity",
    "FederationSyncPayload",
    "TrustAnchorCache",
    "make_federation_sync",
    "validate_cross_registry_command",
    # v1.6 — Constrained Transports (GAP-17)
    "transport",
    "TransportEncoding",
    "TransportNegotiation",
    "TransportError",
    "encode_compact",
    "decode_compact",
    "encode_minimal",
    "decode_minimal",
    "encode_ble_frame",
    "decode_ble_frames",
    "select_transport",
    # v1.6 — Multi-Modal Payloads (GAP-18)
    "multimodal",
    "MediaEncoding",
    "MediaChunk",
    "StreamChunk",
    "MediaSizeError",
    "add_media_inline",
    "add_media_ref",
    "validate_media_chunks",
    "make_training_data_message",
    "make_stream_chunk",
    # v1.6 — Human Identity Verification (GAP-14)
    "identity",
    "LevelOfAssurance",
    "IdentityRecord",
    "LoaPolicy",
    "DEFAULT_LOA_POLICY",
    "PRODUCTION_LOA_POLICY",
    "extract_loa_from_jwt",
    "validate_loa_for_scope",
    # v1.6 exceptions
    "FederationError",
    "IdentityError",
    # Sub-modules (imported explicitly)
    # rcan.registry — RegistryClient (requires rcan[http])
    # rcan.signing  — KeyPair, sign_message, verify_message (requires rcan[crypto])
    # rcan.audit    — AuditChain
]
