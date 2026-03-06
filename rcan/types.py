"""
rcan.types — TypedDict definitions for RCAN config and message shapes.

These types document the expected structure of RCAN YAML config files
and message envelopes, and can be used for static type checking with
mypy or pyright.
"""

from __future__ import annotations

from typing import Any, Dict

try:
    from typing import TypedDict
except ImportError:  # Python < 3.8
    from typing_extensions import TypedDict  # type: ignore[assignment]


class RCANMetadata(TypedDict, total=False):
    """robot.metadata block in a RCAN YAML config."""

    manufacturer: str
    model: str
    version: str
    device_id: str
    robot_name: str  # backwards-compat alias for device_id
    rrn: str  # Robot Registry Number, assigned by rcan.dev


class RCANAgentConfig(TypedDict, total=False):
    """robot.agent block in a RCAN YAML config."""

    provider: str
    model: str
    temperature: float
    confidence_gates: Dict[str, Any]
    hitl_gates: Dict[str, Any]
    commitment_chain: Dict[str, Any]


class RCANConfig(TypedDict, total=False):
    """Top-level RCAN YAML config structure."""

    rcan_version: str
    metadata: RCANMetadata
    agent: RCANAgentConfig
    channels: Dict[str, Any]
    rcan_protocol: Dict[str, Any]  # legacy key


class RCANMessageEnvelope(TypedDict, total=False):
    """Wire format of a signed RCAN message envelope."""

    cmd: str
    target: str
    rcan_version: str
    confidence: float
    timestamp_ns: int
    params: Dict[str, Any]
    signature: str


class RegistryNode(TypedDict, total=False):
    """A distributed RCAN registry node manifest (/.well-known/rcan-node.json)."""

    rcan_node_version: str
    node_type: str  # root | authoritative | resolver | cache
    operator: str
    namespace_prefix: str
    public_key: str
    api_base: str
    capabilities: list
    ttl_seconds: int
    last_sync: str


class Robot(TypedDict, total=False):
    """A robot record returned by the RCAN registry API."""

    rrn: str
    uri: str
    manufacturer: str
    model: str
    version: str
    device_id: str
    verification_tier: str
    metadata: dict
    registered_at: str


__all__ = [
    "RCANMetadata",
    "RCANAgentConfig",
    "RCANConfig",
    "RCANMessageEnvelope",
    "RegistryNode",
    "Robot",
]
