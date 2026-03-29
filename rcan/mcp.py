"""rcan/mcp.py — MCP integration helpers for RCAN v2.2.

Provides type definitions and helper functions for implementing RCAN-compliant
MCP servers and validating MCP client configurations.

These types are provider-agnostic: the LoA is tied to the token, not the
model or AI provider.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any


# LoA → RCAN scope/role mapping (RCAN v2.2 §22.4)
LOA_TO_SCOPE: dict[int, list[str]] = {
    0: ["discover", "status", "transparency"],   # read-only
    1: ["chat", "control", "system"],            # operate
    3: ["system", "safety"],                     # admin / M2M_TRUSTED
}

TOOL_LOA_REQUIREMENTS: dict[str, int] = {
    # Tier 0 — read
    "robot_ping": 0,
    "robot_status": 0,
    "robot_telemetry": 0,
    "fleet_list": 0,
    "rrf_lookup": 0,
    "compliance_report": 0,
    # Tier 1 — operate
    "robot_command": 1,
    "harness_get": 1,
    "research_run": 1,
    "contribute_toggle": 1,
    "components_list": 1,
    # Tier 3 — admin
    "harness_set": 3,
    "system_upgrade": 3,
    "loa_enable": 3,
}


@dataclass
class McpClientConfig:
    """Configuration entry for a single MCP client.

    Stored in the robot's RCAN yaml under ``mcp_clients:``:

    .. code-block:: yaml

        mcp_clients:
          - name: "claude-code-laptop"
            token_hash: "sha256:abc123..."
            loa: 3
    """

    name: str
    token_hash: str   # "sha256:<hex>" — never the raw token
    loa: int          # 0, 1, or 3

    def allows_tool(self, tool_name: str) -> bool:
        """Return True if this client's LoA satisfies the tool's requirement."""
        required = TOOL_LOA_REQUIREMENTS.get(tool_name, 99)
        return self.loa >= required

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "token_hash": self.token_hash, "loa": self.loa}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "McpClientConfig":
        return cls(name=d["name"], token_hash=d["token_hash"], loa=int(d.get("loa", 0)))

    @classmethod
    def generate(cls, name: str, loa: int) -> tuple["McpClientConfig", str]:
        """Generate a new client config with a random token.

        Returns
        -------
        (config, raw_token)
            The config to store in yaml and the raw token to give the client.
        """
        raw = secrets.token_urlsafe(32)
        token_hash = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
        return cls(name=name, token_hash=token_hash, loa=loa), raw


@dataclass
class McpServerConfig:
    """Top-level MCP server configuration, extracted from the RCAN yaml."""

    rrn: str
    clients: list[McpClientConfig] = field(default_factory=list)

    def resolve_loa(self, raw_token: str) -> int | None:
        """Return the LoA for a raw token, or None if unrecognised."""
        token_hash = "sha256:" + hashlib.sha256(raw_token.encode()).hexdigest()
        for client in self.clients:
            if secrets.compare_digest(client.token_hash, token_hash):
                return client.loa
        return None

    @classmethod
    def from_rcan_config(cls, cfg: dict[str, Any]) -> "McpServerConfig":
        """Build from a loaded RCAN yaml dict."""
        rrn = cfg.get("rrn", "")
        clients = [
            McpClientConfig.from_dict(c) for c in cfg.get("mcp_clients", [])
        ]
        return cls(rrn=rrn, clients=clients)
