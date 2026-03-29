"""
rcan.delegation — Command Delegation Chain (GAP-01).

Every RCAN command issued by a robot on behalf of a human MUST carry a
delegation chain proving the chain of authority. Max depth 4 hops.

Spec: §12 — Command Delegation and Chain of Custody
"""

from __future__ import annotations

import base64
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from rcan.exceptions import (
    DelegationChainExceededError,
)

logger = logging.getLogger(__name__)

# Maximum allowed delegation depth (§12)
MAX_DELEGATION_DEPTH = 4


@dataclass
class DelegationHop:
    """A single hop in a command delegation chain.

    Attributes:
        issuer_ruri:   RURI of the issuing principal (robot or human).
        human_subject: RURI or identifier of the human whose authority is being delegated.
        timestamp:     Unix timestamp of this hop.
        scope:         Scope being delegated (e.g. ``"teleop"``, ``"operator"``).
        signature:     Base64-encoded Ed25519 signature over hop canonical bytes.
        hop_id:        Unique identifier for this hop.
    """

    issuer_ruri: str
    human_subject: str
    scope: str
    timestamp: float = field(default_factory=time.time)
    signature: str = ""
    hop_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "hop_id": self.hop_id,
            "issuer_ruri": self.issuer_ruri,
            "human_subject": self.human_subject,
            "timestamp": self.timestamp,
            "scope": self.scope,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DelegationHop":
        return cls(
            issuer_ruri=data.get("issuer_ruri", ""),
            human_subject=data.get("human_subject", ""),
            scope=data.get("scope", ""),
            timestamp=data.get("timestamp", time.time()),
            signature=data.get("signature", ""),
            hop_id=data.get("hop_id", str(uuid.uuid4())),
        )

    def canonical_bytes(self) -> bytes:
        """Return canonical bytes over which the signature is computed."""
        payload = {
            "hop_id": self.hop_id,
            "issuer_ruri": self.issuer_ruri,
            "human_subject": self.human_subject,
            "timestamp": self.timestamp,
            "scope": self.scope,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def add_delegation_hop(
    msg: Any,
    issuer_ruri: str,
    human_subject: str,
    scope: str,
    private_key: Any,
) -> Any:
    """Sign and add a delegation hop to *msg*.

    Args:
        msg:           :class:`~rcan.message.RCANMessage` to add hop to.
        issuer_ruri:   RURI of the issuing principal.
        human_subject: RURI/id of the human whose authority is delegated.
        scope:         Scope being delegated.
        private_key:   :class:`~rcan.signing.KeyPair` with private key, OR None
                       for unsigned hops (unsigned hops are accepted but warned).

    Returns:
        The same message with updated ``delegation_chain``.

    Raises:
        DelegationChainExceededError: If adding this hop would exceed MAX_DELEGATION_DEPTH.
    """
    current_chain = list(getattr(msg, "delegation_chain", []))

    # Deserialize any raw dicts in the chain
    normalized: list[DelegationHop] = []
    for hop in current_chain:
        if isinstance(hop, DelegationHop):
            normalized.append(hop)
        elif isinstance(hop, dict):
            normalized.append(DelegationHop.from_dict(hop))

    if len(normalized) >= MAX_DELEGATION_DEPTH:
        raise DelegationChainExceededError(
            f"Delegation chain depth ({len(normalized)}) would exceed maximum ({MAX_DELEGATION_DEPTH})"
        )

    hop = DelegationHop(
        issuer_ruri=issuer_ruri,
        human_subject=human_subject,
        scope=scope,
    )

    # Sign the hop
    if private_key is not None:
        try:
            raw_sig = private_key.sign_bytes(hop.canonical_bytes())
            hop.signature = base64.urlsafe_b64encode(raw_sig).decode()
        except Exception as exc:
            logger.warning("Failed to sign delegation hop: %s", exc)
    else:
        logger.warning(
            "Adding unsigned delegation hop — not recommended for production. "
            "issuer=%s",
            issuer_ruri,
        )

    normalized.append(hop)
    msg.delegation_chain = normalized
    return msg


def validate_delegation_chain(
    msg: Any,
    get_public_key_fn: Callable[[str], Optional[Any]],
) -> tuple[bool, str]:
    """Validate all hops in the delegation chain.

    Args:
        msg:               :class:`~rcan.message.RCANMessage` with delegation_chain.
        get_public_key_fn: Callable ``(issuer_ruri: str) -> KeyPair | None``
                           that resolves a public key for each issuer.

    Returns:
        ``(valid: bool, reason: str)``

    Raises:
        DelegationChainExceededError: If chain depth > MAX_DELEGATION_DEPTH.
    """
    chain = getattr(msg, "delegation_chain", [])

    if not chain:
        # No chain — allowed if sender is acting on own behalf
        return True, ""

    if len(chain) > MAX_DELEGATION_DEPTH:
        return False, (
            f"Delegation chain depth {len(chain)} exceeds maximum {MAX_DELEGATION_DEPTH}"
        )

    for i, hop_raw in enumerate(chain):
        if isinstance(hop_raw, dict):
            hop = DelegationHop.from_dict(hop_raw)
        elif isinstance(hop_raw, DelegationHop):
            hop = hop_raw
        else:
            return False, f"Delegation hop {i} is not a valid DelegationHop"

        if not hop.signature:
            logger.warning(
                "Delegation hop %d has no signature — skipping verification", i
            )
            continue

        # Resolve public key for this issuer
        keypair = get_public_key_fn(hop.issuer_ruri)
        if keypair is None:
            return False, (
                f"Cannot resolve public key for delegation hop {i} issuer={hop.issuer_ruri!r}"
            )

        # Verify signature
        try:
            raw_sig = base64.urlsafe_b64decode(hop.signature + "==")
            keypair.verify_bytes(hop.canonical_bytes(), raw_sig)
        except Exception as exc:
            return False, (f"Delegation hop {i} signature verification failed: {exc}")

    return True, ""


__all__ = [
    "DelegationHop",
    "add_delegation_hop",
    "validate_delegation_chain",
    "MAX_DELEGATION_DEPTH",
]
