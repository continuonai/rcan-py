"""
RCAN Audit — CommitmentRecord for tamper-evident action logging.

Every safety-critical robot action can be sealed into a CommitmentRecord:
an HMAC-chained record that provides forensic-grade proof of what the system
did, when, at what confidence, and under which authorization.

Spec: https://rcan.dev/spec#section-16
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CommitmentRecord:
    """
    A tamper-evident commitment to a robot action.

    The record is sealed with an HMAC over its canonical JSON form. Chaining
    records (each including the previous record's hash) provides a forensic
    audit trail: altering any record breaks all subsequent hashes.

    Attributes:
        record_id:       Unique record identifier.
        timestamp:       Unix timestamp of the action.
        action:          Command name (e.g. ``"move_forward"``).
        params:          Command parameters.
        robot_uri:       Target robot URI string.
        confidence:      AI confidence score if applicable.
        model_identity:  Model name/version that drove the decision.
        operator:        Operator identity.
        safety_approved: Whether safety gate passed.
        safety_reason:   Reason if blocked.
        previous_hash:   Hash of the previous record (for chaining).
        schema_version:  Commitment schema version.
        hmac_value:      HMAC-SHA256 over the canonical payload (set by :meth:`seal`).
    """

    action: str
    params: dict[str, Any] = field(default_factory=dict)
    robot_uri: str = ""
    confidence: float | None = None
    model_identity: str | None = None
    operator: str | None = None
    safety_approved: bool = True
    safety_reason: str = ""
    previous_hash: str | None = None
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    schema_version: str = "0.3.0"
    hmac_value: str | None = None  # Set by seal()

    # ------------------------------------------------------------------
    # HMAC sealing
    # ------------------------------------------------------------------

    def _canonical_payload(self) -> bytes:
        """Return the canonical JSON bytes used for HMAC computation."""
        payload = {
            "schema_version": self.schema_version,
            "record_id": self.record_id,
            "timestamp": self.timestamp,
            "action": self.action,
            "params": self.params,
            "robot_uri": self.robot_uri,
            "confidence": self.confidence,
            "model_identity": self.model_identity,
            "operator": self.operator,
            "safety_approved": self.safety_approved,
            "safety_reason": self.safety_reason,
            "previous_hash": self.previous_hash,
        }
        # Stable serialization: sorted keys
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def seal(self, secret: bytes | str) -> "CommitmentRecord":
        """
        Compute and store the HMAC-SHA256 over this record's canonical payload.

        Args:
            secret: HMAC key (bytes or str — str will be UTF-8 encoded).

        Returns:
            self (for chaining).
        """
        if isinstance(secret, str):
            secret = secret.encode()
        mac = hmac.new(secret, self._canonical_payload(), hashlib.sha256)
        self.hmac_value = mac.hexdigest()
        return self

    def verify(self, secret: bytes | str) -> bool:
        """
        Verify this record's HMAC against the provided secret.

        Returns:
            True if valid, False if tampered or unsealed.
        """
        if self.hmac_value is None:
            return False
        if isinstance(secret, str):
            secret = secret.encode()
        mac = hmac.new(secret, self._canonical_payload(), hashlib.sha256)
        return hmac.compare_digest(mac.hexdigest(), self.hmac_value)

    @property
    def content_hash(self) -> str:
        """SHA-256 hash of the canonical payload (for chain linking)."""
        return hashlib.sha256(self._canonical_payload()).hexdigest()

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict."""
        d: dict[str, Any] = {
            "schema_version": self.schema_version,
            "record_id": self.record_id,
            "timestamp": self.timestamp,
            "action": self.action,
            "params": self.params,
            "robot_uri": self.robot_uri,
            "safety_approved": self.safety_approved,
        }
        if self.confidence is not None:
            d["confidence"] = self.confidence
        if self.model_identity is not None:
            d["model_identity"] = self.model_identity
        if self.operator is not None:
            d["operator"] = self.operator
        if self.safety_reason:
            d["safety_reason"] = self.safety_reason
        if self.previous_hash is not None:
            d["previous_hash"] = self.previous_hash
        if self.hmac_value is not None:
            d["hmac"] = self.hmac_value
        return d

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CommitmentRecord":
        return cls(
            schema_version=data.get("schema_version", "0.3.0"),
            record_id=data.get("record_id", str(uuid.uuid4())),
            timestamp=data.get("timestamp", time.time()),
            action=data["action"],
            params=data.get("params", {}),
            robot_uri=data.get("robot_uri", ""),
            confidence=data.get("confidence"),
            model_identity=data.get("model_identity"),
            operator=data.get("operator"),
            safety_approved=data.get("safety_approved", True),
            safety_reason=data.get("safety_reason", ""),
            previous_hash=data.get("previous_hash"),
            hmac_value=data.get("hmac"),
        )

    # ------------------------------------------------------------------
    # Chain helpers
    # ------------------------------------------------------------------

    def next_record(self, action: str, **kwargs: Any) -> "CommitmentRecord":
        """
        Create the next record in the chain, linked to this one.

        Args:
            action: Command for the next record.
            **kwargs: Additional fields for the next :class:`CommitmentRecord`.
        """
        return CommitmentRecord(
            action=action,
            previous_hash=self.content_hash,
            **kwargs,
        )

    def __repr__(self) -> str:
        sealed = "sealed" if self.hmac_value else "unsealed"
        return f"CommitmentRecord(action={self.action!r}, {sealed}, id={self.record_id[:8]})"


class AuditChain:
    """
    An ordered chain of :class:`CommitmentRecord` objects.

    Provides append, verify-all, and JSONL export.
    """

    def __init__(self, secret: bytes | str) -> None:
        self._secret = secret if isinstance(secret, bytes) else secret.encode()
        self._records: list[CommitmentRecord] = []

    def append(self, record: CommitmentRecord) -> CommitmentRecord:
        """Seal and append a record, linking it to the previous."""
        if self._records:
            record.previous_hash = self._records[-1].content_hash
        record.seal(self._secret)
        self._records.append(record)
        return record

    def verify_all(self) -> bool:
        """Verify HMAC and chain integrity for every record."""
        prev_hash: str | None = None
        for record in self._records:
            if not record.verify(self._secret):
                return False
            if prev_hash is not None and record.previous_hash != prev_hash:
                return False
            prev_hash = record.content_hash
        return True

    def to_jsonl(self) -> str:
        """Serialize the chain as JSONL (one record per line)."""
        return "\n".join(r.to_json() for r in self._records)

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self):
        return iter(self._records)
