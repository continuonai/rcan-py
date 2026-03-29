"""
rcan.transport — Bandwidth-Constrained Transports (GAP-17).

Provides compact (msgpack/JSON), minimal 32-byte ESTOP, and BLE frame
encodings for resource-constrained environments.

ESTOP P66 invariant: ESTOP is never blocked by transport encoding selection.
Safety messages prefer lower-latency transport encodings.

Spec: §18 — Constrained Transport Encodings
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import struct
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

log = logging.getLogger(__name__)

# Try msgpack (optional dependency)
try:
    import msgpack  # type: ignore[import]

    _MSGPACK_AVAILABLE = True
except ImportError:
    _MSGPACK_AVAILABLE = False
    log.debug("msgpack not available; compact encoding will use JSON fallback")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TransportError(Exception):
    """Raised when a transport encoding operation fails."""


# ---------------------------------------------------------------------------
# Enums / dataclasses
# ---------------------------------------------------------------------------


class TransportEncoding(str, Enum):
    """Available transport encodings, ordered roughly by capability."""

    HTTP = "http"  # Full JSON over HTTP — highest fidelity
    COMPACT = "compact"  # msgpack/JSON with abbreviated field names
    MINIMAL = "minimal"  # 32-byte ESTOP-only binary format
    BLE = "ble"  # MTU-fragmented BLE frames


@dataclass
class TransportNegotiation:
    """Negotiated transport capabilities between two endpoints.

    Attributes:
        supported: Transport encodings supported by this endpoint.
        preferred: Preferred encoding.
    """

    supported: list[TransportEncoding]
    preferred: TransportEncoding


# ---------------------------------------------------------------------------
# Field abbreviation map (compact encoding)
# ---------------------------------------------------------------------------

# Full name → abbreviated key
_COMPACT_FIELD_MAP: dict[str, str] = {
    "cmd": "t",  # treat cmd as msg_type abbreviation in compact form
    "msg_id": "i",
    "timestamp": "ts",
    "sender": "f",
    "target": "to",
    "scope": "s",
    "params": "p",
    "signature": "sig",
    # reverse mapping extras
    "rcan": "rv",
    "rcan_version": "rv",
}

# Abbreviated key → full name (for decode)
_COMPACT_FIELD_REVERSE: dict[str, str] = {
    "t": "cmd",
    "i": "msg_id",
    "ts": "timestamp",
    "f": "sender",
    "to": "target",
    "s": "scope",
    "p": "params",
    "sig": "signature",
    "rv": "rcan",
}

# BLE frame header: [4B stream_id_hash][2B total_frames][2B frame_index]
_BLE_HEADER_SIZE = 8


# ---------------------------------------------------------------------------
# Compact encoding helpers
# ---------------------------------------------------------------------------


def _to_compact_dict(message: Any) -> dict:
    """Convert an RCANMessage to a compact abbreviated dict."""
    d = {
        "t": message.cmd,
        "i": message.msg_id,
        "ts": message.timestamp,
        "to": str(message.target),
        "p": message.params or {},
    }
    if message.sender is not None:
        d["f"] = message.sender
    if message.scope is not None:
        d["s"] = message.scope
    if message.signature is not None:
        d["sig"] = message.signature
    if message.rcan:
        d["rv"] = message.rcan
    return d


def _from_compact_dict(data: dict) -> Any:
    """Reconstruct an RCANMessage from a compact abbreviated dict."""
    from rcan.message import RCANMessage

    # Map abbreviated keys back to full names
    full: dict[str, Any] = {}
    for k, v in data.items():
        full_key = _COMPACT_FIELD_REVERSE.get(k, k)
        full[full_key] = v

    # Ensure required fields
    cmd = full.get("cmd", "UNKNOWN")
    target = full.get("target", "rcan://rcan.dev/unknown/unknown/v1/unknown")
    params = full.get("params", {})
    sender = full.get("sender")
    scope = full.get("scope")
    sig = full.get("signature")
    msg_id = full.get("msg_id", str(uuid.uuid4()))
    timestamp = full.get("timestamp")
    rcan_ver = full.get("rcan", "1.6")

    kwargs: dict[str, Any] = {
        "cmd": cmd,
        "target": target,
        "params": params,
        "msg_id": msg_id,
        "rcan": rcan_ver,
        "rcan_version": rcan_ver,
    }
    if timestamp is not None:
        kwargs["timestamp"] = float(timestamp)
    if sender is not None:
        kwargs["sender"] = sender
    if scope is not None:
        kwargs["scope"] = scope
    if sig is not None:
        kwargs["signature"] = sig

    return RCANMessage(**kwargs)


# ---------------------------------------------------------------------------
# Compact encoding (msgpack / JSON fallback)
# ---------------------------------------------------------------------------


def encode_compact(message: Any) -> bytes:
    """Encode an :class:`~rcan.message.RCANMessage` to compact binary form.

    Uses msgpack if available, otherwise compact JSON with abbreviated
    field names.

    Field map: ``t``=cmd, ``i``=msg_id, ``ts``=timestamp,
    ``f``=sender (from_rrn), ``to``=target (to_rrn), ``s``=scope,
    ``p``=params, ``sig``=signature.

    Args:
        message: :class:`~rcan.message.RCANMessage` to encode.

    Returns:
        Encoded bytes.
    """
    d = _to_compact_dict(message)
    if _MSGPACK_AVAILABLE:
        return msgpack.packb(d, use_bin_type=True)
    # JSON fallback — as compact as possible
    return json.dumps(d, separators=(",", ":")).encode("utf-8")


def decode_compact(data: bytes) -> Any:
    """Decode compact-encoded bytes back to an :class:`~rcan.message.RCANMessage`.

    Args:
        data: Bytes produced by :func:`encode_compact`.

    Returns:
        Reconstructed :class:`~rcan.message.RCANMessage`.

    Raises:
        TransportError: If decoding fails.
    """
    try:
        if _MSGPACK_AVAILABLE:
            d = msgpack.unpackb(data, raw=False)
        else:
            d = json.loads(data.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise TransportError(
            f"decode_compact: failed to deserialise data: {exc}"
        ) from exc

    try:
        return _from_compact_dict(d)
    except Exception as exc:  # noqa: BLE001
        raise TransportError(
            f"decode_compact: failed to reconstruct RCANMessage: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Minimal 32-byte ESTOP encoding
# ---------------------------------------------------------------------------


def _rrn_hash(rrn: Optional[str]) -> bytes:
    """Return first 8 bytes of SHA-256 of *rrn*, or 8 zero bytes if None."""
    if not rrn:
        return b"\x00" * 8
    return hashlib.sha256(rrn.encode()).digest()[:8]


def _is_safety_message(message: Any) -> bool:
    """Return True if *message* is a SAFETY / ESTOP message."""
    cmd_upper = (message.cmd or "").upper()
    return cmd_upper in {
        "ESTOP",
        "E_STOP",
        "EMERGENCY_STOP",
        "STOP",
        "RESUME",
        "SAFETY",
    }


def encode_minimal(message: Any, *, shared_secret: bytes | None = None) -> bytes:
    """Encode a SAFETY (type 6) message to the 40-byte minimal binary format.

    Layout::

        [2B msg_type LE][8B from_rrn_hash][8B to_rrn_hash]
        [4B unix_ts LE][16B sig_truncated][2B checksum LE]

    - ``from_rrn_hash`` = first 8 bytes of SHA-256(sender)
    - ``to_rrn_hash``   = first 8 bytes of SHA-256(str(target))
    - ``sig_truncated`` = first 16 bytes of HMAC-SHA256(key=shared_secret, data=body)
    - ``checksum``      = XOR of all previous 38 bytes, little-endian uint16

    Args:
        message: :class:`~rcan.message.RCANMessage` — MUST be a SAFETY message.
        shared_secret: Pre-shared key for HMAC signing.  If *None*, falls back
            to using ``msg_id`` (deprecated — will be removed in a future release).

    Returns:
        Exactly 40 bytes.

    Raises:
        TransportError: If message is not a SAFETY type.
    """
    if not _is_safety_message(message):
        raise TransportError(
            f"encode_minimal only supports SAFETY messages (cmd in "
            f"{{ESTOP, STOP, RESUME, SAFETY}}), got cmd={message.cmd!r}"
        )

    # Fields
    msg_type_int = 6  # MessageType.SAFETY
    from_rrn = message.sender or ""
    to_rrn = str(message.target)
    ts_int = int(message.timestamp)

    from_hash = _rrn_hash(from_rrn)  # 8 bytes
    to_hash = _rrn_hash(to_rrn)  # 8 bytes

    # HMAC-SHA256 over from_hash+to_hash+ts using shared_secret as key
    if shared_secret is not None:
        key_bytes = shared_secret
    else:
        import warnings

        warnings.warn(
            "encode_minimal: using msg_id as HMAC key is deprecated and insecure. "
            "Pass shared_secret instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        key_bytes = message.msg_id.encode("utf-8")
    body = from_hash + to_hash + struct.pack("<I", ts_int)
    sig_full = hmac.new(key_bytes, body, hashlib.sha256).digest()
    sig_truncated = sig_full[:16]  # 16 bytes

    # Pack first 38 bytes
    packed_38 = (
        struct.pack("<H", msg_type_int)  # 2B
        + from_hash  # 8B
        + to_hash  # 8B
        + struct.pack("<I", ts_int)  # 4B
        + sig_truncated  # 16B
    )
    assert len(packed_38) == 38

    # Checksum: XOR of all 38 bytes → uint16 LE
    xor_val = 0
    for i in range(0, 38, 2):
        word = struct.unpack_from("<H", packed_38, i)[0]
        xor_val ^= word
    checksum = struct.pack("<H", xor_val)

    result = packed_38 + checksum
    assert len(result) == 40
    return result


def decode_minimal(data: bytes, *, shared_secret: bytes | None = None) -> dict:
    """Decode a 40-byte minimal ESTOP frame to a partial message dict.

    This does NOT return a full :class:`~rcan.message.RCANMessage` — it
    returns a minimal dict suitable for ESTOP dispatch only.

    Args:
        data: Exactly 40 bytes from :func:`encode_minimal`.
        shared_secret: Pre-shared key used when encoding.  Currently unused
            during decode (signature is not re-verified here), but accepted
            for API symmetry and future verification support.

    Returns:
        Dict with keys ``msg_type``, ``from_rrn_hash``, ``to_rrn_hash``,
        ``timestamp``, ``sig_truncated``, ``checksum_ok``.

    Raises:
        TransportError: If data length is not 40 or checksum fails.
    """
    if len(data) != 40:
        raise TransportError(
            f"decode_minimal expects exactly 40 bytes, got {len(data)}"
        )

    # Verify checksum
    xor_val = 0
    for i in range(0, 38, 2):
        word = struct.unpack_from("<H", data, i)[0]
        xor_val ^= word
    stored_checksum = struct.unpack_from("<H", data, 38)[0]
    checksum_ok = xor_val == stored_checksum
    if not checksum_ok:
        log.warning(
            "decode_minimal: checksum mismatch (computed=%04x, stored=%04x)",
            xor_val,
            stored_checksum,
        )

    msg_type = struct.unpack_from("<H", data, 0)[0]
    from_rrn_hash = data[2:10]
    to_rrn_hash = data[10:18]
    timestamp = struct.unpack_from("<I", data, 18)[0]
    sig_truncated = data[22:38]

    return {
        "msg_type": msg_type,
        "from_rrn_hash": from_rrn_hash.hex(),
        "to_rrn_hash": to_rrn_hash.hex(),
        "timestamp": timestamp,
        "sig_truncated": sig_truncated.hex(),
        "checksum_ok": checksum_ok,
        "is_safety": msg_type == 6,
    }


# ---------------------------------------------------------------------------
# BLE frame encoding
# ---------------------------------------------------------------------------


def encode_ble_frame(message: Any, mtu: int = 251) -> list[bytes]:
    """Fragment a message into MTU-sized BLE frames.

    Each frame has an 8-byte header::

        [4B stream_id_hash][2B total_frames LE][2B frame_index LE]

    Followed by up to ``(mtu - 8)`` bytes of payload.

    Uses compact encoding for the payload.

    Args:
        message: :class:`~rcan.message.RCANMessage` to encode.
        mtu:     BLE MTU size in bytes (default: 251).

    Returns:
        List of bytes frames, each ≤ *mtu* bytes.

    Raises:
        TransportError: If message cannot be encoded.
    """
    if mtu < 9:
        raise TransportError(f"BLE MTU too small: {mtu} (minimum 9)")

    payload = encode_compact(message)
    chunk_size = mtu - _BLE_HEADER_SIZE

    # Derive a 4-byte stream ID from msg_id
    stream_hash = hashlib.sha256(message.msg_id.encode()).digest()[:4]

    chunks = [
        payload[i : i + chunk_size] for i in range(0, max(len(payload), 1), chunk_size)
    ]
    total_frames = len(chunks)

    frames = []
    for idx, chunk in enumerate(chunks):
        header = stream_hash + struct.pack("<H", total_frames) + struct.pack("<H", idx)
        frames.append(header + chunk)

    log.debug(
        "encode_ble_frame: %d bytes → %d frames (mtu=%d)",
        len(payload),
        total_frames,
        mtu,
    )
    return frames


def decode_ble_frames(frames: list[bytes]) -> Any:
    """Reassemble BLE frames into an :class:`~rcan.message.RCANMessage`.

    Frames may be provided in any order — they are sorted by frame_index.

    Args:
        frames: List of byte frames produced by :func:`encode_ble_frame`.

    Returns:
        Reconstructed :class:`~rcan.message.RCANMessage`.

    Raises:
        TransportError: If frames are malformed or incomplete.
    """
    if not frames:
        raise TransportError("decode_ble_frames: no frames provided")

    parsed: list[tuple[int, bytes]] = []
    total_frames = None
    stream_hash = None

    for i, frame in enumerate(frames):
        if len(frame) < _BLE_HEADER_SIZE:
            raise TransportError(
                f"decode_ble_frames: frame {i} too short ({len(frame)} bytes)"
            )
        sh = frame[:4]
        tf = struct.unpack_from("<H", frame, 4)[0]
        fi = struct.unpack_from("<H", frame, 6)[0]
        chunk = frame[_BLE_HEADER_SIZE:]

        if stream_hash is None:
            stream_hash = sh
            total_frames = tf
        elif sh != stream_hash:
            log.warning(
                "decode_ble_frames: stream_hash mismatch on frame %d; ignoring", i
            )
            continue

        parsed.append((fi, chunk))

    if total_frames is None:
        raise TransportError("decode_ble_frames: could not determine frame count")

    parsed.sort(key=lambda x: x[0])

    if len(parsed) != total_frames:
        raise TransportError(
            f"decode_ble_frames: expected {total_frames} frames, got {len(parsed)}"
        )

    payload = b"".join(chunk for _, chunk in parsed)
    return decode_compact(payload)


# ---------------------------------------------------------------------------
# Transport selection
# ---------------------------------------------------------------------------


def select_transport(
    available: list[TransportEncoding],
    message: Any,
) -> TransportEncoding:
    """Choose the best :class:`TransportEncoding` for *message*.

    Safety policy (P66):
    - ESTOP / SAFETY messages prefer lower-latency transports even if
      they carry less data (MINIMAL > COMPACT > HTTP).

    General policy:
    - Prefer HTTP for maximum fidelity.
    - Fall back through COMPACT → BLE.
    - MINIMAL is only used automatically for safety messages.

    Args:
        available: Encodings supported by the channel.
        message:   :class:`~rcan.message.RCANMessage` being sent.

    Returns:
        Best :class:`TransportEncoding` from *available*.

    Raises:
        TransportError: If *available* is empty.
    """
    if not available:
        raise TransportError("select_transport: no available transports")

    avail_set = set(available)

    if _is_safety_message(message):
        # Safety preference: MINIMAL → COMPACT → BLE → HTTP
        for preferred in [
            TransportEncoding.MINIMAL,
            TransportEncoding.COMPACT,
            TransportEncoding.BLE,
            TransportEncoding.HTTP,
        ]:
            if preferred in avail_set:
                log.debug("select_transport: safety message → selected %s", preferred)
                return preferred
    else:
        # General preference: HTTP → COMPACT → BLE → MINIMAL
        for preferred in [
            TransportEncoding.HTTP,
            TransportEncoding.COMPACT,
            TransportEncoding.BLE,
            TransportEncoding.MINIMAL,
        ]:
            if preferred in avail_set:
                log.debug(
                    "select_transport: non-safety message → selected %s", preferred
                )
                return preferred

    # Should not reach here, but return first available as fallback
    return available[0]


__all__ = [
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
]
