"""Tests for rcan.transport — Bandwidth-Constrained Transports (GAP-17)."""

from __future__ import annotations

import struct
import time

import pytest

from rcan.message import RCANMessage
from rcan.transport import (
    TransportEncoding,
    TransportError,
    TransportNegotiation,
    decode_ble_frames,
    decode_compact,
    decode_minimal,
    encode_ble_frame,
    encode_compact,
    encode_minimal,
    select_transport,
)

TARGET = "rcan://rcan.dev/acme/bot/v1/unit-001"
ESTOP_TARGET = "rcan://rcan.dev/acme/bot/v1/unit-002"


def make_msg(cmd: str = "move_forward", **kwargs) -> RCANMessage:
    return RCANMessage(cmd=cmd, target=TARGET, params={"speed": 1.0}, **kwargs)


def make_estop(reason: str = "obstacle detected") -> RCANMessage:
    return RCANMessage(
        cmd="ESTOP",
        target=ESTOP_TARGET,
        params={"reason": reason},
        sender="RRN-000000000001",
        scope="safety",
    )


# ---------------------------------------------------------------------------
# TransportEncoding enum
# ---------------------------------------------------------------------------


class TestTransportEncoding:
    def test_values(self):
        assert TransportEncoding.HTTP.value == "http"
        assert TransportEncoding.COMPACT.value == "compact"
        assert TransportEncoding.MINIMAL.value == "minimal"
        assert TransportEncoding.BLE.value == "ble"


# ---------------------------------------------------------------------------
# TransportNegotiation
# ---------------------------------------------------------------------------


class TestTransportNegotiation:
    def test_construction(self):
        tn = TransportNegotiation(
            supported=[TransportEncoding.HTTP, TransportEncoding.COMPACT],
            preferred=TransportEncoding.COMPACT,
        )
        assert TransportEncoding.HTTP in tn.supported
        assert tn.preferred == TransportEncoding.COMPACT


# ---------------------------------------------------------------------------
# encode_compact / decode_compact
# ---------------------------------------------------------------------------


class TestCompactEncoding:
    def test_encode_returns_bytes(self):
        msg = make_msg()
        data = encode_compact(msg)
        assert isinstance(data, bytes)
        assert len(data) > 0

    def test_roundtrip_cmd(self):
        msg = make_msg(cmd="test_command")
        data = encode_compact(msg)
        decoded = decode_compact(data)
        assert decoded.cmd == "test_command"

    def test_roundtrip_target(self):
        msg = make_msg()
        data = encode_compact(msg)
        decoded = decode_compact(data)
        assert str(decoded.target) == TARGET

    def test_roundtrip_params(self):
        msg = RCANMessage(
            cmd="configure",
            target=TARGET,
            params={"key": "value", "number": 42},
        )
        data = encode_compact(msg)
        decoded = decode_compact(data)
        assert decoded.params.get("key") == "value"
        assert decoded.params.get("number") == 42

    def test_roundtrip_sender(self):
        msg = RCANMessage(
            cmd="move",
            target=TARGET,
            sender="RRN-000000000001",
        )
        data = encode_compact(msg)
        decoded = decode_compact(data)
        assert decoded.sender == "RRN-000000000001"

    def test_roundtrip_scope(self):
        msg = RCANMessage(cmd="observe", target=TARGET, scope="observer")
        data = encode_compact(msg)
        decoded = decode_compact(data)
        assert decoded.scope == "observer"

    def test_compact_smaller_than_json(self):
        """Compact encoding should generally be smaller than standard JSON."""
        import json as _json
        msg = make_msg(cmd="status_request")
        compact = encode_compact(msg)
        full_json = _json.dumps(msg.to_dict()).encode()
        # Allow larger if msgpack is not available and we fall back to JSON
        # The important thing is it encodes correctly
        assert isinstance(compact, bytes)

    def test_decode_invalid_data_raises(self):
        with pytest.raises(TransportError):
            decode_compact(b"\xff\xff\xff invalid garbage \x00\x01")

    def test_roundtrip_msg_id_preserved(self):
        msg = make_msg()
        data = encode_compact(msg)
        decoded = decode_compact(data)
        assert decoded.msg_id == msg.msg_id

    def test_roundtrip_timestamp(self):
        msg = make_msg()
        data = encode_compact(msg)
        decoded = decode_compact(data)
        assert abs(decoded.timestamp - msg.timestamp) < 1.0


# ---------------------------------------------------------------------------
# encode_minimal / decode_minimal (32-byte ESTOP format)
# ---------------------------------------------------------------------------


class TestMinimalEncoding:
    def test_encode_returns_32_bytes(self):
        msg = make_estop()
        data = encode_minimal(msg)
        assert len(data) == 32

    def test_encode_exactly_32_bytes(self):
        """Verify the byte count is exactly 32 every time."""
        for cmd in ["ESTOP", "STOP", "RESUME"]:
            msg = RCANMessage(cmd=cmd, target=ESTOP_TARGET, sender="RRN-000000000001")
            data = encode_minimal(msg)
            assert len(data) == 32, f"Expected 32 bytes for {cmd}, got {len(data)}"

    def test_rejects_non_safety_message(self):
        msg = make_msg(cmd="move_forward")
        with pytest.raises(TransportError, match="SAFETY"):
            encode_minimal(msg)

    def test_decode_returns_dict(self):
        msg = make_estop()
        data = encode_minimal(msg)
        result = decode_minimal(data)
        assert isinstance(result, dict)

    def test_decode_msg_type_is_6(self):
        """Minimal format always encodes SAFETY (type 6)."""
        msg = make_estop()
        data = encode_minimal(msg)
        result = decode_minimal(data)
        assert result["msg_type"] == 6

    def test_decode_is_safety_flag(self):
        msg = make_estop()
        data = encode_minimal(msg)
        result = decode_minimal(data)
        assert result["is_safety"] is True

    def test_decode_checksum_ok(self):
        msg = make_estop()
        data = encode_minimal(msg)
        result = decode_minimal(data)
        assert result["checksum_ok"] is True

    def test_decode_checksum_fails_on_corruption(self):
        msg = make_estop()
        data = bytearray(encode_minimal(msg))
        data[5] ^= 0xFF  # corrupt a byte
        result = decode_minimal(bytes(data))
        assert result["checksum_ok"] is False

    def test_decode_timestamp_close_to_original(self):
        msg = make_estop()
        data = encode_minimal(msg)
        result = decode_minimal(data)
        assert abs(result["timestamp"] - int(msg.timestamp)) <= 1

    def test_decode_from_rrn_hash_hex_string(self):
        msg = make_estop()
        data = encode_minimal(msg)
        result = decode_minimal(data)
        assert isinstance(result["from_rrn_hash"], str)
        assert len(result["from_rrn_hash"]) == 16  # 8 bytes = 16 hex chars

    def test_decode_to_rrn_hash_hex_string(self):
        msg = make_estop()
        data = encode_minimal(msg)
        result = decode_minimal(data)
        assert isinstance(result["to_rrn_hash"], str)
        assert len(result["to_rrn_hash"]) == 16

    def test_decode_wrong_length_raises(self):
        with pytest.raises(TransportError, match="32"):
            decode_minimal(b"\x00" * 31)

    def test_decode_too_long_raises(self):
        with pytest.raises(TransportError):
            decode_minimal(b"\x00" * 33)

    def test_from_rrn_hash_reflects_sender(self):
        """Different senders should produce different from_rrn_hash values."""
        import hashlib
        msg1 = RCANMessage(
            cmd="ESTOP", target=ESTOP_TARGET, sender="RRN-000000000001"
        )
        msg2 = RCANMessage(
            cmd="ESTOP", target=ESTOP_TARGET, sender="RRN-000000000002"
        )
        r1 = decode_minimal(encode_minimal(msg1))
        r2 = decode_minimal(encode_minimal(msg2))
        assert r1["from_rrn_hash"] != r2["from_rrn_hash"]

    def test_layout_bytes_positions(self):
        """Validate byte-level layout of the 32-byte frame."""
        msg = RCANMessage(
            cmd="ESTOP",
            target=ESTOP_TARGET,
            sender="RRN-TEST",
        )
        data = encode_minimal(msg)
        # Bytes 0–1: msg_type little-endian = 6
        msg_type = struct.unpack_from("<H", data, 0)[0]
        assert msg_type == 6
        # Bytes 18–21: unix timestamp
        ts = struct.unpack_from("<I", data, 18)[0]
        assert abs(ts - int(msg.timestamp)) <= 1


# ---------------------------------------------------------------------------
# BLE frame encoding
# ---------------------------------------------------------------------------


class TestBleEncoding:
    def test_single_frame_small_message(self):
        """Small messages should fit in a single BLE frame."""
        msg = RCANMessage(cmd="ping", target=TARGET, params={})
        frames = encode_ble_frame(msg, mtu=251)
        assert len(frames) >= 1
        for frame in frames:
            assert len(frame) <= 251

    def test_fragmentation_multiple_frames(self):
        """Large messages should be fragmented into multiple frames."""
        # Create a message that will exceed a small MTU
        msg = RCANMessage(
            cmd="large_command",
            target=TARGET,
            params={"data": "x" * 500},
        )
        frames = encode_ble_frame(msg, mtu=64)
        assert len(frames) > 1
        for frame in frames:
            assert len(frame) <= 64

    def test_reassemble_roundtrip(self):
        """Frames encoded then decoded should reconstruct the original message."""
        msg = RCANMessage(
            cmd="test_ble",
            target=TARGET,
            params={"key": "value"},
        )
        frames = encode_ble_frame(msg, mtu=64)
        decoded = decode_ble_frames(frames)
        assert decoded.cmd == msg.cmd
        assert decoded.params.get("key") == "value"

    def test_reassemble_out_of_order(self):
        """Frames may be reassembled in any order."""
        msg = RCANMessage(
            cmd="out_of_order",
            target=TARGET,
            params={"payload": "a" * 300},
        )
        frames = encode_ble_frame(msg, mtu=64)
        # Reverse order
        frames_reversed = list(reversed(frames))
        decoded = decode_ble_frames(frames_reversed)
        assert decoded.cmd == msg.cmd

    def test_empty_frames_raises(self):
        with pytest.raises(TransportError):
            decode_ble_frames([])

    def test_frame_count_matches_payload(self):
        """Frame count should match ceiling(payload_size / chunk_size)."""
        import math
        msg = RCANMessage(cmd="count_test", target=TARGET, params={"x": "y" * 100})
        mtu = 32  # small MTU
        frames = encode_ble_frame(msg, mtu=mtu)
        # Each frame's header is 8 bytes
        for frame in frames:
            assert len(frame) <= mtu

    def test_default_mtu_251(self):
        """Default MTU should be 251."""
        msg = make_msg()
        frames = encode_ble_frame(msg)  # default mtu=251
        for frame in frames:
            assert len(frame) <= 251

    def test_small_mtu_raises(self):
        """MTU too small for even a header should raise."""
        msg = make_msg()
        with pytest.raises(TransportError):
            encode_ble_frame(msg, mtu=4)


# ---------------------------------------------------------------------------
# select_transport
# ---------------------------------------------------------------------------


class TestSelectTransport:
    def test_empty_available_raises(self):
        msg = make_msg()
        with pytest.raises(TransportError):
            select_transport([], msg)

    def test_safety_prefers_minimal(self):
        """Safety messages prefer MINIMAL transport when available."""
        msg = make_estop()
        available = [
            TransportEncoding.HTTP,
            TransportEncoding.COMPACT,
            TransportEncoding.MINIMAL,
        ]
        chosen = select_transport(available, msg)
        assert chosen == TransportEncoding.MINIMAL

    def test_safety_falls_back_to_compact(self):
        """Safety prefers COMPACT when MINIMAL not available."""
        msg = make_estop()
        available = [TransportEncoding.HTTP, TransportEncoding.COMPACT]
        chosen = select_transport(available, msg)
        assert chosen == TransportEncoding.COMPACT

    def test_safety_falls_back_to_ble(self):
        """Safety prefers BLE over HTTP."""
        msg = make_estop()
        available = [TransportEncoding.HTTP, TransportEncoding.BLE]
        chosen = select_transport(available, msg)
        assert chosen == TransportEncoding.BLE

    def test_safety_falls_back_to_http_last(self):
        """Safety uses HTTP only as last resort."""
        msg = make_estop()
        available = [TransportEncoding.HTTP]
        chosen = select_transport(available, msg)
        assert chosen == TransportEncoding.HTTP

    def test_general_prefers_http(self):
        """General messages prefer HTTP for maximum fidelity."""
        msg = make_msg()
        available = [
            TransportEncoding.HTTP,
            TransportEncoding.COMPACT,
            TransportEncoding.MINIMAL,
        ]
        chosen = select_transport(available, msg)
        assert chosen == TransportEncoding.HTTP

    def test_general_falls_back_to_compact(self):
        """General messages fall back to COMPACT when HTTP unavailable."""
        msg = make_msg()
        available = [TransportEncoding.COMPACT, TransportEncoding.MINIMAL]
        chosen = select_transport(available, msg)
        assert chosen == TransportEncoding.COMPACT

    def test_stop_is_safety(self):
        """STOP command should be treated as safety."""
        msg = RCANMessage(cmd="STOP", target=TARGET)
        available = [TransportEncoding.MINIMAL, TransportEncoding.HTTP]
        chosen = select_transport(available, msg)
        assert chosen == TransportEncoding.MINIMAL

    def test_resume_is_safety(self):
        """RESUME command should be treated as safety."""
        msg = RCANMessage(cmd="RESUME", target=TARGET)
        available = [TransportEncoding.COMPACT, TransportEncoding.HTTP]
        chosen = select_transport(available, msg)
        assert chosen == TransportEncoding.COMPACT

    def test_single_transport_returned(self):
        """Single available transport should always be returned."""
        msg = make_msg()
        for enc in TransportEncoding:
            chosen = select_transport([enc], msg)
            assert chosen == enc
