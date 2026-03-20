"""Integration tests for RCAN non-HTTP transport layer."""
import json

import pytest

from rcan import RCANMessage
from rcan.transport import (
    TransportEncoding,
    TransportNegotiation,
    decode_ble_frames,
    decode_compact,
    decode_minimal,
    encode_ble_frame,
    encode_compact,
    encode_minimal,
    select_transport,
)

_TARGET = "rcan://opencastor.com/acme/bot/v1/x01"


def _make_msg(**kwargs):
    defaults = {"cmd": "navigate", "target": _TARGET}
    defaults.update(kwargs)
    return RCANMessage(**defaults)


def _make_estop():
    return RCANMessage(cmd="ESTOP", target=_TARGET)


# ── Compact encoding ─────────────────────────────────────────────────────


class TestCompactEncoding:
    def test_roundtrip(self):
        msg = _make_msg()
        payload = encode_compact(msg)
        recovered = decode_compact(payload)
        assert recovered.cmd == msg.cmd

    def test_smaller_than_json(self):
        msg = _make_msg()
        compact = encode_compact(msg)
        json_bytes = json.dumps(msg.to_dict()).encode()
        assert len(compact) < len(json_bytes)

    def test_preserves_target(self):
        msg = _make_msg()
        recovered = decode_compact(encode_compact(msg))
        assert str(recovered.target) == _TARGET


# ── Minimal (ESTOP) encoding ─────────────────────────────────────────────


class TestMinimalEncoding:
    def test_estop_size(self):
        msg = _make_estop()
        raw = encode_minimal(msg)
        # Minimal is a fixed-size binary frame (40 bytes in current impl)
        assert len(raw) <= 64, f"Minimal should fit in single BLE frame, got {len(raw)}"

    def test_estop_decode_is_safety(self):
        msg = _make_estop()
        raw = encode_minimal(msg)
        decoded = decode_minimal(raw)
        assert decoded.get("is_safety") is True

    def test_estop_checksum_ok(self):
        msg = _make_estop()
        raw = encode_minimal(msg)
        decoded = decode_minimal(raw)
        assert decoded.get("checksum_ok") is True

    def test_estop_deterministic(self):
        msg = _make_estop()
        d1 = decode_minimal(encode_minimal(msg))
        d2 = decode_minimal(encode_minimal(msg))
        assert d1["is_safety"] == d2["is_safety"]


# ── Encoding size comparison ─────────────────────────────────────────────


class TestEncodingSizes:
    def test_compact_vs_json(self):
        msg = _make_msg()
        json_size = len(json.dumps(msg.to_dict()).encode())
        compact_size = len(encode_compact(msg))
        estop_size = len(encode_minimal(_make_estop()))

        assert compact_size < json_size
        assert estop_size <= 64


# ── Transport negotiation + selection ────────────────────────────────────


class TestTransportNegotiation:
    def test_enum_values(self):
        assert TransportEncoding.HTTP is not None
        assert TransportEncoding.COMPACT is not None
        assert TransportEncoding.MINIMAL is not None
        assert TransportEncoding.BLE is not None

    def test_negotiation_common(self):
        a = TransportNegotiation(
            supported=[TransportEncoding.HTTP, TransportEncoding.COMPACT],
            preferred=TransportEncoding.COMPACT,
        )
        b = TransportNegotiation(
            supported=[TransportEncoding.HTTP],
            preferred=TransportEncoding.HTTP,
        )
        common = [e for e in a.supported if e in b.supported]
        assert TransportEncoding.HTTP in common

    def test_select_transport_normal(self):
        msg = _make_msg()
        result = select_transport(
            [TransportEncoding.HTTP, TransportEncoding.COMPACT], msg
        )
        # For non-safety messages, prefers efficient transport
        assert result in (TransportEncoding.HTTP, TransportEncoding.COMPACT)

    def test_select_transport_estop_prefers_minimal(self):
        msg = _make_estop()
        result = select_transport(
            [TransportEncoding.HTTP, TransportEncoding.COMPACT, TransportEncoding.MINIMAL],
            msg,
        )
        assert result == TransportEncoding.MINIMAL


# ── BLE frames ───────────────────────────────────────────────────────────


class TestBLEFrames:
    def test_frames_fit_mtu(self):
        msg = _make_msg()
        frames = encode_ble_frame(msg, mtu=244)
        assert all(len(f) <= 244 for f in frames)

    def test_roundtrip(self):
        msg = _make_msg()
        frames = encode_ble_frame(msg, mtu=244)
        recovered = decode_ble_frames(frames)
        assert recovered.cmd == msg.cmd


# ── Contribute message types (v1.7) ──────────────────────────────────────


class TestContributeMessages:
    def test_contribute_message_types_exist(self):
        from rcan.message import MessageType

        assert MessageType.CONTRIBUTE_REQUEST == 33
        assert MessageType.CONTRIBUTE_RESULT == 34
        assert MessageType.CONTRIBUTE_CANCEL == 35

    def test_contribute_scope_in_field_map(self):
        from rcan.identity import _SCOPE_FIELD_MAP

        assert "contribute" in _SCOPE_FIELD_MAP
