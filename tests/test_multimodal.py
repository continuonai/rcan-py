"""Tests for rcan.multimodal — Multi-Modal Payloads (GAP-18)."""

from __future__ import annotations

import base64
import hashlib

import pytest

from rcan.message import RCANMessage
from rcan.multimodal import (
    INLINE_MAX_BYTES,
    MediaChunk,
    MediaEncoding,
    MediaSizeError,
    StreamChunk,
    add_media_inline,
    add_media_ref,
    make_stream_chunk,
    make_training_data_message,
    validate_media_chunks,
)

TARGET = "rcan://rcan.dev/acme/bot/v1/unit-001"


def base_msg() -> RCANMessage:
    return RCANMessage(cmd="test", target=TARGET)


# ---------------------------------------------------------------------------
# MediaEncoding enum
# ---------------------------------------------------------------------------


class TestMediaEncoding:
    def test_values(self):
        assert MediaEncoding.BASE64.value == "base64"
        assert MediaEncoding.REF.value == "ref"


# ---------------------------------------------------------------------------
# MediaChunk
# ---------------------------------------------------------------------------


class TestMediaChunk:
    def test_construction_inline(self):
        chunk = MediaChunk(
            chunk_id="c1",
            mime_type="image/jpeg",
            encoding=MediaEncoding.BASE64,
            hash_sha256="a" * 64,
            size_bytes=100,
            data_b64="ZGF0YQ==",
        )
        assert chunk.chunk_id == "c1"
        assert chunk.encoding == MediaEncoding.BASE64

    def test_to_dict_roundtrip(self):
        chunk = MediaChunk(
            chunk_id="c2",
            mime_type="audio/wav",
            encoding=MediaEncoding.REF,
            hash_sha256="b" * 64,
            size_bytes=5000,
            ref_url="https://example.com/audio.wav",
        )
        d = chunk.to_dict()
        c2 = MediaChunk.from_dict(d)
        assert c2.chunk_id == "c2"
        assert c2.encoding == MediaEncoding.REF
        assert c2.ref_url == "https://example.com/audio.wav"

    def test_optional_fields_absent_in_dict(self):
        chunk = MediaChunk(
            chunk_id="c3",
            mime_type="image/png",
            encoding=MediaEncoding.BASE64,
            hash_sha256="c" * 64,
            size_bytes=50,
        )
        d = chunk.to_dict()
        assert "ref_url" not in d
        assert "data_b64" not in d


# ---------------------------------------------------------------------------
# add_media_inline
# ---------------------------------------------------------------------------


class TestAddMediaInline:
    def test_adds_chunk(self):
        msg = base_msg()
        data = b"hello world"
        msg = add_media_inline(msg, data, "text/plain")
        assert len(msg.media_chunks) == 1

    def test_chunk_mime_type(self):
        msg = base_msg()
        add_media_inline(msg, b"data", "image/jpeg")
        assert msg.media_chunks[0].mime_type == "image/jpeg"

    def test_chunk_encoding_is_base64(self):
        msg = base_msg()
        add_media_inline(msg, b"data", "image/jpeg")
        assert msg.media_chunks[0].encoding == MediaEncoding.BASE64

    def test_chunk_data_b64_correct(self):
        msg = base_msg()
        raw = b"\x00\x01\x02\x03"
        add_media_inline(msg, raw, "application/octet-stream")
        expected = base64.b64encode(raw).decode("ascii")
        assert msg.media_chunks[0].data_b64 == expected

    def test_chunk_sha256_correct(self):
        msg = base_msg()
        raw = b"test data"
        add_media_inline(msg, raw, "text/plain")
        expected = hashlib.sha256(raw).hexdigest()
        assert msg.media_chunks[0].hash_sha256 == expected

    def test_chunk_size_bytes(self):
        msg = base_msg()
        raw = b"x" * 1234
        add_media_inline(msg, raw, "text/plain")
        assert msg.media_chunks[0].size_bytes == 1234

    def test_multiple_chunks(self):
        msg = base_msg()
        add_media_inline(msg, b"a", "text/plain")
        add_media_inline(msg, b"b", "image/png")
        assert len(msg.media_chunks) == 2

    def test_size_limit_64kb(self):
        """Data exactly at the limit should be accepted."""
        msg = base_msg()
        data = b"x" * INLINE_MAX_BYTES
        add_media_inline(msg, data, "application/octet-stream")  # should not raise

    def test_size_limit_exceeded(self):
        """Data exceeding 64 KB should raise MediaSizeError."""
        msg = base_msg()
        data = b"x" * (INLINE_MAX_BYTES + 1)
        with pytest.raises(MediaSizeError):
            add_media_inline(msg, data, "application/octet-stream")

    def test_returns_message(self):
        """add_media_inline should return the message for chaining."""
        msg = base_msg()
        result = add_media_inline(msg, b"data", "text/plain")
        assert result is msg


# ---------------------------------------------------------------------------
# add_media_ref
# ---------------------------------------------------------------------------


class TestAddMediaRef:
    def test_adds_ref_chunk(self):
        msg = base_msg()
        add_media_ref(
            msg,
            ref_url="https://example.com/video.mp4",
            mime_type="video/mp4",
            hash_sha256="a" * 64,
            size_bytes=1024 * 1024,
        )
        assert len(msg.media_chunks) == 1
        assert msg.media_chunks[0].encoding == MediaEncoding.REF

    def test_ref_url_stored(self):
        msg = base_msg()
        url = "https://example.com/image.png"
        add_media_ref(msg, url, "image/png", "b" * 64, 5000)
        assert msg.media_chunks[0].ref_url == url

    def test_no_data_b64_for_ref(self):
        msg = base_msg()
        add_media_ref(msg, "https://example.com/f", "video/mp4", "c" * 64, 100)
        assert msg.media_chunks[0].data_b64 is None

    def test_returns_message(self):
        msg = base_msg()
        result = add_media_ref(msg, "https://ex.com/f", "text/plain", "d" * 64, 10)
        assert result is msg

    def test_no_size_limit_for_ref(self):
        """REF mode has no size limit."""
        msg = base_msg()
        add_media_ref(
            msg, "https://example.com/bigfile", "video/mp4",
            "e" * 64, 10 * 1024 * 1024 * 1024  # 10 GB
        )  # should not raise


# ---------------------------------------------------------------------------
# validate_media_chunks
# ---------------------------------------------------------------------------


class TestValidateMediaChunks:
    def test_valid_inline_chunk(self):
        msg = base_msg()
        add_media_inline(msg, b"hello", "text/plain")
        valid, reason = validate_media_chunks(msg)
        assert valid
        assert reason == "ok"

    def test_invalid_hash(self):
        msg = base_msg()
        add_media_inline(msg, b"hello", "text/plain")
        # Corrupt the stored hash
        msg.media_chunks[0].hash_sha256 = "0" * 64
        valid, reason = validate_media_chunks(msg)
        assert not valid
        assert "sha-256" in reason.lower() or "mismatch" in reason.lower()

    def test_invalid_base64_data(self):
        msg = base_msg()
        add_media_inline(msg, b"hello", "text/plain")
        msg.media_chunks[0].data_b64 = "!!! invalid base64 !!!"
        valid, reason = validate_media_chunks(msg)
        assert not valid

    def test_none_data_b64_inline(self):
        msg = base_msg()
        chunk = MediaChunk(
            chunk_id="bad",
            mime_type="text/plain",
            encoding=MediaEncoding.BASE64,
            hash_sha256="a" * 64,
            size_bytes=5,
            data_b64=None,  # Missing!
        )
        msg.media_chunks.append(chunk)
        valid, reason = validate_media_chunks(msg)
        assert not valid

    def test_valid_ref_chunk(self):
        msg = base_msg()
        add_media_ref(msg, "https://example.com/f", "video/mp4", "a" * 64, 100)
        valid, reason = validate_media_chunks(msg)
        assert valid

    def test_invalid_ref_hash_too_short(self):
        msg = base_msg()
        add_media_ref(msg, "https://example.com/f", "video/mp4", "abc", 100)
        valid, reason = validate_media_chunks(msg)
        assert not valid
        assert "64" in reason

    def test_invalid_ref_hash_non_hex(self):
        msg = base_msg()
        add_media_ref(msg, "https://example.com/f", "video/mp4", "z" * 64, 100)
        valid, reason = validate_media_chunks(msg)
        assert not valid
        assert "hex" in reason.lower()

    def test_empty_chunks_valid(self):
        msg = base_msg()
        valid, reason = validate_media_chunks(msg)
        assert valid
        assert reason == "ok"

    def test_multiple_valid_chunks(self):
        msg = base_msg()
        add_media_inline(msg, b"img1", "image/jpeg")
        add_media_inline(msg, b"img2", "image/png")
        add_media_ref(msg, "https://example.com/v", "video/mp4", "f" * 64, 9999)
        valid, _ = validate_media_chunks(msg)
        assert valid

    def test_mixed_valid_and_invalid(self):
        msg = base_msg()
        add_media_inline(msg, b"good", "text/plain")  # valid
        add_media_ref(msg, "https://example.com/f", "video/mp4", "bad", 100)  # invalid hash
        valid, _ = validate_media_chunks(msg)
        assert not valid


# ---------------------------------------------------------------------------
# make_training_data_message
# ---------------------------------------------------------------------------


class TestMakeTrainingDataMessage:
    def test_returns_rcan_message(self):
        msg = make_training_data_message([(b"frame1", "image/jpeg")])
        assert isinstance(msg, RCANMessage)

    def test_cmd_is_training_data(self):
        msg = make_training_data_message([])
        assert msg.cmd == "TRAINING_DATA"

    def test_media_attached(self):
        msg = make_training_data_message([
            (b"frame1", "image/jpeg"),
            (b"frame2", "image/jpeg"),
        ])
        assert len(msg.media_chunks) == 2

    def test_media_encoding_base64(self):
        msg = make_training_data_message([(b"data", "image/png")])
        assert msg.media_chunks[0].encoding == MediaEncoding.BASE64

    def test_media_count_in_params(self):
        msg = make_training_data_message([
            (b"a", "image/jpeg"),
            (b"b", "audio/wav"),
        ])
        assert msg.params["media_count"] == 2

    def test_empty_media_list(self):
        msg = make_training_data_message([])
        assert len(msg.media_chunks) == 0
        assert msg.params["media_count"] == 0

    def test_size_limit_enforced(self):
        """Individual items over 64 KB should raise MediaSizeError."""
        big = b"x" * (INLINE_MAX_BYTES + 1)
        with pytest.raises(MediaSizeError):
            make_training_data_message([(big, "application/octet-stream")])

    def test_custom_target_uri(self):
        msg = make_training_data_message(
            [],
            target_uri="rcan://rcan.dev/acme/bot/v1/unit-999",
        )
        assert "unit-999" in str(msg.target)

    def test_hash_correctness(self):
        raw = b"pixel data"
        msg = make_training_data_message([(raw, "image/jpeg")])
        expected_hash = hashlib.sha256(raw).hexdigest()
        assert msg.media_chunks[0].hash_sha256 == expected_hash


# ---------------------------------------------------------------------------
# make_stream_chunk
# ---------------------------------------------------------------------------


class TestMakeStreamChunk:
    def test_returns_rcan_message(self):
        msg = make_stream_chunk("stream-1", b"data", "image/jpeg", 0, False)
        assert isinstance(msg, RCANMessage)

    def test_cmd_is_stream_chunk(self):
        msg = make_stream_chunk("stream-1", b"data", "image/jpeg", 0, False)
        assert msg.cmd == "STREAM_CHUNK"

    def test_params_contain_stream_id(self):
        msg = make_stream_chunk("my-stream", b"data", "image/jpeg", 0, False)
        assert msg.params["stream_id"] == "my-stream"

    def test_params_chunk_index(self):
        msg = make_stream_chunk("s", b"d", "image/jpeg", 5, False)
        assert msg.params["chunk_index"] == 5

    def test_params_is_final(self):
        msg = make_stream_chunk("s", b"d", "image/jpeg", 0, True)
        assert msg.params["is_final"] is True

    def test_media_chunk_attached(self):
        msg = make_stream_chunk("s", b"hello", "text/plain", 0, False)
        assert len(msg.media_chunks) == 1

    def test_media_chunk_hash(self):
        raw = b"chunk data"
        msg = make_stream_chunk("s", raw, "application/octet-stream", 0, True)
        expected = hashlib.sha256(raw).hexdigest()
        assert msg.media_chunks[0].hash_sha256 == expected

    def test_stream_chunk_object(self):
        """verify StreamChunk dataclass can be constructed."""
        raw = b"test"
        chunk = MediaChunk(
            chunk_id="c1",
            mime_type="image/jpeg",
            encoding=MediaEncoding.BASE64,
            hash_sha256=hashlib.sha256(raw).hexdigest(),
            size_bytes=len(raw),
            data_b64=base64.b64encode(raw).decode(),
        )
        sc = StreamChunk(
            stream_id="stream-xyz",
            chunk_index=3,
            is_final=True,
            chunk=chunk,
        )
        assert sc.stream_id == "stream-xyz"
        assert sc.chunk_index == 3
        assert sc.is_final is True
        assert sc.chunk.mime_type == "image/jpeg"
