"""
rcan.multimodal — Multi-Modal Payload Support (GAP-18).

Enables RCAN messages to carry inline or referenced media chunks
(images, audio, video, sensor data). Provides streaming chunk helpers
for incremental media delivery.

Size limit: inline media chunks must be ≤ 64 KB. Use REF mode for larger.

Spec: §19 — Multi-Modal Payloads
"""

from __future__ import annotations

import base64
import hashlib
import logging
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

log = logging.getLogger(__name__)

# 64 KB inline size limit
INLINE_MAX_BYTES: int = 64 * 1024


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class MediaSizeError(Exception):
    """Raised when inline media exceeds the 64 KB limit."""


# ---------------------------------------------------------------------------
# Enums / dataclasses
# ---------------------------------------------------------------------------


class MediaEncoding(str, Enum):
    """How the media data is stored in the chunk."""

    BASE64 = "base64"  # Inline base64-encoded bytes
    REF = "ref"  # External reference URL


@dataclass
class MediaChunk:
    """A single unit of media data attached to an RCAN message.

    Attributes:
        chunk_id:    Unique identifier for this chunk.
        mime_type:   MIME type (e.g. ``"image/jpeg"``, ``"audio/wav"``).
        encoding:    Storage encoding: ``BASE64`` for inline, ``REF`` for URL.
        hash_sha256: Hex-encoded SHA-256 of the raw (decoded) bytes.
        data_b64:    Base64-encoded data (only when encoding=BASE64).
        ref_url:     URL to fetch data from (only when encoding=REF).
        size_bytes:  Byte size of the raw (decoded) data.
    """

    chunk_id: str
    mime_type: str
    encoding: MediaEncoding
    hash_sha256: str
    size_bytes: int
    data_b64: Optional[str] = None
    ref_url: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "chunk_id": self.chunk_id,
            "mime_type": self.mime_type,
            "encoding": self.encoding.value,
            "hash_sha256": self.hash_sha256,
            "size_bytes": self.size_bytes,
        }
        if self.data_b64 is not None:
            d["data_b64"] = self.data_b64
        if self.ref_url is not None:
            d["ref_url"] = self.ref_url
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MediaChunk":
        return cls(
            chunk_id=data["chunk_id"],
            mime_type=data["mime_type"],
            encoding=MediaEncoding(data.get("encoding", "base64")),
            hash_sha256=data["hash_sha256"],
            size_bytes=data.get("size_bytes", 0),
            data_b64=data.get("data_b64"),
            ref_url=data.get("ref_url"),
        )


@dataclass
class StreamChunk:
    """A single chunk in an incremental media stream.

    Attributes:
        stream_id:    Identifier for the stream (shared across all chunks).
        chunk_index:  Zero-based index of this chunk within the stream.
        is_final:     True if this is the last chunk in the stream.
        chunk:        The :class:`MediaChunk` carrying the data.
    """

    stream_id: str
    chunk_index: int
    is_final: bool
    chunk: MediaChunk


# ---------------------------------------------------------------------------
# Media attachment helpers
# ---------------------------------------------------------------------------


def add_media_inline(message: Any, data: bytes, mime_type: str) -> Any:
    """Attach inline media to a message.

    Computes SHA-256 of *data*, base64-encodes it, creates a
    :class:`MediaChunk`, and appends it to ``message.media_chunks``.

    Args:
        message:   :class:`~rcan.message.RCANMessage` to attach media to.
        data:      Raw bytes of the media.
        mime_type: MIME type string (e.g. ``"image/jpeg"``).

    Returns:
        The modified message (mutated in place and returned).

    Raises:
        MediaSizeError: If *data* exceeds 64 KB.
    """
    if len(data) > INLINE_MAX_BYTES:
        raise MediaSizeError(
            f"Inline media size {len(data):,} bytes exceeds the 64 KB limit "
            f"({INLINE_MAX_BYTES:,} bytes). Use add_media_ref() for larger payloads."
        )

    sha256 = hashlib.sha256(data).hexdigest()
    data_b64 = base64.b64encode(data).decode("ascii")
    chunk = MediaChunk(
        chunk_id=str(uuid.uuid4()),
        mime_type=mime_type,
        encoding=MediaEncoding.BASE64,
        hash_sha256=sha256,
        size_bytes=len(data),
        data_b64=data_b64,
    )
    message.media_chunks.append(chunk)
    log.debug(
        "add_media_inline: attached %d-byte %s chunk (sha256=%s…)",
        len(data),
        mime_type,
        sha256[:8],
    )
    return message


def add_media_ref(
    message: Any,
    ref_url: str,
    mime_type: str,
    hash_sha256: str,
    size_bytes: int,
) -> Any:
    """Attach an external media reference to a message.

    The data itself is not transmitted inline; the receiver must fetch it
    from *ref_url* and verify the SHA-256 hash.

    Args:
        message:     :class:`~rcan.message.RCANMessage` to attach to.
        ref_url:     URL where the media can be fetched.
        mime_type:   MIME type string.
        hash_sha256: Hex-encoded SHA-256 of the media bytes at *ref_url*.
        size_bytes:  Byte size of the media.

    Returns:
        The modified message (mutated in place and returned).
    """
    chunk = MediaChunk(
        chunk_id=str(uuid.uuid4()),
        mime_type=mime_type,
        encoding=MediaEncoding.REF,
        hash_sha256=hash_sha256,
        size_bytes=size_bytes,
        ref_url=ref_url,
    )
    message.media_chunks.append(chunk)
    log.debug(
        "add_media_ref: attached ref chunk %s (size=%d, sha256=%s…)",
        ref_url,
        size_bytes,
        hash_sha256[:8],
    )
    return message


def validate_media_chunks(message: Any) -> tuple[bool, str]:
    """Validate the integrity of all media chunks on *message*.

    - **Inline chunks** (BASE64): recompute SHA-256 from ``data_b64``
      and compare to ``hash_sha256``.
    - **Ref chunks** (REF): verify ``hash_sha256`` is a valid 64-char
      hex string.

    Args:
        message: :class:`~rcan.message.RCANMessage` with ``media_chunks``.

    Returns:
        ``(valid: bool, reason: str)`` — reason is ``"ok"`` on success.
    """
    chunks: list[MediaChunk] = getattr(message, "media_chunks", [])
    for idx, chunk in enumerate(chunks):
        if chunk.encoding == MediaEncoding.BASE64:
            if chunk.data_b64 is None:
                return (
                    False,
                    f"Chunk {idx} ({chunk.chunk_id}): data_b64 is None for inline chunk",
                )
            try:
                raw = base64.b64decode(chunk.data_b64)
            except Exception as exc:  # noqa: BLE001
                return False, f"Chunk {idx} ({chunk.chunk_id}): invalid base64: {exc}"
            actual_hash = hashlib.sha256(raw).hexdigest()
            if actual_hash != chunk.hash_sha256:
                return False, (
                    f"Chunk {idx} ({chunk.chunk_id}): SHA-256 mismatch "
                    f"(stored={chunk.hash_sha256!r}, actual={actual_hash!r})"
                )
        elif chunk.encoding == MediaEncoding.REF:
            if len(chunk.hash_sha256) != 64:
                return False, (
                    f"Chunk {idx} ({chunk.chunk_id}): hash_sha256 must be "
                    f"64 hex chars, got {len(chunk.hash_sha256)}"
                )
            if not all(c in "0123456789abcdefABCDEF" for c in chunk.hash_sha256):
                return False, (
                    f"Chunk {idx} ({chunk.chunk_id}): hash_sha256 contains "
                    f"non-hex characters"
                )
    return True, "ok"


# ---------------------------------------------------------------------------
# Message builders
# ---------------------------------------------------------------------------


def make_training_data_message(
    media: list[tuple[bytes, str]],
    target_uri: str = "rcan://rcan.dev/system/training/v1/local",
) -> Any:
    """Build a TRAINING_DATA :class:`~rcan.message.RCANMessage` with all
    media attached as inline chunks.

    Args:
        media:      List of ``(raw_bytes, mime_type)`` tuples.
        target_uri: RCAN URI to address the message to.

    Returns:
        :class:`~rcan.message.RCANMessage` with ``cmd="TRAINING_DATA"``
        and all media chunks attached.

    Raises:
        MediaSizeError: If any individual item exceeds 64 KB.
    """
    from rcan.message import RCANMessage

    msg = RCANMessage(
        cmd="TRAINING_DATA",
        target=target_uri,
        params={"media_count": len(media)},
    )
    for raw, mime_type in media:
        add_media_inline(msg, raw, mime_type)
    log.debug(
        "make_training_data_message: created message with %d media chunks", len(media)
    )
    return msg


def make_stream_chunk(
    stream_id: str,
    data: bytes,
    mime_type: str,
    chunk_index: int,
    is_final: bool,
    target_uri: str = "rcan://rcan.dev/system/stream/v1/local",
) -> Any:
    """Build a STREAM_CHUNK :class:`~rcan.message.RCANMessage`.

    Inline media must be ≤ 64 KB per chunk. Split larger streams into
    multiple calls.

    Args:
        stream_id:    Shared identifier for this stream.
        data:         Raw bytes for this chunk.
        mime_type:    MIME type of the data.
        chunk_index:  Zero-based index within the stream.
        is_final:     True if this is the last chunk.
        target_uri:   RCAN URI to address the message to.

    Returns:
        :class:`~rcan.message.RCANMessage` with ``cmd="STREAM_CHUNK"``
        and the media chunk attached.
    """
    from rcan.message import RCANMessage

    media_chunk = MediaChunk(
        chunk_id=str(uuid.uuid4()),
        mime_type=mime_type,
        encoding=MediaEncoding.BASE64,
        hash_sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        data_b64=base64.b64encode(data).decode("ascii"),
    )
    stream_chunk = StreamChunk(
        stream_id=stream_id,
        chunk_index=chunk_index,
        is_final=is_final,
        chunk=media_chunk,
    )
    msg = RCANMessage(
        cmd="STREAM_CHUNK",
        target=target_uri,
        params={
            "stream_id": stream_id,
            "chunk_index": chunk_index,
            "is_final": is_final,
        },
    )
    msg.media_chunks.append(media_chunk)
    log.debug(
        "make_stream_chunk: stream=%s index=%d final=%s size=%d",
        stream_id,
        chunk_index,
        is_final,
        len(data),
    )
    return msg


__all__ = [
    "MediaEncoding",
    "MediaChunk",
    "StreamChunk",
    "MediaSizeError",
    "INLINE_MAX_BYTES",
    "add_media_inline",
    "add_media_ref",
    "validate_media_chunks",
    "make_training_data_message",
    "make_stream_chunk",
]
