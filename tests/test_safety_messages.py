"""
Tests for rcan.safety — RCAN Safety Message helpers (MessageType 6).
"""

from __future__ import annotations

import re
import time

import pytest

from rcan.safety import (
    SAFETY_MESSAGE_TYPE,
    is_safety_message,
    make_estop_message,
    make_resume_message,
    make_stop_message,
    validate_safety_message,
)

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

_SAMPLE_RURI = "rcan://rcan.dev/boston-dynamics/spot/bd-spot-001a2b3c"
_SAMPLE_REASON = "Unit test safety check"


# ---------------------------------------------------------------------------
# make_estop_message
# ---------------------------------------------------------------------------


def test_make_estop_message():
    """Creates a valid ESTOP message with message_type=6."""
    msg = make_estop_message(_SAMPLE_RURI, _SAMPLE_REASON)
    assert msg["message_type"] == 6
    assert msg["safety_event"] == "ESTOP"
    assert msg["ruri"] == _SAMPLE_RURI
    assert msg["reason"] == _SAMPLE_REASON


# ---------------------------------------------------------------------------
# make_stop_message
# ---------------------------------------------------------------------------


def test_make_stop_message():
    """Creates a valid STOP message with message_type=6."""
    msg = make_stop_message(_SAMPLE_RURI, _SAMPLE_REASON)
    assert msg["message_type"] == 6
    assert msg["safety_event"] == "STOP"
    assert msg["ruri"] == _SAMPLE_RURI


# ---------------------------------------------------------------------------
# make_resume_message
# ---------------------------------------------------------------------------


def test_make_resume_message():
    """Creates a valid RESUME message with message_type=6."""
    msg = make_resume_message(_SAMPLE_RURI, _SAMPLE_REASON)
    assert msg["message_type"] == 6
    assert msg["safety_event"] == "RESUME"
    assert msg["ruri"] == _SAMPLE_RURI


# ---------------------------------------------------------------------------
# message_id is UUID4
# ---------------------------------------------------------------------------


def test_message_id_is_uuid4():
    """message_id field matches the UUID4 format."""
    for factory in (make_estop_message, make_stop_message, make_resume_message):
        msg = factory(_SAMPLE_RURI, _SAMPLE_REASON)
        assert _UUID4_RE.match(msg["message_id"]), (
            f"{factory.__name__} produced non-UUID4 message_id: {msg['message_id']!r}"
        )


# ---------------------------------------------------------------------------
# reason truncation
# ---------------------------------------------------------------------------


def test_reason_truncated_at_512():
    """Reason strings longer than 512 chars are truncated to exactly 512."""
    long_reason = "x" * 600
    for factory in (make_estop_message, make_stop_message, make_resume_message):
        msg = factory(_SAMPLE_RURI, long_reason)
        assert len(msg["reason"]) == 512, (
            f"{factory.__name__} did not truncate reason to 512 chars"
        )


# ---------------------------------------------------------------------------
# timestamp_ms is a positive integer
# ---------------------------------------------------------------------------


def test_timestamp_ms_is_int():
    """timestamp_ms is a positive integer representing ms since epoch."""
    before = int(time.time() * 1000)
    msg = make_estop_message(_SAMPLE_RURI, _SAMPLE_REASON)
    after = int(time.time() * 1000)

    assert isinstance(msg["timestamp_ms"], int)
    assert msg["timestamp_ms"] > 0
    assert before <= msg["timestamp_ms"] <= after


# ---------------------------------------------------------------------------
# is_safety_message
# ---------------------------------------------------------------------------


def test_is_safety_message():
    """Returns True for message_type=6, False for other types."""
    assert is_safety_message({"message_type": 6}) is True
    assert is_safety_message({"message_type": 1}) is False
    assert is_safety_message({"message_type": 0}) is False
    assert is_safety_message({}) is False

    # All three safety factories should produce safety messages
    for factory in (make_estop_message, make_stop_message, make_resume_message):
        assert is_safety_message(factory(_SAMPLE_RURI, _SAMPLE_REASON)) is True


# ---------------------------------------------------------------------------
# validate_safety_message — valid message
# ---------------------------------------------------------------------------


def test_validate_safety_message_valid():
    """A well-formed safety message returns an empty error list."""
    msg = make_estop_message(_SAMPLE_RURI, _SAMPLE_REASON)
    errors = validate_safety_message(msg)
    assert errors == [], f"Expected no errors, got: {errors}"


# ---------------------------------------------------------------------------
# validate_safety_message — missing reason
# ---------------------------------------------------------------------------


def test_validate_safety_message_missing_reason():
    """A message with missing reason field returns at least one error."""
    msg = make_estop_message(_SAMPLE_RURI, _SAMPLE_REASON)
    del msg["reason"]
    errors = validate_safety_message(msg)
    assert len(errors) >= 1
    assert any("reason" in e.lower() for e in errors), (
        f"Expected an error mentioning 'reason', got: {errors}"
    )


# ---------------------------------------------------------------------------
# Additional coverage
# ---------------------------------------------------------------------------


def test_validate_safety_message_wrong_type():
    """Wrong message_type produces a validation error."""
    msg = make_estop_message(_SAMPLE_RURI, _SAMPLE_REASON)
    msg["message_type"] = 1
    errors = validate_safety_message(msg)
    assert any("message_type" in e for e in errors)


def test_validate_safety_message_invalid_event():
    """Unknown safety_event produces a validation error."""
    msg = make_estop_message(_SAMPLE_RURI, _SAMPLE_REASON)
    msg["safety_event"] = "LAUNCH"
    errors = validate_safety_message(msg)
    assert any("safety_event" in e for e in errors)


def test_validate_safety_message_missing_ruri():
    """Missing ruri produces a validation error."""
    msg = make_estop_message(_SAMPLE_RURI, _SAMPLE_REASON)
    del msg["ruri"]
    errors = validate_safety_message(msg)
    assert any("ruri" in e for e in errors)


def test_safety_message_type_constant():
    """SAFETY_MESSAGE_TYPE constant equals 6."""
    assert SAFETY_MESSAGE_TYPE == 6
