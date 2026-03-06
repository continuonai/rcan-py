"""Tests for rcan.exceptions hierarchy."""

from __future__ import annotations

import pytest

from rcan.exceptions import (
    RCANError,
    RCANAddressError,
    RCANValidationError,
    RCANGateError,
    RCANSignatureError,
    RCANRegistryError,
    RCANTimeoutError,
)


# ---------------------------------------------------------------------------
# Base hierarchy
# ---------------------------------------------------------------------------


def test_rcan_error_is_exception():
    with pytest.raises(RCANError):
        raise RCANError("base error")


def test_all_subclass_rcan_error():
    for cls in (
        RCANAddressError,
        RCANValidationError,
        RCANGateError,
        RCANSignatureError,
        RCANRegistryError,
        RCANTimeoutError,
    ):
        assert issubclass(cls, RCANError), f"{cls} not subclass of RCANError"


# ---------------------------------------------------------------------------
# Each exception can be raised and caught
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc_cls,args",
    [
        (RCANAddressError, ("bad address",)),
        (RCANValidationError, ("invalid message",)),
        (RCANSignatureError, ("bad sig",)),
        (RCANRegistryError, ("registry down",)),
        (RCANTimeoutError, ("timed out",)),
    ],
)
def test_each_exception_raise_catch(exc_cls, args):
    with pytest.raises(exc_cls):
        raise exc_cls(*args)


def test_catch_as_rcan_error():
    for cls in (
        RCANAddressError,
        RCANValidationError,
        RCANSignatureError,
        RCANRegistryError,
        RCANTimeoutError,
    ):
        with pytest.raises(RCANError):
            raise cls("msg")


# ---------------------------------------------------------------------------
# RCANGateError attributes
# ---------------------------------------------------------------------------


def test_gate_error_full_attrs():
    exc = RCANGateError("blocked", gate_type="confidence", value=0.4, threshold=0.8)
    assert exc.gate_type == "confidence"
    assert exc.value == pytest.approx(0.4)
    assert exc.threshold == pytest.approx(0.8)
    assert str(exc) == "blocked"


def test_gate_error_defaults():
    exc = RCANGateError("blocked")
    assert exc.gate_type == "unknown"
    assert exc.value is None
    assert exc.threshold is None


def test_gate_error_is_rcan_error():
    with pytest.raises(RCANError):
        raise RCANGateError("gate fired", gate_type="hitl")


# ---------------------------------------------------------------------------
# str() / repr() includes the message
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc_cls,msg",
    [
        (RCANError, "hello error"),
        (RCANAddressError, "bad ruri"),
        (RCANValidationError, "schema mismatch"),
        (RCANSignatureError, "sig invalid"),
        (RCANRegistryError, "registry 500"),
        (RCANTimeoutError, "deadline exceeded"),
    ],
)
def test_str_includes_message(exc_cls, msg):
    exc = exc_cls(msg)
    assert msg in str(exc)


def test_gate_error_str_includes_message():
    exc = RCANGateError("gate blocked command", gate_type="confidence")
    assert "gate blocked command" in str(exc)
