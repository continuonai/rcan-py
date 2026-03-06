"""Tests for rcan.message — RCANMessage and RCANResponse."""

import json
import pytest
from rcan import RCANMessage, RCANResponse, RobotURI
from rcan.exceptions import RCANValidationError

TARGET = "rcan://registry.rcan.dev/acme/arm/v1/unit-001"


def make_msg(**kwargs) -> RCANMessage:
    return RCANMessage(cmd="move_forward", target=TARGET, **kwargs)


# ---------------------------------------------------------------------------
# RCANMessage
# ---------------------------------------------------------------------------

def test_basic_construction():
    msg = make_msg(params={"distance_m": 1.0}, confidence=0.9)
    assert msg.cmd == "move_forward"
    assert isinstance(msg.target, RobotURI)
    assert msg.confidence == 0.9


def test_target_string_parsed():
    msg = make_msg()
    assert isinstance(msg.target, RobotURI)
    assert str(msg.target) == TARGET


def test_target_uri_accepted():
    uri = RobotURI.parse(TARGET)
    msg = RCANMessage(cmd="stop", target=uri)
    assert msg.target is uri


def test_invalid_confidence_high():
    with pytest.raises(RCANValidationError):
        make_msg(confidence=1.5)


def test_invalid_confidence_low():
    with pytest.raises(RCANValidationError):
        make_msg(confidence=-0.1)


def test_empty_cmd():
    with pytest.raises(RCANValidationError):
        RCANMessage(cmd="", target=TARGET)


def test_to_dict_required_fields():
    msg = make_msg()
    d = msg.to_dict()
    assert d["cmd"] == "move_forward"
    assert d["target"] == TARGET
    assert "rcan" in d
    assert "msg_id" in d
    assert "timestamp" in d


def test_to_dict_optional_fields_absent():
    msg = make_msg()
    d = msg.to_dict()
    assert "confidence" not in d
    assert "sig" not in d
    assert "sender" not in d


def test_to_dict_optional_fields_present():
    msg = make_msg(confidence=0.8, sender="operator-1", scope="fleet")
    d = msg.to_dict()
    assert d["confidence"] == 0.8
    assert d["sender"] == "operator-1"
    assert d["scope"] == "fleet"


def test_to_json_roundtrip():
    msg = make_msg(params={"distance_m": 2.0}, confidence=0.85)
    restored = RCANMessage.from_json(msg.to_json())
    assert restored.cmd == msg.cmd
    assert str(restored.target) == str(msg.target)
    assert restored.confidence == msg.confidence
    assert restored.params == msg.params


def test_from_json_invalid_json():
    with pytest.raises(RCANValidationError):
        RCANMessage.from_json("not json")


def test_from_dict_missing_required():
    with pytest.raises(RCANValidationError):
        RCANMessage.from_dict({"cmd": "move"})  # missing target and rcan


def test_is_ai_driven():
    assert make_msg(confidence=0.9).is_ai_driven is True
    assert make_msg().is_ai_driven is False


def test_is_signed():
    assert make_msg(signature={"alg": "ed25519", "kid": "k1", "value": "abc"}).is_signed is True
    assert make_msg().is_signed is False


def test_repr():
    msg = make_msg()
    assert "move_forward" in repr(msg)


# ---------------------------------------------------------------------------
# RCANResponse
# ---------------------------------------------------------------------------

def test_response_ok():
    r = RCANResponse(msg_id="abc", status="ok", message="done")
    assert r.ok is True
    assert r.blocked is False


def test_response_blocked():
    r = RCANResponse(msg_id="abc", status="blocked", safety_approved=False)
    assert r.blocked is True
    assert r.ok is False


def test_response_from_dict():
    d = {"msg_id": "x", "status": "ok", "message": "success", "duration_ms": 94.0}
    r = RCANResponse.from_dict(d)
    assert r.ok is True
    assert r.duration_ms == 94.0


def test_response_to_dict():
    r = RCANResponse(msg_id="x", status="ok")
    d = r.to_dict()
    assert d["status"] == "ok"
    assert "timestamp" in d
