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


# ---------------------------------------------------------------------------
# v1.5 RCANMessage field tests
# ---------------------------------------------------------------------------

def test_rcan_version_default():
    """rcan_version should default to SPEC_VERSION."""
    from rcan.version import SPEC_VERSION
    msg = make_msg()
    assert msg.rcan_version == SPEC_VERSION


def test_sender_type_none_by_default():
    msg = make_msg()
    assert msg.sender_type is None


def test_sender_type_cloud_function():
    from rcan.message import SenderType
    msg = make_msg(sender_type=SenderType.cloud_function, cloud_provider="google-cloud")
    assert msg.sender_type == SenderType.cloud_function
    assert msg.cloud_provider == "google-cloud"


def test_cloud_function_requires_provider():
    from rcan.message import SenderType
    from rcan.exceptions import RCANValidationError
    with pytest.raises(RCANValidationError):
        make_msg(sender_type=SenderType.cloud_function)


def test_cloud_relay_in_to_dict():
    from rcan.message import SenderType
    msg = make_msg(sender_type=SenderType.cloud_function, cloud_provider="aws-lambda")
    d = msg.to_dict()
    assert d["sender_type"] == "cloud_function"
    assert d["cloud_provider"] == "aws-lambda"


def test_qos_default_is_zero():
    msg = make_msg()
    assert msg.qos == 0


def test_qos_set():
    msg = make_msg(qos=2)
    assert msg.qos == 2


def test_sequence_number_none_by_default():
    msg = make_msg()
    assert msg.sequence_number is None


def test_delegation_chain_default_empty():
    msg = make_msg()
    assert msg.delegation_chain == []


def test_group_id_default_none():
    msg = make_msg()
    assert msg.group_id is None


def test_group_id_set():
    msg = make_msg(group_id="fleet-group-1")
    assert msg.group_id == "fleet-group-1"


def test_presence_verified_default_false():
    msg = make_msg()
    assert msg.presence_verified is False


def test_proximity_m_default_none():
    msg = make_msg()
    assert msg.proximity_m is None


def test_make_cloud_relay_message():
    from rcan.message import make_cloud_relay_message, SenderType
    base = make_msg()
    relay = make_cloud_relay_message(base, provider="gcp")
    assert relay.sender_type == SenderType.cloud_function
    assert relay.cloud_provider == "gcp"


def test_validate_version_compat_same_version():
    from rcan.message import validate_version_compat
    from rcan.version import SPEC_VERSION
    assert validate_version_compat(SPEC_VERSION) is True


def test_validate_version_compat_lower_minor():
    from rcan.message import validate_version_compat
    assert validate_version_compat("1.0") is True


def test_validate_version_compat_wrong_major():
    from rcan.message import validate_version_compat
    from rcan.exceptions import VersionIncompatibleError
    with pytest.raises(VersionIncompatibleError):
        validate_version_compat("2.0")


def test_from_dict_version_check():
    """from_dict should validate version compatibility."""
    from rcan.exceptions import VersionIncompatibleError
    data = {
        "rcan": "2.0",
        "rcan_version": "2.0",
        "cmd": "move_forward",
        "target": TARGET,
    }
    with pytest.raises(VersionIncompatibleError):
        RCANMessage.from_dict(data)
