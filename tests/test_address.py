"""Tests for rcan.address.RobotURI."""

import pytest

from rcan import RobotURI
from rcan.exceptions import RCANAddressError

VALID_URI = "rcan://registry.rcan.dev/acme/robotarm/v2/unit-001"


def test_parse_valid():
    uri = RobotURI.parse(VALID_URI)
    assert uri.registry == "registry.rcan.dev"
    assert uri.manufacturer == "acme"
    assert uri.model == "robotarm"
    assert uri.version == "v2"
    assert uri.device_id == "unit-001"


def test_parse_trailing_slash():
    uri = RobotURI.parse(VALID_URI + "/")
    assert uri.device_id == "unit-001"


def test_str_roundtrip():
    uri = RobotURI.parse(VALID_URI)
    assert str(uri) == VALID_URI


def test_build():
    uri = RobotURI.build("acme", "robotarm", "v2", "unit-001")
    assert uri.registry == "registry.rcan.dev"
    assert str(uri) == VALID_URI


def test_build_custom_registry():
    uri = RobotURI.build("acme", "bot", "v1", "x01", registry="myregistry.example.com")
    assert "myregistry.example.com" in str(uri)


def test_parse_invalid_scheme():
    with pytest.raises(RCANAddressError):
        RobotURI.parse("http://registry.rcan.dev/acme/arm/v1/x")


def test_parse_too_few_segments():
    with pytest.raises(RCANAddressError):
        RobotURI.parse("rcan://registry.rcan.dev/acme/arm/v1")


def test_parse_invalid_chars():
    with pytest.raises(RCANAddressError):
        RobotURI.parse("rcan://registry.rcan.dev/ac me/arm/v1/x")


def test_namespace():
    uri = RobotURI.parse(VALID_URI)
    assert uri.namespace == "acme/robotarm"


def test_registry_url():
    uri = RobotURI.parse(VALID_URI)
    assert uri.registry_url.startswith(
        "https://registry.rcan.dev/registry/acme/robotarm"
    )


def test_with_device():
    uri = RobotURI.parse(VALID_URI)
    new_uri = uri.with_device("unit-002")
    assert new_uri.device_id == "unit-002"
    assert new_uri.manufacturer == uri.manufacturer


def test_immutable():
    uri = RobotURI.parse(VALID_URI)
    with pytest.raises(Exception):
        uri.manufacturer = "evil"
