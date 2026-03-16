"""Tests for rcan.delegation — Command Delegation Chain (GAP-01)."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from rcan.delegation import (
    DelegationHop,
    add_delegation_hop,
    validate_delegation_chain,
    MAX_DELEGATION_DEPTH,
)
from rcan.exceptions import DelegationChainExceededError
from rcan.message import RCANMessage

TARGET = "rcan://registry.rcan.dev/acme/arm/v1/unit-001"
ROBOT_A = "rcan://rcan.dev/acme/arm/v1/unit-001"
ROBOT_B = "rcan://rcan.dev/acme/arm/v1/unit-002"
HUMAN_A = "user://auth.rcan.dev/alice"


def make_msg(**kwargs) -> RCANMessage:
    return RCANMessage(cmd="move_forward", target=TARGET, **kwargs)


class TestDelegationHop:
    def test_construction(self):
        hop = DelegationHop(
            issuer_ruri=ROBOT_A,
            human_subject=HUMAN_A,
            scope="teleop",
        )
        assert hop.issuer_ruri == ROBOT_A
        assert hop.human_subject == HUMAN_A
        assert hop.scope == "teleop"
        assert hop.signature == ""

    def test_roundtrip(self):
        hop = DelegationHop(
            issuer_ruri=ROBOT_A,
            human_subject=HUMAN_A,
            scope="operator",
            signature="sig123",
        )
        restored = DelegationHop.from_dict(hop.to_dict())
        assert restored.issuer_ruri == ROBOT_A
        assert restored.signature == "sig123"

    def test_canonical_bytes_stable(self):
        """canonical_bytes() output should be deterministic."""
        hop = DelegationHop(
            issuer_ruri=ROBOT_A,
            human_subject=HUMAN_A,
            scope="teleop",
            timestamp=1234567890.0,
        )
        b1 = hop.canonical_bytes()
        b2 = hop.canonical_bytes()
        assert b1 == b2


class TestAddDelegationHop:
    def test_adds_hop(self):
        msg = make_msg()
        msg = add_delegation_hop(
            msg,
            issuer_ruri=ROBOT_A,
            human_subject=HUMAN_A,
            scope="teleop",
            private_key=None,
        )
        assert len(msg.delegation_chain) == 1

    def test_unsigned_hop_allowed_with_warning(self, recwarn):
        msg = make_msg()
        msg = add_delegation_hop(
            msg,
            issuer_ruri=ROBOT_A,
            human_subject=HUMAN_A,
            scope="teleop",
            private_key=None,
        )
        assert len(msg.delegation_chain) == 1
        assert msg.delegation_chain[0].signature == ""

    def test_exceeds_max_depth_raises(self):
        msg = make_msg()
        # Add MAX_DELEGATION_DEPTH hops
        for i in range(MAX_DELEGATION_DEPTH):
            msg = add_delegation_hop(
                msg,
                issuer_ruri=f"rcan://rcan.dev/acme/arm/v1/unit-00{i}",
                human_subject=HUMAN_A,
                scope="teleop",
                private_key=None,
            )
        with pytest.raises(DelegationChainExceededError):
            add_delegation_hop(
                msg,
                issuer_ruri=ROBOT_B,
                human_subject=HUMAN_A,
                scope="teleop",
                private_key=None,
            )

    def test_max_depth_is_4(self):
        assert MAX_DELEGATION_DEPTH == 4

    def test_hop_is_delegation_hop_instance(self):
        msg = make_msg()
        add_delegation_hop(
            msg,
            issuer_ruri=ROBOT_A,
            human_subject=HUMAN_A,
            scope="teleop",
            private_key=None,
        )
        assert isinstance(msg.delegation_chain[0], DelegationHop)


class TestValidateDelegationChain:
    def test_empty_chain_valid(self):
        msg = make_msg()
        valid, reason = validate_delegation_chain(msg, lambda ruri: None)
        assert valid is True

    def test_unsigned_hop_skipped_with_warning(self):
        """Unsigned hops have empty signature — validation skips them."""
        msg = make_msg()
        add_delegation_hop(
            msg,
            issuer_ruri=ROBOT_A,
            human_subject=HUMAN_A,
            scope="teleop",
            private_key=None,
        )
        valid, reason = validate_delegation_chain(msg, lambda ruri: None)
        assert valid is True  # unsigned hops are warned but not rejected

    def test_chain_exceeds_max_depth(self):
        """A chain with >4 hops should be invalid."""
        msg = make_msg()
        # Manually stuff the chain beyond the limit
        for i in range(5):
            msg.delegation_chain.append(DelegationHop(
                issuer_ruri=f"ruri-{i}",
                human_subject=HUMAN_A,
                scope="teleop",
            ))
        valid, reason = validate_delegation_chain(msg, lambda ruri: None)
        assert valid is False
        assert "depth" in reason.lower() or "exceed" in reason.lower()

    def test_signed_hop_verified(self):
        """A signed hop should be verified against the provided keypair."""
        import importlib
        try:
            from rcan.signing import KeyPair
        except ImportError:
            pytest.skip("cryptography not available")

        keypair = KeyPair.generate()
        msg = make_msg()
        add_delegation_hop(
            msg,
            issuer_ruri=ROBOT_A,
            human_subject=HUMAN_A,
            scope="teleop",
            private_key=keypair,
        )

        def get_public_key(ruri):
            if ruri == ROBOT_A:
                return KeyPair.from_public_pem(keypair.public_pem)
            return None

        valid, reason = validate_delegation_chain(msg, get_public_key)
        assert valid is True

    def test_invalid_signature_rejected(self):
        """A hop with a bad signature should fail validation."""
        import importlib
        try:
            from rcan.signing import KeyPair
        except ImportError:
            pytest.skip("cryptography not available")

        keypair = KeyPair.generate()
        wrong_keypair = KeyPair.generate()

        msg = make_msg()
        add_delegation_hop(
            msg,
            issuer_ruri=ROBOT_A,
            human_subject=HUMAN_A,
            scope="teleop",
            private_key=keypair,
        )

        # Resolve with WRONG key
        def get_wrong_key(ruri):
            return KeyPair.from_public_pem(wrong_keypair.public_pem)

        valid, reason = validate_delegation_chain(msg, get_wrong_key)
        assert valid is False
