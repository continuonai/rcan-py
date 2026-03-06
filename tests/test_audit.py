"""Tests for rcan.audit — CommitmentRecord and AuditChain."""

import json
import pytest
from rcan import CommitmentRecord
from rcan.audit import AuditChain

SECRET = b"test-secret-key"


def make_record(action: str = "move_forward", **kwargs) -> CommitmentRecord:
    return CommitmentRecord(action=action, robot_uri="rcan://r.rcan.dev/a/b/v1/x", **kwargs)


# ---------------------------------------------------------------------------
# CommitmentRecord
# ---------------------------------------------------------------------------


def test_seal_and_verify():
    record = make_record(confidence=0.9)
    record.seal(SECRET)
    assert record.hmac_value is not None
    assert record.verify(SECRET) is True


def test_verify_wrong_secret():
    record = make_record()
    record.seal(SECRET)
    assert record.verify(b"wrong-secret") is False


def test_verify_unsealed():
    record = make_record()
    assert record.verify(SECRET) is False


def test_content_hash_stable():
    record = make_record(record_id="fixed-id", timestamp=1234567890.0)
    h1 = record.content_hash
    h2 = record.content_hash
    assert h1 == h2


def test_tamper_breaks_verify():
    record = make_record()
    record.seal(SECRET)
    original_hmac = record.hmac_value
    # Tamper with the record
    object.__setattr__(record, "action", "self_destruct") if False else None
    record.action = "self_destruct"  # dataclass not frozen
    assert record.verify(SECRET) is False


def test_to_dict_and_from_dict():
    record = make_record(confidence=0.85, model_identity="Qwen2.5-7B")
    record.seal(SECRET)
    d = record.to_dict()
    restored = CommitmentRecord.from_dict(d)
    assert restored.action == record.action
    assert restored.confidence == record.confidence
    assert restored.hmac_value == record.hmac_value
    assert restored.verify(SECRET) is True


def test_to_json():
    record = make_record()
    record.seal(SECRET)
    payload = json.loads(record.to_json())
    assert payload["action"] == "move_forward"
    assert "hmac" in payload


def test_next_record_chaining():
    r1 = make_record(action="move_forward")
    r1.seal(SECRET)
    r2 = r1.next_record(action="stop")
    assert r2.previous_hash == r1.content_hash


def test_repr_sealed():
    record = make_record()
    record.seal(SECRET)
    assert "sealed" in repr(record)


def test_repr_unsealed():
    record = make_record()
    assert "unsealed" in repr(record)


# ---------------------------------------------------------------------------
# AuditChain
# ---------------------------------------------------------------------------


def test_chain_append_and_verify():
    chain = AuditChain(SECRET)
    r1 = chain.append(make_record(action="move_forward"))
    r2 = chain.append(make_record(action="stop"))
    assert chain.verify_all() is True
    assert r2.previous_hash == r1.content_hash


def test_chain_len():
    chain = AuditChain(SECRET)
    chain.append(make_record())
    chain.append(make_record())
    assert len(chain) == 2


def test_chain_tamper_breaks_verify():
    chain = AuditChain(SECRET)
    r1 = chain.append(make_record(action="move_forward"))
    chain.append(make_record(action="stop"))
    # Tamper with first record after sealing
    r1.action = "self_destruct"
    assert chain.verify_all() is False


def test_chain_to_jsonl():
    chain = AuditChain(SECRET)
    chain.append(make_record(action="move_forward"))
    chain.append(make_record(action="stop"))
    jsonl = chain.to_jsonl()
    lines = jsonl.strip().split("\n")
    assert len(lines) == 2
    assert json.loads(lines[0])["action"] == "move_forward"


def test_chain_iter():
    chain = AuditChain(SECRET)
    chain.append(make_record(action="a"))
    chain.append(make_record(action="b"))
    actions = [r.action for r in chain]
    assert actions == ["a", "b"]
