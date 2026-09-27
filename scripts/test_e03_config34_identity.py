"""Two-member controls for the E03 PQ Config34 JSON/BOC identity gate."""

import base64
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pytosiq_core import Builder, HashMap

from e03_config34_identity import (
    INITIAL_VALIDATOR_DOMAIN,
    KEY_ID_DOMAIN,
    decode,
    verify,
    verify_genesis_member,
)


def pq_bytes(data):
    tail = None
    chunks = [data[index:index + 127] for index in range(0, len(data), 127)]
    for chunk in reversed(chunks):
        builder = Builder().store_bytes(chunk)
        if tail is not None:
            builder.store_ref(tail)
        tail = builder.end_cell()
    return Builder().store_uint(len(data), 32).store_ref(tail).end_cell()


def response(indices=(0, 1), *, wrong_key=False):
    entries = HashMap(16)
    for member, index in enumerate(indices):
        public = bytes([0x31 + member]) * 1312
        key_id = hashlib.sha256(KEY_ID_DOMAIN + b"\x01\x00" + public).digest()
        if wrong_key and member == 1:
            key_id = bytes([0x77]) * 32
        descriptor = (Builder().store_uint(0xB3, 8)
                      .store_bytes(bytes([0x11 + member]) * 32)
                      .store_uint(1, 16).store_bytes(key_id)
                      .store_uint(7 + member, 64)
                      .store_bytes(bytes([0x21 + member]) * 32)
                      .store_ref(pq_bytes(public)).end_cell())
        entries.set_int_key(index, descriptor)
    cell = (Builder().store_uint(0x12, 8).store_uint(100, 32).store_uint(200, 32)
            .store_uint(2, 16).store_uint(1, 16).store_uint(15, 64)
            .store_dict(entries.serialize()).end_cell())
    raw = {"result": {"config": {"bytes": base64.b64encode(cell.to_boc()).decode()}}}
    if not wrong_key and indices == (0, 1):
        decoded = decode(raw)
        raw["result"]["validator_set"] = {
            field: decoded[field]
            for field in ("utime_since", "utime_until", "total", "main", "total_weight")
        }
        raw["result"]["validator_set"]["validators"] = [
            {**item, "public_key": None}
            for item in decoded["validators"]
        ]
    return raw


def test_two_members_match_in_parser_order():
    raw = response()
    decoded = decode(raw)
    verify(raw, decoded)
    assert [member["index"] for member in decoded["validators"]] == [0, 1]
    assert [member["weight"] for member in decoded["validators"]] == ["7", "8"]


def test_swapped_json_members_are_refused():
    raw = response()
    decoded = decode(raw)
    raw["result"]["validator_set"]["validators"].reverse()
    with pytest.raises(AssertionError, match="JSON validator index differs"):
        verify(raw, decoded)


def test_wrong_reported_index_is_refused():
    raw = response()
    decoded = decode(raw)
    raw["result"]["validator_set"]["validators"][0]["index"] = 1
    with pytest.raises(AssertionError, match="JSON validator index differs"):
        verify(raw, decoded)


def test_same_index_identity_swap_is_refused():
    raw = response()
    decoded = decode(raw)
    validators = raw["result"]["validator_set"]["validators"]
    validators[0]["validator_id"], validators[1]["validator_id"] = (
        validators[1]["validator_id"], validators[0]["validator_id"])
    with pytest.raises(AssertionError, match="validator 0 validator_id"):
        verify(raw, decoded)


def test_noncontiguous_boc_indices_are_refused():
    with pytest.raises(AssertionError, match="indices are not contiguous"):
        decode(response(indices=(0, 2)))


def test_wrong_key_derivation_is_refused():
    with pytest.raises(AssertionError, match="key_id does not derive"):
        decode(response(wrong_key=True))


def test_genesis_member_binds_config_adnl_and_key_tool(tmp_path, monkeypatch):
    root = tmp_path / "node1"
    root.mkdir()
    (root / "pq-consensus.seed").touch()
    expected_id = hashlib.sha256(INITIAL_VALIDATOR_DOMAIN + b"validator-id\x00" + bytes(4)).digest()
    public = bytes([0x55]) * 1312
    key_id = hashlib.sha256(KEY_ID_DOMAIN + b"\x01\x00" + public).digest()
    adnl = bytes([0x66]) * 32
    config = {"extraconfig": {"pq_consensus": {
        "validator_id": base64.b64encode(expected_id).decode(),
        "consensus_key_file": str(root / "pq-consensus.seed"),
    }}, "validators": [{"adnl_addrs": [{"id": base64.b64encode(adnl).decode()}]}]}
    (root / "config.json").write_text(json.dumps(config))
    decoded = {"total": 1, "main": 1, "validators": [{
        "validator_id": base64.b64encode(expected_id).decode(),
        "key_id": base64.b64encode(key_id).decode(),
        "pq_public_key": base64.b64encode(public).decode(),
        "adnl_address": base64.b64encode(adnl).decode(),
    }]}
    monkeypatch.setattr("e03_config34_identity.subprocess.run", lambda *_, **__: SimpleNamespace(
        stdout=f"key_id {key_id.hex()}\npublic {public.hex()}\n"))
    verify_genesis_member(decoded, root, Path("key-tool"))
    wrong = copy.deepcopy(decoded)
    wrong["validators"][0]["adnl_address"] = base64.b64encode(bytes([0x67]) * 32).decode()
    with pytest.raises(AssertionError):
        verify_genesis_member(wrong, root, Path("key-tool"))
