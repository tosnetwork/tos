"""Compare decoded JSON-RPC PQ validator identities with the returned raw BOC.

This checks the bytes the API actually returned, not a second genesis fixture.
The BOC parser deliberately supports the PQ descriptor used by E03 only.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path

from pytosiq_core import Cell


def unpack_pq_bytes(cell):
    source = cell.begin_parse()
    length = source.load_uint(32)
    assert 0 < length <= 8192 and source.remaining_bits == 0 and source.remaining_refs == 1
    current = source.load_ref().begin_parse()
    result = bytearray()
    while len(result) < length:
        count = min(127, length - len(result))
        assert current.remaining_bits == count * 8
        result.extend(current.load_bytes(count))
        if len(result) < length:
            assert current.remaining_refs == 1
            current = current.load_ref().begin_parse()
        else:
            assert current.remaining_refs == 0
    return bytes(result)


def decode(raw_response):
    result = raw_response["result"]
    boc = base64.b64decode(result["config"]["bytes"], validate=True)
    source = Cell.one_from_boc(boc).begin_parse()
    assert source.load_uint(8) == 0x12, "E03 expects validators_ext#12"
    since, until = source.load_uint(32), source.load_uint(32)
    total, main = source.load_uint(16), source.load_uint(16)
    total_weight = source.load_uint(64)
    entries = source.load_dict(16)
    assert source.remaining_bits == 0 and source.remaining_refs == 0
    assert len(entries) == total and total > 0
    validators = []
    for index, entry in sorted(entries.items()):
        assert entry.load_uint(8) == 0xB3, "E03 expects validator_pq#b3"
        validator_id = entry.load_bytes(32)
        algorithm_id = entry.load_uint(16)
        key_id = entry.load_bytes(32)
        weight = entry.load_uint(64)
        adnl = entry.load_bytes(32)
        assert entry.remaining_bits == 0 and entry.remaining_refs == 1
        public_key = unpack_pq_bytes(entry.load_ref())
        validators.append({
            "index": index,
            "validator_id": base64.b64encode(validator_id).decode(),
            "key_id": base64.b64encode(key_id).decode(),
            "algorithm_id": algorithm_id,
            "pq_public_key": base64.b64encode(public_key).decode(),
            "adnl_address": base64.b64encode(adnl).decode(),
            "weight": str(weight),
        })
    return {"boc_sha256": hashlib.sha256(boc).hexdigest(), "utime_since": since,
            "utime_until": until, "total": total, "main": main,
            "total_weight": str(total_weight), "validators": validators}


def verify(raw_response, decoded):
    reported = raw_response["result"]["validator_set"]
    for field in ("utime_since", "utime_until", "total", "main", "total_weight"):
        assert str(reported[field]) == str(decoded[field]), f"Config34 {field} differs from BOC"
    assert len(reported["validators"]) == decoded["total"]
    for expected, actual in zip(decoded["validators"], reported["validators"]):
        assert actual.get("public_key") is None, "PQ JSON exposes an Ed25519 placeholder as public_key"
        for field in ("validator_id", "key_id", "algorithm_id", "pq_public_key", "adnl_address", "weight"):
            assert str(actual.get(field)) == str(expected[field]), (
                f"Config34 validator {expected['index']} {field} differs from BOC")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = json.loads(args.raw.read_text())
    decoded = decode(raw)
    args.output.write_text(json.dumps(decoded, indent=2) + "\n")
    verify(raw, decoded)
    print(f"E03_CONFIG34_PQ_IDENTITY_OK boc_sha256={decoded['boc_sha256']} total={decoded['total']}")


if __name__ == "__main__":
    main()
