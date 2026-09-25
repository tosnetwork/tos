"""Check E03 Config34 JSON against its BOC and the separately provisioned genesis node.

The BOC parser deliberately supports the PQ descriptor used by E03 only.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import urllib.request

from pytosiq_core import Cell

KEY_ID_DOMAIN = b"TOS-PQ-CONSENSUS-KEY-v1"
INITIAL_VALIDATOR_DOMAIN = b"tos-test-pq-initial-validator-v1\x00"
ML_DSA_44_PUBLIC_KEY_BYTES = 1312


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
    assert 0 < main <= total and len(entries) == total
    assert sorted(entries) == list(range(total)), "Config34 validator indices are not contiguous"
    validators = []
    seen_ids, seen_keys, seen_adnl = set(), set(), set()
    weight_sum = 0
    for index, entry in sorted(entries.items()):
        assert entry.load_uint(8) == 0xB3, "E03 expects validator_pq#b3"
        validator_id = entry.load_bytes(32)
        algorithm_id = entry.load_uint(16)
        key_id = entry.load_bytes(32)
        weight = entry.load_uint(64)
        adnl = entry.load_bytes(32)
        assert entry.remaining_bits == 0 and entry.remaining_refs == 1
        public_key = unpack_pq_bytes(entry.load_ref())
        assert algorithm_id == 1 and len(public_key) == ML_DSA_44_PUBLIC_KEY_BYTES
        assert validator_id != bytes(32) and key_id != bytes(32) and adnl != bytes(32)
        assert validator_id not in seen_ids and key_id not in seen_keys and adnl not in seen_adnl
        seen_ids.add(validator_id)
        seen_keys.add(key_id)
        seen_adnl.add(adnl)
        assert key_id == hashlib.sha256(KEY_ID_DOMAIN + algorithm_id.to_bytes(2, "little") + public_key).digest(), (
            f"Config34 validator {index} key_id does not derive from its PQ public key")
        weight_sum += weight
        assert weight > 0
        validators.append({
            "index": index,
            "validator_id": base64.b64encode(validator_id).decode(),
            "key_id": base64.b64encode(key_id).decode(),
            "algorithm_id": algorithm_id,
            "pq_public_key": base64.b64encode(public_key).decode(),
            "adnl_address": base64.b64encode(adnl).decode(),
            "weight": str(weight),
            "cumulative_weight": str(weight_sum - weight),
        })
    assert since < until and weight_sum == total_weight
    return {"boc_sha256": hashlib.sha256(boc).hexdigest(), "utime_since": since,
            "utime_until": until, "total": total, "main": main,
            "total_weight": str(total_weight), "validators": validators}


def verify(raw_response, decoded):
    reported = raw_response["result"]["validator_set"]
    for field in ("utime_since", "utime_until", "total", "main", "total_weight"):
        assert str(reported[field]) == str(decoded[field]), f"Config34 {field} differs from BOC"
    assert len(reported["validators"]) == decoded["total"]
    assert [item["index"] for item in decoded["validators"]] == list(range(decoded["total"]))
    for expected, actual in zip(decoded["validators"], reported["validators"]):
        assert actual.get("public_key") is None, "PQ JSON exposes an Ed25519 placeholder as public_key"
        assert actual.get("index") == expected["index"], "Config34 JSON validator index differs from BOC"
        for field in ("validator_id", "key_id", "algorithm_id", "pq_public_key", "adnl_address",
                      "weight", "cumulative_weight"):
            assert str(actual.get(field)) == str(expected[field]), (
                f"Config34 validator {expected['index']} {field} differs from BOC")


def verify_genesis_member(decoded, node_dir: Path, key_tool: Path):
    """Bind the live Config34 member to the independently provisioned node key and ADNL."""
    assert decoded["total"] == decoded["main"] == 1, "E03 expects one genesis validator"
    config = json.loads((node_dir / "config.json").read_text())
    member = decoded["validators"][0]
    validator_id = base64.b64decode(config["extraconfig"]["pq_consensus"]["validator_id"], validate=True)
    expected_id = hashlib.sha256(INITIAL_VALIDATOR_DOMAIN + b"validator-id\x00" + bytes(4)).digest()
    assert validator_id == expected_id, "node PQ identity differs from deterministic genesis identity"
    assert base64.b64decode(member["validator_id"], validate=True) == expected_id
    adnl = base64.b64decode(config["validators"][0]["adnl_addrs"][0]["id"], validate=True)
    assert base64.b64decode(member["adnl_address"], validate=True) == adnl
    key_file = Path(config["extraconfig"]["pq_consensus"]["consensus_key_file"])
    assert key_file.resolve() == (node_dir / "pq-consensus.seed").resolve()
    tool = subprocess.run([str(key_tool), "show", str(key_file)], capture_output=True, text=True, check=True)
    key_id = re.search(r"^key_id\s+([0-9a-f]{64})$", tool.stdout, re.MULTILINE)
    public = re.search(r"^public\s+([0-9a-f]{2624})$", tool.stdout, re.MULTILINE)
    assert key_id is not None and public is not None, "PQ key tool did not report the public identity"
    assert base64.b64decode(member["key_id"], validate=True) == bytes.fromhex(key_id.group(1))
    assert base64.b64decode(member["pq_public_key"], validate=True) == bytes.fromhex(public.group(1))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rpc", help="capture the live getConfigParam 34 reply before verification")
    parser.add_argument("--node-dir", type=Path)
    parser.add_argument("--key-tool", type=Path)
    args = parser.parse_args()
    if args.rpc:
        request_body = json.dumps({"jsonrpc": "2.0", "id": "e03-config34", "method": "getConfigParam",
                                   "params": {"param": 34}}).encode()
        request = urllib.request.Request(args.rpc.rstrip("/") + "/jsonRPC", data=request_body,
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=10) as response:
            raw_body = response.read()
            args.raw.write_bytes(raw_body + b"\n")
    raw = json.loads(args.raw.read_text())
    decoded = decode(raw)
    verify(raw, decoded)
    assert (args.node_dir is None) == (args.key_tool is None), "genesis check needs both node and key tool"
    if args.node_dir is not None:
        verify_genesis_member(decoded, args.node_dir, args.key_tool)
    args.output.write_text(json.dumps({**decoded, "json_boc_verified": True,
                                       "genesis_member_verified": args.node_dir is not None}, indent=2) + "\n")
    print(f"E03_CONFIG34_PQ_IDENTITY_OK boc_sha256={decoded['boc_sha256']} total={decoded['total']}")


if __name__ == "__main__":
    main()
