"""A stand-in for tos-proof-verify, for tests of what a consumer does with the
verifier's answer: whether it binds that answer to its own request and refuses
everything else. It authenticates nothing and is never installed.

Usage: fake_verifier.py BEHAVIOUR.json verify --anchor FILE --request FILE ...

BEHAVIOUR.json:
  stacks     method name -> result stack, in the verifier's JSON encoding
  mutation   one of the names in MUTATIONS, or "none"
  target     optional {"seqno","root_hash","file_hash"} for live requests
  gen_utime  time of the target block
  now        the verifier's clock, for live requests
  log        optional path; every request this stand-in received is appended
"""

import hashlib
import json
import sys
import time

INTERFACE = "tos-proof-verify/1"


def method_id(name):
    crc = 0
    for byte in name.encode():
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc | 0x10000


def main():
    behaviour = json.load(open(sys.argv[1]))
    args = sys.argv[2:]
    assert args[0] == "verify", args
    options = {}
    i = 1
    while i < len(args):
        options[args[i]] = args[i + 1]
        i += 2
    request_bytes = open(options["--request"], "rb").read()
    request = json.loads(request_bytes)
    anchor = json.load(open(options["--anchor"]))
    if behaviour.get("log"):
        with open(behaviour["log"], "a") as log:
            log.write(json.dumps({"request": request, "options": options}) + "\n")

    mutation = behaviour.get("mutation", "none")
    gen_utime = behaviour.get("gen_utime", 1791201441)
    if request["mode"] == "historical":
        target = dict(request["target"])
    else:
        target = dict(behaviour["target"])
    target.update(
        {
            "workchain": -1,
            "shard": "8000000000000000",
            "gen_utime": gen_utime,
            "is_key_block": False,
        }
    )
    block = {k: target[k] for k in ("workchain", "shard", "seqno", "root_hash", "file_hash")}
    address = request["account"]
    shard_block = (
        dict(block)
        if address.startswith("-1:")
        else {
            "workchain": 0,
            "shard": "8000000000000000",
            "seqno": 77,
            "root_hash": "77" * 32,
            "file_hash": "78" * 32,
        }
    )
    answer = {
        "status": "verified",
        "interface": INTERFACE,
        "mode": request["mode"],
        "anchor": anchor,
        "start": {k: anchor[k] for k in ("workchain", "shard", "seqno", "root_hash", "file_hash")},
        "target": target,
        "chain": {"links": 1, "key_blocks": []},
        "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
        "account": {
            "address": address,
            "shard_block": shard_block,
            "exists": True,
            "gen_utime": gen_utime,
            "gen_lt": 1000,
            "last_trans_lt": 999,
            "last_trans_hash": "99" * 32,
            "state_hash": "5a" * 32,
            "state_boc": "",
            "balance": "123456789",
            "active": True,
            "code_hash": "c0" * 32,
            "data_hash": "da" * 32,
        },
        "execution_context": {
            "unixtime": gen_utime,
            "block_lt": 1000,
            "rand_seed": "00" * 32,
            "config_root_hash": "cf" * 32,
            "global_version": 18,
            "gas_limit": 1000000,
            "libraries": [],
        },
        "get_methods": [
            {
                "method": m["method"],
                "method_id": method_id(m["method"]),
                "args": m["args"],
                "exit_code": 0,
                "gas_used": 1000,
                "stack": behaviour["stacks"][m["method"]],
                "stack_boc": "",
            }
            for m in request["get_methods"]
        ],
    }
    if request["mode"] == "live":
        now = behaviour["now"]
        answer["live"] = {
            "now": now,
            "age_seconds": now - gen_utime,
            "max_age_seconds": request["max_age_seconds"],
        }

    code = 0
    if mutation == "none":
        pass
    elif mutation == "nonzero_exit":
        code = 1
    elif mutation == "refusal":
        answer = {"status": "refused", "interface": INTERFACE, "reason": "test refusal"}
        code = 1
    elif mutation == "status":
        answer["status"] = "refused"
    elif mutation == "interface":
        answer["interface"] = "tos-proof-verify/2"
    elif mutation.startswith("missing:"):
        del answer[mutation.split(":", 1)[1]]
    elif mutation == "anchor":
        answer["anchor"]["root_hash"] = "ab" * 32
    elif mutation == "target":
        answer["target"]["root_hash"] = "ab" * 32
    elif mutation == "target_seqno":
        answer["target"]["seqno"] += 1
    elif mutation == "request_hash":
        answer["request_sha256"] = "ab" * 32
    elif mutation == "mode":
        answer["mode"] = "live" if request["mode"] == "historical" else "historical"
    elif mutation == "live_evidence":
        answer["live"] = {"now": gen_utime, "age_seconds": 0, "max_age_seconds": 60}
    elif mutation == "max_age":
        answer["live"]["max_age_seconds"] += 1
    elif mutation == "account":
        workchain, _ = address.split(":")
        answer["account"]["address"] = workchain + ":" + "ab" * 32
    elif mutation == "inactive":
        answer["account"]["active"] = False
    elif mutation == "shard_block":
        answer["account"]["shard_block"]["root_hash"] = "ab" * 32
    elif mutation == "shard_workchain":
        answer["account"]["shard_block"]["workchain"] = 1
    elif mutation == "method":
        answer["get_methods"][0]["method"] = "get_other_data"
    elif mutation == "method_id":
        answer["get_methods"][0]["method_id"] += 1
    elif mutation == "args":
        answer["get_methods"][0]["args"] = [{"type": "int", "value": "1"}]
    elif mutation == "method_count":
        answer["get_methods"].pop()
    elif mutation == "method_order":
        answer["get_methods"].reverse()
    elif mutation == "exit_code":
        answer["get_methods"][0]["exit_code"] = 11
    elif mutation == "stack_type":
        answer["get_methods"][0]["stack"] = [{"type": "nan"}]
    elif mutation in ("malformed", "partial", "trailing", "two_lines", "sleep", "empty"):
        pass
    else:
        raise SystemExit("unknown mutation " + mutation)

    text = json.dumps(answer, separators=(",", ":"))
    if mutation == "malformed":
        text = "verified"
    elif mutation == "partial":
        text = text[: len(text) // 2]
    elif mutation == "trailing":
        text = text + " {}"
    elif mutation == "two_lines":
        text = text + "\n" + text
    elif mutation == "empty":
        text = ""
    elif mutation == "sleep":
        time.sleep(30)
    sys.stdout.write(text + ("\n" if text else ""))
    sys.stdout.flush()
    sys.exit(code)


main()
