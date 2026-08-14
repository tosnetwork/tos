#!/usr/bin/env python3
"""Deploy and independently observe the frozen Gate D escrow StateInit."""

import argparse
import base64
import importlib.util
import json
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "test/tostester/src"))

import nacl.signing  # noqa: E402
from pytosiq_core import Address, Builder, Cell, StateInit  # noqa: E402

MODULE_PATH = REPO / "scripts/atos-native-registry-local-gate-c.py"
module_spec = importlib.util.spec_from_file_location("native_gate_c", MODULE_PATH)
gate = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(gate)


def rpc(endpoint, method, **params):
    request = urllib.request.Request(endpoint, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        value = json.loads(response.read().decode())
    if not value.get("ok"):
        raise RuntimeError(f"{endpoint} {method}: {value}")
    return value["result"]


def wait_account(config_path, address):
    deadline = time.monotonic() + 30
    last_error = None
    while time.monotonic() < deadline:
        try:
            return gate.account_code(config_path, address), gate.account_data(config_path, address)
        except Exception as error:
            last_error = error
            time.sleep(0.5)
    raise RuntimeError(f"escrow account did not activate: {last_error}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--global-config", default="/data/tos-global.json")
    parser.add_argument("--state-dir", default="/data/testnet/state")
    parser.add_argument("--network-id", default="tos-local-gate-c-20260814")
    parser.add_argument("--state-init-vector", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()

    config_path = Path(args.global_config)
    zero = json.loads(config_path.read_text())["validator"]["zero_state"]
    vector = json.loads(Path(args.state_init_vector).read_text())
    if vector.get("schema") != "atos.native.escrow-state-init.v1":
        raise RuntimeError("invalid escrow StateInit vector")
    state_init_cell = Cell.one_from_boc(base64.b64decode(vector["escrow_state_init_boc_base64"], validate=True))
    state_init = StateInit.deserialize(state_init_cell.begin_parse())
    destination = Address(vector["escrow_address"])
    if destination.to_tl_account_id()["id"].lower() != state_init.serialize().hash.hex():
        raise RuntimeError("StateInit does not derive the requested escrow address")

    payer_key = nacl.signing.SigningKey(gate.read_private(Path(args.state_dir) / "main-wallet.pk"))
    address_file = gate.read_private(Path(args.state_dir) / "main-wallet.addr")
    payer = Address((int.from_bytes(address_file[32:36], "big", signed=True), address_file[:32]))
    deployed_now = False
    try:
        code = gate.account_code(config_path, destination.to_str())
        data = gate.account_data(config_path, destination.to_str())
    except Exception:
        gate.send_wallet_message(config_path, payer_key, payer, destination, 2 * gate.NANO,
            Builder().end_cell(), state_init)
        code, data = wait_account(config_path, destination.to_str())
        deployed_now = True
    if "tvm-cell-sha256:" + code.hash.hex() != vector["escrow_code_hash"]:
        raise RuntimeError("deployed escrow code hash mismatch")
    if "tvm-cell-sha256:" + data.hash.hex() != vector["escrow_data_hash"]:
        raise RuntimeError("deployed escrow data does not match the typed StateInit")

    endpoints = [f"http://127.0.0.1:{port}/jsonRPC" for port in (8011, 8012, 8013)]
    heads = [rpc(endpoint, "getMasterchainInfo") for endpoint in endpoints]
    checkpoint = min(head["last"]["seqno"] for head in heads)
    observations = []
    votes = set()
    for endpoint in endpoints:
        info = rpc(endpoint, "getAddressInformation", address=destination.to_str(), seqno=checkpoint)
        observed_code = Cell.one_from_boc(base64.b64decode(info["code"], validate=True))
        observed_data = Cell.one_from_boc(base64.b64decode(info["data"], validate=True))
        vote = (observed_code.hash.hex(), observed_data.hash.hex(), info["block_id"]["root_hash"], info["block_id"]["file_hash"])
        votes.add(vote)
        observations.append({"endpoint": endpoint, "checkpoint": checkpoint,
            "block_root_hash": info["block_id"]["root_hash"], "block_file_hash": info["block_id"]["file_hash"],
            "code_hash": "tvm-cell-sha256:" + observed_code.hash.hex(), "data_hash": "tvm-cell-sha256:" + observed_data.hash.hex()})
    if len(votes) != 1 or next(iter(votes))[0] != code.hash.hex() or next(iter(votes))[1] != data.hash.hex():
        raise RuntimeError("three endpoints did not agree on the escrow account")

    evidence = {"schema": "atos.native.escrow-deployment.v1", "deployed_now": deployed_now,
        "network": {"network_id": args.network_id,
            "genesis_root_hash": "sha256:" + base64.b64decode(zero["root_hash"]).hex(),
            "genesis_file_hash": "sha256:" + base64.b64decode(zero["file_hash"]).hex()},
        "escrow": vector, "transaction": gate.account_transaction(config_path, destination.to_str()),
        "checkpoint": gate.master_checkpoint(config_path), "endpoint_verification": observations,
        "quorum": 2, "verdict": "PASS_CANONICAL_QUOTE_ACCEPTANCE_DEPLOYMENT"}
    Path(args.evidence).write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
