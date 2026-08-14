#!/usr/bin/env python3
"""Bind the frozen software-work manifest to a fresh Native Capability."""

import argparse
import base64
import hashlib
import importlib.util
import json
import sys
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SPEC = REPO.parent / "atos-spec"
sys.path.insert(0, str(REPO / "test/tostester/src"))

import nacl.signing  # noqa: E402
from atos_test_identities import load_test_identity  # noqa: E402

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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--global-config", default="/data/tos-global.json")
    parser.add_argument("--state-dir", default="/data/testnet/state")
    parser.add_argument("--network-id", default="tos-local-gate-c-20260814")
    parser.add_argument(
        "--test-identities",
        default=str(SPEC / "test-vectors/atos-test-identities-v1.json"),
    )
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()

    config_path = Path(args.global_config)
    global_config = json.loads(config_path.read_text())
    zero = global_config["validator"]["zero_state"]
    root = base64.b64decode(zero["root_hash"])
    file_hash = base64.b64decode(zero["file_hash"])
    vector = json.loads((SPEC / "test-vectors/software-work-manifest-v1.json").read_text())
    manifest_digest = bytes.fromhex(vector["expected"]["digest"].removeprefix("sha256:"))

    code = gate.Cell.one_from_boc(base64.b64decode(b"".join(
        (REPO / "crypto/smartcont/atos-native-registry-v1.boc.base64").read_bytes().split())))
    if code.hash.hex() != gate.CODE_HASH:
        raise RuntimeError("frozen Native Registry code hash mismatch")
    config = gate.registry_config(root, file_hash, args.network_id, 0, code)
    signed_domain = gate.domain_cell(root, file_hash, args.network_id, code.hash)

    payer_key = nacl.signing.SigningKey(gate.read_private(Path(args.state_dir) / "main-wallet.pk"))
    address_file = gate.read_private(Path(args.state_dir) / "main-wallet.addr")
    payer = gate.Address((int.from_bytes(address_file[32:36], "big", signed=True), address_file[:32]))
    provider_key = load_test_identity(Path(args.test_identities), "provider-controller")
    provider_id = bytes.fromhex("5ad89bcf2d25bd5e7a53e36e976851fd1b937d70c2f0db80a18f7cbafcca1be4")
    provider_address = gate.Address("EQCrLBpT4SQxrXvpVNcdVRjlkZGunO72m5L3q7ZiHcOncKrZ")
    provider_state = gate.state_view(gate.account_data(config_path, provider_address.to_str()))
    if provider_state["tombstone"] or provider_state["generation"] != 1 or provider_state["sequence"] != 2:
        raise RuntimeError("provider Agent is not on the migrated test-identity policy")

    initial_version = b"software-work-v1"
    initial_manifest_digest = bytes.fromhex("a08cd75a4166bc1df44b645a4a4ca687004d05428a3764ce95d3d152be858e38")
    capability_version = b"1.2.0"
    capability_nonce = hashlib.sha256(b"atos-gate-d-software-work-capability-v1").digest()
    capability_id = gate.capability_identity(root, file_hash, args.network_id, capability_nonce,
        provider_id, initial_version, initial_manifest_digest)
    capability_init = gate.state_init(code, config, 2, capability_id)
    capability_address = gate.address_of(0, capability_init)
    deployed_now = False
    try:
        view = gate.state_view(gate.account_data(config_path, capability_address.to_str()))
    except Exception:
        raise RuntimeError("the original software-work Capability is absent")
    if view["generation"] != 1 or view["sequence"] not in (1, 2, 3) or view["tombstone"] or view["owner_id"] != "agent_" + provider_id.hex():
        raise RuntimeError("existing Capability does not match the expected lineage")
    if view["sequence"] == 1:
        current = gate.native_state(gate.account_data(config_path, capability_address.to_str()))
        legacy_version = b"1.1.0"
        legacy_manifest_digest = bytes.fromhex("c3155c8b56939dcaa3884e49035fc32b723fe64891ef8b7f1a50ac56468845c2")
        details = (gate.Builder().store_bytes(provider_id).store_bytes(hashlib.sha256(legacy_version).digest())
                   .store_bytes(legacy_manifest_digest).store_ref(gate.Builder().store_bytes(legacy_version).end_cell()).end_cell())
        action = gate.action(gate.ADD_CAPABILITY_VERSION, 2, 1, 2, capability_id,
            current.hash, 0x83, signed_domain, details)
        query = int.from_bytes(action.hash[:8], "big")
        gate.send_wallet_message(config_path, payer_key, payer, provider_address, 5 * gate.NANO,
            gate.body(gate.OP_AUTHORIZE_CAPABILITY, query, action,
                gate.signature_set(provider_key, action), gate.signature_set(None, action)))
        view = gate.wait_state(config_path, capability_address.to_str(), 1, 2)
        deployed_now = True
    if view["sequence"] == 2:
        current = gate.native_state(gate.account_data(config_path, capability_address.to_str()))
        details = (gate.Builder().store_bytes(provider_id).store_bytes(hashlib.sha256(capability_version).digest())
                   .store_bytes(manifest_digest).store_ref(gate.Builder().store_bytes(capability_version).end_cell()).end_cell())
        action = gate.action(gate.ADD_CAPABILITY_VERSION, 2, 1, 3, capability_id,
            current.hash, 0x84, signed_domain, details)
        query = int.from_bytes(action.hash[:8], "big")
        gate.send_wallet_message(config_path, payer_key, payer, provider_address, 5 * gate.NANO,
            gate.body(gate.OP_AUTHORIZE_CAPABILITY, query, action,
                gate.signature_set(provider_key, action), gate.signature_set(None, action)))
        view = gate.wait_state(config_path, capability_address.to_str(), 1, 3)
        deployed_now = True
    if view["sequence"] != 3:
        raise RuntimeError("software-work Capability version was not finalized")

    endpoints = [f"http://127.0.0.1:{port}/jsonRPC" for port in (8011, 8012, 8013)]
    heads = [rpc(endpoint, "getMasterchainInfo") for endpoint in endpoints]
    checkpoint = min(head["last"]["seqno"] for head in heads)
    endpoint_evidence = []
    votes = set()
    for endpoint in endpoints:
        info = rpc(endpoint, "getAddressInformation", address=capability_address.to_str(), seqno=checkpoint)
        if info.get("state") != "active" or info["block_id"]["seqno"] != checkpoint:
            raise RuntimeError(f"non-finalized Capability response from {endpoint}")
        observed_code = gate.Cell.one_from_boc(base64.b64decode(info["code"]))
        observed_data = gate.Cell.one_from_boc(base64.b64decode(info["data"]))
        observed = gate.state_view(observed_data)
        if observed_code.hash != code.hash or observed != view:
            raise RuntimeError(f"Capability disagreement at {endpoint}")
        vote = (info["block_id"]["root_hash"], info["block_id"]["file_hash"], observed_data.hash.hex())
        votes.add(vote)
        endpoint_evidence.append({"endpoint": endpoint, "checkpoint": checkpoint, "block_root_hash": info["block_id"]["root_hash"], "block_file_hash": info["block_id"]["file_hash"], "data_hash": "tvm-cell-sha256:" + observed_data.hash.hex()})
    if len(votes) != 1:
        raise RuntimeError("three endpoints did not produce one Capability state vote")

    evidence = {
        "schema": "atos.native.software-work-capability-deployment.v1",
        "deployed_now": deployed_now,
        "network": {"network_id": args.network_id, "genesis_root_hash": "sha256:" + root.hex(), "genesis_file_hash": "sha256:" + file_hash.hex()},
        "capability_version": capability_version.decode(),
        "manifest": {"protocol": vector["manifest"]["protocol"], "version": vector["manifest"]["version"], "digest": vector["expected"]["digest"], "canonical_cbor_base64": vector["expected"]["canonical_cbor_base64"]},
        "provider_agent_id": "agent_" + provider_id.hex(),
        "provider_agent_address": provider_address.to_str(),
        "capability_id": "cap_" + capability_id.hex(),
        "capability_address": capability_address.to_str(),
        "registry_code_hash": "tvm-cell-sha256:" + code.hash.hex(),
        "state": view,
        "transaction": gate.account_transaction(config_path, capability_address.to_str()),
        "checkpoint": gate.master_checkpoint(config_path),
        "endpoint_verification": endpoint_evidence,
        "quorum": 2,
        "verdict": "PASS_SOFTWARE_WORK_CAPABILITY_VERSION_BINDING"
    }
    Path(args.evidence).write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
