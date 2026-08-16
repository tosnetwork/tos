#!/usr/bin/env python3
"""Bind the frozen software-work manifest to a fresh Native Capability."""

import argparse
import base64
import hashlib
import importlib.util
import json
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SPEC = REPO.parent / "tos-service-spec"
sys.path.insert(0, str(REPO / "test/tostester/src"))

import nacl.signing  # noqa: E402
from tos_service_test_identities import load_test_identity  # noqa: E402

MODULE_PATH = REPO / "scripts/tos-service-native-registry-local-gate-c.py"
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
        default=str(SPEC / "test-vectors/tos-service-test-identities-v1.json"),
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
        (REPO / "crypto/smartcont/tos-service-native-registry-v1.boc.base64").read_bytes().split())))
    if code.hash.hex() != gate.CODE_HASH:
        raise RuntimeError("frozen Native Registry code hash mismatch")
    config = gate.registry_config(root, file_hash, args.network_id, 0, code)
    signed_domain = gate.domain_cell(root, file_hash, args.network_id, code.hash)

    payer_key = nacl.signing.SigningKey(gate.read_private(Path(args.state_dir) / "main-wallet.pk"))
    address_file = gate.read_private(Path(args.state_dir) / "main-wallet.addr")
    payer = gate.Address((int.from_bytes(address_file[32:36], "big", signed=True), address_file[:32]))
    provider_key = load_test_identity(Path(args.test_identities), "provider-controller")
    provider_nonce = bytes([0x72]) * 32
    provider_policy = gate.policy(provider_key)
    provider_id = gate.agent_identity(root, file_hash, args.network_id, provider_nonce, provider_policy)
    provider_init = gate.state_init(code, config, 1, provider_id)
    provider_address = gate.address_of(0, provider_init)
    provider_state = gate.state_view(gate.account_data(config_path, provider_address.to_str()))
    if provider_state["tombstone"] or provider_state["generation"] != 1 or provider_state["sequence"] != 1:
        raise RuntimeError("active provider Agent from the current local Gate C rehearsal is absent")

    capability_version = b"1.2.0"
    capability_nonce = hashlib.sha256(b"tos-service-local-software-work-capability-v1").digest()
    capability_id = gate.capability_identity(root, file_hash, args.network_id, capability_nonce,
        provider_id, capability_version, manifest_digest)
    capability_init = gate.state_init(code, config, 2, capability_id)
    capability_address = gate.address_of(0, capability_init)
    deployed_now = False
    try:
        view = gate.state_view(gate.account_data(config_path, capability_address.to_str()))
    except Exception:
        details = (gate.Builder().store_bytes(hashlib.sha256(capability_version).digest())
                   .store_bytes(manifest_digest)
                   .store_ref(gate.Builder().store_bytes(capability_version).end_cell()).end_cell())
        payload = (gate.Builder().store_bytes(capability_nonce).store_bytes(provider_id)
                   .store_ref(details).end_cell())
        query = int(time.time_ns()) & ((1 << 64) - 1)
        action = gate.action(gate.REGISTER_CAPABILITY, 2, 1, 1, capability_id,
            bytes(32), 0x83, signed_domain, payload)
        gate.send_wallet_message(config_path, payer_key, payer, provider_address, 20 * gate.NANO,
            gate.body(gate.OP_AUTHORIZE_CAPABILITY, query, action,
                gate.signature_set(provider_key, action), gate.signature_set(None, action)))
        view = gate.wait_state(config_path, capability_address.to_str(), 1, 1)
        deployed_now = True
    if (view["generation"] != 1 or view["sequence"] != 1 or view["tombstone"]
            or view["owner_id"] != "agent_" + provider_id.hex()):
        raise RuntimeError("software-work Capability does not match the expected current lineage")

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
        "schema": "tos.service.software-work-capability-deployment.v1",
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
