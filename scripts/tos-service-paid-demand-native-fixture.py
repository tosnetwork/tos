#!/usr/bin/env python3
"""Create the live Native authority used by the OpenFox three-node campaign.

This is an opt-in local acceptance fixture, not a production key path.  It
registers one deterministic provider Agent and one long-lived Capability, then
can append a uniquely named task version committing an exact execution
manifest digest.  Every mutation is submitted to the real local TOS network;
the caller independently resolves the resulting accounts through all three
JSON-RPC nodes.
"""

import argparse
import base64
import hashlib
import importlib.util
import json
import sys
import time
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

PROVIDER_NONCE = hashlib.sha256(b"openfox-paid-demand-live-provider-v1").digest()
CAPABILITY_NONCE = hashlib.sha256(b"openfox-paid-demand-live-capability-v1").digest()
BASE_VERSION = b"base-v1"
BASE_MANIFEST = hashlib.sha256(b"openfox-paid-demand-live-capability-base-v1").digest()


def read_network(config_path: Path, network_id: str):
    global_config = json.loads(config_path.read_text())
    zero = global_config["validator"]["zero_state"]
    root = base64.b64decode(zero["root_hash"])
    file_hash = base64.b64decode(zero["file_hash"])
    code_bytes = base64.b64decode(
        b"".join(
            (
                REPO / "crypto/smartcont/tos-service-native-registry-v1.boc.base64"
            ).read_bytes().split()
        ),
        validate=True,
    )
    code = gate.Cell.one_from_boc(code_bytes)
    if code.hash.hex() != gate.CODE_HASH:
        raise RuntimeError("frozen Native Registry code hash mismatch")
    return root, file_hash, code


def payer(state_dir: Path):
    key = nacl.signing.SigningKey(gate.read_private(state_dir / "main-wallet.pk"))
    raw = gate.read_private(state_dir / "main-wallet.addr")
    address = gate.Address(
        (int.from_bytes(raw[32:36], "big", signed=True), raw[:32])
    )
    return key, address


def existing_view(config_path: Path, address):
    try:
        return gate.state_view(gate.account_data(config_path, address.to_str()))
    except Exception:
        return None


def action_nonce(query: int) -> int:
    return (query % 255) + 1


def ensure_base(args):
    config_path = Path(args.global_config).resolve()
    state_dir = Path(args.state_dir).resolve()
    identities = Path(args.test_identities).resolve()
    root, file_hash, code = read_network(config_path, args.network_id)
    registry = gate.registry_config(root, file_hash, args.network_id, 0, code)
    signed_domain = gate.domain_cell(root, file_hash, args.network_id, code.hash)
    payer_key, payer_address = payer(state_dir)
    controller = load_test_identity(identities, "provider-controller")
    controller_policy = gate.policy(controller)

    provider_raw = gate.agent_identity(
        root, file_hash, args.network_id, PROVIDER_NONCE, controller_policy
    )
    provider_id = "agent_" + provider_raw.hex()
    provider_init = gate.state_init(code, registry, 1, provider_raw)
    provider_address = gate.address_of(0, provider_init)
    provider_view = existing_view(config_path, provider_address)
    if provider_view is None:
        query = int(time.time_ns()) & ((1 << 64) - 1)
        payload = (
            gate.Builder()
            .store_bytes(PROVIDER_NONCE)
            .store_ref(controller_policy)
            .end_cell()
        )
        action = gate.action(
            gate.REGISTER_AGENT,
            1,
            1,
            1,
            provider_raw,
            bytes(32),
            action_nonce(query),
            signed_domain,
            payload,
        )
        gate.send_wallet_message(
            config_path,
            payer_key,
            payer_address,
            provider_address,
            20 * gate.NANO,
            gate.body(
                gate.OP_SUBMIT,
                query,
                action,
                gate.signature_set(controller, action),
                gate.signature_set(None, action),
            ),
            provider_init,
        )
        provider_view = gate.wait_state(config_path, provider_address.to_str(), 1, 1)
    if (
        provider_view["kind"] != "agent"
        or provider_view["tombstone"]
        or provider_view["generation"] < 1
    ):
        raise RuntimeError("local Paid Demand provider Agent is not active")

    capability_raw = gate.capability_identity(
        root,
        file_hash,
        args.network_id,
        CAPABILITY_NONCE,
        provider_raw,
        BASE_VERSION,
        BASE_MANIFEST,
    )
    capability_id = "cap_" + capability_raw.hex()
    capability_init = gate.state_init(code, registry, 2, capability_raw)
    capability_address = gate.address_of(0, capability_init)
    capability_view = existing_view(config_path, capability_address)
    if capability_view is None:
        details = (
            gate.Builder()
            .store_bytes(hashlib.sha256(BASE_VERSION).digest())
            .store_bytes(BASE_MANIFEST)
            .store_ref(gate.Builder().store_bytes(BASE_VERSION).end_cell())
            .end_cell()
        )
        payload = (
            gate.Builder()
            .store_bytes(CAPABILITY_NONCE)
            .store_bytes(provider_raw)
            .store_ref(details)
            .end_cell()
        )
        query = int(time.time_ns()) & ((1 << 64) - 1)
        action = gate.action(
            gate.REGISTER_CAPABILITY,
            2,
            1,
            1,
            capability_raw,
            bytes(32),
            action_nonce(query),
            signed_domain,
            payload,
        )
        gate.send_wallet_message(
            config_path,
            payer_key,
            payer_address,
            provider_address,
            20 * gate.NANO,
            gate.body(
                gate.OP_AUTHORIZE_CAPABILITY,
                query,
                action,
                gate.signature_set(controller, action),
                gate.signature_set(None, action),
            ),
        )
        capability_view = gate.wait_state(
            config_path, capability_address.to_str(), 1, 1
        )
    if (
        capability_view["kind"] != "capability"
        or capability_view["tombstone"]
        or capability_view.get("owner_id") != provider_id
    ):
        raise RuntimeError("local Paid Demand Capability is not active or has another owner")

    return {
        "schema": "tos.service.openfox-paid-demand-native-fixture.v1",
        "network_id": args.network_id,
        "provider_agent_id": provider_id,
        "provider_agent_address": provider_address.to_str(),
        "capability_id": capability_id,
        "capability_address": capability_address.to_str(),
        "registry_code_hash": "tvm-cell-sha256:" + code.hash.hex(),
        "provider_state": provider_view,
        "capability_state": capability_view,
    }, (config_path, signed_domain, payer_key, payer_address, controller, provider_raw, provider_address, capability_raw, capability_address)


def add_version(args, result, runtime):
    if not args.version or len(args.version.encode()) > 128:
        raise RuntimeError("a bounded task version is required")
    if not args.manifest_digest.startswith("sha256:"):
        raise RuntimeError("a canonical execution manifest digest is required")
    try:
        manifest = bytes.fromhex(args.manifest_digest.removeprefix("sha256:"))
    except ValueError as error:
        raise RuntimeError("execution manifest digest is malformed") from error
    if len(manifest) != 32:
        raise RuntimeError("execution manifest digest is malformed")

    (
        config_path,
        signed_domain,
        payer_key,
        payer_address,
        controller,
        provider_raw,
        provider_address,
        capability_raw,
        capability_address,
    ) = runtime
    data = gate.account_data(config_path, capability_address.to_str())
    state = gate.native_state(data)
    view = gate.state_view(data)
    if view["tombstone"] or view.get("owner_id") != result["provider_agent_id"]:
        raise RuntimeError("Capability cannot accept a task version")
    version = args.version.encode()
    payload = (
        gate.Builder()
        .store_bytes(provider_raw)
        .store_bytes(hashlib.sha256(version).digest())
        .store_bytes(manifest)
        .store_ref(gate.Builder().store_bytes(version).end_cell())
        .end_cell()
    )
    query = int(time.time_ns()) & ((1 << 64) - 1)
    action = gate.action(
        gate.ADD_CAPABILITY_VERSION,
        2,
        view["generation"],
        view["sequence"] + 1,
        capability_raw,
        state.hash,
        action_nonce(query),
        signed_domain,
        payload,
    )
    gate.send_wallet_message(
        config_path,
        payer_key,
        payer_address,
        provider_address,
        5 * gate.NANO,
        gate.body(
            gate.OP_AUTHORIZE_CAPABILITY,
            query,
            action,
            gate.signature_set(controller, action),
            gate.signature_set(None, action),
        ),
    )
    updated = gate.wait_state(
        config_path,
        capability_address.to_str(),
        view["generation"],
        view["sequence"] + 1,
    )
    result["task_version"] = args.version
    result["task_manifest_digest"] = args.manifest_digest
    result["capability_state"] = updated
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--global-config", default="/data/tos-global.json")
    parser.add_argument("--state-dir", default="/data/testnet/state")
    parser.add_argument("--network-id", required=True)
    parser.add_argument(
        "--test-identities",
        default=str(SPEC / "test-vectors/tos-service-test-identities-v1.json"),
    )
    parser.add_argument("--add-version", action="store_true")
    parser.add_argument("--version", default="")
    parser.add_argument("--manifest-digest", default="")
    parser.add_argument("--evidence", default="")
    args = parser.parse_args()

    result, runtime = ensure_base(args)
    if args.add_version:
        result = add_version(args, result, runtime)
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
    if args.evidence:
        output = Path(args.evidence).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(encoded)


if __name__ == "__main__":
    main()
