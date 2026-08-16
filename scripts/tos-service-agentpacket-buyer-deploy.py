#!/usr/bin/env python3
"""Deploy one live local Native Agent for real Agent Packet transport tests."""

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
sys.path[:0] = [str(REPO / "scripts"), str(REPO / "test/tostester/src")]

import nacl.signing  # noqa: E402
from pytosiq_core import Address, Cell  # noqa: E402
from tos_service_test_identities import load_test_identity  # noqa: E402


def load_gate():
    source = REPO / "scripts/tos-service-native-registry-local-gate-c.py"
    spec = importlib.util.spec_from_file_location("native_gate_c", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load_gate()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--global-config", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--network-id", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument(
        "--test-identities",
        default=str(SPEC / "test-vectors/tos-service-test-identities-v1.json"),
    )
    parser.add_argument("--role", default="test-usdt-buyer")
    args = parser.parse_args()

    config_path = Path(args.global_config).resolve()
    state_dir = Path(args.state_dir).resolve()
    identities = Path(args.test_identities).resolve()
    global_config = json.loads(config_path.read_text())
    zero = global_config["validator"]["zero_state"]
    root = base64.b64decode(zero["root_hash"])
    file_hash = base64.b64decode(zero["file_hash"])
    code_bytes = base64.b64decode(
        b"".join(
            (
                REPO
                / "crypto/smartcont/tos-service-native-registry-v1.boc.base64"
            ).read_bytes().split()
        ),
        validate=True,
    )
    code = Cell.one_from_boc(code_bytes)
    if code.hash.hex() != gate.CODE_HASH:
        raise RuntimeError("frozen Native Registry code hash mismatch")

    registry = gate.registry_config(root, file_hash, args.network_id, 0, code)
    signed_domain = gate.domain_cell(root, file_hash, args.network_id, code.hash)
    controller = load_test_identity(identities, args.role)
    initial_policy = gate.policy(controller)
    nonce = hashlib.sha256(b"tos-service-local-agentpacket-buyer-v1").digest()
    agent_id = gate.agent_identity(
        root, file_hash, args.network_id, nonce, initial_policy
    )
    init = gate.state_init(code, registry, 1, agent_id)
    address = gate.address_of(0, init)

    deployed_now = False
    try:
        view = gate.state_view(gate.account_data(config_path, address.to_str()))
    except Exception:
        payer_key = nacl.signing.SigningKey(
            gate.read_private(state_dir / "main-wallet.pk")
        )
        address_file = gate.read_private(state_dir / "main-wallet.addr")
        payer = Address(
            (
                int.from_bytes(address_file[32:36], "big", signed=True),
                address_file[:32],
            )
        )
        query = int(time.time_ns()) & ((1 << 64) - 1)
        payload = gate.Builder().store_bytes(nonce).store_ref(initial_policy).end_cell()
        action = gate.action(
            gate.REGISTER_AGENT,
            1,
            1,
            1,
            agent_id,
            bytes(32),
            0x74,
            signed_domain,
            payload,
        )
        gate.send_wallet_message(
            config_path,
            payer_key,
            payer,
            address,
            20 * gate.NANO,
            gate.body(
                gate.OP_SUBMIT,
                query,
                action,
                gate.signature_set(controller, action),
                gate.signature_set(None, action),
            ),
            init,
        )
        view = gate.wait_state(config_path, address.to_str(), 1, 1)
        deployed_now = True

    if view["tombstone"] or view["generation"] != 1 or view["sequence"] != 1:
        raise RuntimeError("Agent Packet buyer Agent is not live")
    evidence = {
        "schema": "tos.service.local-agentpacket-buyer.v1",
        "verdict": "PASS_LIVE_LOCAL_AGENTPACKET_BUYER",
        "network_id": args.network_id,
        "role": args.role,
        "agent_id": "agent_" + agent_id.hex(),
        "registry_address": address.to_str(),
        "registry_address_raw": (
            f"{address.to_tl_account_id()['workchain']}:"
            f"{address.to_tl_account_id()['id']}"
        ),
        "state": view,
        "transaction": gate.account_transaction(config_path, address.to_str()),
        "checkpoint": gate.master_checkpoint(config_path),
        "deployed_now": deployed_now,
    }
    output = Path(args.evidence).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"PASS live Agent Packet buyer: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
