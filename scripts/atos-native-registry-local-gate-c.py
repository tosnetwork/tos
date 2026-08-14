#!/usr/bin/env python3
"""Deploy and exercise the ATOS Native Registry on a running local TOS chain.

This is node-backed Gate C rehearsal evidence, not public-testnet acceptance.
It sends every action through the genesis wallet and verifies committed account
data through each configured liteserver. Controller keys come from a tosctl
test-only identity fixture and are never written to the evidence file.
"""

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "test/tostester/src"))

import nacl.signing  # noqa: E402
from atos_test_identities import load_test_identity  # noqa: E402
from pytosiq_core import (  # noqa: E402
    Address,
    Builder,
    Cell,
    CurrencyCollection,
    ExternalMsgInfo,
    InternalMsgInfo,
    MessageAny,
    StateInit,
    WalletMessage,
)

MAGIC_DATA = 0x4E564431
MAGIC_ACTION = 0x4E564131
MAGIC_STATE = 0x4E565331
MAGIC_POLICY = 0x4E565031
MAGIC_IDENTITY = 0x4E564931
OP_SUBMIT = 0x4E560001
OP_AUTHORIZE_CAPABILITY = 0x4E560002

REGISTER_AGENT = 1
UPDATE_AGENT_POLICY = 2
INITIATE_RECOVERY = 4
COMPLETE_RECOVERY = 5
REVOKE_AGENT = 6
REGISTER_CAPABILITY = 7
ADD_CAPABILITY_VERSION = 8
TRANSFER_CAPABILITY = 9
REVOKE_CAPABILITY = 10

NANO = 1_000_000_000
CODE_HASH = "600f2fda83462bc86a1c32af930c35a4fc8f80f1d2966f5593ceba217a91ffa0"


def read_private(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except PermissionError:
        return subprocess.run(
            ["sudo", "-n", "cat", str(path)], check=True, capture_output=True
        ).stdout


def lite(config: Path, *commands: str, timeout: int = 30) -> str:
    argv = ["/usr/local/bin/tos-lite-client", "-C", str(config), "-v", "0"]
    for command in commands:
        argv += ["-c", command]
    argv += ["-c", "quit"]
    result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout + result.stderr


def seqno(config: Path, address: str) -> int:
    output = lite(config, "time", f"runmethod {address} seqno")
    match = re.search(r"result:\s*\[\s*(\d+)\s*\]", output)
    if not match:
        raise RuntimeError(f"cannot read wallet seqno: {output}")
    return int(match.group(1))


def account_output(config: Path, address: str) -> str:
    return lite(config, "time", f"getaccount {address}")


def account_transaction(config: Path, address: str) -> dict:
    output = account_output(config, address)
    match = re.search(r"last transaction lt = (\d+) hash = ([0-9A-Fa-f]{64})", output)
    if not match:
        raise RuntimeError(f"cannot read account transaction: {output}")
    return {"lt": int(match.group(1)), "hash": match.group(2).lower()}


def master_checkpoint(config: Path) -> dict:
    output = lite(config, "time", "last")
    match = re.search(
        r"latest masterchain block known to server is \(-1,8000000000000000,(\d+)\):"
        r"([0-9A-Fa-f]{64}):([0-9A-Fa-f]{64}) created at (\d+)",
        output,
    )
    if not match:
        raise RuntimeError(f"cannot read master checkpoint: {output}")
    return {
        "seqno": int(match.group(1)),
        "root_hash": match.group(2).lower(),
        "file_hash": match.group(3).lower(),
        "unix_time": int(match.group(4)),
    }


def account_cell(config: Path, address: str, component: str) -> Cell:
    if component not in {"code", "data"}:
        raise ValueError("account component must be code or data")
    with tempfile.NamedTemporaryFile(suffix=".boc", delete=False) as output:
        path = Path(output.name)
    try:
        path.unlink(missing_ok=True)
        text = lite(config, "time", f"saveaccount{component} {path} {address}")
        if not path.exists():
            raise RuntimeError(f"account {component} unavailable for {address}: {text}")
        return Cell.one_from_boc(path.read_bytes())
    finally:
        path.unlink(missing_ok=True)


def account_data(config: Path, address: str) -> Cell:
    return account_cell(config, address, "data")


def account_code(config: Path, address: str) -> Cell:
    return account_cell(config, address, "code")


def native_state(data: Cell) -> Cell:
    value = data.begin_parse()
    if value.load_uint(32) != MAGIC_DATA or value.load_uint(16) != 1:
        raise RuntimeError("unexpected Native account data")
    value.load_uint(8)
    value.load_bytes(32)
    value.load_ref()
    if not value.load_bit():
        raise RuntimeError("Native object is not registered")
    return value.load_ref()


def state_view(data: Cell) -> dict:
    state = native_state(data)
    value = state.begin_parse()
    if value.load_uint(32) != MAGIC_STATE or value.load_uint(16) != 1:
        raise RuntimeError("unexpected Native state")
    kind = value.load_uint(8)
    result = {
        "kind": "agent" if kind == 1 else "capability",
        "tombstone": bool(value.load_bit()),
        "generation": value.load_uint(64),
        "sequence": value.load_uint(64),
        "action_hash": value.load_bytes(32).hex(),
        "state_hash": state.hash.hex(),
        "data_hash": data.hash.hex(),
    }
    if kind == 2:
        result["owner_id"] = "agent_" + value.load_bytes(32).hex()
    return result


def policy(key: nacl.signing.SigningKey) -> Cell:
    public = bytes(key.verify_key)
    controller = (
        Builder()
        .store_bytes(public)
        .store_bytes(public)
        .store_uint(1, 32)
        .store_uint(0x0F, 16)
        .store_bit(1)
        .end_cell()
    )
    return (
        Builder()
        .store_uint(MAGIC_POLICY, 32)
        .store_uint(1, 16)
        .store_uint(1, 32)
        .store_uint(1, 32)
        .store_uint(10, 64)
        .store_uint(1, 8)
        .store_ref(controller)
        .end_cell()
    )


def signature_set(key: nacl.signing.SigningKey | None, action: Cell) -> Cell:
    if key is None:
        return Builder().store_uint(0, 8).end_cell()
    public = bytes(key.verify_key)
    entry = Builder().store_bytes(public).store_bytes(key.sign(action.hash).signature).end_cell()
    return Builder().store_uint(1, 8).store_ref(entry).end_cell()


def domain_cell(root: bytes, file: bytes, network: str, code_hash: bytes) -> Cell:
    signed_code = Builder().store_bytes(code_hash).end_cell()
    return (
        Builder()
        .store_bytes(root)
        .store_bytes(file)
        .store_bytes(hashlib.sha256(network.encode()).digest())
        .store_ref(signed_code)
        .end_cell()
    )


def identity_domain(root: bytes, file: bytes, network: str) -> Cell:
    return (
        Builder()
        .store_bytes(root)
        .store_bytes(file)
        .store_bytes(hashlib.sha256(network.encode()).digest())
        .end_cell()
    )


def action(
    kind: int,
    target_kind: int,
    generation: int,
    sequence: int,
    object_id: bytes,
    predecessor: bytes,
    nonce: int,
    domain: Cell,
    payload: Cell,
) -> Cell:
    return (
        Builder()
        .store_uint(MAGIC_ACTION, 32)
        .store_uint(1, 16)
        .store_uint(kind, 8)
        .store_uint(target_kind, 8)
        .store_uint(generation, 64)
        .store_uint(sequence, 64)
        .store_bytes(object_id)
        .store_bytes(predecessor)
        .store_bytes(bytes([nonce]) * 32)
        .store_ref(domain)
        .store_ref(payload)
        .end_cell()
    )


def body(
    opcode: int, query_id: int, action_cell: Cell, authority: Cell, counterparty: Cell
) -> Cell:
    return (
        Builder()
        .store_uint(opcode, 32)
        .store_uint(query_id, 64)
        .store_ref(action_cell)
        .store_ref(authority)
        .store_ref(counterparty)
        .end_cell()
    )


def registry_config(root: bytes, file: bytes, network: str, workchain: int, code: Cell) -> Cell:
    runtime = (
        Builder()
        .store_int(workchain, 32)
        .store_bytes(code.hash)
        .store_ref(Builder().store_bytes(network.encode()).end_cell())
        .store_ref(code)
        .end_cell()
    )
    return (
        Builder()
        .store_bytes(root)
        .store_bytes(file)
        .store_bytes(hashlib.sha256(network.encode()).digest())
        .store_ref(runtime)
        .end_cell()
    )


def state_init(code: Cell, config: Cell, kind: int, object_id: bytes) -> StateInit:
    data = (
        Builder()
        .store_uint(MAGIC_DATA, 32)
        .store_uint(1, 16)
        .store_uint(kind, 8)
        .store_bytes(object_id)
        .store_ref(config)
        .store_bit(0)
        .end_cell()
    )
    return StateInit(code=code, data=data)


def send_wallet_message(
    config: Path,
    key: nacl.signing.SigningKey,
    source: Address,
    destination: Address,
    amount: int,
    message_body: Cell,
    init: StateInit | None = None,
) -> int:
    before = seqno(config, source.to_str())
    internal = MessageAny(
        info=InternalMsgInfo(
            ihr_disabled=True,
            bounce=False,
            bounced=False,
            src=source,
            dest=destination,
            value=CurrencyCollection(amount),
            ihr_fee=0,
            fwd_fee=0,
            created_lt=0,
            created_at=0,
        ),
        init=init,
        body=message_body,
    )
    wallet_message = WalletMessage(send_mode=3, message=internal)
    to_sign = Builder().store_uint(before, 32).store_cell(wallet_message.serialize()).end_cell()
    signed = Builder().store_bytes(key.sign(to_sign.hash).signature).store_cell(to_sign).end_cell()
    external = MessageAny(info=ExternalMsgInfo(None, source, 0), init=None, body=signed)
    with tempfile.NamedTemporaryFile(suffix=".boc", delete=False) as output:
        path = Path(output.name)
        output.write(external.serialize().to_boc())
    try:
        lite(config, "time", f"sendfile {path}")
    finally:
        path.unlink(missing_ok=True)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        time.sleep(0.5)
        if seqno(config, source.to_str()) > before:
            return before + 1
    raise RuntimeError("wallet message was not included")


def wait_state(
    config: Path, address: str, generation: int, sequence: int, timeout: int = 45
) -> dict:
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            data = account_data(config, address)
            view = state_view(data)
            if (view["generation"], view["sequence"]) == (generation, sequence):
                return view
        except Exception as error:  # account may not exist yet
            last_error = error
        time.sleep(0.75)
    raise RuntimeError(f"state {generation}/{sequence} not observed at {address}: {last_error}")


def agent_identity(
    root: bytes, file: bytes, network: str, nonce: bytes, initial_policy: Cell
) -> bytes:
    return (
        Builder()
        .store_uint(MAGIC_IDENTITY, 32)
        .store_uint(1, 8)
        .store_bytes(nonce)
        .store_bytes(initial_policy.hash)
        .store_ref(identity_domain(root, file, network))
        .end_cell()
        .hash
    )


def capability_identity(
    root: bytes,
    file: bytes,
    network: str,
    nonce: bytes,
    owner: bytes,
    version: bytes,
    manifest: bytes,
) -> bytes:
    details = (
        Builder().store_bytes(hashlib.sha256(version).digest()).store_bytes(manifest).end_cell()
    )
    return (
        Builder()
        .store_uint(MAGIC_IDENTITY, 32)
        .store_uint(2, 8)
        .store_bytes(nonce)
        .store_bytes(owner)
        .store_ref(identity_domain(root, file, network))
        .store_ref(details)
        .end_cell()
        .hash
    )


def address_of(workchain: int, init: StateInit) -> Address:
    return Address((workchain, init.serialize().hash))


def git_head(path: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"], check=True, text=True, capture_output=True
    ).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--global-config", default="/data/tos-global.json")
    parser.add_argument("--state-dir", default="/data/testnet/state")
    parser.add_argument("--network-id", default="tos-local-gate-c-20260814")
    parser.add_argument(
        "--test-identities",
        default=str(REPO.parent / "atos-spec/test-vectors/atos-test-identities-v1.json"),
    )
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()

    config_path = Path(args.global_config)
    global_config = json.loads(config_path.read_text())
    zero = global_config["validator"]["zero_state"]
    root = base64.b64decode(zero["root_hash"])
    file = base64.b64decode(zero["file_hash"])
    network = args.network_id
    workchain = 0

    code_bytes = base64.b64decode(
        b"".join(
            (REPO / "crypto/smartcont/atos-native-registry-v1.boc.base64").read_bytes().split()
        ),
        validate=True,
    )
    code = Cell.one_from_boc(code_bytes)
    if code.hash.hex() != CODE_HASH:
        raise RuntimeError(f"frozen code hash mismatch: {code.hash.hex()}")
    config = registry_config(root, file, network, workchain, code)
    signed_domain = domain_cell(root, file, network, code.hash)

    state_dir = Path(args.state_dir)
    payer_key = nacl.signing.SigningKey(read_private(state_dir / "main-wallet.pk"))
    address_file = read_private(state_dir / "main-wallet.addr")
    payer = Address((int.from_bytes(address_file[32:36], "big", signed=True), address_file[:32]))

    identities = Path(args.test_identities)
    key_a0 = load_test_identity(identities, "agent-a-controller-0")
    key_a1 = load_test_identity(identities, "agent-a-controller-1")
    key_recovery = load_test_identity(identities, "agent-recovery")
    key_b = load_test_identity(identities, "provider-controller")
    policy_a0, policy_a1, policy_recovery, policy_b = map(
        policy, (key_a0, key_a1, key_recovery, key_b)
    )
    nonce_a, nonce_b, nonce_cap = bytes([0x71]) * 32, bytes([0x72]) * 32, bytes([0x73]) * 32
    id_a = agent_identity(root, file, network, nonce_a, policy_a0)
    id_b = agent_identity(root, file, network, nonce_b, policy_b)
    init_a = state_init(code, config, 1, id_a)
    init_b = state_init(code, config, 1, id_b)
    addr_a, addr_b = address_of(workchain, init_a), address_of(workchain, init_b)

    evidence = {
        "schema": "atos.native.gate-c.local-rehearsal.v1",
        "qualifies_as_public_testnet_gate_c": False,
        "reason": "single-host validators and liteservers are not independently operated public infrastructure",
        "network": {
            "network_id": network,
            "global_id": 3,
            "genesis_root_hash": root.hex(),
            "genesis_file_hash": file.hex(),
            "config_param_8_version": 14,
            "genesis_validators": 4,
            "online_validators": 3,
            "liteserver_ports": [entry["port"] for entry in global_config["liteservers"]],
        },
        "release": {
            "code_hash": "tvm-cell-sha256:" + code.hash.hex(),
            "boc_sha256": "sha256:" + hashlib.sha256(code_bytes).hexdigest(),
            "boc_bytes": len(code_bytes),
        },
        "source_commits": {
            "tos": git_head(REPO),
            "tos_protocol": git_head(REPO.parent / "tos-protocol"),
            "atos_spec": git_head(REPO.parent / "atos-spec"),
        },
        "payer": payer.to_str(),
        "steps": [],
    }
    query = 1

    def record(name: str, address: Address, view: dict, extra: dict | None = None):
        item = {
            "name": name,
            "address": address.to_str(),
            "state": view,
            "transaction": account_transaction(config_path, address.to_str()),
            "checkpoint": master_checkpoint(config_path),
        }
        if extra:
            item.update(extra)
        evidence["steps"].append(item)
        print(
            f"PASS {name}: {address.to_str()} {view['generation']}/{view['sequence']} {view['state_hash']}"
        )

    def register_agent(
        agent_id: bytes, nonce: bytes, initial_policy: Cell, key, init: StateInit, addr: Address
    ):
        nonlocal query
        payload = Builder().store_bytes(nonce).store_ref(initial_policy).end_cell()
        act = action(REGISTER_AGENT, 1, 1, 1, agent_id, bytes(32), query, signed_domain, payload)
        send_wallet_message(
            config_path,
            payer_key,
            payer,
            addr,
            20 * NANO,
            body(OP_SUBMIT, query, act, signature_set(key, act), signature_set(None, act)),
            init,
        )
        query += 1
        return wait_state(config_path, addr.to_str(), 1, 1)

    record(
        "agent_a_register",
        addr_a,
        register_agent(id_a, nonce_a, policy_a0, key_a0, init_a, addr_a),
        {"object_id": "agent_" + id_a.hex()},
    )
    record(
        "agent_b_register",
        addr_b,
        register_agent(id_b, nonce_b, policy_b, key_b, init_b, addr_b),
        {"object_id": "agent_" + id_b.hex()},
    )

    current = native_state(account_data(config_path, addr_a.to_str()))
    payload = Builder().store_ref(policy_a1).end_cell()
    act = action(UPDATE_AGENT_POLICY, 1, 1, 2, id_a, current.hash, query, signed_domain, payload)
    send_wallet_message(
        config_path,
        payer_key,
        payer,
        addr_a,
        5 * NANO,
        body(OP_SUBMIT, query, act, signature_set(key_a0, act), signature_set(key_a1, act)),
    )
    query += 1
    record("agent_a_policy_update", addr_a, wait_state(config_path, addr_a.to_str(), 1, 2))

    current = native_state(account_data(config_path, addr_a.to_str()))
    execute_after = int(time.time()) + 12
    payload = Builder().store_uint(execute_after, 64).store_ref(policy_recovery).end_cell()
    act = action(INITIATE_RECOVERY, 1, 1, 3, id_a, current.hash, query, signed_domain, payload)
    initiation_hash = act.hash
    send_wallet_message(
        config_path,
        payer_key,
        payer,
        addr_a,
        5 * NANO,
        body(OP_SUBMIT, query, act, signature_set(key_a1, act), signature_set(key_recovery, act)),
    )
    query += 1
    record(
        "agent_a_recovery_initiate",
        addr_a,
        wait_state(config_path, addr_a.to_str(), 1, 3),
        {"execute_after": execute_after},
    )
    while time.time() <= execute_after + 1:
        time.sleep(0.5)
    current = native_state(account_data(config_path, addr_a.to_str()))
    payload = Builder().store_bytes(initiation_hash).end_cell()
    act = action(COMPLETE_RECOVERY, 1, 2, 1, id_a, current.hash, query, signed_domain, payload)
    send_wallet_message(
        config_path,
        payer_key,
        payer,
        addr_a,
        5 * NANO,
        body(OP_SUBMIT, query, act, signature_set(key_a1, act), signature_set(None, act)),
    )
    query += 1
    record("agent_a_recovery_complete", addr_a, wait_state(config_path, addr_a.to_str(), 2, 1))

    version_100 = b"1.0.0"
    version_110 = b"1.1.0"
    manifest_100 = bytes([0x81]) * 32
    cap_id = capability_identity(root, file, network, nonce_cap, id_a, version_100, manifest_100)
    cap_init = state_init(code, config, 2, cap_id)
    cap_addr = address_of(workchain, cap_init)
    details = (
        Builder()
        .store_bytes(hashlib.sha256(version_100).digest())
        .store_bytes(manifest_100)
        .store_ref(Builder().store_bytes(version_100).end_cell())
        .end_cell()
    )
    payload = Builder().store_bytes(nonce_cap).store_bytes(id_a).store_ref(details).end_cell()
    act = action(REGISTER_CAPABILITY, 2, 1, 1, cap_id, bytes(32), query, signed_domain, payload)
    send_wallet_message(
        config_path,
        payer_key,
        payer,
        addr_a,
        20 * NANO,
        body(
            OP_AUTHORIZE_CAPABILITY,
            query,
            act,
            signature_set(key_recovery, act),
            signature_set(None, act),
        ),
    )
    query += 1
    record(
        "capability_register",
        cap_addr,
        wait_state(config_path, cap_addr.to_str(), 1, 1),
        {"object_id": "cap_" + cap_id.hex()},
    )

    current = native_state(account_data(config_path, cap_addr.to_str()))
    payload = (
        Builder()
        .store_bytes(id_a)
        .store_bytes(hashlib.sha256(version_110).digest())
        .store_bytes(bytes([0x82]) * 32)
        .store_ref(Builder().store_bytes(version_110).end_cell())
        .end_cell()
    )
    act = action(
        ADD_CAPABILITY_VERSION, 2, 1, 2, cap_id, current.hash, query, signed_domain, payload
    )
    send_wallet_message(
        config_path,
        payer_key,
        payer,
        addr_a,
        5 * NANO,
        body(
            OP_AUTHORIZE_CAPABILITY,
            query,
            act,
            signature_set(key_recovery, act),
            signature_set(None, act),
        ),
    )
    query += 1
    record("capability_add_version", cap_addr, wait_state(config_path, cap_addr.to_str(), 1, 2))

    current = native_state(account_data(config_path, cap_addr.to_str()))
    payload = (
        Builder()
        .store_bytes(id_a)
        .store_bit(1)
        .store_bytes(hashlib.sha256(version_110).digest())
        .store_ref(Builder().store_bytes(version_110).end_cell())
        .end_cell()
    )
    act = action(REVOKE_CAPABILITY, 2, 1, 3, cap_id, current.hash, query, signed_domain, payload)
    send_wallet_message(
        config_path,
        payer_key,
        payer,
        addr_a,
        5 * NANO,
        body(
            OP_AUTHORIZE_CAPABILITY,
            query,
            act,
            signature_set(key_recovery, act),
            signature_set(None, act),
        ),
    )
    query += 1
    record("capability_revoke_version", cap_addr, wait_state(config_path, cap_addr.to_str(), 1, 3))

    current = native_state(account_data(config_path, cap_addr.to_str()))
    payload = Builder().store_bytes(id_a).store_bytes(id_b).end_cell()
    act = action(TRANSFER_CAPABILITY, 2, 2, 1, cap_id, current.hash, query, signed_domain, payload)
    send_wallet_message(
        config_path,
        payer_key,
        payer,
        addr_a,
        8 * NANO,
        body(
            OP_AUTHORIZE_CAPABILITY,
            query,
            act,
            signature_set(key_recovery, act),
            signature_set(key_b, act),
        ),
    )
    query += 1
    transferred = wait_state(config_path, cap_addr.to_str(), 2, 1)
    if transferred.get("owner_id") != "agent_" + id_b.hex():
        raise RuntimeError("Capability transfer did not atomically install the new owner")
    record("capability_atomic_transfer", cap_addr, transferred)

    current = native_state(account_data(config_path, cap_addr.to_str()))
    old_hash = current.hash.hex()
    payload = (
        Builder()
        .store_bytes(id_a)
        .store_bytes(hashlib.sha256(b"2.0.0").digest())
        .store_bytes(bytes([0x83]) * 32)
        .store_ref(Builder().store_bytes(b"2.0.0").end_cell())
        .end_cell()
    )
    act = action(
        ADD_CAPABILITY_VERSION, 2, 2, 2, cap_id, current.hash, query, signed_domain, payload
    )
    send_wallet_message(
        config_path,
        payer_key,
        payer,
        addr_a,
        5 * NANO,
        body(
            OP_AUTHORIZE_CAPABILITY,
            query,
            act,
            signature_set(key_recovery, act),
            signature_set(None, act),
        ),
    )
    query += 1
    time.sleep(3)
    rejected = state_view(account_data(config_path, cap_addr.to_str()))
    if rejected["state_hash"] != old_hash:
        raise RuntimeError("former owner changed Capability state")
    record(
        "capability_former_owner_rejected", cap_addr, rejected, {"expected_state_unchanged": True}
    )

    current = native_state(account_data(config_path, cap_addr.to_str()))
    payload = Builder().store_bytes(id_b).store_bit(0).end_cell()
    act = action(REVOKE_CAPABILITY, 2, 2, 2, cap_id, current.hash, query, signed_domain, payload)
    send_wallet_message(
        config_path,
        payer_key,
        payer,
        addr_b,
        5 * NANO,
        body(
            OP_AUTHORIZE_CAPABILITY, query, act, signature_set(key_b, act), signature_set(None, act)
        ),
    )
    query += 1
    terminal = wait_state(config_path, cap_addr.to_str(), 2, 2)
    if not terminal["tombstone"]:
        raise RuntimeError("Capability terminal revocation did not tombstone state")
    record("capability_terminal_revoke", cap_addr, terminal)

    current = native_state(account_data(config_path, addr_a.to_str()))
    act = action(
        REVOKE_AGENT, 1, 2, 2, id_a, current.hash, query, signed_domain, Builder().end_cell()
    )
    send_wallet_message(
        config_path,
        payer_key,
        payer,
        addr_a,
        5 * NANO,
        body(OP_SUBMIT, query, act, signature_set(key_recovery, act), signature_set(None, act)),
    )
    revoked_agent = wait_state(config_path, addr_a.to_str(), 2, 2)
    if not revoked_agent["tombstone"]:
        raise RuntimeError("Agent revocation did not tombstone state")
    record("agent_a_terminal_revoke", addr_a, revoked_agent)

    endpoint_results = []
    with tempfile.TemporaryDirectory() as temporary:
        for entry in global_config["liteservers"]:
            endpoint_config = dict(global_config)
            endpoint_config["liteservers"] = [entry]
            endpoint_path = Path(temporary) / f"liteserver-{entry['port']}.json"
            endpoint_path.write_text(json.dumps(endpoint_config))
            endpoint_results.append(
                {
                    "port": entry["port"],
                    "checkpoint": master_checkpoint(endpoint_path),
                    "deployed_code_hash": "tvm-cell-sha256:"
                    + account_code(endpoint_path, addr_a.to_str()).hash.hex(),
                    "agent_a": state_view(account_data(endpoint_path, addr_a.to_str())),
                    "agent_b": state_view(account_data(endpoint_path, addr_b.to_str())),
                    "capability": state_view(account_data(endpoint_path, cap_addr.to_str())),
                }
            )
    final_hashes = {
        (
            item["agent_a"]["state_hash"],
            item["agent_b"]["state_hash"],
            item["capability"]["state_hash"],
        )
        for item in endpoint_results
    }
    if len(final_hashes) != 1:
        raise RuntimeError("local liteservers disagree on finalized Native state")
    if any(
        item["deployed_code_hash"] != "tvm-cell-sha256:" + CODE_HASH for item in endpoint_results
    ):
        raise RuntimeError("local liteserver returned an unexpected Registry code hash")
    evidence["endpoint_verification"] = endpoint_results
    evidence["verdict"] = "PASS_LOCAL_REHEARSAL_ONLY"
    evidence_path = Path(args.evidence)
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"PASS local Gate C rehearsal; evidence: {evidence_path}")
    print("NOT ACCEPTED as Gate C: public independently operated infrastructure was not used")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
