#!/usr/bin/env python3
"""Deploy a deterministic test-only USDT-style Jetton to the running TOS testnet."""

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "test/tostester/src"))

import nacl.signing  # noqa: E402
from tos_service_test_identities import load_test_identity  # noqa: E402
from contract import WalletV1Blueprint  # noqa: E402
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

CONTRACT_DIR = REPO / "crypto/smartcont/reference/usdt-jetton-master/contracts"
FUNC = REPO / "build/crypto/func"
FIFT = REPO / "build/crypto/fift"
FIFT_LIB = REPO / "crypto/fift/lib"

OP_MINT = 0x642B7D07
OP_INTERNAL_TRANSFER = 0x178D4519
OP_TOP_UP = 0xD372158C
NANO = 1_000_000_000
DEFAULT_SUPPLY = 1_000_000 * 1_000_000
DEFAULT_METADATA_URI = (
    "data:application/json,%7B%22symbol%22%3A%22tUSDT%22%2C%22decimals%22%3A6%7D"
)


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


def rpc(endpoint: str, method: str, **params):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    request = urllib.request.Request(
        endpoint, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        result = json.loads(response.read().decode())
    if not result.get("ok"):
        raise RuntimeError(f"{endpoint} {method}: {result}")
    return result["result"]


def compile_contract(source: str, output: Path, assembly: Path):
    env = dict(os.environ, FIFTPATH=str(FIFT_LIB))
    subprocess.run(
        [str(FUNC), "-W", str(output), "-AP", "-o", str(assembly), source],
        cwd=CONTRACT_DIR,
        env=env,
        check=True,
    )
    subprocess.run([str(FIFT), str(assembly)], cwd=CONTRACT_DIR, env=env, check=True)


def reproducible_contracts(directory: Path) -> tuple[bytes, bytes]:
    if not FUNC.is_file() or not FIFT.is_file():
        raise RuntimeError("build/crypto/func and build/crypto/fift are required")
    outputs = []
    for build in ("a", "b"):
        build_dir = directory / build
        build_dir.mkdir()
        wallet = build_dir / "test-usdt-wallet.boc"
        minter = build_dir / "test-usdt-minter.boc"
        compile_contract("jetton-wallet.fc", wallet, build_dir / "wallet.fif")
        compile_contract("jetton-minter.fc", minter, build_dir / "minter.fif")
        outputs.append((minter.read_bytes(), wallet.read_bytes()))
    if outputs[0] != outputs[1]:
        raise RuntimeError("test USDT contract rebuilds are not byte-identical")
    return outputs[0]


def seqno(config: Path, address: str) -> int:
    output = lite(config, "time", f"runmethod {address} seqno")
    match = re.search(r"result:\s*\[\s*(\d+)\s*\]", output)
    if not match:
        raise RuntimeError(f"cannot read wallet seqno: {output}")
    return int(match.group(1))


def account_cell(config: Path, address: str, component: str) -> Cell:
    if component not in {"code", "data"}:
        raise ValueError("invalid account component")
    with tempfile.NamedTemporaryFile(suffix=".boc", delete=False) as output:
        path = Path(output.name)
    try:
        path.unlink(missing_ok=True)
        text = lite(config, "time", f"saveaccount{component} {path} {address}")
        if not path.exists():
            raise RuntimeError(f"account {component} unavailable: {text}")
        return Cell.one_from_boc(path.read_bytes())
    finally:
        path.unlink(missing_ok=True)


def account_transaction(config: Path, address: str) -> dict:
    output = lite(config, "time", f"getaccount {address}")
    match = re.search(r"last transaction lt = (\d+) hash = ([0-9A-Fa-f]{64})", output)
    if not match:
        raise RuntimeError(f"cannot read account transaction: {output}")
    return {"logical_time": int(match.group(1)), "hash": "sha256:" + match.group(2).lower()}


def send_wallet_message(
    config: Path,
    key: nacl.signing.SigningKey,
    source: Address,
    destination: Address,
    amount: int,
    body: Cell,
    init: StateInit | None = None,
):
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
        body=body,
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
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        time.sleep(0.5)
        if seqno(config, source.to_str()) > before:
            return
    raise RuntimeError("wallet message was not included")


def address_of(init: StateInit) -> Address:
    return Address((0, init.serialize().hash))


def master_view(data: Cell) -> dict:
    value = data.begin_parse()
    supply = value.load_coins()
    admin = value.load_address()
    next_admin = value.load_address()
    wallet_code = value.load_ref()
    metadata_uri = value.load_ref().begin_parse().load_snake_string()
    if value.remaining_bits or value.remaining_refs:
        raise RuntimeError("unexpected test USDT master data suffix")
    return {
        "total_supply": str(supply),
        "admin": admin.to_str() if admin else None,
        "next_admin": next_admin.to_str() if next_admin else None,
        "wallet_code_hash": "tvm-cell-sha256:" + wallet_code.hash.hex(),
        "metadata_uri": metadata_uri,
    }


def wallet_view(data: Cell) -> dict:
    value = data.begin_parse()
    status = value.load_uint(4)
    balance = value.load_coins()
    owner = value.load_address()
    master = value.load_address()
    if value.remaining_bits or value.remaining_refs:
        raise RuntimeError("unexpected test USDT wallet data suffix")
    return {
        "status": status,
        "balance": str(balance),
        "owner": owner.to_str(),
        "master": master.to_str(),
    }


def wallet_v1_view(data: Cell) -> dict:
    value = data.begin_parse()
    sequence = value.load_uint(32)
    public_key = value.load_bytes(32)
    if value.remaining_bits or value.remaining_refs:
        raise RuntimeError("unexpected test buyer wallet data suffix")
    return {"sequence": sequence, "public_key": public_key.hex()}


def wait_view(config: Path, address: Address, decoder, predicate, timeout: int = 60):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            view = decoder(account_cell(config, address.to_str(), "data"))
            if predicate(view):
                return view
        except Exception as error:
            last_error = error
        time.sleep(0.75)
    raise RuntimeError(f"expected state not observed at {address.to_str()}: {last_error}")


def endpoint_account(endpoint: str, address: Address, checkpoint: int) -> tuple[dict, Cell, Cell]:
    info = rpc(endpoint, "getAddressInformation", address=address.to_str(), seqno=checkpoint)
    if info.get("state") != "active" or info["block_id"]["seqno"] != checkpoint:
        raise RuntimeError(f"non-finalized account response from {endpoint}")
    code = Cell.one_from_boc(base64.b64decode(info["code"]))
    data = Cell.one_from_boc(base64.b64decode(info["data"]))
    return info, code, data


def canonical_hash(value: str) -> str:
    return "sha256:" + base64.b64decode(value).hex()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--global-config", default="/data/tos-global.json")
    parser.add_argument("--state-dir", default="/data/testnet/state")
    parser.add_argument("--network-id", default="tos-local-gate-c-20260814")
    parser.add_argument("--metadata-uri", default=DEFAULT_METADATA_URI)
    parser.add_argument("--target-supply", type=int, default=DEFAULT_SUPPLY)
    parser.add_argument(
        "--test-identities",
        default=str(REPO.parent / "tos-service-spec/test-vectors/tos-service-test-identities-v1.json"),
    )
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    if not 0 < args.target_supply < 1 << 120 or len(args.metadata_uri.encode()) > 512:
        raise RuntimeError("invalid bounded test asset parameters")

    config = Path(args.global_config)
    state_dir = Path(args.state_dir)
    private_key = nacl.signing.SigningKey(read_private(state_dir / "main-wallet.pk"))
    address_file = read_private(state_dir / "main-wallet.addr")
    admin = Address(
        (int.from_bytes(address_file[32:36], "big", signed=True), address_file[:32])
    )
    buyer_key_path = Path(args.test_identities)
    buyer_key = load_test_identity(buyer_key_path, "test-usdt-buyer")
    buyer_blueprint = WalletV1Blueprint(workchain=0, private_key=buyer_key)
    buyer = buyer_blueprint.address

    buyer_deployed_now = False
    try:
        buyer_code = account_cell(config, buyer.to_str(), "code")
        if buyer_code.hash != buyer_blueprint.CODE_BOC.hash:
            raise RuntimeError("deterministic test buyer address contains unexpected code")
    except RuntimeError as error:
        if "unavailable" not in str(error):
            raise
        send_wallet_message(
            config,
            private_key,
            admin,
            buyer,
            5 * NANO,
            Cell.empty(),
            buyer_blueprint.state_init,
        )
        wait_view(config, buyer, wallet_v1_view, lambda view: view["sequence"] == 0)
        buyer_deployed_now = True

    with tempfile.TemporaryDirectory() as temporary:
        minter_boc, wallet_boc = reproducible_contracts(Path(temporary))
    minter_code, wallet_code = Cell.one_from_boc(minter_boc), Cell.one_from_boc(wallet_boc)
    metadata = Builder().store_snake_string(args.metadata_uri).end_cell()
    master_data = (
        Builder()
        .store_coins(0)
        .store_address(admin)
        .store_address(None)
        .store_ref(wallet_code)
        .store_ref(metadata)
        .end_cell()
    )
    master_init = StateInit(code=minter_code, data=master_data)
    master = address_of(master_init)
    wallet_data = (
        Builder()
        .store_uint(0, 4)
        .store_coins(0)
        .store_address(buyer)
        .store_address(master)
        .end_cell()
    )
    wallet_init = StateInit(code=wallet_code, data=wallet_data)
    wallet = address_of(wallet_init)

    deployed_now = False
    try:
        existing_code = account_cell(config, master.to_str(), "code")
        if existing_code.hash != minter_code.hash:
            raise RuntimeError("deterministic test asset address contains unexpected code")
    except RuntimeError as error:
        if "unavailable" not in str(error):
            raise
        deploy_body = Builder().store_uint(OP_TOP_UP, 32).store_uint(1, 64).end_cell()
        send_wallet_message(config, private_key, admin, master, 5 * NANO, deploy_body, master_init)
        wait_view(config, master, master_view, lambda view: view["total_supply"] == "0")
        deployed_now = True

    current = master_view(account_cell(config, master.to_str(), "data"))
    if current["admin"] != admin.to_str() or current["metadata_uri"] != args.metadata_uri:
        raise RuntimeError("test asset master configuration mismatch")
    supply = int(current["total_supply"])
    minted_now = False
    if supply == 0:
        query_id = int(time.time())
        internal_transfer = (
            Builder()
            .store_uint(OP_INTERNAL_TRANSFER, 32)
            .store_uint(query_id, 64)
            .store_coins(args.target_supply)
            .store_address(buyer)
            .store_address(buyer)
            .store_coins(0)
            .store_bit(0)
            .end_cell()
        )
        mint = (
            Builder()
            .store_uint(OP_MINT, 32)
            .store_uint(query_id, 64)
            .store_address(buyer)
            .store_coins(2 * NANO)
            .store_ref(internal_transfer)
            .end_cell()
        )
        send_wallet_message(config, private_key, admin, master, 4 * NANO, mint)
        wait_view(
            config,
            master,
            master_view,
            lambda view: int(view["total_supply"]) == args.target_supply,
        )
        wait_view(
            config,
            wallet,
            wallet_view,
            lambda view: int(view["balance"]) == args.target_supply,
        )
        minted_now = True
    elif supply != args.target_supply:
        raise RuntimeError(f"test asset already has unexpected supply {supply}")

    endpoints = [f"http://127.0.0.1:{port}/jsonRPC" for port in (8011, 8012, 8013)]
    chain_heads = [rpc(endpoint, "getMasterchainInfo") for endpoint in endpoints]
    network_votes = {
        (head["init"]["root_hash"], head["init"]["file_hash"]) for head in chain_heads
    }
    if len(network_votes) != 1:
        raise RuntimeError("testnet endpoints disagree on genesis identity")
    checkpoint = min(head["last"]["seqno"] for head in chain_heads)
    endpoint_evidence = []
    votes = set()
    for endpoint in endpoints:
        master_info, observed_minter_code, observed_master_data = endpoint_account(
            endpoint, master, checkpoint
        )
        wallet_info, observed_wallet_code, observed_wallet_data = endpoint_account(
            endpoint, wallet, checkpoint
        )
        observed_master = master_view(observed_master_data)
        observed_wallet = wallet_view(observed_wallet_data)
        if observed_minter_code.hash != minter_code.hash:
            raise RuntimeError(f"unexpected test USDT minter code from {endpoint}")
        if observed_wallet_code.hash != wallet_code.hash:
            raise RuntimeError(f"unexpected test USDT wallet code from {endpoint}")
        if (
            observed_master["total_supply"] != str(args.target_supply)
            or observed_master["admin"] != admin.to_str()
            or observed_master["wallet_code_hash"]
            != "tvm-cell-sha256:" + wallet_code.hash.hex()
            or observed_master["metadata_uri"] != args.metadata_uri
        ):
            raise RuntimeError(f"unexpected test USDT master state from {endpoint}")
        if (
            observed_wallet["status"] != 0
            or observed_wallet["balance"] != str(args.target_supply)
            or observed_wallet["owner"] != buyer.to_str()
            or observed_wallet["master"] != master.to_str()
        ):
            raise RuntimeError(f"unexpected test USDT wallet state from {endpoint}")
        vote = (
            master_info["block_id"]["root_hash"],
            master_info["block_id"]["file_hash"],
            observed_minter_code.hash.hex(),
            observed_master_data.hash.hex(),
            observed_wallet_code.hash.hex(),
            observed_wallet_data.hash.hex(),
        )
        votes.add(vote)
        endpoint_evidence.append(
            {
                "endpoint": endpoint,
                "checkpoint": {
                    "seqno": checkpoint,
                    "root_hash": canonical_hash(master_info["block_id"]["root_hash"]),
                    "file_hash": canonical_hash(master_info["block_id"]["file_hash"]),
                },
                "master_state_hash": "tvm-cell-sha256:" + observed_master_data.hash.hex(),
                "wallet_state_hash": "tvm-cell-sha256:" + observed_wallet_data.hash.hex(),
                "master": observed_master,
                "wallet": observed_wallet,
            }
        )
    if len(votes) != 1:
        raise RuntimeError("testnet endpoints disagree on test USDT state")

    evidence = {
        "schema": "tos.service.test-stablecoin-deployment.v1",
        "status": "active-test-only",
        "deployed_now": deployed_now,
        "buyer_wallet_deployed_now": buyer_deployed_now,
        "minted_now": minted_now,
        "network": {
            "network_id": args.network_id,
            "genesis_root_hash": canonical_hash(chain_heads[0]["init"]["root_hash"]),
            "genesis_file_hash": canonical_hash(chain_heads[0]["init"]["file_hash"]),
        },
        "asset": {
            "name": "TOS Service Protocol Test USDT",
            "symbol": "tUSDT",
            "decimals": 6,
            "master_contract": master.to_str(),
            "master_contract_raw": f"0:{master.hash_part.hex()}",
            "admin": admin.to_str(),
            "metadata_uri": args.metadata_uri,
            "total_supply_atomic": str(args.target_supply),
            "test_buyer_wallet": buyer.to_str(),
            "test_buyer_wallet_key_file": str(buyer_key_path),
            "test_buyer_jetton_wallet_contract": wallet.to_str(),
        },
        "release": {
            "source": "crypto/smartcont/reference/usdt-jetton-master",
            "source_commit": subprocess.run(
                ["git", "-C", str(REPO), "rev-parse", "HEAD"],
                check=True,
                text=True,
                capture_output=True,
            ).stdout.strip(),
            "license": "MIT",
            "minter_code_hash": "tvm-cell-sha256:" + minter_code.hash.hex(),
            "minter_boc_sha256": "sha256:" + hashlib.sha256(minter_boc).hexdigest(),
            "minter_boc_bytes": len(minter_boc),
            "wallet_code_hash": "tvm-cell-sha256:" + wallet_code.hash.hex(),
            "wallet_boc_sha256": "sha256:" + hashlib.sha256(wallet_boc).hexdigest(),
            "wallet_boc_bytes": len(wallet_boc),
            "reproducible_builds": 2,
        },
        "transactions": {
            "master_last": account_transaction(config, master.to_str()),
            "wallet_last": account_transaction(config, wallet.to_str()),
        },
        "quorum": 2,
        "endpoint_verification": endpoint_evidence,
        "limitations": [
            "test-only asset with no claim on real-world USDT reserves",
            "issuer admin can mint, freeze wallets, change metadata, and upgrade code",
            "all initial testnet endpoints are operated on one host",
        ],
        "verdict": "PASS_TEST_STABLECOIN_DEPLOYMENT",
    }
    output = Path(args.evidence)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"PASS tUSDT master: {master.to_str()}")
    print(f"PASS tUSDT wallet: {wallet.to_str()}")
    print(f"PASS supply: {args.target_supply} atomic units")
    print(f"PASS evidence: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
