#!/usr/bin/env python3
"""Disposable three-validator RPC integration using public genesis allocations.

No wallet signing, key possession, release readiness or production admission claim.
The generated accounts contain synthetic public key bytes and receive test funds only.
"""

import argparse
import asyncio
import base64
import hashlib
import json
import os
import signal
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from bounded_process_group import stop_process_group

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
from cells import Cell, from_boc  # noqa: E402


def chain(raw):
    result = None
    for offset in reversed(range(0, len(raw), 127)):
        next_cell = Cell().raw(raw[offset : offset + 127])
        if result is not None:
            next_cell.ref(result)
        result = next_cell
    return result


def fixtures(build, out):
    manifest = json.loads((build / "generated/explorer-pq-registry.json").read_text())
    assert manifest["quantum_wallet_network_tag"] == "42" * 32
    codes = {
        entry["family"]: from_boc((build / ("generated/" + entry["family"] + ".boc")).read_bytes())
        for entry in manifest["codes"]
    }
    public_key = bytes((i % 256 for i in range(1312)))
    namespace = int("42" * 32, 16)
    module = (
        Cell()
        .uint(1, 8)
        .sint(1, 32)
        .uint(namespace, 256)
        .uint(1, 8)
        .uint(456, 256)
        .uint(2, 8)
        .ref(chain(public_key))
    )
    module_init = Cell().uint(6, 5).ref(codes["quantum_module_v1"]).ref(module)
    fee_key = Cell().uint(1, 32).uint(8, 32).uint(3, 32).uint(0, 384)
    fee = (
        Cell()
        .uint(1, 8)
        .uint(1, 8)
        .uint(0, 256)
        .uint(1700000000, 32)
        .uint(3600, 32)
        .uint(4, 16)
        .ref(fee_key)
    )
    auth = (
        Cell()
        .uint(4, 8)
        .uint(2, 2)
        .uint(2, 16)
        .uint(2**64 - 1, 64)
        .uint(42, 64)
        .uint(43, 64)
        .ref(module_init)
        .ref(fee)
    )
    wallet = (
        Cell().uint(0, 1).uint(2**32 - 1, 32).uint(2**32 - 1, 32).uint(0, 256).uint(0, 1).ref(auth)
    )
    wallet_init = Cell().uint(6, 5).ref(codes["quantum_wallet_v4"]).ref(wallet)
    wallet_hash = int.from_bytes(wallet_init.hash, "big")
    module_hash = int.from_bytes(module_init.hash, "big")
    prefix = (
        Cell()
        .uint(0x41553252, 32)
        .sint(1, 32)
        .uint(namespace, 256)
        .addr((0, wallet_hash))
        .uint(module_hash, 256)
        .uint(2, 8)
    )
    parties = Cell().addr((0, wallet_hash)).uint(module_hash, 256)
    vault = (
        Cell()
        .uint(3, 8)
        .uint(1048576, 32)
        .uint(123, 256)
        .uint(1700000000, 32)
        .addr((0, module_hash))
        .uint(int.from_bytes(parties.hash, "big"), 256)
        .ref(fee_key)
        .ref(prefix)
    )
    high = (
        Cell()
        .uint(123, 32)
        .uint(0, 2)
        .uint(2**64 - 1, 64)
        .uint(3600, 22)
        .ref(Cell().uint(1312, 32).ref(chain(public_key)))
    )
    states = {
        "quantum_self_pay_v1": Cell()
        .uint(1, 8)
        .uint(2**32 - 1, 32)
        .uint(7, 32)
        .uint(2, 16)
        .uint(2**64 - 1, 64)
        .uint(42, 64)
        .uint(43, 64)
        .ref(
            Cell()
            .uint(1, 8)
            .sint(1, 32)
            .uint(int("43" * 32, 16), 256)
            .uint(1, 8)
            .uint(456, 256)
            .uint(1, 8)
            .ref(chain(public_key))
        ),
        "quantum_module_v1": module,
        "quantum_wallet_v4": wallet,
        "quantum_fee_vault_v3": vault,
        "pq_highload_mldsa44_v1": high,
        "mldsa44_auth_module_v1": Cell().sint(1, 32).ref(chain(public_key)),
        "falcon512_padded_auth_module_v1": Cell().sint(1, 32).uint(1, 16).ref(chain(bytes(897))),
    }
    # Additional active contracts exercise unknown-code and malformed recognized-code semantics.
    unknown = Cell().uint(1, 1)
    extras = {
        "unknown_code": (unknown, module),
        "malformed_module": (codes["mldsa44_auth_module_v1"], Cell().uint(1, 1)),
    }
    script = [
        '"Fift.fif" include',
        '"TosUtil.fif" include',
        '"State.fif" include',
        "0 setworkchain",
        "1 setglobalid",
    ]
    addresses = {}
    for name, (code, data) in list(
        (name, (codes[name], data)) for name, data in states.items()
    ) + list(extras.items()):
        code_path, data_path = out / (name + "-code.boc"), out / (name + "-data.boc")
        code_path.write_bytes(code.boc())
        data_path.write_bytes(data.boc())
        state_init = Cell().uint(6, 5).ref(code).ref(data)
        addresses[name] = "0:" + state_init.hash.hex()
        script += [
            f'"{code_path}" file>B B>boc',
            f'"{data_path}" file>B B>boc',
            "empty_cell 1000000000000 0 0 2 register_smc",
            f'0x{state_init.hash.hex()} = not abort"fixture address mismatch"',
        ]
    script.append('create_state 31 boc+>B "basestate0.boc" B>file')
    script_path = out / "accounts.fif"
    script_path.write_text("\n".join(script) + "\n")
    with (out / "genesis-build.log").open("w") as log:
        subprocess.run(
            [
                str(build / "crypto/create-state"),
                "-n",
                "-I",
                str(ROOT / "crypto/fift/lib") + ":" + str(ROOT / "crypto/smartcont"),
                "-s",
                str(script_path),
            ],
            cwd=out,
            stdout=log,
            stderr=log,
            check=True,
            timeout=30,
        )
    return addresses


async def serve(build, workdir, rpc_port, base_port, ordinary):
    """Start only the read-only nodes needed for public RPC observations."""
    from tostester.install import Install
    from tostester.network import Network, StartOptions
    from tostester.pq_initial_validator import make_deterministic_pq_initial_validator

    workdir.mkdir(parents=True)
    async with Network(Install(build, ROOT), workdir, base_port=base_port) as network:
        network.config.global_id = 1
        network.config.global_version = 16
        network.config.auth_network_tag = bytes.fromhex(("43" if ordinary else "42") * 32)
        if not ordinary:
            network.config.quantum_admission_candidate = True
            network.config.deployment_fee_schedule = True
            network.config.basechain_fixture = (workdir.parent / "basestate0.boc").read_bytes()
        dht = network.create_dht_node()
        nodes = [network.create_full_node() for _ in range(3)]
        for index, node in enumerate(nodes):
            make_deterministic_pq_initial_validator(node, index)
            node.announce_to(dht)
        (workdir / "lite-client.json").write_text(nodes[0].liteserver_config.to_json())
        await dht.run()
        await asyncio.gather(
            *(
                node.run(StartOptions(args=["--json-rpc-address", f"127.0.0.1:{rpc_port + index}"]))
                for index, node in enumerate(nodes)
            )
        )
        await asyncio.Event().wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--rpc-port", type=int, default=48545)
    parser.add_argument("--base-port", type=int, default=44000)
    parser.add_argument("--serve", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--ordinary-config",
        "--legacy-config",
        dest="legacy_config",
        action="store_true",
        help="Use an ordinary version-16 network with an explicit public test namespace",
    )
    args = parser.parse_args()
    build, out = args.build_dir.resolve(), args.out.resolve()
    if args.serve:
        asyncio.run(serve(build, out, args.rpc_port, args.base_port, args.legacy_config))
        return
    out.mkdir(parents=True, exist_ok=True)
    attempts = out / ("attempt-" + str(time.time_ns()))
    attempts.mkdir()
    out = attempts
    addresses = {} if args.legacy_config else fixtures(build, out)
    (out / "addresses.json").write_text(json.dumps(addresses, indent=2) + "\n")
    records = []

    def request(method, params, *, rest=False, get=False, node=0, error=None):
        """Call one method; ``error`` is the expected (code, reason) of a refusal.

        Every method answer is HTTP 200 on every route: success carries
        ``result``, a refusal carries an ``error`` object whose ``data`` holds
        the stable reason and the retry hint.
        """
        body = params if rest else {"jsonrpc": "2.0", "id": 7, "method": method, "params": params}
        data = None if get else json.dumps(body).encode()
        url = f"http://127.0.0.1:{args.rpc_port + node}/" + (method if rest or get else "jsonRPC")
        if get:
            url += "?" + urllib.parse.urlencode(
                {
                    key: str(value).lower() if isinstance(value, bool) else value
                    for key, value in params.items()
                }
            )
        try:
            with urllib.request.urlopen(
                urllib.request.Request(
                    url, data=data, headers={"Content-Type": "application/json"}
                ),
                timeout=35,
            ) as response:
                status, raw = response.status, response.read(17 << 20)
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read(17 << 20)
        value = json.loads(raw)
        records.append(
            {
                "method": method,
                "params": params,
                "rest": rest,
                "get": get,
                "node": node,
                "http_status": status,
                "response_bytes": len(raw),
                "response_sha256": hashlib.sha256(raw).hexdigest(),
                "response": value,
            }
        )
        assert status == 200, (method, status, value)
        assert "ok" not in value and "error_info" not in value, (method, value)
        if error is None:
            assert "result" in value and "error" not in value, (method, value)
        else:
            code, reason = error
            failure = value.get("error")
            assert isinstance(failure, dict), (method, value)
            assert failure.get("code") == code, (method, value)
            assert failure.get("data", {}).get("reason") == reason, (method, value)
        return value

    env = dict(os.environ, TOS_BUILD_DIR=str(build), PYTHONUNBUFFERED="1")
    env.pop("TOS_GLOBAL_VERSION", None)
    env.pop("TOS_AUTH_NETWORK_TAG", None)
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--serve",
        "--build-dir",
        str(build),
        "--out",
        str(out / "network"),
        "--rpc-port",
        str(args.rpc_port),
        "--base-port",
        str(args.base_port),
    ]
    if args.legacy_config:
        command.append("--ordinary-config")
    with (out / "network.log").open("w") as log:
        process = subprocess.Popen(
            command, cwd=ROOT, env=env, stdout=log, stderr=log, start_new_session=True
        )
        try:
            deadline = time.monotonic() + 180
            while True:
                if process.poll() is not None:
                    raise RuntimeError(
                        f"localnet exited {process.returncode}; see {out / 'network.log'}"
                    )
                try:
                    ids = [
                        request("getMasterchainInfo", {}, node=node)["result"]["last"]
                        for node in range(3)
                    ]
                    if min(value["seqno"] for value in ids) >= 3:
                        break
                except (OSError, AssertionError, KeyError):
                    pass
                assert time.monotonic() < deadline, "three-validator startup timeout"
                time.sleep(0.5)
            seqno = min(value["seqno"] for value in ids) - 1
            # Resolve a historic full ID from the existing header endpoint.
            signature = request(
                "getMasterchainBlockSignatures", {"seqno": seqno, "with_proof": True}
            )["result"]
            block = signature["id"]
            assert signature["verification"]["status"] == "node_verified"
            assert signature["verification"]["scope"] == "anchored_finality"
            assert 2 <= len(signature["signatures"]) <= 3
            assert signature["session_id"] == signature["verification"]["expected_session_id"]
            assert int(signature["verification"]["verified_weight"]) >= int(
                signature["verification"]["quorum_threshold"]
            )
            by_get = request(
                "getMasterchainBlockSignatures", {"seqno": seqno, "with_proof": True}, get=True
            )["result"]
            assert (
                by_get["id"] == block and by_get["signing_payload"] == signature["signing_payload"]
            )
            assert "proof" in by_get
            for node in range(3):
                same = request(
                    "getMasterchainBlockSignatures", {"block_id": block}, rest=True, node=node
                )["result"]
                assert (
                    same["id"] == block and same["signing_payload"] == signature["signing_payload"]
                )
                assert "proof" not in same
            fork = dict(block, file_hash=base64.b64encode(bytes(32)).decode())
            wrong = request(
                "getMasterchainBlockSignatures",
                {"block_id": fork},
                error=(-32009, "BLOCK_ID_MISMATCH"),
            )
            assert wrong["error"]["data"]["retryable"] is False
            # Account state is read through the basechain block a masterchain block
            # references. Until the first basechain block reaches the masterchain, that
            # reference is the basechain zero state, which has no block data, so every
            # account read at such a block is refused. Pin the first observation that
            # references a real basechain block.
            while True:
                observation = request("getMasterchainInfo", {})["result"]["last"]
                shards = request("getShards", {"seqno": observation["seqno"]})["result"]["shards"]
                basechain = [shard["seqno"] for shard in shards if shard["workchain"] == 0]
                if basechain and min(basechain) >= 1:
                    break
                assert time.monotonic() < deadline, ("basechain block startup timeout", observation)
                time.sleep(0.5)
            for name, address in addresses.items():
                params = {
                    "address": address,
                    "block_id": observation,
                    "include_pq": True,
                    "with_proof": True,
                }
                if name == "malformed_module":
                    bad = request("getAccountCapability", params, error=(-32603, "STATE_INVALID"))
                    assert bad["error"]["data"]["retryable"] is False
                    continue
                first = request("getAccountCapability", params)["result"]
                second = request("getWalletInformation", params, rest=True)["result"]
                pq = first["pq_authorization"]
                assert pq == second["pq_authorization"]
                assert pq["state_verified"] is True
                assert pq["observed_masterchain_block"] == observation
                assert (pq["recognition"] == "unknown_code") == (name == "unknown_code")
                if name != "unknown_code":
                    assert pq["code_family"] == name and pq["public_state"]["kind"] == name
                if name == "quantum_self_pay_v1":
                    state = pq["public_state"]
                    assert first["account_model"] == "advanced.wallet.quantum_self_pay"
                    assert state["fee_payment"] == "wallet_balance"
                    assert state["authority_epoch"] == str(2**64 - 1)
                    assert second["seqno"] == 2**32 - 1 and second["wallet_id"] == 7
                    assert (
                        state["network_tag"] == base64.b64encode(bytes.fromhex("43" * 32)).decode()
                    )
                    assert state["rescue"]["policy"] == "ready"
                    assert state["primary"]["algorithm_id"] == 1
                    assert state["rescue"]["algorithm_id"] == 3
                    assert "fee" not in state and "module" not in state
                # Default classification still uses the original path.
                legacy = request(
                    "getAccountCapability", {"address": address, "seqno": observation["seqno"]}
                )["result"]
                assert "pq_authorization" not in legacy
            absent_account = request(
                "getAccountCapability",
                {"address": "0:" + "0" * 64, "block_id": observation, "include_pq": True},
            )["result"]["pq_authorization"]
            assert (
                absent_account["recognition"] == "no_active_code"
                and absent_account["public_state"] is None
            )
            by_get = request(
                "getAccountCapability",
                {"address": "0:" + "0" * 64, "seqno": observation["seqno"], "include_pq": True},
                get=True,
            )["result"]["pq_authorization"]
            assert by_get == absent_account
            by_get = request(
                "getConfigParam",
                {
                    "param": 8,
                    "seqno": observation["seqno"],
                    "include_decoded": True,
                    "with_proof": True,
                },
                get=True,
            )["result"]
            assert by_get["decoded"]["observation"]["block_id"] == observation
            assert "config_proof" in by_get
            # ConfigParam 47, the retired controller code list, is not in the genesis.
            request(
                "getConfigParam",
                {"param": 47, "block_id": observation, "include_decoded": True},
                error=(-32004, "CONFIG_PARAM_ABSENT"),
            )
            for param in (8, 43, 48):
                typed = request(
                    "getConfigParam",
                    {
                        "param": param,
                        "block_id": observation,
                        "include_decoded": True,
                        "with_proof": True,
                    },
                )["result"]
                same = request(
                    "getConfigParam",
                    {"param": param, "block_id": observation, "include_decoded": True},
                    rest=True,
                )["result"]
                assert typed["decoded"] == same["decoded"]
                assert typed["decoded"]["observation"]["vm_version"] == 16
                assert typed["decoded"]["observation"]["block_id"] == observation
            if args.legacy_config:
                ordinary_policy = request(
                    "getConfigParam",
                    {"param": 48, "block_id": observation, "include_decoded": True},
                )["result"]
                assert (
                    ordinary_policy["decoded"]["value"]["network_tag"]
                    == base64.b64encode(bytes.fromhex("43" * 32)).decode()
                )
            # The current generated TL store writes a bare blockIdExt and a
            # count-prefixed bare vector. Pin Config 8 to compare exact replies.
            query_bytes = struct.pack(
                "<Iiiqi",
                589251042,
                0x10000,
                observation["workchain"],
                int(observation["shard"]),
                observation["seqno"],
            )
            query_bytes += base64.b64decode(observation["root_hash"]) + base64.b64decode(
                observation["file_hash"]
            )
            query_bytes += struct.pack("<ii", 1, 8)
            query = base64.b64encode(query_bytes).decode()
            first = request("getProofQuery", {"query": query})["result"]
            second = request("getProofQuery", {"query": query}, rest=True)["result"]
            assert first == second and base64.b64decode(first["reply"], validate=True)

        finally:
            try:
                stop_process_group(process)
            finally:
                (out / "rpc-evidence.json").write_text(json.dumps(records, indent=2) + "\n")
                (out / "network-exit.json").write_text(
                    json.dumps({"exit": process.returncode}) + "\n"
                )
    print(
        json.dumps(
            {
                "status": "passed",
                "requests": len(records),
                "evidence": str(out / "rpc-evidence.json"),
            }
        )
    )


if __name__ == "__main__":

    def interrupted(_signal, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    main()
