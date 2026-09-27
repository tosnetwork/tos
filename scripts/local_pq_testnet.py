#!/usr/bin/env python3
"""Prepare and verify a persistent four-validator local PQ network.

Only prepare generates keys. Deploy sends a local faucet transaction; check
is read-only. The pool uses the development verifying key, never a release key.
"""

import argparse
import asyncio
import json
import os
import re
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def write_json(path, value, mode=0o644):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(mode)


def rpc(port, method, **params):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}",
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        {"Content-Type": "application/json"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=10) as response:
        result = json.load(response)
    if result.get("error") or "result" not in result:
        raise RuntimeError(f"{method}: {result.get('error', result)}")
    return result["result"]


def block_id(value):
    # Retain the full block identity; equality of heights alone is insufficient.
    return tuple(value[key] for key in ("workchain", "shard", "seqno", "root_hash", "file_hash"))


def validate_pq_set(decoded, ports):
    expected = {(n["validator_id"], n["pq_key_id"]) for n in ports}
    actual = {(n["controller_id_hex"], n["consensus_key_id_hex"]) for n in decoded["validators"]}
    if len(expected) != 4 or decoded["total"] != 4 or decoded["main"] != 4 or actual != expected:
        raise RuntimeError("live ConfigParam34 does not contain the four provisioned PQ identities")


async def prepare(args):
    from tosapi import tos_api
    from tostester.install import Install
    from tostester.network import Network

    data = args.data
    if (data / "testnet").exists():
        raise RuntimeError("existing network; use setup-testnet.sh --clean to reinitialize")
    async with Network(Install(args.build, REPO), data / "testnet", base_port=2000) as network:
        network.config.global_version = 18
        network.config.deployment_fee_schedule = True
        network.config.shard_validators = 4
        # This is a persistent local rehearsal, not an election lifecycle test.
        network.config.bootstrap_validator_set_valid_for = 30 * 86400
        dht = network.create_dht_node()
        nodes = []
        for _ in range(4):
            node = network.create_full_node()
            node.make_initial_pq_validator(os.urandom(32), os.urandom(32))
            node.announce_to(dht)
            nodes.append(node)
        zs = network._get_or_generate_zerostate()
        ports = []
        for i, node in enumerate(nodes, 1):
            static = node._directory / "static"
            static.mkdir()
            for state in (zs.masterchain, zs.shardchain):
                shutil.copyfile(state.file, static / state.file_hash.hex().upper())
            (node._directory / "config.json").write_text(node._local_config.to_json())
            (node._directory / "lite-client.json").write_text(node.liteserver_config.to_json())
            node._engine_console_server_key.write_pub_key_file(
                node._directory / "console-server.pub"
            )
            ports.append(
                {
                    "idx": i,
                    "directory": str(node._directory),
                    "validator_port": node._addr.port,
                    "liteserver_port": node._liteserver_addr.port,
                    "console_port": node._engine_console_addr.port,
                    "json_rpc_port": 8010 + i,
                    "validator_id": node.pq_initial_validator.validator_id.hex(),
                    "pq_key_id": node.pq_initial_validator.key_id.hex(),
                }
            )
        (dht._directory / "config.json").write_text(dht._local_config.to_json())
        config = tos_api.Config_global(
            dht=tos_api.Dht_config_global(
                static_nodes=tos_api.Dht_nodes(nodes=[dht._signed_address]), k=6, a=3
            ),
            validator=zs.as_validator_config(),
        ).to_dict()
        config["liteservers"] = [
            json.loads(n.liteserver_config.to_json())["liteservers"][0] for n in nodes
        ]
        write_json(data / "tos-global.json", config)
        write_json(
            data / "testnet-ports.json", {"mode": "pq", "dht_port": dht._addr.port, "nodes": ports}
        )
        write_json(
            data / "network.json",
            {
                "mode": "pq",
                "validators": 4,
                "global_id": 3,
                "global_version": 18,
                "genesis_wallet_address": zs.main_wallet_address.to_str(is_user_friendly=False),
                "zerostate_root": zs.masterchain.root_hash.hex(),
                "zerostate_file": zs.masterchain.file_hash.hex(),
                "genesis_validator_set_expires_unix": int(time.time()) + 30 * 86400,
                "scope": "local-development",
            },
        )
        export = data / "configs"
        export.mkdir()
        for i, node in enumerate(nodes, 1):
            shutil.copyfile(node._directory / "config.json", export / f"node-{i}.json")
            shutil.copyfile(node._directory / "lite-client.json", export / f"node-{i}-lite.json")
            (export / f"node-{i}.json").chmod(0o644)
            (export / f"node-{i}-lite.json").chmod(0o644)
        shutil.copyfile(data / "tos-global.json", export / "global.json")
        (export / "global.json").chmod(0o644)
        export.chmod(0o755)
    print("Prepared four PQ validator configurations")


async def wait_network(args):
    import base64

    from pytosiq_core import Cell
    from pytosiq_core.tlb.config import ConfigParam8
    from x02_config34_proof import decode_validator_set

    ports = json.loads((args.data / "testnet-ports.json").read_text())["nodes"]
    if len(ports) != 4:
        raise RuntimeError("expected exactly four validators")
    deadline = time.monotonic() + args.timeout
    error = None
    while time.monotonic() < deadline:
        try:
            results = await asyncio.gather(
                *[asyncio.to_thread(rpc, n["json_rpc_port"], "getMasterchainInfo") for n in ports]
            )
            height = min(r["last"]["seqno"] for r in results)
            if height < 2:
                raise RuntimeError("waiting for height 2")
            headers = await asyncio.gather(
                *[
                    asyncio.to_thread(
                        rpc,
                        n["json_rpc_port"],
                        "getBlockHeader",
                        workchain=-1,
                        shard="-9223372036854775808",
                        seqno=height,
                    )
                    for n in ports
                ]
            )
            ids = [block_id(h["id"]) for h in headers]
            if len(set(ids)) != 1:
                raise RuntimeError("four validators disagree on the full block ID")
            version, validators = await asyncio.gather(
                *[
                    asyncio.to_thread(
                        rpc, ports[0]["json_rpc_port"], "getConfigParam", param=param, seqno=height
                    )
                    for param in (8, 34)
                ]
            )
            version_cell = Cell.one_from_boc(base64.b64decode(version["config"]["bytes"]))
            if ConfigParam8.deserialize(version_cell.begin_parse()).version != 18:
                raise RuntimeError("live ConfigParam8 version must be 18")
            validator_cell = Cell.one_from_boc(base64.b64decode(validators["config"]["bytes"]))
            decoded = decode_validator_set(validator_cell)
            validate_pq_set(decoded, ports)
            return {
                "height": height,
                "block_id": headers[0]["id"],
                "nodes": 4,
                "global_version": 18,
                "pq_validators": decoded,
            }
        except (OSError, RuntimeError, KeyError, ValueError) as exc:
            error = str(exc)
            await asyncio.sleep(2)
    raise RuntimeError(f"network did not become ready: {error}")


def get_method(build, data, address, method):
    result = subprocess.run(
        [
            str(build / "lite-client/lite-client"),
            "-C",
            str(data / "configs/node-1-lite.json"),
            "-v",
            "0",
            "-c",
            f"runmethod {address} {method}",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    match = re.search(r"result:\s*\[\s*([0-9-]+)\s*\]", result.stdout)
    if result.returncode or not match:
        raise RuntimeError(f"pool get-method {method} failed: {result.stderr[-1000:]}")
    return int(match.group(1))


async def pool_methods(args, pool, initial=False):
    names = ["reserve_floor", "backed"]
    if initial:
        names += ["commitment_root", "nullifier_root", "native_liability", "commitment_next_index"]
    values = {}
    # Pace separate lite clients rather than bursting requests at one connection.
    for name in names:
        values[name] = await asyncio.to_thread(
            get_method, args.build, args.data, pool["address"], name
        )
    expected = {"reserve_floor": int(pool["reserve_floor_nanotos"]), "backed": -1}
    if initial:
        expected.update(
            commitment_root=int(pool["commitment_root"]),
            nullifier_root=int(pool["nullifier_root"]),
            native_liability=0,
            commitment_next_index=0,
        )
    if any(values[name] != value for name, value in expected.items()):
        raise RuntimeError(f"pool state differs: {values}")
    return values


async def deploy(args):
    import nacl.signing
    from contract import WalletV1, tos
    from pytosiq_core import Address, Cell, InternalMsgInfo, MessageAny, StateInit, WalletMessage
    from tosapi import tos_api
    from toslib.toslib_cdll import ToslibCDLL

    from toslib import ToslibClient

    observation = await wait_network(args)
    pooldir = args.data / "shielded-pool"
    pool = json.loads((pooldir / "pool.json").read_text())
    code = Cell.one_from_boc((pooldir / "code.boc").read_bytes())
    state = Cell.one_from_boc((pooldir / "data.boc").read_bytes())
    init = StateInit(code=code, data=state)
    address = Address((0, init.serialize().hash))
    if address.to_str(is_user_friendly=False).lower() != pool["address"].lower():
        raise RuntimeError("pool address does not match the compiled code and data")
    network = json.loads((args.data / "network.json").read_text())
    config = tos_api.Liteclient_config_global.from_dict(
        json.loads((args.data / "testnet/node1/lite-client.json").read_text())
    )
    cdll = ToslibCDLL(args.build / "toslib/libtoslibjson.so")
    cdll.client_set_verbosity_level(0)
    async with ToslibClient(config, cdll) as client:
        account = await client.raw_get_account_state(address)
        if not account.code:
            key = nacl.signing.SigningKey((args.data / "testnet/state/main-wallet.pk").read_bytes())
            wallet = WalletV1(client, Address(network["genesis_wallet_address"]), key)
            await wallet.send(
                WalletMessage(
                    send_mode=3,
                    message=MessageAny(
                        info=InternalMsgInfo(
                            ihr_disabled=True,
                            bounce=False,
                            bounced=False,
                            src=wallet.address,
                            dest=address,
                            value=tos(100),
                            ihr_fee=0,
                            fwd_fee=0,
                            created_lt=0,
                            created_at=0,
                        ),
                        init=init,
                        body=Cell.empty(),
                    ),
                )
            )
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            account = await client.raw_get_account_state(address)
            if account.code:
                actual = Cell.one_from_boc(account.code)
                if actual.hash != code.hash:
                    raise RuntimeError("on-chain pool code differs from the compiled source")
                record = {
                    **pool,
                    "deployed": True,
                    "balance_nanotos": account.balance,
                    "verified_code_hash": actual.hash.hex(),
                    "network": observation,
                    "deployed_at_unix": int(time.time()),
                }
                record["get_methods"] = await pool_methods(args, pool, initial=True)
                write_json(pooldir / "deployment.json", record)
                print(json.dumps(record, indent=2))
                return
            await asyncio.sleep(2)
    raise RuntimeError("pool deployment did not become active")


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "deploy", "check"])
    parser.add_argument("--data", type=Path, default=Path("/data"))
    parser.add_argument("--build", type=Path, default=REPO / "build")
    parser.add_argument("--timeout", type=float, default=240)
    args = parser.parse_args()
    if args.command == "prepare":
        await prepare(args)
    elif args.command == "deploy":
        await deploy(args)
    else:
        start = await wait_network(args)
        await asyncio.sleep(3)
        end = await wait_network(args)
        if end["height"] <= start["height"]:
            raise RuntimeError("four-node network is not advancing")
        pool = json.loads((args.data / "shielded-pool/pool.json").read_text())
        end["pool"] = {"address": pool["address"], "get_methods": await pool_methods(args, pool)}
        print(json.dumps(end, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
