"""A validator serves JSON-RPC without the wallet index under --json-rpc-without-wallet-index.

Four PQ validators produce blocks. Validator 0 runs the epoch-5 validator layout:
loopback JSON-RPC for its operator tool and no wallet index. An indexed follower is
the control. Both must answer the chain methods the operator tool uses; only the
follower may answer an account-index method, the validator must say the index is
disabled, and only the follower may create `<db>/wc0-index`.
"""

import argparse
import asyncio
import hashlib
import json
import logging
import socket
import urllib.request
from pathlib import Path
from typing import Any

from tostester.install import Install
from tostester.network import FullNode, Network, StartOptions

INDEX_DISABLED = -32601


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def ports_free(base: int, count: int) -> bool:
    for port in range(base, base + count):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(socket.AF_INET, kind) as probe:
                try:
                    probe.bind(("127.0.0.1", port))
                except OSError:
                    return False
    return True


def call(address: str, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})
    request = urllib.request.Request(
        f"http://{address}/jsonRPC",
        data=payload.encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        document = json.loads(response.read().decode())
    require(isinstance(document, dict), f"{address} {method}: not a JSON-RPC answer")
    return document


async def answered(
    address: str, method: str, params: dict[str, Any] | None = None
) -> dict[str, Any]:
    """The node's answer once its JSON-RPC server is up."""
    for _ in range(120):
        try:
            return await asyncio.to_thread(call, address, method, params)
        except OSError:
            await asyncio.sleep(1)
    raise AssertionError(f"{address} {method}: no answer within 120 s")


async def main(args: argparse.Namespace) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    require(
        ports_free(args.base_port, 200) and ports_free(args.base_port + 1000, 200),
        f"ports {args.base_port}+200 and {args.base_port + 1000}+200 are not all free",
    )
    working_dir = args.working_dir.resolve()
    working_dir.mkdir(parents=True, exist_ok=False)
    install = Install(repo_root / "build", repo_root)
    install.toslibjson.client_set_verbosity_level(1)
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s][%(asctime)s] %(message)s")

    async with Network(install, working_dir, base_port=args.base_port) as network:
        dht = network.create_dht_node()
        network.config.shard_validators = 4
        validators: list[FullNode] = []
        for index in range(4):
            node = network.create_full_node()
            node.make_initial_pq_validator(
                hashlib.sha256(f"no-index-validator-id-{index}".encode()).digest(),
                hashlib.sha256(f"no-index-validator-seed-{index}".encode()).digest(),
            )
            node.announce_to(dht)
            validators.append(node)
        follower = network.create_full_node()
        follower.announce_to(dht)

        unindexed = f"127.0.0.1:{args.base_port + 150}"
        indexed = f"127.0.0.1:{args.base_port + 151}"
        async with asyncio.TaskGroup() as group:
            _ = group.create_task(dht.run())
            _ = group.create_task(
                validators[0].run(
                    StartOptions(
                        verbosity=2,
                        args=["--json-rpc-address", unindexed, "--json-rpc-without-wallet-index"],
                    )
                )
            )
            for node in validators[1:]:
                _ = group.create_task(node.run(StartOptions(verbosity=2)))
            _ = group.create_task(
                follower.run(StartOptions(verbosity=2, args=["--json-rpc-address", indexed]))
            )

        await network.wait_mc_block(seqno=3)
        _ = await network.wait_block(workchain=0, shard=-(2**63), seqno=1)
        client = await validators[0].toslib_client()
        wallet = network.zerostate.main_wallet(client).address.to_str(is_user_friendly=False)

        for name, address in (("validator", unindexed), ("follower", indexed)):
            info = await answered(address, "getMasterchainInfo")
            require("result" in info, f"{name}: getMasterchainInfo failed: {info}")
            state = await answered(address, "getAddressInformation", {"address": wallet})
            require("result" in state, f"{name}: getAddressInformation failed: {state}")

        refused = await answered(unindexed, "getAccountEvents", {"address": wallet})
        error = refused.get("error") or {}
        require(
            error.get("code") == INDEX_DISABLED and "disabled" in str(error.get("message", "")),
            f"validator: getAccountEvents did not report a disabled index: {refused}",
        )
        served = await answered(indexed, "getAccountEvents", {"address": wallet})
        require("result" in served, f"follower: getAccountEvents failed: {served}")

        require(
            not (validators[0].directory / "wc0-index").exists(),
            "validator: <db>/wc0-index was created",
        )
        require((follower.directory / "wc0-index").is_dir(), "follower: no <db>/wc0-index")
        print("JSON_RPC_WITHOUT_WALLET_INDEX_OK")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--working-dir", type=Path, required=True)
    parser.add_argument("--base-port", type=int, default=24100)
    return parser.parse_args()


if __name__ == "__main__":
    asyncio.run(main(parse_args()))
