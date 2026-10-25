"""Validators never open a wallet index; standalone services replay and serve it.

Exercise the real liteserver transport, archive secondary reader and HTTP proxy,
then kill and restart the index while the source continues producing blocks.
"""

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import signal
import socket
import time
import urllib.request
from pathlib import Path
from typing import Any

from contract import WalletV1Blueprint, tos
from pytosiq_core import MessageAny
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


def call(
    address: str, method: str, params: dict[str, Any] | None = None, source: str = ""
) -> dict[str, Any]:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})
    request = urllib.request.Request(
        f"http://{address}/jsonRPC",
        data=payload.encode(),
        headers={"Content-Type": "application/json"},
    )
    if source:
        request.add_header("X-Real-IP", source)
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
        network.config.auth_network_tag = hashlib.sha256(b"standalone-services-test").digest()
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
                        args=[
                            "--json-rpc-address",
                            unindexed,
                            "--json-rpc-without-wallet-index",
                            "--json-rpc-trust-proxy-headers",
                        ],
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
        config = working_dir / "rpc-config.json"
        config.write_text(follower.liteserver_config.to_json())
        public = f"127.0.0.1:{args.base_port + 152}"
        index_address = f"127.0.0.1:{args.base_port + 153}"
        index_args = [
            str(install.build_dir / "services/tos-wallet-index"),
            "--source-db",
            str(follower.directory),
            "--data-dir",
            str(working_dir / "wallet-service"),
            "--listen",
            index_address,
        ]
        index_log = (working_dir / "wallet-service.log").open("ab")
        rpc_log = (working_dir / "rpc-service.log").open("ab")
        processes = []
        try:
            index_process = await asyncio.create_subprocess_exec(
                *index_args, stdout=index_log, stderr=index_log
            )
            processes.append(index_process)
            rpc_process = await asyncio.create_subprocess_exec(
                str(install.build_dir / "services/tos-rpc"),
                "-C",
                str(config),
                "--listen",
                public,
                "--trust-proxy-headers",
                "--submission-address",
                unindexed,
                "--index-address",
                index_address,
                stdout=rpc_log,
                stderr=rpc_log,
            )
            processes.append(rpc_process)
            info = await answered(public, "getMasterchainInfo")
            require("result" in info, f"standalone chain query: {info}")
            for method in ("getConsensusBlock", "getMasterchainBlockSignatures"):
                response = await answered(public, method, {"seqno": 1})
                require(
                    response.get("error", {}).get("code") == -32601,
                    f"unsafe standalone method: {response}",
                )
                require(rpc_process.returncode is None, "standalone RPC exited on manager method")

            recipient = WalletV1Blueprint(workchain=0)

            class RpcProvider:
                @property
                def latest_state_reader(self):
                    return client.latest_state_reader

                async def send_external(self, message: MessageAny) -> None:
                    require(
                        time.monotonic() - submission_window < 10,
                        "submission isolation window elapsed",
                    )
                    response = await asyncio.to_thread(
                        call,
                        public,
                        "sendBoc",
                        {"boc": base64.b64encode(message.serialize().to_boc()).decode()},
                        "198.51.100.2",
                    )
                    require("result" in response, f"victim's valid transfer refused: {response}")

            payer = network.zerostate.main_wallet(RpcProvider())
            payer_seqno = (await payer.current).seqno
            submission_window = time.monotonic()
            # Different public clients retain independent production mempool source budgets.
            for attempt in range(31):
                response = await asyncio.to_thread(
                    call,
                    public,
                    "sendBoc",
                    {"boc": base64.b64encode(f"invalid-relay-message-{attempt}".encode()).decode()},
                    "198.51.100.1",
                )
                limited = "source rate limit exceeded" in json.dumps(response)
                require(
                    limited == (attempt == 30),
                    f"unexpected submission admission {attempt}: {response}",
                )
            victim = await asyncio.to_thread(
                call,
                public,
                "sendBoc",
                {"boc": base64.b64encode(b"independent-client").decode()},
                "198.51.100.2",
            )
            require(
                "source rate limit exceeded" not in json.dumps(victim),
                f"shared submission bucket: {victim}",
            )
            require("error" in victim, f"invalid message unexpectedly accepted: {victim}")
            await payer.deploy(recipient, tos(5), payer_seqno)

            async def caught_up(minimum=1):
                result: dict[str, Any] = {}
                for _ in range(120):
                    require(
                        index_process.returncode is None,
                        "index process exited; inspect wallet-service.log",
                    )
                    result = await answered(public, "getAccountTokens", {"address": wallet})
                    state = result.get("result", {}).get("index_state", {})
                    replay = state.get("replay", {})
                    if (
                        replay.get("masterchain_seqno", 0) >= minimum
                        and replay.get("caught_up")
                        and state.get("complete")
                    ):
                        return replay["masterchain_seqno"]
                    await asyncio.sleep(1)
                raise AssertionError(f"index did not catch up: {result}")

            recipient_address = recipient.address.to_str(is_user_friendly=False)

            async def recipient_events():
                result: dict[str, Any] = {}
                for _ in range(90):
                    result = await answered(
                        public, "getAccountEvents", {"address": recipient_address}
                    )
                    events = result.get("result", {}).get("events", [])
                    if events:
                        return events
                    await asyncio.sleep(1)
                raise AssertionError(f"funding transaction missing from replay: {result}")

            events_before = await recipient_events()
            before = await caught_up()
            index_process.send_signal(signal.SIGTERM)
            require(
                await asyncio.wait_for(index_process.wait(), 10) == 0,
                "index with cached source state did not shut down cleanly",
            )
            index_process = await asyncio.create_subprocess_exec(
                *index_args, stdout=index_log, stderr=index_log
            )
            processes.append(index_process)
            await caught_up(before)
            index_process.kill()
            await index_process.wait()
            await network.wait_mc_block(seqno=before + 3)
            index_process = await asyncio.create_subprocess_exec(
                *index_args, stdout=index_log, stderr=index_log
            )
            processes.append(index_process)
            await caught_up(before + 3)
            require(
                await recipient_events() == events_before,
                "restart changed historical event records",
            )
            served = await answered(public, "getAccountEvents", {"address": wallet})
            require("result" in served, f"standalone events query: {served}")
            for process in (index_process, rpc_process):
                process.send_signal(signal.SIGTERM)
                require(await asyncio.wait_for(process.wait(), 10) == 0, "unclean service shutdown")
        finally:
            for process in processes:
                if process.returncode is None:
                    process.kill()
                    await process.wait()
            index_log.close()
            rpc_log.close()
        served = await answered(indexed, "getAccountEvents", {"address": wallet})
        require("error" in served, f"follower still owns an embedded index: {served}")

        require(
            not (validators[0].directory / "wc0-index").exists(),
            "validator: <db>/wc0-index was created",
        )
        require(
            not (follower.directory / "wc0-index").exists(), "follower created an embedded index"
        )
        print("JSON_RPC_WITHOUT_WALLET_INDEX_OK")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--working-dir", type=Path, required=True)
    parser.add_argument("--base-port", type=int, default=24100)
    return parser.parse_args()


if __name__ == "__main__":
    asyncio.run(main(parse_args()))
