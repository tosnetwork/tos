"""Build a native dump source that actually downloaded a nonzero persistent state.

Only disposable local nodes are used. A previous-bucket Genesis and a preloaded
next PQ validator set make the configuration contract produce a persistent key
block. An empty observer joins at that block without receiving Genesis files.
The resulting image feeds the production create/bootstrap lifecycle regression.
"""

import argparse
import asyncio
import hashlib
import json
import logging
import resource
import socket
import time
from dataclasses import replace
from pathlib import Path

from pytosiq_core import ShardStateUnsplit
from pytosiq_core.boc.deserialize import Boc
from pytosiq_core.tlb.tlb import require
from tosapi import tos_api, toslib_api
from tostester.install import Install
from tostester.network import FullNode, Network, StartOptions, _retryable_startup_lite_error
from tostester.pq_initial_validator import deterministic_pq_initial_validator_seed
from tostester.wallet_index_verify_fixtures import WalletFixtures

from toslib import ToslibClient, ToslibError

REPO = Path(__file__).resolve().parents[2]
PERIOD = 1 << 17
REFUSAL = "test-state-serializer-no-delay requires on-chain global id 3"
NO_DELAY = "--test-state-serializer-no-delay"


def previous_bucket_genesis(now: int) -> int:
    """Absolute buckets, including near their boundary; never a relative age guess."""
    return (now // PERIOD) * PERIOD - 1


async def tip(
    client: ToslibClient, minimum: int, timeout: float = 180
) -> toslib_api.Tos_blockIdExt:
    async with asyncio.timeout(timeout):
        while True:
            try:
                last = (await client.get_masterchain_info()).last
                if last is not None and last.seqno >= minimum:
                    return last
            except ToslibError as error:
                if not _retryable_startup_lite_error(error):
                    raise
            await asyncio.sleep(0.2)


async def native_refusal(node: FullNode, options: StartOptions) -> None:
    await node.run(replace(options, args=[*options.args, NO_DELAY]))
    async with asyncio.timeout(60):
        while REFUSAL not in node.log_path.read_text(errors="replace"):
            await asyncio.sleep(0.1)
    await node.stop()


async def check_nonlocal_refusal(install: Install, root: Path, base_port: int) -> None:
    """The gate uses loaded chain data on both first start and database reopen."""
    for index, global_id in enumerate((1, 2)):
        async with Network(
            install, root / f"nonlocal-{global_id}", base_port=base_port + 100 * index
        ) as network:
            network.config.global_id = global_id
            network.config.auth_network_tag = hashlib.sha256(
                f"serializer-refusal-{global_id}".encode()
            ).digest()
            node = network.create_full_node()
            node.make_initial_pq_validator(
                (global_id + 20).to_bytes(32, "big"),
                deterministic_pq_initial_validator_seed(global_id + 20),
            )
            options = StartOptions(
                threads=2,
                verbosity=1,
                args=[
                    "--initial-sync-delay",
                    "0",
                    "--skip-key-sync",
                    "--celldb-cache-size",
                    "33554432",
                    "--celldb-cache-min-size",
                    "33554432",
                ],
            )
            await native_refusal(node, options)
            # The same nonlocal chain starts normally without the test override.
            await node.run(options)
            await tip(await node.toslib_client(), 3)
            await node.stop()
            await native_refusal(node, options)
    print("NATIVE_SERIALIZER_NONLOCAL_REFUSAL_OK", flush=True)


def assert_no_zero_state(database: Path) -> None:
    if (database / "static").exists():
        raise RuntimeError("init-block source was supplied static Genesis data")
    if any((database / "archive/states").glob("zerostate_*")):
        raise RuntimeError("init-block source downloaded a zero-state file")


async def run(
    root: Path,
    build: Path,
    capture: Path | None,
    base_port: int,
    *,
    wallet_index_fixtures: bool = False,
    wallet_index_only: bool = False,
) -> None:
    if root.exists():
        raise RuntimeError("fixture root already exists; refusing to overwrite")
    root.mkdir(mode=0o700, parents=True)
    install = Install(build, REPO)
    install.toslibjson.client_set_verbosity_level(0)
    if not wallet_index_only:
        await check_nonlocal_refusal(install, root, base_port + 100)
    async with Network(install, root / "network", base_port=base_port) as network:
        genesis_time = previous_bucket_genesis(int(time.time()))
        # Traffic must commit before the first key block. Give the wallet image
        # enough runway even on a busy native CI worker.
        activation_time = int(time.time()) + (
            180 if wallet_index_fixtures or wallet_index_only else 90
        )
        network.config.genesis_time = genesis_time
        network.config.genesis_wallet_seed = bytes([0x63]) * 32
        network.config.auth_network_tag = hashlib.sha256(b"native-init-block-publisher").digest()
        network.config.shard_validators = 4
        network.config.bootstrap_validator_set_valid_for = PERIOD * 3
        network.config.bootstrap_next_validator_set_since = activation_time
        dht = network.create_dht_node()
        validators = []
        for index in range(1, 5):
            node = network.create_full_node()
            node.make_initial_pq_validator(
                index.to_bytes(32, "big"), deterministic_pq_initial_validator_seed(index)
            )
            node.announce_to(dht)
            validators.append(node)
        source = network.create_full_node()
        source._local_config.validators = []
        source.announce_to(dht)
        target = network.create_full_node()
        target._local_config.validators = []
        target.announce_to(dht)
        await dht.run(StartOptions(threads=1, verbosity=1))
        options = StartOptions(
            threads=2,
            verbosity=2,
            args=[
                "--initial-sync-delay",
                "0",
                "--skip-key-sync",
                "--celldb-cache-size",
                "67108864",
                "--celldb-cache-min-size",
                "67108864",
            ],
            env={"TOS_ROCKSDB_BLOCK_CACHE_SIZE": "33554432"},
        )
        reference_sockets = [socket.socket() for _ in range(2)]
        try:
            for reference_socket in reference_sockets:
                reference_socket.bind(("127.0.0.1", 0))
            references = [f"127.0.0.1:{sock.getsockname()[1]}" for sock in reference_sockets]
        finally:
            for reference_socket in reference_sockets:
                reference_socket.close()
        for index, node in enumerate(validators):
            args = [*options.args, NO_DELAY]
            if index < len(references):
                args.extend(["--json-rpc-address", references[index]])
            await node.run(replace(options, args=args))
        state = require(
            ShardStateUnsplit.deserialize(
                Boc(network.zerostate.masterchain.file.read_bytes()).deserialize()[0].begin_parse()
            )
        )
        config = require(require(state.custom).config.config)
        # Read only the validators_ext header here. The native engine validates
        # the PQ descriptors; the SDK's legacy descriptor decoder does not support them.
        next_set = config[36].copy()
        if next_set.load_uint(8) != 0x12:
            raise RuntimeError("next PQ set has an unexpected encoding")
        next_since = next_set.load_uint(32)
        next_set.load_uint(32)
        if next_since != activation_time or next_set.load_uint(16) != 4:
            raise RuntimeError("Genesis did not preload the requested next PQ set")
        client = await validators[0].toslib_client()
        fixtures = None
        if wallet_index_fixtures or wallet_index_only:
            await tip(client, 5)
            fixtures = WalletFixtures(
                client, network.zerostate.main_wallet(client), root / "wallet-traffic"
            )
            await fixtures.before_init()
        async with asyncio.timeout(240):
            while True:
                last = await tip(client, 5)
                header = await client.get_block_header(last)
                key_seqno = last.seqno if header.is_key_block else header.prev_key_block_seqno
                if key_seqno > 0:
                    break
                await asyncio.sleep(0.2)
        anchor = await client.lookup_block(workchain=-1, shard=-(1 << 63), seqno=key_seqno)
        key_header = await client.get_block_header(anchor)
        if not key_header.is_key_block or key_header.gen_utime // PERIOD <= genesis_time // PERIOD:
            raise RuntimeError(
                "key block is not the first key block of a new persistent-state bucket"
            )
        if key_header.prev_key_block_seqno != 0:
            raise RuntimeError("fixture produced an unexpected earlier key block")
        if any(shard.seqno == 0 for shard in (await client.get_shards(anchor)).shards):
            raise RuntimeError(
                "key block precedes basechain progress; persistent fixture is incomplete"
            )
        active = (await client.get_config_param(34)).begin_parse()
        if active.load_uint(8) != 0x12 or active.load_uint(32) != next_since:
            raise RuntimeError("configuration contract did not activate the next set")
        init = tos_api.TosNode_blockIdExt(
            workchain=anchor.workchain,
            shard=anchor.shard,
            seqno=anchor.seqno,
            root_hash=anchor.root_hash,
            file_hash=anchor.file_hash,
        )
        validator_config = tos_api.Validator_config_global(
            zero_state=network.zerostate.as_block(),
            init_block=init,
        )
        # This is the source's first process. No source DB, state, archive, or static
        # tree is seeded; the production downloader must obtain the persistent state.
        if any(
            (source.directory / name).exists() for name in ("state", "celldb", "archive", "static")
        ):
            raise RuntimeError("init-block source is not empty")
        await source._run(
            install.validator_engine_exe, source._local_config, validator_config, options
        )
        # The default harness lite-client config starts at Genesis. Bind the client to
        # this node's actual held init block as well, so reads need no early archive.
        lite_config = source.liteserver_config
        lite_config.validator = validator_config
        joined_client = ToslibClient(lite_config, install.toslibjson)
        try:
            await joined_client.init()
            joined_tip = await tip(joined_client, anchor.seqno + 4, timeout=240)
            if fixtures is not None:
                checkpoint = await fixtures.after_init(anchor.seqno)
                joined_tip = await tip(joined_client, checkpoint.seqno + 3, timeout=240)
            # The join retains the anchor's proof link, not its old block file.
            # Compare the followed frontier to a live validator; the native worker
            # separately proves both held anchors from that frontier's state.
            await tip(client, joined_tip.seqno)
            same = await client.lookup_block(
                workchain=-1, shard=joined_tip.shard, seqno=joined_tip.seqno
            )
            if same != joined_tip:
                raise RuntimeError("joining source followed another frontier full identity")
        finally:
            await joined_client.aclose()
        await source.stop()
        assert_no_zero_state(source.directory)
        if (
            "finished downloading and storing shard state (-1,8000000000000000,"
            not in source.log_path.read_text(errors="replace")
        ):
            raise RuntimeError("source never completed the native masterchain state download")
        # Prepare an independent, never-started receiver identity. Do not copy the
        # source's keyring or chain roots into it.
        (target.directory / "config.json").write_text(target._local_config.to_json())
        (target.directory / "config.global.json").write_bytes(
            (source.directory / "config.global.json").read_bytes()
        )
        if not wallet_index_only:
            if capture is None:
                raise ValueError("--capture is required unless --wallet-index-only is selected")
            process = await asyncio.create_subprocess_exec(
                capture,
                source.directory,
                root / "checked-generation",
                install.validator_engine_exe,
                source.directory / "config.global.json",
                *[f"http://{address}" for address in references],
            )
            try:
                async with asyncio.timeout(240):
                    if await process.wait() != 0:
                        raise RuntimeError("native capture/validation refused the joined source")
            finally:
                if process.returncode is None:
                    process.kill()
                    await process.wait()
        assert_no_zero_state(source.directory)
        receipt = {
            "result": (
                "NATIVE_WALLET_INDEX_IMAGE_OK" if wallet_index_only else "NATIVE_INIT_BLOCK_JOIN_OK"
            ),
            "genesis_time": genesis_time,
            "init_block": init.to_dict(),
            "frontier": joined_tip.to_dict(),
            "source": source.directory.name,
            "target": target.directory.name,
            "zero_state_files": 0,
            "static_supplied": False,
            "wallet_index_fixtures": fixtures is not None,
        }
        (root / "init-block-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt), flush=True)
        print(receipt["result"], flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--build", type=Path, default=REPO / "build")
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--base-port", type=int, default=42000)
    parser.add_argument("--wallet-index-fixtures", action="store_true")
    parser.add_argument(
        "--wallet-index-only",
        action="store_true",
        help="build the real joined chain and wallet traffic without the unrelated capture checks",
    )
    args = parser.parse_args()
    if not args.wallet_index_only and args.capture is None:
        parser.error("--capture is required unless --wallet-index-only is selected")
    # Public-network refusal controls deliberately terminate the engine at startup.
    # Core files are not useful evidence and must not multiply fixture disk usage.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    logging.basicConfig(level=logging.INFO)
    asyncio.run(
        run(
            args.root.resolve(),
            args.build.resolve(),
            args.capture.resolve() if args.capture else None,
            args.base_port,
            wallet_index_fixtures=args.wallet_index_fixtures,
            wallet_index_only=args.wallet_index_only,
        )
    )


if __name__ == "__main__":
    main()
