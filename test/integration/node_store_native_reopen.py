"""Prove typed StateDb reconstruction on an engine-created disposable chain.

This is a compatibility fixture, not an operator restore command. No network
outside the disposable local network is queried. Identity remains the fixture's own.
"""

import argparse
import asyncio
import hashlib
import json
import logging
from pathlib import Path

from toslib.toslibjson import ToslibError
from tostester.install import Install
from tostester.network import Network, StartOptions, _retryable_startup_lite_error
from tostester.pq_initial_validator import deterministic_pq_initial_validator_seed

REPO = Path(__file__).resolve().parents[2]


async def run(root: Path, build: Path, reconstruct: Path, validate_generation: Path | None = None):
    if root.exists():
        raise RuntimeError("fixture root already exists; refusing to overwrite")
    root.mkdir(mode=0o700, parents=True)
    install = Install(build, REPO)
    install.toslibjson.client_set_verbosity_level(0)
    async with Network(install, root / "network", base_port=41000) as network:
        network.config.global_id = 3
        global_id = network.config.global_id
        network.config.auth_network_tag = hashlib.sha256(b"node-store-native-proof").digest()
        network.config.shard_validators = 4
        network.config.bootstrap_validator_set_valid_for = 3600
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
        await dht.run(StartOptions(threads=2, verbosity=1))
        options = StartOptions(
            threads=4,
            verbosity=1,
            args=[
                "--initial-sync-delay",
                "1",
                "--celldb-cache-size",
                "268435456",
                "--celldb-cache-min-size",
                "268435456",
            ],
            env={"TOS_ROCKSDB_BLOCK_CACHE_SIZE": "134217728"},
        )
        for node in validators:
            await node.run(options)
        await source.run(options)
        await asyncio.wait_for(network.wait_mc_block(5), 180)
        client = await source.toslib_client()
        async with asyncio.timeout(180):
            while True:
                before = (await client.get_masterchain_info()).last
                if before is not None and before.seqno >= 5:
                    break
                await asyncio.sleep(0.2)
        await source.stop()
        if validate_generation is not None:
            # The harness shares genesis files through symlinks; production capture refuses links.
            # Materialize only fixture-owned static inputs, retaining the capture refusal unchanged.
            for state in (source.directory / "static").iterdir():
                if state.is_symlink():
                    original = state.resolve(strict=True)
                    if not original.is_relative_to(root.resolve()):
                        raise RuntimeError("static fixture points outside its private root")
                    content = original.read_bytes()
                    temporary = state.with_suffix(".copy")
                    temporary.write_bytes(content)
                    temporary.chmod(0o600)
                    temporary.replace(state)
            # A valid unadopted record for a deliberately absent hash exercises startup recovery
            # in the captured image without modifying any real fixture cell.
            rollback = (
                source.directory / "tmp/persistent-state/node-sync.celldb-rollback.fixture.partial"
            )
            rollback.parent.mkdir(parents=True, exist_ok=True)
            rollback.write_bytes(bytes([0xA5]) * 32 + (1).to_bytes(4, "little") + b"x")
            process = await asyncio.create_subprocess_exec(
                validate_generation,
                source.directory,
                root / "checked-generation",
                build / "validator-engine/validator-engine",
                source.directory / "config.global.json",
            )
            if await process.wait() != 0:
                raise RuntimeError("native cold-generation validation refused the fixture")
            if not rollback.exists():
                raise RuntimeError("capture changed the stopped source's recovery material")
            recovered = root / "checked-generation/image/tmp/persistent-state" / rollback.name
            if recovered.exists():
                raise RuntimeError("published generation skipped native rollback recovery")
            log = (root / "checked-generation/checked/reopen-0.log").read_bytes()
            if b"processed=1 erased=0" not in log or rollback.name.encode() not in log:
                raise RuntimeError("native recovery did not process the captured rollback record")
        original = source.directory / "state"
        frozen = source.directory / "proof-original-state"
        original.rename(frozen)
        process = await asyncio.create_subprocess_exec(reconstruct, frozen, original)
        if await process.wait() != 0:
            raise RuntimeError("typed reconstruction refused engine-created StateDb")
        await source.run(options)
        client = await source.toslib_client()
        async with asyncio.timeout(180):
            while True:
                try:
                    after = (await client.get_masterchain_info()).last
                except ToslibError as error:
                    if not _retryable_startup_lite_error(error):
                        raise
                    await asyncio.sleep(0.2)
                    continue
                if after is not None and after.seqno >= before.seqno:
                    break
                await asyncio.sleep(0.2)
        same_height = await client.lookup_block(
            workchain=before.workchain, shard=before.shard, seqno=before.seqno
        )
        if same_height != before:
            raise RuntimeError("production reopen changed the fixture's full block identity")
        print(
            json.dumps(
                {
                    "result": "NODE_STORE_ENGINE_REOPEN_OK",
                    "global_id": global_id,
                    "before": str(before),
                    "after": str(after),
                    "same_height": str(same_height),
                }
            ),
            flush=True,
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--build", type=Path, default=REPO / "build")
    parser.add_argument("--reconstruct", type=Path, required=True)
    parser.add_argument("--validate-generation", type=Path)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    asyncio.run(
        run(
            args.root.resolve(),
            args.build.resolve(),
            args.reconstruct.resolve(),
            args.validate_generation.resolve() if args.validate_generation else None,
        )
    )


if __name__ == "__main__":
    main()
