#!/usr/bin/env python3
"""Opt-in real-manager cold-join baseline; not full state-sync acceptance.

Uses independent process databases and only a shared trusted genesis. Keeps
diagnostics, refuses more than three retained runs per profile, and never targets other
test directories. Requires Python 3.14 and the tostester runtime dependencies.
"""
import argparse
import asyncio
import fcntl
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "test/tostester/src"))
from tostester.install import Install
from tostester.network import Network, StartOptions


async def reach(node, seqno):
    client = await node.toslib_client()
    while True:
        try:
            info = await client.get_masterchain_info()
            if info.last.seqno >= seqno:
                return client, info.last
        except Exception as error:
            # Startup and transport failures retry within the outer deadline;
            # expiry fails the run rather than producing a successful report.
            print(f"waiting for {node.name}: {type(error).__name__}", flush=True)
        await asyncio.sleep(1)


async def counter_tip(node):
    client = await node.toslib_client()
    while True:
        info = await client.get_masterchain_info()
        shards = await client.get_shards(info.last)
        for shard in shards.shards:
            if shard.workchain == 2 and shard.seqno >= 3:
                return shard
        await asyncio.sleep(1)


async def exercise(root, build, port, join_timeout, counter):
    install = Install(build, REPO, validator_engine=(
        build / "validator-engine/test-counter-validator-engine" if counter else None))
    install.toslibjson.client_set_verbosity_level(1)
    network_dir = root / "network"
    network_dir.mkdir()
    async with Network(install, network_dir, base_port=port) as network:
        network.config.global_id = -23902
        if counter:
            network.config.global_id = -23903
            network.config.global_version = 15
            network.config.counter_workchain = True
        network.config.shard_validators = 4
        dht = network.create_dht_node()
        validators = [network.create_full_node() for _ in range(4)]
        for node in validators:
            node.make_initial_validator()
            node.announce_to(dht)
        options = StartOptions(threads=4, verbosity=3, args=(
            "--max-archive-fd", "64", "--celldb-cache-size", "67108864",
            "--celldb-cache-min-size", "67108864"), env={
            "TOS_ROCKSDB_BLOCK_CACHE_SIZE": "67108864",
            "TOS_ROCKSDB_WRITE_BUFFER_SIZE": "16777216",
            "TOS_ROCKSDB_GLOBAL_WRITE_BUFFER_SIZE": "268435456",
            "TOS_ROCKSDB_CRITICAL_WRITE_BUFFER_SIZE": "268435456",
        })
        await dht.run(StartOptions(threads=2, verbosity=3))
        for node in validators:
            await node.run(options)
        _, target = await asyncio.wait_for(reach(validators[0], 5), 150)
        counter_target = await asyncio.wait_for(counter_tip(validators[0]), join_timeout) if counter else None
        # Construct the joining node only after the target already exists. No
        # warm database, block archive or proof is copied into its directory.
        cold = network.create_full_node()
        cold.announce_to(dht)
        print(f"cold join starts after masterchain height {target.seqno}", flush=True)
        await cold.run(options)
        cold_client, observed = await asyncio.wait_for(reach(cold, target.seqno + 2), join_timeout)
        same = await cold_client.lookup_block(-1, target.shard, seqno=target.seqno)
        if same.to_json() != target.to_json():
            raise AssertionError("cold node disagrees on the pre-existing finalized block")
        header = await cold_client.get_block_header(same)
        counter_header = None
        if counter_target is not None:
            await asyncio.wait_for(counter_tip(cold), join_timeout)
            acquired = await cold_client.lookup_block(2, counter_target.shard, seqno=counter_target.seqno)
            if acquired.to_json() != counter_target.to_json():
                raise AssertionError("cold node disagrees on the finalized Counter block")
            counter_header = await cold_client.get_block_header(acquired)
            (root / "counter-target.json").write_text(counter_target.to_json())
            (root / "counter-header.json").write_text(counter_header.to_json())
        (root / "cold-header.json").write_text(header.to_json())
        (root / "target-block.json").write_text(target.to_json())
        print(f"cold node reached height {observed.seqno}; stopping all validators", flush=True)
        for node in validators:
            await node.stop()
        # The warm servers are gone: fetching the already acquired block again
        # must be served by the joining node's own manager/database.
        header_again = await asyncio.wait_for(cold_client.get_block_header(same), 20)
        if header_again.to_json() != header.to_json():
            raise AssertionError("cold node did not retain the acquired block header")
        if counter_header is not None:
            again = await asyncio.wait_for(cold_client.get_block_header(counter_target), 20)
            if again.to_json() != counter_header.to_json():
                raise AssertionError("cold node did not retain the Counter block header")
        return {"scope": "Counter real-manager cold-join" if counter else "native/masterchain real-manager cold-join baseline only",
                "counter_workchain_tested": counter, "uno_sync_accepted": False,
                "counter_block": json.loads(counter_target.to_json()) if counter_target else None,
                "invalid_proof_rejection_tested": False, "cold_executor_state_tested": False,
                "validator_processes": 4, "cold_observer_processes": 1,
                "target_seqno": target.seqno, "cold_seqno": observed.seqno,
                "block": json.loads(target.to_json()), "served_without_warm_validators": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=REPO / "build")
    parser.add_argument("--base-port", type=int, default=38600)
    parser.add_argument("--join-timeout", type=int, default=150)
    parser.add_argument("--counter", action="store_true", help="use the explicit test-only Counter node target")
    args = parser.parse_args()
    build = args.build.resolve(strict=True)
    if not 1 <= args.join_timeout <= 600:
        parser.error("join timeout must be between 1 and 600 seconds")
    if not (build / "CMakeCache.txt").is_file() or not 1024 <= args.base_port <= 65000:
        parser.error("requires a build directory and an unprivileged port range")
    if shutil.disk_usage(build).free < 20 * 1024**3:
        parser.error("requires at least 20 GiB of free disk space")
    if args.counter and not (build / "validator-engine/test-counter-validator-engine").is_file():
        parser.error("build the test-counter-validator-engine target first")
    prefix = "m1-counter-network-run-" if args.counter else "m1-real-manager-run-"
    # Refuse occupied ports; never stop another experiment to acquire them.
    for port in range(args.base_port + 1, args.base_port + 18):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(socket.AF_INET, kind) as check:
                check.bind(("127.0.0.1", port))
    with (build / "m1-real-manager-runs.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if len(list(build.glob(prefix + "*"))) >= 3:
            parser.error("three retained M1 network runs exist; inspect before starting another")
        root = Path(tempfile.mkdtemp(prefix=prefix, dir=build))
    print(f"M1 real-manager diagnostics retained at {root}", flush=True)
    report = {"passed": False, "root": str(root), "base_port": args.base_port,
              "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()}
    try:
        report.update(asyncio.run(exercise(root, build, args.base_port, args.join_timeout, args.counter)))
        report["passed"] = True
    except BaseException as error:
        report["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
