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
import re
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
from dataclasses import replace

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "test/tostester/src"))
from tostester.install import Install
from tostester.network import Network, StartOptions
from tostester.zerostate import counter_payload_tree
from pytosiq_core import Address, Cell


async def counter_state(client, block, payload=None):
    state = await client.raw_get_account_state(Address((2, bytes(32))), block_id=block)
    if state.block_id is None or state.block_id.to_json() != block.to_json():
        raise AssertionError("Counter account response is not bound to the requested block")
    if state.last_transaction_id is None:
        raise AssertionError("Counter account has no transaction identity")
    wrapper = Cell.one_from_boc(state.data).begin_parse()
    if wrapper.remaining_bits != 33 or wrapper.remaining_refs != 2 or wrapper.load_uint(32) != 0x57424531:
        raise AssertionError("invalid Counter executor wrapper")
    if wrapper.load_uint(1) != 1:
        raise AssertionError("confirmed Counter block has no batch witness")
    engine = wrapper.load_ref().begin_parse()
    if engine.remaining_bits != 64 or engine.remaining_refs != int(payload is not None):
        raise AssertionError("invalid Counter engine state")
    value = engine.load_uint(64)
    if value != 40 + block.seqno:
        raise AssertionError("Counter state does not reflect one increment per confirmed block")
    if payload is not None and engine.load_ref().hash != payload.hash:
        raise AssertionError("Counter payload content changed during synchronization")
    return state


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


async def require_proof_probe(node, signatures=False):
    while True:
        log = node.log_path.read_text(errors="replace")
        if "COUNTER_PROOF_PROBE_FAIL" in log:
            raise AssertionError(f"real-manager proof probe failed: {node.log_path}")
        if "COUNTER_PROOF_PROBE_PASS root-binding" in log and (
            not signatures or "COUNTER_SIGNATURE_PROBE_PASS" in log
        ):
            return
        await asyncio.sleep(0.2)


def signature_proof_results(root):
    logs = "\n".join(log.read_text(errors="replace") for log in (root / "network").glob("node*/log"))
    cold_path = root / "network/node5/log"
    cold_log = cold_path.read_text(errors="replace") if cold_path.exists() else ""

    def fingerprints(marker, text):
        return {value.upper() for value in re.findall(marker + r" ([0-9a-fA-F]{64})", text)}

    # Any receiver accepting the injected proof fails; successful rejection
    # evidence must come from the cold observer, not another committee node.
    return (fingerprints("COUNTER_BAD_SIGNATURE_SENT", logs), fingerprints("COUNTER_REMOTE_PROOF_ACCEPTED", logs),
            fingerprints("COUNTER_REMOTE_PROOF_REJECTED", cold_log))


async def watch_proof_acceptance(root):
    while True:
        for log in (root / "network").glob("node*/log"):
            if "COUNTER_MISBOUND_PROOF_ACCEPTED" in log.read_text(errors="replace"):
                raise AssertionError(f"real receiver accepted a misbound peer proof: {log}")
        sent, accepted, _ = signature_proof_results(root)
        if sent & accepted:
            raise AssertionError("real receiver accepted a peer proof with a corrupted committee signature")
        await asyncio.sleep(0.2)


async def guarded_exercise(root, *args):
    # Observe acceptance while synchronization runs. A broken verifier can
    # stall later state acquisition; that timeout is not the property tested.
    run = asyncio.create_task(exercise(root, *args))
    watch = asyncio.create_task(watch_proof_acceptance(root))
    try:
        done, _ = await asyncio.wait((run, watch), return_when=asyncio.FIRST_COMPLETED)
        if watch in done:
            await watch
        return await run
    finally:
        run.cancel()
        watch.cancel()
        await asyncio.gather(run, watch, return_exceptions=True)


async def exercise(root, build, port, join_timeout, counter, reencoded_state=False, misbound_proof=False,
                   bad_signature=False, large_payload=False):
    payload = counter_payload_tree() if large_payload else None
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
            network.config.counter_payload = large_payload
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
            "TOS_COUNTER_SIGNATURE_PROBE": "0",
            "TOS_COUNTER_REENCODE_ZERO_STATE": "0",
            "TOS_COUNTER_MISBOUND_PROOF_FILE": "",
            "TOS_COUNTER_BAD_SIGNATURE_FILE": "",
            "TOS_COUNTER_PAYLOAD": "1" if large_payload else "0",
        })
        await dht.run(StartOptions(threads=2, verbosity=3))
        for node in validators:
            await node.run(replace(options, env={
                **options.env, "TOS_COUNTER_SIGNATURE_PROBE": "1",
                "TOS_COUNTER_REENCODE_ZERO_STATE": "1" if reencoded_state else "0",
                "TOS_COUNTER_MISBOUND_PROOF_FILE": str(root / "proof-fault-armed") if misbound_proof else "",
                "TOS_COUNTER_BAD_SIGNATURE_FILE": str(root / "proof-fault-armed") if bad_signature else "",
            }) if counter else options)
        _, target = await asyncio.wait_for(reach(validators[0], 5), 150)
        counter_target = await asyncio.wait_for(counter_tip(validators[0]), join_timeout) if counter else None
        if counter:
            for node in validators:
                await asyncio.wait_for(require_proof_probe(node, signatures=True), 10)
        # Construct the joining node only after the target already exists. No
        # warm database, block archive or proof is copied into its directory.
        cold = network.create_full_node()
        cold.announce_to(dht)
        if misbound_proof or bad_signature:
            (root / "proof-fault-armed").touch()
        print(f"cold join starts after masterchain height {target.seqno}", flush=True)
        await cold.run(options, seed_extra_states=False)
        if counter and len(list((cold.log_path.parent / "static").iterdir())) != 2:
            raise AssertionError("cold node must have only masterchain/native static states")
        cold_client, observed = await asyncio.wait_for(reach(cold, target.seqno + 2), join_timeout)
        same = await cold_client.lookup_block(-1, target.shard, seqno=target.seqno)
        if same.to_json() != target.to_json():
            raise AssertionError("cold node disagrees on the pre-existing finalized block")
        header = await cold_client.get_block_header(same)
        counter_header = None
        executor_state = None
        if counter_target is not None:
            await asyncio.wait_for(counter_tip(cold), join_timeout)
            acquired = await cold_client.lookup_block(2, counter_target.shard, seqno=counter_target.seqno)
            if acquired.to_json() != counter_target.to_json():
                raise AssertionError("cold node disagrees on the finalized Counter block")
            counter_header = await cold_client.get_block_header(acquired)
            executor_state = await asyncio.wait_for(counter_state(cold_client, acquired, payload), 20)
            await asyncio.wait_for(require_proof_probe(cold), 10)
            cold_log = cold.log_path.read_text(errors="replace")
            if bad_signature:
                sent, accepted, rejected = signature_proof_results(root)
                if sent & accepted:
                    raise AssertionError("real receiver accepted a peer proof with a corrupted committee signature")
                if not (sent & rejected):
                    raise AssertionError("no injected committee-signature proof was rejected by the real receiver")
            if misbound_proof:
                if "COUNTER_MISBOUND_PROOF_ACCEPTED" in cold_log:
                    raise AssertionError("real receiver accepted a misbound peer proof")
                if "COUNTER_MISBOUND_PROOF_REJECTED" not in cold_log:
                    raise AssertionError("real receiver did not reject a misbound peer proof")
                if not any("COUNTER_MISBOUND_PROOF_SENT" in node.log_path.read_text(errors="replace")
                           for node in validators):
                    raise AssertionError("no remote server injected a misbound proof")
            zero_id = "(2,8000000000000000,0)"
            if (not any(f"downloading state {zero_id}" in line and " from " in line
                        for line in cold_log.splitlines()) or
                    f"finished downloading state {zero_id}" not in cold_log):
                raise AssertionError("cold node did not download Counter zerostate through peers")
            if reencoded_state:
                if not any("COUNTER_ZERO_STATE_REENCODED" in node.log_path.read_text(errors="replace")
                           for node in validators):
                    raise AssertionError("no peer served a reencoded Counter zerostate")
                stored = list((cold.log_path.parent / "archive/states").glob("zerostate_2_*"))
                if len(stored) != 1 or stored[0].read_bytes() != (network_dir / "state/counter-state.boc").read_bytes():
                    raise AssertionError("cold node persisted an unbound Counter zerostate representation")
                if "received bad state from net: file hash mismatch" not in cold_log:
                    raise AssertionError("cold node did not reject the peer's reencoded zerostate")
            (root / "counter-account.json").write_text(executor_state.to_json())
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
            # Reopen the actual observer database with every warm node stopped.
            # Preserve the first process log: run() otherwise truncates it.
            await cold.stop()
            shutil.copyfile(cold.log_path, root / "cold-before-restart.log")
            await cold.run(options)
            restarted, _ = await asyncio.wait_for(reach(cold, observed.seqno), join_timeout)
            restored = await asyncio.wait_for(counter_state(restarted, counter_target, payload), 20)
            if restored.data != executor_state.data or restored.last_transaction_id.to_json() != executor_state.last_transaction_id.to_json():
                raise AssertionError("Counter state changed across cold database reopening")
            (root / "counter-account-reopened.json").write_text(restored.to_json())
        return {"scope": "Counter real-manager cold-join" if counter else "native/masterchain real-manager cold-join baseline only",
                "counter_workchain_tested": counter, "uno_sync_accepted": False,
                "counter_block": json.loads(counter_target.to_json()) if counter_target else None,
                "invalid_proof_rejection_tested": False, "cold_executor_state_tested": counter,
                "cold_database_reopened": counter,
                "bounded_payload_reopened": large_payload,
                "executor_data_boc_bytes": len(executor_state.data) if executor_state else None,
                "payload_cells": 32767 if large_payload else 0,
                "cold_counter_zerostate_peer_download_tested": counter,
                "remote_reencoded_zerostate_rejection_tested": reencoded_state,
                "remote_misbound_proof_rejection_tested": misbound_proof,
                "remote_committee_signature_rejection_tested": bad_signature,
                "manager_proof_root_binding_tested": counter,
                "manager_broadcast_signature_rejection_tested": counter,
                "validator_processes": 4, "cold_observer_processes": 1,
                "target_seqno": target.seqno, "cold_seqno": observed.seqno,
                "block": json.loads(target.to_json()), "served_without_warm_validators": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=REPO / "build")
    parser.add_argument("--base-port", type=int, default=38600)
    parser.add_argument("--join-timeout", type=int, default=150)
    parser.add_argument("--counter", action="store_true", help="use the explicit test-only Counter node target")
    parser.add_argument("--counter-payload", action="store_true",
                        help="preserve a bounded 32,767-cell payload through cold join and reopening")
    parser.add_argument("--counter-reencoded-state", action="store_true",
                        help="require rejection/recovery after peers reencode one Counter zerostate response each")
    parser.add_argument("--counter-misbound-proof", action="store_true",
                        help="require real receiver rejection of a peer proof naming the wrong file hash")
    parser.add_argument("--counter-bad-signature", action="store_true",
                        help="require rejection of a masterchain proof with one corrupted committee signature")
    args = parser.parse_args()
    if args.counter_payload and not args.counter:
        parser.error("--counter-payload requires --counter")
    if args.counter_reencoded_state and not args.counter:
        parser.error("--counter-reencoded-state requires --counter")
    if args.counter_misbound_proof and not args.counter:
        parser.error("--counter-misbound-proof requires --counter")
    if args.counter_bad_signature and not args.counter:
        parser.error("--counter-bad-signature requires --counter")
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
        report.update(asyncio.run(guarded_exercise(root, build, args.base_port, args.join_timeout, args.counter,
                                      args.counter_reencoded_state, args.counter_misbound_proof,
                                      args.counter_bad_signature, args.counter_payload)))
        report["passed"] = True
    except BaseException as error:
        report["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
