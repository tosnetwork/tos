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
import time
from dataclasses import replace

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "test/tostester/src"))
from tostester.install import Install
from tostester.network import Network, StartOptions
from tostester.zerostate import counter_payload_tree
from tostester.counter_committee import read_committee, retired_signature_manifest, submit_committee_update, wait_committee_updated
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


def require_validator_replay_cache(logs, required_validator=None):
    evidence = {}
    owners = {}
    for name, log in logs.items():
        raw = re.findall(r"Batch replay storage cache: hit=(true|false) transaction=([0-9A-Fa-f]{64}) elapsed_ns=([0-9]+)(?![0-9A-Za-z_.])", log)
        if any(int(ns) <= 0 for _, _, ns in raw):
            raise AssertionError("replay timing must be positive nanoseconds")
        matches = [(hit, tx) for hit, tx, _ in raw]
        hits = {tx.lower() for hit, tx in matches if hit == "true"}
        for tx in hits:
            owners.setdefault(tx, []).append(name)
        evidence[name] = {"hit_transactions": sorted(hits),
                          "miss_transactions": sorted({tx.lower() for hit, tx in matches if hit == "false"}),
                          "first_observed_replay": {"cache_hit": matches[0][0] == "true",
                                                    "transaction": matches[0][1].lower(),
                                                    "elapsed_ns": int(raw[0][2])} if matches else None,
                          "timing_samples": [{"cache_hit": hit == "true", "transaction": tx.lower(),
                                              "elapsed_ns": int(ns)} for hit, tx, ns in raw]}
    shared = {tx: names for tx, names in owners.items() if len(names) >= 2}
    if not shared:
        raise AssertionError("need the same cache-hit replay in two independent validators")
    if required_validator is not None and not any(required_validator in names for names in shared.values()):
        raise AssertionError("replacement validator must share a cache-hit replay with its committee")
    return {"validators": evidence, "shared_hit_transactions": shared,
            "scope": "validator candidate replay, not cold observer replay or an RSS bound"}


def node_memory_observation(node, proc_root=Path("/proc")):
    pid = node.process_id
    if pid is None:
        raise AssertionError("cannot measure memory of a stopped node")
    directory = proc_root / str(pid)

    def start_ticks():
        # comm may contain spaces or parentheses; fields after it start at 3.
        fields = (directory / "stat").read_text().rsplit(")", 1)[1].split()
        return int(fields[19])

    started = start_ticks()
    status = (directory / "status").read_text()
    values = {}
    for field in ("VmRSS", "VmHWM"):
        matches = re.findall(rf"^{field}:\s+([0-9]+) kB$", status, re.MULTILINE)
        if len(matches) != 1 or int(matches[0]) == 0:
            raise AssertionError(f"missing or invalid {field} memory observation")
        values[field] = int(matches[0]) * 1024
    if start_ticks() != started or node.process_id != pid:
        raise AssertionError("node identity changed during memory observation")
    return {"pid": pid, "process_start_ticks": started,
            "rss_bytes": values["VmRSS"], "kernel_reported_peak_rss_bytes": values["VmHWM"],
            "source": "/proc/pid/status", "scope": "whole node since start through observation, not importer-only",
            "observed_monotonic_seconds": time.monotonic()}


def validator_memory_observation(nodes, expected_count, previous=None):
    if len(nodes) != expected_count:
        raise AssertionError("validator memory observation has incomplete committee coverage")
    readings = {}
    identities = set()
    for node in nodes:
        name = node.log_path.parent.name
        reading = node_memory_observation(node)
        identity = (reading["pid"], reading["process_start_ticks"])
        if name in readings or identity in identities:
            raise AssertionError("validator memory observation has duplicate process identity")
        if previous is not None and (name not in previous or identity != (
                previous[name]["pid"], previous[name]["process_start_ticks"])):
            raise AssertionError("validator process changed between memory observations")
        identities.add(identity)
        readings[name] = reading
    return readings


def require_membership_signers(signed, block, introduced, retired):
    if signed.id is None or signed.id.to_json() != block.to_json():
        raise AssertionError("membership signature response is not block-bound")
    signers = {signature.node_id_short for signature in signed.signatures}
    if len(signers) != len(signed.signatures) or any(len(signature.signature) != 64 for signature in signed.signatures):
        raise AssertionError("invalid membership signature list shape")
    if introduced not in signers or retired in signers:
        raise AssertionError("post-transition proof does not demonstrate the replacement signer")


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


async def reach_authenticated(client, seqno):
    # Server readiness is not the client's verified proof-chain cursor.
    while True:
        verified = await client.sync_toslib()
        if verified.seqno >= seqno:
            return verified
        await asyncio.sleep(0.2)


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


async def require_checkpoint_serialized(nodes, seqno):
    marker = f"finished serializing persistent state for (-1,8000000000000000,{seqno})"
    while True:
        for node in nodes:
            if marker in node.log_path.read_text(errors="replace"):
                return
        await asyncio.sleep(0.2)


def require_checkpoint_acquired(log, block):
    identity = json.loads(block.to_json())
    marker = (f"best handle is [ w=-1 s=9223372036854775808 seq={block.seqno} "
              f"{identity['root_hash']} {identity['file_hash']} ]")
    if block.seqno == 0 or marker not in log:
        raise AssertionError("cold node did not select the generated persistent checkpoint")
    if "persistent state download finished" not in log:
        raise AssertionError("cold node did not finish persistent checkpoint acquisition")
    if not any("finished downloading state (2,8000000000000000," in line
               and "(2,8000000000000000,0)" not in line for line in log.splitlines()):
        raise AssertionError("cold node did not download a non-genesis Counter snapshot")


def require_checkpoint_streamed(log):
    downloaded = set(re.findall(r"finished downloading state (\(2,8000000000000000,[1-9][0-9]*\):[A-F0-9]+:[A-F0-9]+):[^\n]*\(file\)", log))
    imported = set(re.findall(r"import_persistent_state_streaming for (\(2,8000000000000000,[1-9][0-9]*\):[A-F0-9]+:[A-F0-9]+), cells_persisted=[1-9][0-9]*", log))
    if not downloaded & imported:
        raise AssertionError("cold Counter snapshot did not traverse file download and actor-local streaming import")


def signature_proof_results(root, cold_name="node5", sent_marker="COUNTER_BAD_SIGNATURE_SENT"):
    logs = "\n".join(log.read_text(errors="replace") for log in (root / "network").glob("node*/log"))
    cold_path = root / "network" / cold_name / "log"
    cold_log = cold_path.read_text(errors="replace") if cold_path.exists() else ""

    def fingerprints(marker, text):
        return {value.upper() for value in re.findall(marker + r" ([0-9a-fA-F]{64})", text)}

    # Any receiver accepting the injected proof fails; successful rejection
    # evidence must come from the cold observer, not another committee node.
    return (fingerprints(sent_marker, logs), fingerprints("COUNTER_REMOTE_PROOF_ACCEPTED", logs),
            fingerprints("COUNTER_REMOTE_PROOF_REJECTED", cold_log))


async def watch_proof_acceptance(root):
    while True:
        for log in (root / "network").glob("node*/log"):
            if "COUNTER_MISBOUND_PROOF_ACCEPTED" in log.read_text(errors="replace"):
                raise AssertionError(f"real receiver accepted a misbound peer proof: {log}")
        sent, accepted, _ = signature_proof_results(root)
        if sent & accepted:
            raise AssertionError("real receiver accepted a peer proof with a corrupted committee signature")
        retired, accepted, _ = signature_proof_results(root, sent_marker="COUNTER_RETIRED_SIGNATURE_SENT")
        if retired & accepted:
            raise AssertionError("real receiver accepted a proof signed by a retired committee member")
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
                   bad_signature=False, large_payload=False, reweight=False, membership=False, retired_signature=False,
                   checkpoint=False, streaming=False):
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
            if checkpoint:
                # Older than the native two-day early-start heuristic as well
                # as the current snapshot bucket; the committee remains valid.
                network.config.counter_checkpoint_genesis_time = int(time.time()) - 2 * 86400 - 60
        committee_size = 4
        network.config.shard_validators = committee_size
        dht = network.create_dht_node()
        validators = [network.create_full_node() for _ in range(4)]
        for node in validators:
            node.make_initial_validator()
            node.announce_to(dht)
        options = StartOptions(threads=4, verbosity=4 if large_payload else 3, args=(
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
            "TOS_COUNTER_CHECKPOINT": "1" if checkpoint else "0",
            "TOS_COUNTER_RETIRED_SIGNATURE_FILE": str(root / "retired-signature.bin") if retired_signature else "",
        })
        await dht.run(StartOptions(threads=2, verbosity=3))
        for node in validators:
            await node.run(replace(options, args=(*options.args, "--skip-key-sync") if checkpoint else options.args, env={
                **options.env, "TOS_COUNTER_SIGNATURE_PROBE": "1",
                "TOS_COUNTER_REENCODE_ZERO_STATE": "1" if reencoded_state else "0",
                "TOS_COUNTER_MISBOUND_PROOF_FILE": str(root / "proof-fault-armed") if misbound_proof else "",
                "TOS_COUNTER_BAD_SIGNATURE_FILE": str(root / "proof-fault-armed") if bad_signature else "",
            }) if counter else options)
        warm_client, target = await asyncio.wait_for(reach(validators[0], 5), 150)
        counter_target = await asyncio.wait_for(counter_tip(validators[0]), join_timeout) if counter else None
        if counter:
            for node in validators:
                await asyncio.wait_for(require_proof_probe(node, signatures=True), 10)
        committee_key = None
        replacement = None
        if membership:
            replacement_node = network.create_full_node()
            replacement_node.announce_to(dht)
            await replacement_node.run(options, seed_extra_states=False)
            if len(list((replacement_node.log_path.parent / "static").iterdir())) != 2:
                raise AssertionError("replacement validator must start with only masterchain/native static states")
            await asyncio.wait_for(reach(replacement_node, target.seqno), join_timeout)
            replacement = (validators[0].validator_key.public_key.key,
                           replacement_node.validator_key.public_key.key, replacement_node.validator_key.id)
        if reweight or membership:
            pre_committee_header = await warm_client.get_block_header(target)
            (root / "committee-before-header.json").write_text(pre_committee_header.to_json())
            original_committee, new_committee = await submit_committee_update(
                install, network_dir / "state", warm_client, target, replacement)
            target, committee_key = await asyncio.wait_for(wait_committee_updated(warm_client, new_committee), join_timeout)
            (root / "committee-before.boc").write_bytes(original_committee.to_boc())
            (root / "committee-after.boc").write_bytes(new_committee.to_boc())
            (root / "committee-key-block.json").write_text(committee_key.to_json())
            if membership:
                # Two retained members alone cannot reach the four-member quorum.
                # Require subsequent production and a proof carrying the new key.
                await validators[0].stop()
                await validators[1].stop()
                warm_client, target = await asyncio.wait_for(reach(validators[2], target.seqno + 8), join_timeout)

            async def post_committee_counter():
                while True:
                    tip = await counter_tip(validators[2] if membership else validators[0])
                    info = await warm_client.get_block_header(tip)
                    if info.min_ref_mc_seqno >= committee_key.seqno:
                        return tip
                    await asyncio.sleep(0.2)

            counter_target = await asyncio.wait_for(post_committee_counter(), join_timeout)
        if checkpoint:
            await asyncio.wait_for(require_checkpoint_serialized(validators, committee_key.seqno), join_timeout)
            print(f"persistent checkpoint {committee_key.seqno} serialized; starting cold selection", flush=True)
        if retired_signature:
            signed = await warm_client.get_masterchain_block_signatures(target.seqno)
            manifest, transcript = retired_signature_manifest(
                REPO, signed, target, replacement_node.validator_key, validators[0].validator_key)
            (root / "retired-signature-transcript.bin").write_bytes(transcript)
            (root / "retired-signature-control.json").write_text(signed.to_json())
            pending = root / "retired-signature.pending"
            pending.write_bytes(manifest)
            pending.replace(root / "retired-signature.bin")
        cold_options = replace(options, env={**options.env, "TOS_COUNTER_RETIRED_SIGNATURE_FILE": ""})
        if checkpoint:
            cold_options = replace(cold_options, args=(*cold_options.args, "--sync-before", "1"))
        if streaming:
            cold_options = replace(cold_options, args=(*cold_options.args, "--persistent-state-heap-threshold", "1048576"))
        # Construct the joining node only after the target already exists. No
        # warm database, block archive or proof is copied into its directory.
        cold = network.create_full_node()
        cold.announce_to(dht)
        if misbound_proof or bad_signature:
            (root / "proof-fault-armed").touch()
        print(f"cold join starts after masterchain height {target.seqno}", flush=True)
        # Membership tests deliberately stop both the retired validator and
        # one retained validator, forcing the new member to complete quorum.
        active_validators = [*validators[2:], replacement_node] if membership else validators
        expected_active_count = committee_size - 1 if membership else committee_size
        validator_memory = {"before_cold_join": validator_memory_observation(
            active_validators, expected_active_count)}
        (root / "validator-memory.json").write_text(json.dumps(validator_memory, indent=2) + "\n")
        await cold.run(cold_options, seed_extra_states=False)
        memory_observations = {}
        if counter and len(list((cold.log_path.parent / "static").iterdir())) != 2:
            raise AssertionError("cold node must have only masterchain/native static states")
        cold_client, observed = await asyncio.wait_for(reach(cold, target.seqno + 2), join_timeout)
        await asyncio.wait_for(reach_authenticated(cold_client, target.seqno), join_timeout)
        same = await cold_client.lookup_block(-1, target.shard, seqno=target.seqno)
        if same.to_json() != target.to_json():
            raise AssertionError("cold node disagrees on the pre-existing finalized block")
        header = await cold_client.get_block_header(same)
        if membership:
            signed = await cold_client.get_masterchain_block_signatures(same.seqno)
            require_membership_signers(signed, same, replacement_node.validator_key.id, validators[0].validator_key.id)
            (root / "membership-signatures.json").write_text(signed.to_json())
        if committee_key is not None:
            (root / "committee-after-header.json").write_text(header.to_json())
            if header.validator_list_hash_short == pre_committee_header.validator_list_hash_short:
                raise AssertionError("post-transition block still names the original signing committee")
            cold_committee, _ = await read_committee(cold_client, same)
            if cold_committee.hash != new_committee.hash or cold_committee.hash == original_committee.hash:
                raise AssertionError("cold node retained the pre-transition committee")
            if checkpoint:
                # Checkpoint bootstrap stores proofs and state, not necessarily
                # the checkpoint's historical block body required by lookup.
                # Bind selection to both hashes, then verify post-checkpoint
                # state and the authenticated client cursor independently.
                require_checkpoint_acquired(cold.log_path.read_text(errors="replace"), committee_key)
            else:
                cold_key = await cold_client.lookup_block(-1, committee_key.shard, seqno=committee_key.seqno)
                if cold_key.to_json() != committee_key.to_json():
                    raise AssertionError("cold node disagrees on the committee key block")
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
            if streaming:
                require_checkpoint_streamed(cold_log)
            if retired_signature:
                sent, accepted, rejected = signature_proof_results(
                    root, cold.log_path.parent.name, "COUNTER_RETIRED_SIGNATURE_SENT")
                if sent & accepted or not sent & rejected:
                    raise AssertionError("cold receiver did not reject the retired-member proof")
                if not any(f"COUNTER_REMOTE_PROOF_REJECTED {fingerprint} " in line and "unknown node" in line
                           for fingerprint in sent & rejected for line in cold_log.splitlines()):
                    raise AssertionError("retired-member rejection did not reach membership validation")
            if bad_signature:
                sent, accepted, rejected = signature_proof_results(root, cold.log_path.parent.name)
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
            if not checkpoint and (not any(f"downloading state {zero_id}" in line and " from " in line
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
        validator_memory["after_cold_join"] = validator_memory_observation(
            active_validators, expected_active_count, validator_memory["before_cold_join"])
        (root / "validator-memory.json").write_text(json.dumps(validator_memory, indent=2) + "\n")
        for node in validators:
            await node.stop()
        if membership:
            await replacement_node.stop()
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
            memory_observations["cold_join"] = node_memory_observation(cold)
            (root / "cold-memory.json").write_text(json.dumps(memory_observations, indent=2) + "\n")
            await cold.stop()
            shutil.copyfile(cold.log_path, root / "cold-before-restart.log")
            await cold.run(cold_options)
            restarted, _ = await asyncio.wait_for(reach(cold, observed.seqno), join_timeout)
            await asyncio.wait_for(reach_authenticated(restarted, observed.seqno), join_timeout)
            if committee_key is not None:
                reopened_committee, _ = await asyncio.wait_for(read_committee(restarted, same), 20)
                if reopened_committee.hash != new_committee.hash:
                    raise AssertionError("committee changed across cold database reopening")
            restored = await asyncio.wait_for(counter_state(restarted, counter_target, payload), 20)
            if restored.data != executor_state.data or restored.last_transaction_id.to_json() != executor_state.last_transaction_id.to_json():
                raise AssertionError("Counter state changed across cold database reopening")
            (root / "counter-account-reopened.json").write_text(restored.to_json())
            memory_observations["reopened"] = node_memory_observation(cold)
            (root / "cold-memory.json").write_text(json.dumps(memory_observations, indent=2) + "\n")
        replay_cache = None
        if large_payload:
            replay_cache = require_validator_replay_cache({
                node.log_path.parent.name: node.log_path.read_text(errors="replace") for node in active_validators},
                replacement_node.log_path.parent.name if membership else None)
            (root / "validator-replay-cache.json").write_text(json.dumps(replay_cache, indent=2) + "\n")
        return {"scope": "Counter real-manager cold-join" if counter else "native/masterchain real-manager cold-join baseline only",
                "counter_workchain_tested": counter, "uno_sync_accepted": False,
                "counter_block": json.loads(counter_target.to_json()) if counter_target else None,
                "invalid_proof_rejection_tested": False, "cold_executor_state_tested": counter,
                "cold_database_reopened": counter,
                "bounded_payload_reopened": large_payload,
                "cold_process_memory": memory_observations,
                "validator_process_memory": validator_memory,
                "validator_replay_cache": replay_cache,
                "replacement_validator_replay_tested": large_payload and membership,
                "large_state_rss_bound_accepted": False,
                "committee_reweight_cold_join_tested": reweight,
                "committee_key_block_seqno": committee_key.seqno if committee_key else None,
                "committee_membership_rotation_tested": membership,
                "executor_data_boc_bytes": len(executor_state.data) if executor_state else None,
                "payload_cells": 32767 if large_payload else 0,
                "cold_counter_zerostate_peer_download_tested": counter and not checkpoint,
                "persistent_checkpoint_cold_join_tested": checkpoint,
                "persistent_checkpoint_streaming_import_tested": streaming,
                "remote_reencoded_zerostate_rejection_tested": reencoded_state,
                "remote_misbound_proof_rejection_tested": misbound_proof,
                "remote_committee_signature_rejection_tested": bad_signature,
                "remote_retired_member_rejection_tested": retired_signature,
                "manager_proof_root_binding_tested": counter,
                "manager_broadcast_signature_rejection_tested": counter,
                "validator_processes": 5 if membership else 4, "cold_observer_processes": 1,
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
    parser.add_argument("--counter-reweight", action="store_true",
                        help="cold-join after a signed config-owner validator-weight update (not an election)")
    parser.add_argument("--counter-checkpoint", action="store_true",
                        help="use aged genesis and require native persistent-checkpoint cold join; requires --counter-reweight")
    parser.add_argument("--counter-checkpoint-streaming", action="store_true",
                        help="require file download and actor-local import; requires --counter-checkpoint and --counter-payload")
    parser.add_argument("--counter-membership", action="store_true",
                        help="replace one committee member with an independent node, then cold-join")
    parser.add_argument("--counter-retired-signature", action="store_true",
                        help="require rejection of a genuine retired-member signature after replacement")
    parser.add_argument("--counter-reencoded-state", action="store_true",
                        help="require rejection/recovery after peers reencode one Counter zerostate response each")
    parser.add_argument("--counter-misbound-proof", action="store_true",
                        help="require real receiver rejection of a peer proof naming the wrong file hash")
    parser.add_argument("--counter-bad-signature", action="store_true",
                        help="require rejection of a masterchain proof with one corrupted committee signature")
    args = parser.parse_args()
    if args.counter_payload and not args.counter:
        parser.error("--counter-payload requires --counter")
    if args.counter_checkpoint_streaming and (not args.counter_checkpoint or not args.counter_payload):
        parser.error("--counter-checkpoint-streaming requires --counter-checkpoint and --counter-payload")
    if args.counter_reweight and not args.counter:
        parser.error("--counter-reweight requires --counter")
    if args.counter_checkpoint and (not args.counter_reweight or args.counter_reencoded_state
                                   or args.counter_misbound_proof or args.counter_bad_signature):
        parser.error("--counter-checkpoint requires --counter-reweight and excludes proof/zerostate fault profiles")
    if args.counter_membership and (not args.counter or args.counter_reweight):
        parser.error("--counter-membership requires --counter and excludes --counter-reweight")
    if args.counter_retired_signature and (not args.counter_membership or args.counter_bad_signature):
        parser.error("--counter-retired-signature requires --counter-membership and excludes --counter-bad-signature")
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
    for port in range(args.base_port + 1, args.base_port + (21 if args.counter_membership else 18)):
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
                                      args.counter_bad_signature, args.counter_payload, args.counter_reweight,
                                      args.counter_membership, args.counter_retired_signature, args.counter_checkpoint,
                                      args.counter_checkpoint_streaming)))
        report["passed"] = True
    except BaseException as error:
        report["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
