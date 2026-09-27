#!/usr/bin/env python3
"""Read-only X01 fault-window checker; inputs require separately retained raw RPC/process evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

HEX = re.compile(r"[0-9a-fA-F]{64}\Z")
SHARD = "8000000000000000"


def full_id(value: object) -> tuple[int, str, int, str, str]:
    if not isinstance(value, dict):
        raise ValueError("missing full BlockIdExt")
    try:
        wc = value["workchain"]
        shard = value["shard"]
        height = value["seqno"]
        root = value["root_hash"]
        file_hash = value["file_hash"]
    except KeyError as error:
        raise ValueError("incomplete full BlockIdExt") from error
    if (type(wc) is not int or wc != -1 or shard != SHARD
            or type(height) is not int or height < 0
            or not isinstance(root, str) or not HEX.fullmatch(root) or int(root, 16) == 0
            or not isinstance(file_hash, str) or not HEX.fullmatch(file_hash)
            or int(file_hash, 16) == 0):
        raise ValueError("malformed or zero full BlockIdExt")
    return wc, shard, height, root.lower(), file_hash.lower()


def utc_time(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label}: timestamp is absent")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label}: timestamp is malformed") from error
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError(f"{label}: timestamp is not UTC")
    return parsed


def proc_identity(raw_base64: object, label: str) -> tuple[int, int]:
    try:
        raw = base64.b64decode(raw_base64, validate=True)
        prefix, suffix = raw.rsplit(b") ", 1)
        pid = int(prefix.split(b" (", 1)[0])
        fields = suffix.split()
        start_ticks = int(fields[19])  # /proc/<pid>/stat field 22
    except (TypeError, ValueError, IndexError) as error:
        raise ValueError(f"{label}: raw /proc PID/start ticks are malformed") from error
    if pid <= 0 or start_ticks <= 0 or fields[0] not in (b"R", b"S", b"D", b"I", b"T"):
        raise ValueError(f"{label}: raw /proc PID/start ticks are invalid")
    return pid, start_ticks


def require_generations(policy: dict, manifest: dict, os_records: list[dict] | None) -> dict[str, list[dict]]:
    nodes = policy["nodes"]
    schema = manifest.get("schema") if isinstance(manifest, dict) else None
    if schema != "tos.f01.stage-a-capture.v1":
        raise ValueError("X01 requires the sealed F01 capture manifest")
    validators = manifest.get("validators") if isinstance(manifest, dict) else None
    if (not isinstance(validators, list) or len(validators) != 4
            or {row.get("node_name") for row in validators if isinstance(row, dict)} != set(nodes)):
        raise ValueError("X01 requires four F01 process-generation identities")
    result = {}
    seen_process = set()
    seen_cwd = {}
    exe_identity = set()
    seen_log_paths = {}
    seen_log_hashes = {}
    seen_log_inodes = {}

    def log_identity(log: object, basename: str, label: str, node: str) -> None:
        if not isinstance(log, dict):
            raise ValueError(f"{label}: F01 raw log provenance is absent")
        path, digest = log.get("path"), log.get("sha256")
        if (not isinstance(path, str) or Path(path).name != basename
                or not isinstance(digest, str) or not HEX.fullmatch(digest)
                or int(digest, 16) == 0):
            raise ValueError(f"{label}: F01 raw log owner/path/SHA is malformed")
        source = Path(path).resolve(strict=True)
        inode = (source.stat().st_dev, source.stat().st_ino)
        if (seen_log_paths.get(source, node) != node
                or seen_log_inodes.get(inode, node) != node
                or seen_log_hashes.get(digest.lower(), node) != node
                or not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != digest.lower()):
            raise ValueError(f"{label}: F01 raw log aliases another node or differs from bytes")
        seen_log_paths[source] = node
        seen_log_inodes[inode] = node
        seen_log_hashes[digest.lower()] = node

    for validator in validators:
        node = validator["node_name"]
        fixed = nodes[node]
        if any(validator.get(key) != fixed.get(policy_key) for key, policy_key in (
                ("node_data_dir", "node_data_dir"), ("pq_key_id_hex", "pq_key_id_hex"),
                ("adnl_id_hex", "adnl_id_hex"), ("rpc_address", "endpoint"))):
            raise ValueError(f"{node}: F01 generation owner/PQ/ADNL/RPC differs from policy")
        generations = validator.get("process_generations")
        if not isinstance(generations, list) or not generations:
            raise ValueError(f"{node}: F01 process generations are absent")
        previous_ticks = 0
        previous_time = None
        owner_cwd = None
        for index, row in enumerate(generations):
            if not isinstance(row, dict):
                raise ValueError(f"{node}: F01 generation is malformed")
            pid, ticks = row.get("pid"), row.get("proc_start_ticks")
            at = utc_time(row.get("recorded_at"), f"{node} generation")
            cwd = (row.get("proc_cwd_device"), row.get("proc_cwd_inode"))
            exe = (row.get("exe_device"), row.get("exe_inode"))
            if (row.get("node_name") != node or type(row.get("generation")) is not int
                    or row["generation"] != index
                    or type(pid) is not int or pid <= 0 or type(ticks) is not int or ticks <= previous_ticks
                    or (pid, ticks) in seen_process or previous_time is not None and at <= previous_time
                    or row.get("node_data_dir") != fixed["node_data_dir"]
                    or row.get("proc_cwd_link") != fixed["node_data_dir"]
                    or row.get("proc_cwd_realpath") != fixed["node_data_dir"]
                    or any(type(value) is not int or value <= 0 for value in cwd + exe)
                    or row.get("exe_path") != fixed["validator_engine_exe_path"]):
                raise ValueError(f"{node}: F01 PID/start/cwd/binary generation is inconsistent")
            prior_owner = seen_cwd.setdefault(cwd, node)
            if prior_owner != node:
                raise ValueError("X01 validator DB cwd inode is shared across nodes")
            if owner_cwd is not None and cwd != owner_cwd:
                raise ValueError(f"{node}: F01 process generations changed DB cwd inode")
            owner_cwd = cwd
            exe_identity.add(exe)
            seen_process.add((pid, ticks))
            previous_ticks, previous_time = ticks, at
        if fixed["initial_pid"] not in [row["pid"] for row in generations]:
            raise ValueError(f"{node}: frozen policy PID has no F01 generation")
        log_identity(validator.get("combined_log"), f"{node}-finalized.log", node, node)
        segments = validator.get("log_segments")
        if not isinstance(segments, list) or len(segments) != len(generations):
            raise ValueError(f"{node}: F01 log segments omit a process generation")
        for index, segment in enumerate(segments):
            if not isinstance(segment, dict) or segment.get("process") != generations[index]:
                raise ValueError(f"{node}: F01 log segment differs from process generation")
            log_identity(segment, f"{node}-segment-{index:02d}.log", f"{node} segment {index}", node)
        result[node] = generations
    if len(exe_identity) != 1:
        raise ValueError("X01 validator executable inode changed across generations")
    if os_records is not None:
        if not isinstance(os_records, list) or len(os_records) != len(seen_process):
            raise ValueError("X01 independent OS process generations are incomplete")
        os_by_process = {}
        for row in os_records:
            if not isinstance(row, dict) or (row.get("pid"), row.get("proc_start_ticks")) in os_by_process:
                raise ValueError("X01 independent OS process generation is duplicated")
            key = (row.get("pid"), row.get("proc_start_ticks"))
            if key not in seen_process or proc_identity(row.get("proc_stat_raw_base64"), "OS watcher") != key:
                raise ValueError("X01 independent OS /proc PID/start ticks differ")
            os_by_process[key] = row
        for node, generations in result.items():
            fixed = nodes[node]
            for row in generations:
                witness = os_by_process[(row["pid"], row["proc_start_ticks"])]
                try:
                    argv = base64.b64decode(witness["proc_cmdline_raw_base64"], validate=True).rstrip(b"\0").split(b"\0")
                    args = [arg.decode() for arg in argv]
                except (KeyError, TypeError, ValueError, UnicodeDecodeError) as error:
                    raise ValueError(f"{node}: independent OS argv is malformed") from error
                if (any(witness.get(key) != row.get(key) for key in (
                        "exe_path", "exe_device", "exe_inode", "proc_cwd_link",
                        "proc_cwd_realpath", "proc_cwd_device", "proc_cwd_inode"))
                        or witness.get("exe_sha256") != fixed["validator_engine_exe_sha256"]
                        or not args or args[0] != fixed["validator_engine_exe_path"]
                        or not all((flag in args and args.index(flag) + 1 < len(args)
                                    and args[args.index(flag) + 1] == value) for flag, value in (
                            ("--db", "."),
                            ("--local-config", fixed["node_data_dir"] + "/config.json"),
                            ("--json-rpc-address", fixed["endpoint"])))):
                    raise ValueError(f"{node}: independent OS cwd/DB/PQ binary or RPC owner differs")
    return result


def require_process_events(trace: dict, collection: str, phase: str,
                           expected: set[str], nodes: dict) -> dict[str, dict]:
    events = trace.get(collection)
    if not isinstance(events, list):
        raise ValueError(f"{collection}: raw process records are absent")
    selected = [row for row in events if isinstance(row, dict) and row.get("phase") == phase]
    if {row.get("node") for row in selected} != expected or len(selected) != len(expected):
        raise ValueError(f"{phase}: fault-hit identities are absent or ambiguous")
    result = {}
    for row in selected:
        digest = row.get("raw_evidence_sha256")
        stop = collection == "faults"
        if (row.get("kind") != ("process_stopped" if stop else "process_started")
                or row.get("hit") is not True
                or not isinstance(digest, str) or not HEX.fullmatch(digest)
                or int(digest, 16) == 0):
            raise ValueError(f"{phase}: process {'stop' if stop else 'start'} fault has no raw hit evidence")
        try:
            raw = base64.b64decode(row["raw_evidence_base64"], validate=True)
            observation = json.loads(raw)
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"{phase}: process raw evidence is malformed") from error
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError(f"{phase}: process raw evidence SHA-256 differs")
        if (not isinstance(observation, dict)
                or observation.get("schema") != ("tos.x01.process-stop.v1" if stop else "tos.x01.process-start.v1")
                or observation.get("phase") != phase
                or observation.get("node") != row["node"]
                or type(observation.get("pid")) is not int or observation["pid"] <= 0
                or observation.get("running_before") is not stop
                or observation.get("running_after") is not (not stop)
                or observation.get("proc_after_absent" if stop else "old_proc_absent") is not True
                or any(observation.get(field) != nodes[row["node"]].get(field)
                       for field in ("node_data_dir", "node_log_path", "pq_key_id_hex", "adnl_id_hex"))
                or observation.get("exe_path") != nodes[row["node"]].get("validator_engine_exe_path")
                or observation.get("exe_sha256") != nodes[row["node"]].get("validator_engine_exe_sha256")
                or not stop and (type(observation.get("old_pid")) is not int
                                 or observation["old_pid"] <= 0
                                 or observation["old_pid"] == observation["pid"])):
            raise ValueError(f"{phase}: process raw evidence did not prove a hit")
        stat_pid, start_ticks = proc_identity(observation.get("proc_stat_base64"), phase)
        if stat_pid != observation["pid"]:
            raise ValueError(f"{phase}: raw /proc PID evidence disagrees with process event")
        observation["_start_ticks"] = start_ticks
        observation["_at"] = utc_time(observation.get("at"), f"{phase} process event")
        result[row["node"]] = observation
    return result


def rounds(trace: dict, phase: str, expected: set[str], minimum: int) -> list[tuple[int, str, int, str, str]]:
    samples = trace.get("phases", {}).get(phase)
    if not isinstance(samples, list) or len(samples) < minimum:
        raise ValueError(f"{phase}: too few independent samples")
    observed = []
    previous_height = -1
    previous_completed = None
    previous_tips: dict[str, tuple[int, str, int, str, str]] = {}
    for sample in samples:
        if not isinstance(sample, dict) or not isinstance(sample.get("at"), str):
            raise ValueError(f"{phase}: sample lacks timestamp")
        parsed = utc_time(sample["at"], f"{phase} sample start")
        completed = utc_time(sample.get("completed_at"), f"{phase} sample completion")
        if completed < parsed:
            raise ValueError(f"{phase}: sample completion precedes RPC start")
        views = sample.get("nodes")
        if not isinstance(views, dict) or set(views) != expected:
            raise ValueError(f"{phase}: sample has missing or extra node views")
        ids = {full_id(value) for value in views.values()}
        if len(ids) != 1:
            raise ValueError(f"{phase}: live nodes conflict at a common sample")
        block = ids.pop()
        tips = sample.get("tips")
        if not isinstance(tips, dict) or set(tips) != expected:
            raise ValueError(f"{phase}: sample has missing or extra node tips")
        tip_times = sample.get("tip_observed_at")
        if not isinstance(tip_times, dict) or set(tip_times) != expected:
            raise ValueError(f"{phase}: sample has missing or extra tip response times")
        current_tips = {node: full_id(value) for node, value in tips.items()}
        for node, tip in current_tips.items():
            tip_at = utc_time(tip_times[node], f"{phase} {node} tip response")
            if not parsed <= tip_at <= completed:
                raise ValueError(f"{phase}: {node} tip response time outside sample RPC window")
            if tip[2] < block[2] or tip[2] == block[2] and tip != block:
                raise ValueError(f"{phase}: {node} tip disagrees with the common header")
            previous_tip = previous_tips.get(node)
            if previous_tip is not None and (tip[2] < previous_tip[2]
                                             or tip[2] == previous_tip[2] and tip != previous_tip):
                raise ValueError(f"{phase}: {node} tip regressed or changed at one height")
        if previous_completed is not None and parsed <= previous_completed:
            raise ValueError(f"{phase}: sample times overlap or regress")
        if block[2] < previous_height:
            raise ValueError(f"{phase}: sample height regressed")
        previous_completed, previous_height, previous_tips = completed, block[2], current_tips
        observed.append(block)
    return observed


def tip_observation_seconds(trace: dict, phase: str, nodes: set[str],
                            *, tail: int | None = None) -> float:
    """Intersection of the per-node tip observation intervals."""
    samples = trace["phases"][phase]
    if tail is not None:
        samples = samples[-tail:]
    common_start = max(
        utc_time(samples[0]["tip_observed_at"][node], f"{phase} {node} first tip")
        for node in nodes
    )
    common_end = min(
        utc_time(samples[-1]["tip_observed_at"][node], f"{phase} {node} last tip")
        for node in nodes
    )
    return (common_end - common_start).total_seconds()


def window_seconds(trace: dict, phase: str) -> float:
    samples = trace["phases"][phase]
    first = utc_time(samples[0]["at"], f"{phase} first sample start")
    last = utc_time(samples[-1]["completed_at"], f"{phase} last sample completion")
    return (last - first).total_seconds()


def validate(policy: dict, trace: dict, *, generation_manifest: dict | None = None,
             os_process_generations: list[dict] | None = None) -> dict:
    if policy.get("schema") != "tos.x01.window-policy.v1":
        raise ValueError("X01 policy schema is missing")
    nodes = policy.get("nodes")
    if not isinstance(nodes, dict) or len(nodes) != 4 or not all(isinstance(v, dict) for v in nodes.values()):
        raise ValueError("X01 requires four bound validator identities")
    endpoints = [row.get("endpoint") for row in nodes.values()]
    if any(not isinstance(e, str) or not e for e in endpoints) or len(set(endpoints)) != 4:
        raise ValueError("X01 requires four distinct RPC endpoints")
    if len({full_id(row.get("zerostate")) for row in nodes.values()}) != 1:
        raise ValueError("X01 validator views do not share zerostate")
    for field in ("node_data_dir", "node_log_path", "pq_key_id_hex", "adnl_id_hex", "initial_pid"):
        values = [row.get(field) for row in nodes.values()]
        if field == "initial_pid":
            valid = all(type(value) is int and value > 0 for value in values)
        else:
            valid = all(isinstance(value, str) and bool(value) for value in values)
        if not valid or len(set(values)) != 4:
            raise ValueError(f"X01 requires four distinct {field} identities")
    binary_paths = [row.get("validator_engine_exe_path") for row in nodes.values()]
    binary_hashes = [row.get("validator_engine_exe_sha256") for row in nodes.values()]
    if (any(not isinstance(value, str) or not value for value in binary_paths)
            or len(set(binary_paths)) != 1
            or any(not isinstance(value, str) or not HEX.fullmatch(value)
                   or int(value, 16) == 0 for value in binary_hashes)
            or len(set(binary_hashes)) != 1):
        raise ValueError("X01 validator binary provenance is absent or inconsistent")
    generations = require_generations(
        policy, generation_manifest if generation_manifest is not None
        else trace.get("process_generation_manifest"), os_process_generations)
    thresholds = policy.get("thresholds")
    if not isinstance(thresholds, dict):
        raise ValueError("X01 thresholds are absent")
    required = ("three_min_delta", "halt_min_samples", "halt_tail_samples",
                "recovery_min_delta", "three_max_seconds", "halt_min_seconds",
                "halt_tail_min_seconds", "recovery_max_seconds")
    if any(type(thresholds.get(name)) is not int or thresholds[name] < 1 for name in required):
        raise ValueError("X01 thresholds must be pre-fixed positive integers")
    if thresholds["halt_min_samples"] < 4 or thresholds["halt_tail_samples"] < 2:
        raise ValueError("X01 halt window is too short")
    all_nodes = set(nodes)
    ordered = sorted(all_nodes)
    if (not isinstance(trace.get("faults"), list) or len(trace["faults"]) != 3
            or not isinstance(trace.get("restarts"), list) or len(trace["restarts"]) != 3):
        raise ValueError("X01 requires exactly three stop and three start records")
    stop_three = require_process_events(trace, "faults", "three_of_four", {ordered[3]}, nodes)
    stop_two = require_process_events(trace, "faults", "two_of_four", set(ordered[2:]), nodes)
    start_three = require_process_events(trace, "restarts", "three_of_four", {ordered[3]}, nodes)
    start_recovery = require_process_events(trace, "restarts", "recovery", set(ordered[2:]), nodes)
    live_three = set(ordered[:3])
    live_two = set(ordered[:2])
    three = rounds(trace, "three_of_four", live_three, 2)
    if three[-1][2] - three[0][2] < thresholds["three_min_delta"]:
        raise ValueError("3/4 liveness did not meet pre-fixed height delta")
    if window_seconds(trace, "three_of_four") > thresholds["three_max_seconds"]:
        raise ValueError("3/4 liveness exceeded pre-fixed window")
    halted = rounds(trace, "two_of_four", live_two, thresholds["halt_min_samples"])
    if (halted[0][2] < three[-1][2]
            or halted[0][2] == three[-1][2] and halted[0] != three[-1]):
        raise ValueError("2/4 window regressed behind the 3/4 tip")
    tail = halted[-thresholds["halt_tail_samples"]:]
    if len(set(tail)) != 1:
        raise ValueError("2/4 safety window advanced or changed full BlockIdExt")
    for sample in trace["phases"]["two_of_four"][-len(tail):]:
        if any(full_id(sample["tips"][node]) != halted[-1] for node in live_two):
            raise ValueError("2/4 live tip progressed beyond the stable common checkpoint")
    checkpoint = trace.get("recovery_halt_checkpoint")
    if (not isinstance(checkpoint, dict) or set(checkpoint) != all_nodes
            or {full_id(value) for value in checkpoint.values()} != {halted[-1]}):
        raise ValueError("recovered nodes disagree with the exact halt checkpoint")
    if (tip_observation_seconds(trace, "two_of_four", live_two)
            < thresholds["halt_min_seconds"]
            or tip_observation_seconds(trace, "two_of_four", live_two, tail=len(tail))
            < thresholds["halt_tail_min_seconds"]):
        raise ValueError("2/4 common tip window was too short")
    recovered = rounds(trace, "recovery", all_nodes, 2)
    if (recovered[0][2] < halted[-1][2]
            or recovered[0][2] == halted[-1][2] and recovered[0] != halted[-1]):
        raise ValueError("recovery is not continuous with the halt checkpoint")
    phase_times = [trace["phases"][name] for name in
                   ("three_of_four", "two_of_four", "recovery")]
    first_three = utc_time(phase_times[0][0]["at"], "3/4 first sample start")
    last_three = utc_time(phase_times[0][-1]["completed_at"], "3/4 last sample completion")
    first_two = utc_time(phase_times[1][0]["at"], "2/4 first sample start")
    last_two = utc_time(phase_times[1][-1]["completed_at"], "2/4 last sample completion")
    first_recovery_start = utc_time(phase_times[2][0]["at"], "recovery sample start")
    if last_three >= first_two or last_two >= first_recovery_start:
        raise ValueError("X01 fault windows overlap or are out of order")
    node4 = ordered[3]
    def generation_index(node: str, event: dict, label: str) -> int:
        matches = [index for index, row in enumerate(generations[node])
                   if (row["pid"], row["proc_start_ticks"])
                   == (event["pid"], event["_start_ticks"])]
        if len(matches) != 1:
            raise ValueError(f"{label}: PID/start ticks has no unique F01 generation")
        recorded = utc_time(generations[node][matches[0]]["recorded_at"], label)
        if (label.endswith("stop") and recorded > event["_at"]
                or label in ("3/4 restart", "recovery start") and recorded < event["_at"]):
            raise ValueError(f"{label}: F01 process generation time contradicts its event")
        return matches[0]
    initial_node4_index = next(i for i, row in enumerate(generations[node4])
                               if row["pid"] == nodes[node4]["initial_pid"])
    if (stop_three[node4]["pid"] != nodes[node4]["initial_pid"]
            or generation_index(node4, stop_three[node4], "3/4 stop") != initial_node4_index):
        raise ValueError("X01 3/4 stop differs from frozen process generation")
    start_three_index = generation_index(node4, start_three[node4], "3/4 restart")
    stop_two_node4_index = generation_index(node4, stop_two[node4], "2/4 node4 stop")
    stop_two_node3_index = generation_index(ordered[2], stop_two[ordered[2]], "2/4 node3 stop")
    if start_three_index != stop_two_node4_index or start_three_index != initial_node4_index + 1:
        raise ValueError("X01 node4 restarted generation did not reach 2/4 stop")
    if stop_two_node3_index < next(i for i, row in enumerate(generations[ordered[2]])
                                   if row["pid"] == nodes[ordered[2]]["initial_pid"]):
        raise ValueError("X01 node3 stop precedes frozen process generation")
    for node, stopped_index in ((node4, stop_two_node4_index), (ordered[2], stop_two_node3_index)):
        if generation_index(node, start_recovery[node], "recovery start") != stopped_index + 1:
            raise ValueError(f"X01 {node} recovery skipped a process generation")
    if stop_three[node4]["_at"] > first_three:
        raise ValueError("3/4 stop time follows the first sample")
    if (last_three - stop_three[node4]["_at"]).total_seconds() > thresholds["three_max_seconds"]:
        raise ValueError("3/4 fault-to-observation exceeded the pre-fixed window")
    if not last_three < start_three[node4]["_at"] < stop_two[node4]["_at"]:
        raise ValueError("3/4 restart time does not precede the next stop")
    if start_three[node4]["old_pid"] != stop_three[node4]["pid"]:
        raise ValueError("3/4 restart PID continuity failed")
    if stop_two[node4]["pid"] != start_three[node4]["pid"]:
        raise ValueError("second stop PID continuity failed")
    for node in ordered[2:]:
        if not last_three < stop_two[node]["_at"] <= first_two:
            raise ValueError("2/4 stop time is outside the observation window")
        first_recovery_tip = utc_time(
            phase_times[2][0]["tip_observed_at"][node], f"recovery {node} first tip response")
        if not last_two < start_recovery[node]["_at"] <= first_recovery_tip:
            raise ValueError("recovery start time is outside the observation window")
        if start_recovery[node]["old_pid"] != stop_two[node]["pid"]:
            raise ValueError("recovery start PID continuity failed")
    last_recovery = utc_time(phase_times[2][-1]["completed_at"], "recovery sample completion")
    if (last_recovery - min(row["_at"] for row in start_recovery.values())).total_seconds() > thresholds["recovery_max_seconds"]:
        raise ValueError("recovery start-to-observation exceeded the pre-fixed window")
    if recovered[-1][2] - halted[-1][2] < thresholds["recovery_min_delta"]:
        raise ValueError("recovery did not meet pre-fixed height delta")
    if window_seconds(trace, "recovery") > thresholds["recovery_max_seconds"]:
        raise ValueError("recovery exceeded pre-fixed window")
    return {
        "schema": "tos.x01.window-check.v1", "passed": True,
        "three_first": three[0], "three_last": three[-1],
        "halt_tail_id": halted[-1], "halt_samples": len(halted),
        "recovery_last": recovered[-1], "nodes": ordered,
        "process_generations": {node: len(rows) for node, rows in generations.items()},
        "independent_os_checked": os_process_generations is not None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--expected-policy-sha256", required=True,
                        help="policy digest recorded before the fault run")
    parser.add_argument("--f01-manifest", type=Path, required=True)
    parser.add_argument("--expected-f01-manifest-sha256", required=True)
    parser.add_argument("--os-process-generations", type=Path, required=True)
    parser.add_argument("--expected-os-process-generations-sha256", required=True)
    args = parser.parse_args()
    policy_bytes = args.policy.read_bytes()
    policy_digest = hashlib.sha256(policy_bytes).hexdigest()
    if args.expected_policy_sha256 != policy_digest:
        raise ValueError("X01 policy differs from pre-fixed SHA-256")
    trace_bytes = args.trace.read_bytes()
    manifest_bytes = args.f01_manifest.read_bytes()
    os_bytes = args.os_process_generations.read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != args.expected_f01_manifest_sha256:
        raise ValueError("X01 F01 manifest SHA-256 differs")
    if hashlib.sha256(os_bytes).hexdigest() != args.expected_os_process_generations_sha256:
        raise ValueError("X01 independent OS process generation SHA-256 differs")
    report = validate(json.loads(policy_bytes), json.loads(trace_bytes),
                      generation_manifest=json.loads(manifest_bytes),
                      os_process_generations=[json.loads(line) for line in os_bytes.splitlines()])
    report["policy_sha256"] = policy_digest
    report["trace_sha256"] = hashlib.sha256(trace_bytes).hexdigest()
    report["f01_manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
    report["os_process_generations_sha256"] = hashlib.sha256(os_bytes).hexdigest()
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
