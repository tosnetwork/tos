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
        try:
            stat = base64.b64decode(observation["proc_stat_base64"], validate=True)
            stat_pid = int(stat.split(b" (", 1)[0])
            state = stat.rsplit(b") ", 1)[1].split(b" ", 1)[0]
        except (KeyError, TypeError, ValueError, IndexError) as error:
            raise ValueError(f"{phase}: raw /proc PID evidence is malformed") from error
        if stat_pid != observation["pid"] or state not in (b"R", b"S", b"D", b"I", b"T"):
            raise ValueError(f"{phase}: raw /proc PID evidence disagrees with process event")
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


def validate(policy: dict, trace: dict) -> dict:
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
    if (stop_three[node4]["pid"] != nodes[node4]["initial_pid"]
            or stop_two[ordered[2]]["pid"] != nodes[ordered[2]]["initial_pid"]):
        raise ValueError("X01 stopped process differs from pre-fault PID identity")
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
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--expected-policy-sha256", required=True,
                        help="policy digest recorded before the fault run")
    args = parser.parse_args()
    policy_bytes = args.policy.read_bytes()
    policy_digest = hashlib.sha256(policy_bytes).hexdigest()
    if args.expected_policy_sha256 != policy_digest:
        raise ValueError("X01 policy differs from pre-fixed SHA-256")
    trace_bytes = args.trace.read_bytes()
    report = validate(json.loads(policy_bytes), json.loads(trace_bytes))
    report["policy_sha256"] = policy_digest
    report["trace_sha256"] = hashlib.sha256(trace_bytes).hexdigest()
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
