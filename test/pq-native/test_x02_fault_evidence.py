"""Synthetic X02 fault controls; never run tc or start a node."""

import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(os.environ.get("X02_CHECKER_SOURCE",
                             Path(__file__).resolve().parents[2] / "scripts/x02_fault_evidence.py"))
REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("x02_fault_evidence", SOURCE)
x02 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(x02)
NS = 1_000_000_000
ROOT = "1" * 64
FILE = "2" * 64
BOOT = "12345678-1234-1234-1234-123456789abc"


def block(height):
    return {"workchain": -1, "shard": x02.SHARD, "seqno": height,
            "root_hash": f"{height + 1:064x}", "file_hash": f"{height + 101:064x}"}


def raw_command(argv, body, at):
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    return {"argv": argv, "started_ns": int(at * NS),
            "completed_ns": int((at + 0.01) * NS), "exit": 0,
            "stdout_b64": base64.b64encode(data).decode(),
            "stderr_b64": "", "stdout_sha256": x02.digest(data),
            "stderr_sha256": x02.digest(b"")}


def make_rule(index, phase, src, dst):
    pref = 100 + index
    handle = str(index)
    base = ["tc", "filter", "add", "dev", "lo", "egress", "protocol", "ip",
            "pref", str(pref), "handle", handle, "flower", "ip_proto", "udp",
            "src_ip", "127.0.0.1", "dst_ip", "127.0.0.1",
            "src_port", str(20000 + src), "dst_port", str(20000 + dst),
            "action", "drop"]
    return {"id": f"r{index}", "phase": phase, "src_node": f"node{src}",
            "dst_node": f"node{dst}", "mode": "drop_all", "interface": "lo",
            "pref": pref, "handle": handle, "install_argv": base,
            "remove_argv": ["tc", "filter", "del", "dev", "lo", "egress",
                            "pref", str(pref), "handle", handle]}


def policy():
    rules = []
    for src in (1, 2, 3):
        rules.append(make_rule(len(rules) + 1, "three_of_four", src, 4))
        rules.append(make_rule(len(rules) + 1, "three_of_four", 4, src))
    for src in (1, 2):
        rules.append(make_rule(len(rules) + 1, "two_of_four", src, 3))
        rules.append(make_rule(len(rules) + 1, "two_of_four", 3, src))
    source_commit = subprocess.check_output(
        ["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True).strip()
    result = {"schema": "tos.x02.fault-policy.v1",
            "source_commit": source_commit,
            "source_files": {name: hashlib.sha256((REPO / name).read_bytes()).hexdigest()
                             for name in x02.SOURCE_FILES},
            "binary_sha256": "a" * 64,
            "zerostate": {"root_hash": block(0)["root_hash"],
                          "file_hash": block(0)["file_hash"]},
            "nodes": [{"name": f"node{i}", "pid": 1000 + i,
                       "pid_start_ticks": 100 + i, "service": f"validator-{i}",
                       "data_dir": f"/tmp/x02-node{i}",
                       "rpc_url": f"http://127.0.0.1:{30000 + i}/jsonRPC",
                       "peer_ip": "127.0.0.1", "peer_port": 20000 + i,
                       "consensus_key_id": f"{i:064x}",
                       "adnl_id": f"{i + 10:064x}", "exe_sha256": "a" * 64}
                      for i in range(1, 5)],
            "live_nodes": {"three_of_four": ["node1", "node2", "node3"],
                           "two_of_four": ["node1", "node2"]},
            "clsact": {"interface": "lo",
                       "setup_argv": ["tc", "qdisc", "add", "dev", "lo", "clsact"],
                       "cleanup_argv": ["tc", "qdisc", "del", "dev", "lo", "clsact"]},
            "rules": rules,
            "thresholds": {"min_rule_packets": 1, "min_rule_drops": 1,
                           "three_min_delta": 2, "three_max_seconds": 120,
                           "halt_min_seconds": 60, "halt_tail_min_seconds": 20,
                           "halt_tail_samples": 2,
                           "recovery_min_delta": 2,
                           "recovery_max_seconds": 180}}
    manifest = {"schema": "tos.validator-election-experiment-readiness.v2",
                "schema_version": 2, "mode": "experiment",
                "status": "ready", "provenance": {"source_commit": result["source_commit"]},
                "network": {"zero_state": {"masterchain": {
                    "root_hash_hex": result["zerostate"]["root_hash"],
                    "file_hash_hex": result["zerostate"]["file_hash"]}}},
                "validators": [{"node_name": node["name"],
                                "consensus_key_id_hex": node["consensus_key_id"],
                                "adnl_id_hex": node["adnl_id"],
                                "rpc_url": node["rpc_url"],
                                "node_data_dir": node["data_dir"],
                                "process_id": node["pid"],
                                "peer_transport": {"protocol": "udp",
                                                   "ip": node["peer_ip"],
                                                   "port": node["peer_port"]}}
                               for node in result["nodes"]]}
    raw = json.dumps(manifest, sort_keys=True).encode()
    result["readiness_manifest_b64"] = base64.b64encode(raw).decode()
    result["readiness_manifest_sha256"] = x02.digest(raw)
    return result


def flower(rule, hits):
    return {"pref": rule["pref"], "kind": "flower",
            "options": {"handle": rule["handle"],
                        "keys": {"ip_proto": "udp", "src_ip": "127.0.0.1",
                                 "dst_ip": "127.0.0.1",
                                 "src_port": 20000 + int(rule["src_node"][-1]),
                                 "dst_port": 20000 + int(rule["dst_node"][-1])},
                        "actions": [{"kind": "gact", "control_action": {"type": "drop"},
                                     "stats": {"packets": hits, "drops": hits}}]}}


def tc_state(rules, counts, at, clsact=True):
    return {"lo": {"filters": raw_command(
        ["tc", "-j", "-s", "filter", "show", "dev", "lo", "egress"],
        [flower(rule, counts.get(rule["id"], 0)) for rule in rules], at),
        "qdiscs": raw_command(
            ["tc", "-j", "-s", "qdisc", "show", "dev", "lo"],
            ([{"kind": "clsact", "handle": "ffff:"}] if clsact else
             [{"kind": "noqueue", "handle": "0:"}]), at + .01)}}


def process(node):
    stat_fields = ["S"] + ["1"] * 19
    stat_fields[19] = str(node["pid_start_ticks"])
    stat = f"{node['pid']} (validator-engine) ".encode() + " ".join(stat_fields).encode()
    table = ("sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
             f"0: 0100007F:{node['peer_port']:04X} 00000000:0000 07 0:0 00:0 0 1000 0 {9000 + node['pid']}\n").encode()
    cmdline = (f"/tmp/validator-engine\0--db\0.\0--json-rpc-address\0"
               + node["rpc_url"].removeprefix("http://").removesuffix("/jsonRPC")
               + "\0").encode()
    return {"pid": node["pid"], "stat_b64": base64.b64encode(stat).decode(),
            "stat_sha256": x02.digest(stat), "exe_path": "/tmp/validator-engine",
            "exe_sha256": node["exe_sha256"], "data_dir": node["data_dir"],
            "cwd": node["data_dir"], "cmdline_b64": base64.b64encode(cmdline).decode(),
            "cmdline_sha256": x02.digest(cmdline),
            "socket_inodes": [9000 + node["pid"]],
            "udp_table_b64": base64.b64encode(table).decode(),
            "udp_table_sha256": x02.digest(table)}


def rpc_row(node, method, height, at, query_id):
    params = ({"workchain": -1, "shard": x02.SHARD, "seqno": height}
              if method == "getBlockHeader" else {})
    request = {"jsonrpc": "2.0", "id": query_id, "method": method, "params": params}
    result = ({"id": block(height)} if method == "getBlockHeader"
              else {"last": block(height), "init": block(0)})
    raw = json.dumps({"jsonrpc": "2.0", "id": query_id, "result": result}).encode()
    return {"url": node["rpc_url"], "method": method,
            "started_ns": int((at - .02) * NS), "completed_ns": int(at * NS),
            "request_b64": base64.b64encode(json.dumps(request).encode()).decode(),
            "response_b64": base64.b64encode(raw).decode(),
            "response_sha256": x02.digest(raw), "http_status": 200, "error": None}


def snapshot(pol, phase, at, heights, active, counts, journal_overrides=None):
    live = set(pol["live_nodes"].get(phase, [node["name"] for node in pol["nodes"]]))
    common = min(heights[name] for name in live)
    rpc = {"first": {}, "headers": {}, "previous_headers": {},
           "range_headers": {}, "last": {}}
    processes, journals = {}, {}
    for i, node in enumerate(pol["nodes"], start=1):
        name = node["name"]
        processes[name] = process(node)
        line = "".join(
            f"BlockFinalizedInMasterchain {{block=(-1,8000000000000000,{height}):"
            f"{block(height)['root_hash']}:{block(height)['file_hash']}}}\n"
            for height in range(heights[name] + 1))
        if journal_overrides and name in journal_overrides:
            line += journal_overrides[name]
        entries = [{"__CURSOR": f"{name}-{at}-{j}", "_PID": str(node["pid"]),
                    "_BOOT_ID": BOOT.replace("-", ""),
                    "__MONOTONIC_TIMESTAMP": str(int((
                        144 if phase == "recovery" and at >= 145
                        and j - 1 > heights[name] - 2 else
                        .1 if j - 1 <= 10 else 19 if j - 1 == 11 else 29
                    ) * 1_000_000)),
                    "MESSAGE": message}
                   for j, message in enumerate(line.splitlines(), start=1)]
        body = b"".join(json.dumps(item).encode() + b"\n" for item in entries)
        journals[name] = raw_command(["journalctl", "-u", node["service"],
                                      "--no-pager", "-o", "json"], body, at + .01)
        rpc["first"][name] = rpc_row(node, "getMasterchainInfo", heights[name], at + .1 + i * .001, i * 3 + 1)
        if name in live:
            rpc["headers"][name] = rpc_row(node, "getBlockHeader", common, at + .2 + i * .001, i * 3 + 2)
            rpc["previous_headers"][name] = rpc_row(
                node, "getBlockHeader", max(0, common - 1), at + .25 + i * .001, i * 3 + 9)
        last_at = at + (.6 if common > 12 else .4) + i * .001
        rpc["last"][name] = rpc_row(node, "getMasterchainInfo", heights[name], last_at, i * 3 + 3)
    return {"schema": "tos.x02.raw-snapshot.v1", "policy_sha256": "p" * 64,
            "source_commit": pol["source_commit"],
            "source": {"commit": pol["source_commit"], "tracked_status_b64": "",
                       "files_sha256": dict(pol["source_files"])},
            "phase": phase, "started_ns": int(at * NS),
            "boot_id": BOOT,
            "completed_ns": int((at + (.7 if common > 12 else .5)) * NS),
            "tc": tc_state(active, counts, at), "processes": processes,
            "journals": journals, "rpc": rpc, "common_seqno": common,
            "anchor_sha256": None, "anchor_common_seqno": None,
            "previous_sha256": None}


def link_snapshots(pol, snapshots):
    baseline = snapshots[0]
    last_two = [snap for snap in snapshots if snap["phase"] == "two_of_four"][-1]
    previous = None
    for snap in snapshots:
        phase = snap["phase"]
        anchor = (baseline if phase == "three_of_four" else
                  last_two if phase == "recovery" else None)
        if anchor is not None:
            start = anchor["common_seqno"] + 1
            common = snap["common_seqno"]
            snap["anchor_common_seqno"] = anchor["common_seqno"]
            snap["rpc"]["range_headers"] = {
                node["name"]: {str(height): rpc_row(node, "getBlockHeader", height,
                                  snap["started_ns"] / NS + .31 + (height-start)*.04,
                                  height + 100) for height in range(start, common + 1)}
                for node in pol["nodes"] if node["name"] in
                pol["live_nodes"].get(phase, [n["name"] for n in pol["nodes"]])}
        if previous is not None:
            snap["previous_sha256"] = x02.snapshot_digest(previous)
            for node in pol["nodes"]:
                name = node["name"]
                cursor = x02.journal_end_cursor(previous["journals"][name], node)
                snap["journals"][name]["argv"] += ["--cursor", cursor]
                body = base64.b64decode(snap["journals"][name]["stdout_b64"])
                entries = [json.loads(line) for line in body.splitlines()]
                entries.insert(0, x02.journal_entries(previous["journals"][name], node)[-1])
                body = b"".join(json.dumps(item).encode() + b"\n" for item in entries)
                snap["journals"][name]["stdout_b64"] = base64.b64encode(body).decode()
                snap["journals"][name]["stdout_sha256"] = x02.digest(body)
        if anchor is not None:
            snap["anchor_sha256"] = x02.snapshot_digest(anchor)
        previous = snap


def event(pol, rule, action, at, active):
    if rule == "clsact":
        rule_id = "clsact"
        argv = pol["clsact"][action + "_argv"]
        pre_active = []
        pre_clsact = action == "cleanup"
        post_clsact = action == "setup"
    else:
        rule_id = rule["id"]
        argv = rule[action + "_argv"]
        pre_active = ([r for r in active if r != rule] if action == "install"
                      else active + [rule])
        pre_clsact = post_clsact = True
    command = raw_command(argv, b"", at)
    pre = tc_state(pre_active, {}, at - .03, pre_clsact)
    post = tc_state(active, {}, at + .02, post_clsact)
    return {"schema": "tos.x02.tc-event.v1", "policy_sha256": "p" * 64,
            "rule_id": rule_id, "action": action, "command": command,
            "boot_id": BOOT,
            "source": {"commit": pol["source_commit"], "tracked_status_b64": "",
                       "files_sha256": dict(pol["source_files"])},
            "pre_tc": pre, "post_tc": post}


def fixture(jump=False):
    pol = policy()
    rules3 = [r for r in pol["rules"] if r["phase"] == "three_of_four"]
    rules2 = [r for r in pol["rules"] if r["phase"] == "two_of_four"]
    snapshots = [snapshot(pol, "baseline", .3, {f"node{i}": 10 for i in range(1, 5)}, [], {})]
    events = [event(pol, "clsact", "setup", .1, [])]
    active = []
    for i, rule in enumerate(rules3, start=1):
        active.append(rule)
        events.append(event(pol, rule, "install", i, active[:]))
    final_three = 14 if jump else 12
    for at, height, hits in ((10, 10, 1), (20, 11, 2), (30, final_three, 3)):
        snapshots.append(snapshot(pol, "three_of_four", at,
                                  {"node1": height, "node2": height,
                                   "node3": height, "node4": 10}, active[:],
                                  {r["id"]: hits for r in active}))
    for i, rule in enumerate(rules2, start=31):
        active.append(rule)
        events.append(event(pol, rule, "install", i, active[:]))
    for at, hits in ((40, 1), (75, 2), (105, 3)):
        snapshots.append(snapshot(pol, "two_of_four", at,
                                  {"node1": final_three, "node2": final_three,
                                   "node3": final_three, "node4": 10},
                                  active[:], {r["id"]: (3 + hits if r in rules3 else hits)
                                              for r in active}))
    for i, rule in enumerate(pol["rules"], start=110):
        active.remove(rule)
        events.append(event(pol, rule, "remove", i, active[:]))
    for at, height in ((125, final_three), (145, final_three + 2)):
        snapshots.append(snapshot(pol, "recovery", at,
                                  {f"node{i}": height for i in range(1, 5)}, [], {}))
    events.append(event(pol, "clsact", "cleanup", 147, []))
    link_snapshots(pol, snapshots)
    return pol, snapshots, events


def rewrite_raw(row, body):
    raw = json.dumps(body).encode()
    row["stdout_b64"] = base64.b64encode(raw).decode()
    row["stdout_sha256"] = x02.digest(raw)


def append_marker(row, node, marker):
    entries = [json.loads(line) for line in base64.b64decode(row["stdout_b64"]).splitlines()]
    entries.append({"__CURSOR": f"extra-{len(entries)}", "_PID": str(node["pid"]),
                    "_BOOT_ID": BOOT.replace("-", ""),
                    "__MONOTONIC_TIMESTAMP": str((row["completed_ns"] - 1_000_000) // 1000),
                    "MESSAGE": marker})
    raw = b"".join(json.dumps(entry).encode() + b"\n" for entry in entries)
    row["stdout_b64"] = base64.b64encode(raw).decode()
    row["stdout_sha256"] = x02.digest(raw)


def verify_fixture(pol, snapshots, events):
    baseline = snapshots[0]
    two = [snap for snap in snapshots if snap["phase"] == "two_of_four"][-1]
    previous = None
    for snap in snapshots:
        anchor = baseline if snap["phase"] == "three_of_four" else (
            two if snap["phase"] == "recovery" else None)
        if anchor is not None:
            snap["anchor_sha256"] = x02.snapshot_digest(anchor)
            if not snap["rpc"]["range_headers"]:
                start = anchor["common_seqno"] + 1
                snap["anchor_common_seqno"] = anchor["common_seqno"]
                snap["rpc"]["range_headers"] = {
                    node["name"]: {str(height): rpc_row(
                        node, "getBlockHeader", height,
                        snap["started_ns"] / NS + .31 + (height-start)*.04,
                        height + 100) for height in range(start, snap["common_seqno"] + 1)}
                    for node in pol["nodes"] if node["name"] in
                    pol["live_nodes"].get(snap["phase"], [n["name"] for n in pol["nodes"]])}
        if previous is not None:
            snap["previous_sha256"] = x02.snapshot_digest(previous)
            for node in pol["nodes"]:
                name = node["name"]
                cursor = x02.journal_end_cursor(previous["journals"][name], node)
                argv = snap["journals"][name]["argv"]
                if argv[-2:] and argv[-2] == "--cursor":
                    argv[-1] = cursor
                else:
                    argv.extend(["--cursor", cursor])
                entries = [json.loads(line) for line in base64.b64decode(
                    snap["journals"][name]["stdout_b64"]).splitlines()]
                previous_entry = x02.journal_entries(previous["journals"][name], node)[-1]
                if entries[0]["__CURSOR"] != cursor:
                    entries.insert(0, previous_entry)
                else:
                    entries[0] = previous_entry
                raw = b"".join(json.dumps(entry).encode() + b"\n" for entry in entries)
                snap["journals"][name]["stdout_b64"] = base64.b64encode(raw).decode()
                snap["journals"][name]["stdout_sha256"] = x02.digest(raw)
        previous = snap
    return x02.verify(pol, "p" * 64, snapshots, events)


def shift_times(value, amount_ns):
    if isinstance(value, dict):
        for key, item in value.items():
            if key.endswith("_ns") and type(item) is int:
                value[key] = item + amount_ns
            else:
                shift_times(item, amount_ns)
    elif isinstance(value, list):
        for item in value:
            shift_times(item, amount_ns)


class X02IsolationTests(unittest.TestCase):
    def test_journald_compact_boot_id_matches_proc_uuid(self):
        pol, snapshots, events = fixture()
        entry = x02.journal_entries(snapshots[0]["journals"]["node1"], pol["nodes"][0])[0]
        self.assertEqual(entry["_BOOT_ID"], BOOT.replace("-", ""))
        self.assertEqual(x02.normalize_boot_id(entry["_BOOT_ID"]),
                         x02.normalize_boot_id(snapshots[0]["boot_id"]))
        self.assertTrue(x02.verify(pol, "p" * 64, snapshots, events)["passed"])

    def test_same_cursor_changed_payload_is_rejected(self):
        pol, snapshots, events = fixture()
        row = snapshots[1]["journals"]["node1"]
        entries = [json.loads(line) for line in base64.b64decode(row["stdout_b64"]).splitlines()]
        entries[0]["MESSAGE"] = "different record at prior cursor"
        raw = b"".join(json.dumps(entry).encode() + b"\n" for entry in entries)
        row["stdout_b64"] = base64.b64encode(raw).decode()
        row["stdout_sha256"] = x02.digest(raw)
        with self.assertRaisesRegex(ValueError, "cursor payload changed"):
            x02.verify(pol, "p" * 64, snapshots, events)

    def test_precut_native_markers_cannot_count_as_three_of_four_progress(self):
        pol, snapshots, events = fixture(jump=True)
        for node in pol["nodes"][:3]:
            for height in range(11, 15):
                marker = ("BlockFinalizedInMasterchain {block=(-1,8000000000000000,"
                          f"{height}):{block(height)['root_hash']}:"
                          f"{block(height)['file_hash']}}}")
                append_marker(snapshots[0]["journals"][node["name"]], node, marker)
        with self.assertRaisesRegex(ValueError, "predates node4 cut or fault segment"):
            verify_fixture(pol, snapshots, events)

    def test_preremoval_native_markers_cannot_count_as_recovery(self):
        pol, snapshots, events = fixture()
        for node in pol["nodes"]:
            for height in (13, 14):
                marker = ("BlockFinalizedInMasterchain {block=(-1,8000000000000000,"
                          f"{height}):{block(height)['root_hash']}:"
                          f"{block(height)['file_hash']}}}")
                append_marker(snapshots[0]["journals"][node["name"]], node, marker)
        with self.assertRaisesRegex(ValueError, "predates fault removal or recovery segment"):
            verify_fixture(pol, snapshots, events)

    def test_marker_without_monotonic_time_is_rejected(self):
        pol, snapshots, events = fixture()
        row = snapshots[3]["journals"]["node1"]
        entries = [json.loads(line) for line in base64.b64decode(row["stdout_b64"]).splitlines()]
        next(item for item in entries if ",12):" in item["MESSAGE"]).pop(
            "__MONOTONIC_TIMESTAMP")
        raw = b"".join(json.dumps(item).encode() + b"\n" for item in entries)
        row["stdout_b64"] = base64.b64encode(raw).decode()
        row["stdout_sha256"] = x02.digest(raw)
        with self.assertRaisesRegex(ValueError, "lacks bound boot/monotonic time"):
            verify_fixture(pol, snapshots, events)

    def test_fault_event_after_host_reboot_is_rejected(self):
        pol, snapshots, events = fixture()
        events[1]["boot_id"] = "ffffffff-ffff-ffff-ffff-ffffffffffff"
        with self.assertRaisesRegex(ValueError, "host boot changed"):
            verify_fixture(pol, snapshots, events)

    def test_jump_fixture_has_contiguous_full_ids(self):
        pol, snapshots, events = fixture(jump=True)
        self.assertTrue(verify_fixture(pol, snapshots, events)["passed"])

    def test_jump_missing_middle_rpc_header_is_rejected(self):
        pol, snapshots, events = fixture(jump=True)
        del snapshots[3]["rpc"]["range_headers"]["node2"]["12"]
        with self.assertRaisesRegex(ValueError, "per-height header range has a gap"):
            x02.verify(pol, "p" * 64, snapshots, events)

    def test_jump_missing_middle_native_marker_is_rejected(self):
        pol, snapshots, events = fixture(jump=True)
        row = snapshots[3]["journals"]["node2"]
        entries = [json.loads(line) for line in base64.b64decode(row["stdout_b64"]).splitlines()]
        entries = [entry for entry in entries if ",12):" not in entry["MESSAGE"]]
        raw = b"".join(json.dumps(entry).encode() + b"\n" for entry in entries)
        row["stdout_b64"] = base64.b64encode(raw).decode()
        row["stdout_sha256"] = x02.digest(raw)
        with self.assertRaisesRegex(ValueError, "per-height full ID lacks native finalized marker"):
            verify_fixture(pol, snapshots, events)

    def test_jump_middle_height_conflicting_marker_is_rejected(self):
        pol, snapshots, events = fixture(jump=True)
        marker = ("BlockFinalizedInMasterchain {block=(-1,8000000000000000,12):"
                  + "f" * 64 + ":" + block(12)["file_hash"] + "}")
        append_marker(snapshots[3]["journals"]["node2"], pol["nodes"][1], marker)
        with self.assertRaisesRegex(ValueError, "conflicting finalized IDs"):
            verify_fixture(pol, snapshots, events)

    def test_missing_journal_segment_cursor_is_rejected(self):
        pol, snapshots, events = fixture(jump=True)
        snapshots[3]["journals"]["node2"]["argv"][-1] = "lost-segment"
        with self.assertRaisesRegex(ValueError, "journal segment lost previous cursor"):
            x02.verify(pol, "p" * 64, snapshots, events)

    def test_valid_isolation_fixture(self):
        pol, snapshots, events = fixture()
        self.assertTrue(verify_fixture(pol, snapshots, events)["passed"])

    def test_policy_peer_tuple_must_match_stage_a_readiness(self):
        pol, snapshots, events = fixture()
        pol["nodes"][0]["peer_port"] = 65500
        with self.assertRaisesRegex(ValueError, "readiness"):
            verify_fixture(pol, snapshots, events)

    def test_stale_v1_readiness_manifest_is_rejected(self):
        pol, snapshots, events = fixture()
        manifest = json.loads(base64.b64decode(pol["readiness_manifest_b64"]))
        manifest["schema"] = "tos.validator-election-experiment-readiness.v1"
        manifest["schema_version"] = 1
        raw = json.dumps(manifest, sort_keys=True).encode()
        pol["readiness_manifest_b64"] = base64.b64encode(raw).decode()
        pol["readiness_manifest_sha256"] = x02.digest(raw)
        with self.assertRaisesRegex(ValueError, "Stage A readiness provenance differs"):
            verify_fixture(pol, snapshots, events)

    def test_changed_recorder_sha_is_rejected(self):
        pol, snapshots, events = fixture()
        snapshots[0]["source"]["files_sha256"]["scripts/x02_fault_evidence.py"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "source bytes"):
            verify_fixture(pol, snapshots, events)

    def test_capture_refuses_dirty_tracked_tree_before_fault(self):
        pol = policy()
        fake = [SimpleNamespace(stdout=pol["source_commit"] + "\n"),
                SimpleNamespace(stdout=b" M scripts/x02_fault_evidence.py\n")]
        with patch.object(x02.subprocess, "run", side_effect=fake):
            with self.assertRaisesRegex(ValueError, "uncommitted changes"):
                x02.require_source_commit(pol)

    def test_frozen_route_must_isolate_node4_then_node3(self):
        pol = policy()
        pol["live_nodes"]["three_of_four"] = ["node1", "node2", "node4"]
        pol["live_nodes"]["two_of_four"] = ["node1", "node2"]
        swapped = []
        for src in (1, 2, 4):
            swapped.append(make_rule(len(swapped) + 1, "three_of_four", src, 3))
            swapped.append(make_rule(len(swapped) + 1, "three_of_four", 3, src))
        for src in (1, 2):
            swapped.append(make_rule(len(swapped) + 1, "two_of_four", src, 4))
            swapped.append(make_rule(len(swapped) + 1, "two_of_four", 4, src))
        pol["rules"] = swapped
        with self.assertRaisesRegex(ValueError, "node4 before node3"):
            x02.validate_policy(pol)

    def test_extra_live_pair_drop_cannot_explain_halt(self):
        pol = policy()
        pol["rules"].append(make_rule(11, "two_of_four", 1, 2))
        with self.assertRaisesRegex(ValueError, "extra edge"):
            x02.validate_policy(pol)

    def test_early_node3_rule_cannot_hide_in_node4_install_event(self):
        pol, snapshots, events = fixture()
        row = events[1]["post_tc"]["lo"]["filters"]
        body = json.loads(base64.b64decode(row["stdout_b64"]))
        body.append(flower(pol["rules"][6], 0))
        rewrite_raw(row, body)
        with self.assertRaisesRegex(ValueError, "post-state has extra"):
            verify_fixture(pol, snapshots, events)

    def test_pid_must_own_declared_udp_port(self):
        pol, snapshots, events = fixture()
        snapshots[1]["processes"]["node1"]["socket_inodes"] = []
        with self.assertRaisesRegex(ValueError, "peer UDP port"):
            verify_fixture(pol, snapshots, events)

    def test_no_apply_or_rule_hit_is_rejected(self):
        pol, snapshots, events = fixture()
        for snap in snapshots[1:7]:
            row = snap["tc"]["lo"]["filters"]
            body = json.loads(base64.b64decode(row["stdout_b64"]))
            for item in body:
                item["options"]["actions"][0]["stats"] = {"packets": 0, "drops": 0}
            rewrite_raw(row, body)
        with self.assertRaisesRegex(ValueError, "no sustained target peer hit/drop"):
            verify_fixture(pol, snapshots, events)

    def test_missing_install_event_is_rejected(self):
        pol, snapshots, events = fixture()
        with self.assertRaisesRegex(ValueError, "missing install/remove"):
            verify_fixture(pol, snapshots, events[1:])

    def test_packets_without_drops_are_rejected(self):
        pol, snapshots, events = fixture()
        for snap in snapshots[1:7]:
            row = snap["tc"]["lo"]["filters"]
            body = json.loads(base64.b64decode(row["stdout_b64"]))
            for item in body:
                item["options"]["actions"][0]["stats"]["drops"] = 0
            rewrite_raw(row, body)
        with self.assertRaisesRegex(ValueError, "no sustained target peer hit/drop"):
            verify_fixture(pol, snapshots, events)

    def test_middle_halt_sample_cannot_be_filtered_out_after_counter_reset(self):
        pol, snapshots, events = fixture()
        row = snapshots[5]["tc"]["lo"]["filters"]
        body = json.loads(base64.b64decode(row["stdout_b64"]))
        # The node3 cut briefly disappears from the hit set in the middle.
        body[-1]["options"]["actions"][0]["stats"] = {"packets": 0, "drops": 0}
        rewrite_raw(row, body)
        node = pol["nodes"][1]
        snapshots[5]["rpc"]["last"]["node2"] = rpc_row(
            node, "getMasterchainInfo", 13, 75.402, 8)
        with self.assertRaisesRegex(ValueError, "counters reset|tip regressed|lost a target peer hit"):
            verify_fixture(pol, snapshots, events)

    def test_same_height_conflicting_finalized_marker_is_rejected(self):
        pol, snapshots, events = fixture()
        conflicting = ("BlockFinalizedInMasterchain {block=(-1,8000000000000000,12):"
                       + "f" * 64 + ":" + block(12)["file_hash"] + "}\n")
        row = snapshots[6]["journals"]["node1"]
        append_marker(row, pol["nodes"][0], conflicting)
        with self.assertRaisesRegex(ValueError, "conflicting finalized IDs"):
            verify_fixture(pol, snapshots, events)

    def test_earlier_conflict_cannot_be_overwritten_by_later_marker(self):
        pol, snapshots, events = fixture()
        row = snapshots[0]["journals"]["node1"]
        earlier = ("BlockFinalizedInMasterchain {block=(-1,8000000000000000,10):"
                   + "f" * 64 + ":" + block(10)["file_hash"] + "}\n")
        append_marker(row, pol["nodes"][0], earlier)
        with self.assertRaisesRegex(ValueError, "conflicting finalized IDs"):
            verify_fixture(pol, snapshots, events)

    def test_three_of_four_needs_two_new_full_ids(self):
        pol, snapshots, events = fixture()
        snapshots[3] = snapshot(pol, "three_of_four", 30,
                                {"node1": 11, "node2": 11,
                                 "node3": 11, "node4": 10},
                                [r for r in pol["rules"] if r["phase"] == "three_of_four"],
                                {r["id"]: 3 for r in pol["rules"] if r["phase"] == "three_of_four"})
        with self.assertRaisesRegex(ValueError, "two newly common"):
            verify_fixture(pol, snapshots, events)

    def test_rpc_header_without_native_finalized_marker_is_rejected(self):
        pol, snapshots, events = fixture()
        for snap in (snapshots[2], snapshots[3]):
            row = snap["journals"]["node1"]
            raw = base64.b64decode(row["stdout_b64"])
            kept = b"".join(line for line in raw.splitlines(keepends=True)
                            if b"8000000000000000,11)" not in line)
            row["stdout_b64"] = base64.b64encode(kept).decode()
            row["stdout_sha256"] = x02.digest(kept)
        with self.assertRaisesRegex(ValueError, "lacks native finalized marker"):
            verify_fixture(pol, snapshots, events)

    def test_two_of_four_native_marker_cannot_hide_tip_progress(self):
        pol, snapshots, events = fixture()
        row = snapshots[5]["journals"]["node2"]
        extra = ("BlockFinalizedInMasterchain {block=(-1,8000000000000000,13):"
                 + block(13)["root_hash"] + ":" + block(13)["file_hash"] + "}\n").encode()
        append_marker(row, pol["nodes"][1], extra.decode())
        with self.assertRaisesRegex(ValueError, "native finalized marker advanced"):
            verify_fixture(pol, snapshots, events)

    def test_wrong_peer_tuple_is_rejected(self):
        pol, snapshots, events = fixture()
        row = snapshots[1]["tc"]["lo"]["filters"]
        body = json.loads(base64.b64decode(row["stdout_b64"]))
        body[0]["options"]["keys"]["dst_port"] = 65500
        raw = json.dumps(body).encode()
        row["stdout_b64"] = base64.b64encode(raw).decode()
        row["stdout_sha256"] = x02.digest(raw)
        with self.assertRaisesRegex(ValueError, "bound peer flow"):
            verify_fixture(pol, snapshots, events)

    def test_interface_wide_netem_is_rejected(self):
        pol, snapshots, events = fixture()
        row = snapshots[1]["tc"]["lo"]["qdiscs"]
        rewrite_raw(row, [{"kind": "clsact", "handle": "ffff:"},
                          {"kind": "netem", "parent": "root", "handle": "1:"}])
        with self.assertRaisesRegex(ValueError, "interface-wide netem"):
            verify_fixture(pol, snapshots, events)

    def test_counter_read_after_rpc_is_rejected(self):
        pol, snapshots, events = fixture()
        snapshots[1]["tc"]["lo"]["filters"]["completed_ns"] = int(10.3 * NS)
        with self.assertRaisesRegex(ValueError, "read after RPC"):
            verify_fixture(pol, snapshots, events)

    def test_cross_node_same_height_conflict_is_rejected(self):
        pol, snapshots, events = fixture()
        row = snapshots[2]["journals"]["node4"]
        conflict = ("BlockFinalizedInMasterchain {block=(-1,8000000000000000,11):"
                    + "f" * 64 + ":" + block(11)["file_hash"] + "}\n").encode()
        append_marker(row, pol["nodes"][3], conflict.decode())
        with self.assertRaisesRegex(ValueError, "validators disagree on full ID"):
            verify_fixture(pol, snapshots, events)

    def test_late_rpc_progress_is_rejected(self):
        pol, snapshots, events = fixture()
        # Shift progress and all later events; ordering stays valid but 120s expires.
        for snap in snapshots[3:]:
            shift_times(snap, 110 * NS)
        for event_row in events[7:]:
            shift_times(event_row, 110 * NS)
        with self.assertRaisesRegex(ValueError, "120-second"):
            verify_fixture(pol, snapshots, events)

    def test_three_of_four_deadline_starts_at_rule_install_not_late_sample(self):
        pol, snapshots, events = fixture()
        for index, shift in ((1, 90), (2, 95), (3, 100)):
            shift_times(snapshots[index], shift * NS)
        for snap in snapshots[4:]:
            shift_times(snap, 100 * NS)
        for event_row in events[7:]:
            shift_times(event_row, 100 * NS)
        with self.assertRaisesRegex(ValueError, "120-second"):
            verify_fixture(pol, snapshots, events)

    def test_recovery_after_180_seconds_is_rejected(self):
        pol, snapshots, events = fixture()
        shift_times(snapshots[-1], 160 * NS)
        shift_times(events[-1], 160 * NS)
        with self.assertRaisesRegex(ValueError, "180-second"):
            verify_fixture(pol, snapshots, events)

    def test_recovery_needs_two_new_full_ids(self):
        pol, snapshots, events = fixture()
        snapshots[-1] = snapshot(pol, "recovery", 145,
                                 {f"node{i}": 13 for i in range(1, 5)}, [], {})
        with self.assertRaisesRegex(ValueError, "two newly common"):
            verify_fixture(pol, snapshots, events)

    def test_pid_generation_change_is_rejected(self):
        pol, snapshots, events = fixture()
        proc = snapshots[4]["processes"]["node2"]
        stat = base64.b64decode(proc["stat_b64"]).replace(b"102", b"999")
        proc["stat_b64"] = base64.b64encode(stat).decode()
        proc["stat_sha256"] = x02.digest(stat)
        with self.assertRaisesRegex(ValueError, "PID generation"):
            verify_fixture(pol, snapshots, events)

    def test_node2_only_progress_during_halt_is_rejected(self):
        pol, snapshots, events = fixture()
        node = pol["nodes"][1]
        row = snapshots[6]["rpc"]["last"]["node2"]
        replacement = rpc_row(node, "getMasterchainInfo", 13, 105.402, 8)
        row.update(replacement)
        snapshots[7] = snapshot(pol, "recovery", 125,
                                {"node1": 12, "node2": 13, "node3": 12, "node4": 12}, [], {})
        with self.assertRaisesRegex(ValueError, "2/4 live node advanced"):
            verify_fixture(pol, snapshots, events)

    def test_tip_rollback_across_samples_is_rejected(self):
        pol, snapshots, events = fixture()
        node = pol["nodes"][2]
        snapshots[4]["rpc"]["first"]["node3"] = rpc_row(
            node, "getMasterchainInfo", 11, 40.103, 10)
        snapshots[4]["rpc"]["last"]["node3"] = rpc_row(
            node, "getMasterchainInfo", 11, 40.403, 12)
        with self.assertRaisesRegex(ValueError, "tip regressed across samples"):
            verify_fixture(pol, snapshots, events)

    def test_short_common_halt_interval_is_rejected(self):
        pol, snapshots, events = fixture()
        # Each node individually spans >=60s, but their common overlap is 59s.
        snapshots[4]["rpc"]["last"]["node2"]["completed_ns"] = int(46.4 * NS)
        snapshots[4]["completed_ns"] = int(46.5 * NS)
        snapshots[6]["rpc"]["last"]["node2"]["completed_ns"] = int(106.4 * NS)
        snapshots[6]["completed_ns"] = int(106.5 * NS)
        with self.assertRaisesRegex(ValueError, "60 seconds"):
            verify_fixture(pol, snapshots, events)


if __name__ == "__main__":
    unittest.main()
