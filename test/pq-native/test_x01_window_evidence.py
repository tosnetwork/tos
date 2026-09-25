"""Synthetic X01 fault-window controls. No node is started."""

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import unittest

SOURCE = Path(os.environ.get(
    "X01_CHECKER_SOURCE", Path(__file__).resolve().parents[2] / "scripts/x01_window_evidence.py"))
spec = importlib.util.spec_from_file_location("x01_window_evidence", SOURCE)
x01 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(x01)


def block(height, root=None):
    return {
        "workchain": -1, "shard": "8000000000000000", "seqno": height,
        "root_hash": root or f"{height + 1:064x}",
        "file_hash": f"{height + 101:064x}",
    }


def stat_bytes(pid):
    # /proc stat fields 3..22; field 22 is the final token here.
    return f"{pid} (validator-engine) S " + " ".join(["1"] * 18 + [str(pid * 10)])


def generation(policy, node, index, pid, recorded_at):
    fixed = policy["nodes"][node]
    return {"node_name": node, "generation": index, "pid": pid,
            "proc_start_ticks": pid * 10, "node_data_dir": fixed["node_data_dir"],
            "proc_cwd_link": fixed["node_data_dir"], "proc_cwd_realpath": fixed["node_data_dir"],
            "proc_cwd_device": 2049, "proc_cwd_inode": int(node[-1]) + 100,
            "exe_path": fixed["validator_engine_exe_path"], "exe_device": 2049,
            "exe_inode": 500, "recorded_at": recorded_at}


def os_witnesses(policy, trace):
    witnesses = []
    for validator in trace["process_generation_manifest"]["validators"]:
        node = validator["node_name"]
        fixed = policy["nodes"][node]
        for row in validator["process_generations"]:
            args = [fixed["validator_engine_exe_path"], "--db", ".", "--local-config",
                    fixed["node_data_dir"] + "/config.json", "--json-rpc-address", fixed["endpoint"]]
            witnesses.append({**row, "exe_sha256": fixed["validator_engine_exe_sha256"],
                              "proc_stat_raw_base64": base64.b64encode(
                                  stat_bytes(row["pid"]).encode()).decode(),
                              "proc_cmdline_raw_base64": base64.b64encode(
                                  ("\0".join(args) + "\0").encode()).decode()})
    return witnesses


def fixture():
    names = [f"node{i}" for i in range(1, 5)]
    policy = {
        "schema": "tos.x01.window-policy.v1",
        "nodes": {name: {"endpoint": f"127.0.0.1:{25000 + i}",
                         "zerostate": block(0), "node_data_dir": f"/tmp/x01-{name}",
                         "node_log_path": f"/tmp/x01-{name}/engine.log",
                         "pq_key_id_hex": f"{i + 1:064x}",
                         "adnl_id_hex": f"{i + 11:064x}",
                         "validator_engine_exe_path": "/tmp/build/validator-engine",
                         "validator_engine_exe_sha256": "a" * 64,
                         "initial_pid": (i + 1) * 1000 + (i + 1)}
                  for i, name in enumerate(names)},
        "thresholds": {"three_min_delta": 2, "halt_min_samples": 8,
                       "halt_tail_samples": 4, "recovery_min_delta": 2,
                       "three_max_seconds": 5, "halt_min_seconds": 6,
                       "halt_tail_min_seconds": 2, "recovery_max_seconds": 5},
    }
    def sample(index, height, members):
        return {"at": f"2026-09-25T12:00:{index:02d}Z",
                "completed_at": f"2026-09-25T12:00:{index:02d}.100000Z",
                "nodes": {name: block(height) for name in members},
                "tips": {name: block(height) for name in members},
                "tip_observed_at": {
                    name: f"2026-09-25T12:00:{index:02d}.{50000 + position * 10000:06d}Z"
                    for position, name in enumerate(members)}}
    def fault(phase, node, pid):
        raw = json.dumps({"schema": "tos.x01.process-stop.v1", "phase": phase,
                          "node": node, "pid": pid,
                          "at": "2026-09-25T11:59:59Z" if phase == "three_of_four" else "2026-09-25T12:00:01.600000Z",
                          "running_before": True,
                          "proc_after_absent": True,
                          "node_data_dir": f"/tmp/x01-{node}",
                          "node_log_path": f"/tmp/x01-{node}/engine.log",
                          "pq_key_id_hex": f"{int(node[-1]):064x}",
                          "adnl_id_hex": f"{int(node[-1]) + 10:064x}",
                          "exe_path": "/tmp/build/validator-engine", "exe_sha256": "a" * 64,
                          "proc_stat_base64": base64.b64encode(stat_bytes(pid).encode()).decode(),
                          "running_after": False}, sort_keys=True).encode()
        return {"phase": phase, "node": node, "kind": "process_stopped",
                "hit": True, "raw_evidence_sha256": hashlib.sha256(raw).hexdigest(),
                "raw_evidence_base64": base64.b64encode(raw).decode()}
    def restart(phase, node, old_pid, pid, at):
        raw = json.dumps({"schema": "tos.x01.process-start.v1", "phase": phase,
                          "node": node, "old_pid": old_pid, "pid": pid, "at": at,
                          "running_before": False, "running_after": True,
                          "old_proc_absent": True,
                          "node_data_dir": f"/tmp/x01-{node}",
                          "node_log_path": f"/tmp/x01-{node}/engine.log",
                          "pq_key_id_hex": f"{int(node[-1]):064x}",
                          "adnl_id_hex": f"{int(node[-1]) + 10:064x}",
                          "exe_path": "/tmp/build/validator-engine", "exe_sha256": "a" * 64,
                          "proc_stat_base64": base64.b64encode(stat_bytes(pid).encode()).decode()},
                         sort_keys=True).encode()
        return {"phase": phase, "node": node, "kind": "process_started",
                "hit": True, "raw_evidence_sha256": hashlib.sha256(raw).hexdigest(),
                "raw_evidence_base64": base64.b64encode(raw).decode()}
    trace = {
        "faults": [
            fault("three_of_four", "node4", 4004),
            fault("two_of_four", "node3", 3003),
            fault("two_of_four", "node4", 4005),
        ],
        "restarts": [restart("three_of_four", "node4", 4004, 4005, "2026-09-25T12:00:01.200000Z"),
                     restart("recovery", "node3", 3003, 3006, "2026-09-25T12:00:09.500000Z"),
                     restart("recovery", "node4", 4005, 4006, "2026-09-25T12:00:09.600000Z")],
        "phases": {
            "three_of_four": [sample(0, 10, names[:3]), sample(1, 12, names[:3])],
            "two_of_four": [sample(i + 2, 12, names[:2]) for i in range(8)],
            "recovery": [sample(10, 13, names), sample(11, 14, names)],
        },
        "recovery_halt_checkpoint": {name: block(12) for name in names},
    }
    trace["process_generation_manifest"] = {"validators": [
        {"node_name": name, "node_data_dir": policy["nodes"][name]["node_data_dir"],
         "pq_key_id_hex": policy["nodes"][name]["pq_key_id_hex"],
         "adnl_id_hex": policy["nodes"][name]["adnl_id_hex"],
         "rpc_address": policy["nodes"][name]["endpoint"],
         "process_generations": (
             [generation(policy, name, 0, policy["nodes"][name]["initial_pid"], "2026-09-25T11:59:58Z")]
             + ([generation(policy, name, 1, 4005, "2026-09-25T12:00:01.300000Z"),
                 generation(policy, name, 2, 4006, "2026-09-25T12:00:09.700000Z")]
                if name == "node4" else
                [generation(policy, name, 1, 3006, "2026-09-25T12:00:09.700000Z")]
                if name == "node3" else []))}
        for name in names]}
    return policy, trace


class X01WindowTests(unittest.TestCase):
    def test_planned_node3_generation_is_accepted_only_with_exact_raw_start_ticks(self):
        policy, trace = fixture()
        self.rewrite_raw(trace["faults"][1], pid=3005,
                         proc_stat_base64=base64.b64encode(stat_bytes(3005).encode()).decode())
        self.rewrite_raw(trace["restarts"][1], old_pid=3005)
        node3 = trace["process_generation_manifest"]["validators"][2]["process_generations"]
        node3.insert(1, generation(policy, "node3", 1, 3005, "2026-09-25T12:00:01.300000Z"))
        node3[2]["generation"] = 2
        self.assertTrue(x01.validate(policy, trace)["passed"])
        node3[1]["proc_start_ticks"] += 1
        with self.assertRaisesRegex(ValueError, "PID/start ticks has no unique F01 generation"):
            x01.validate(policy, trace)

    def test_generation_cwd_alias_and_missing_witness_fail_closed(self):
        policy, trace = fixture()
        del trace["process_generation_manifest"]
        with self.assertRaisesRegex(ValueError, "requires four F01"):
            x01.validate(policy, trace)
        policy, trace = fixture()
        trace["process_generation_manifest"]["validators"][2]["process_generations"][0]["proc_cwd_inode"] = 101
        with self.assertRaisesRegex(ValueError, "DB cwd inode is shared"):
            x01.validate(policy, trace)

    def test_independent_os_watcher_binds_db_binary_and_start_ticks(self):
        policy, trace = fixture()
        witnesses = os_witnesses(policy, trace)
        self.assertTrue(x01.validate(policy, trace, os_process_generations=witnesses)["independent_os_checked"])
        witnesses[0]["proc_cwd_inode"] = 999
        with self.assertRaisesRegex(ValueError, "independent OS cwd/DB"):
            x01.validate(policy, trace, os_process_generations=witnesses)
        witnesses = os_witnesses(policy, trace)
        witnesses[0]["proc_stat_raw_base64"] = base64.b64encode(stat_bytes(9999).encode()).decode()
        with self.assertRaisesRegex(ValueError, "independent OS /proc PID/start ticks"):
            x01.validate(policy, trace, os_process_generations=witnesses)

    def test_good_fault_window(self):
        policy, trace = fixture()
        result = x01.validate(policy, trace)
        self.assertTrue(result["passed"])
        self.assertEqual(result["halt_tail_id"][2], 12)
        self.assertEqual(result["recovery_last"][2], 14)

    def test_same_height_conflicting_full_id_fails(self):
        policy, trace = fixture()
        trace["phases"]["three_of_four"][1]["nodes"]["node3"]["root_hash"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "conflict"):
            x01.validate(policy, trace)

    def test_halt_tail_advancing_full_id_fails(self):
        policy, trace = fixture()
        trace["phases"]["two_of_four"][-1]["nodes"] = {
            name: block(13) for name in ("node1", "node2")}
        trace["phases"]["two_of_four"][-1]["tips"] = {
            name: block(13) for name in ("node1", "node2")}
        with self.assertRaisesRegex(ValueError, "safety window advanced"):
            x01.validate(policy, trace)

    def test_node2_only_tip_progress_cannot_hide_behind_common_height(self):
        policy, trace = fixture()
        trace["phases"]["two_of_four"][-1]["tips"]["node2"] = block(20)
        with self.assertRaisesRegex(ValueError, "2/4 live tip progressed"):
            x01.validate(policy, trace)

    def test_stale_high_tip_and_missing_tip_are_rejected(self):
        policy, trace = fixture()
        for sample in trace["phases"]["two_of_four"][-4:]:
            sample["tips"]["node2"] = block(20)
        with self.assertRaisesRegex(ValueError, "2/4 live tip progressed"):
            x01.validate(policy, trace)
        policy, trace = fixture()
        del trace["phases"]["two_of_four"][-1]["tips"]["node2"]
        with self.assertRaisesRegex(ValueError, "missing or extra node tips"):
            x01.validate(policy, trace)

    def test_same_height_divergent_tip_hash_is_rejected(self):
        policy, trace = fixture()
        trace["phases"]["two_of_four"][-1]["tips"]["node2"]["root_hash"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "tip disagrees with the common header"):
            x01.validate(policy, trace)

    def test_slow_header_cannot_extend_tip_no_progress_window(self):
        policy, trace = fixture()
        policy["thresholds"]["halt_tail_min_seconds"] = 10
        trace["phases"]["two_of_four"][-1]["completed_at"] = "2026-09-25T12:00:20Z"
        for position, sample in enumerate(trace["phases"]["recovery"], start=21):
            sample["at"] = f"2026-09-25T12:00:{position:02d}Z"
            sample["completed_at"] = f"2026-09-25T12:00:{position:02d}.100000Z"
            sample["tip_observed_at"] = {
                name: f"2026-09-25T12:00:{position:02d}.{50000 + i * 10000:06d}Z"
                for i, name in enumerate(sample["nodes"])}
        self.rewrite_raw(trace["restarts"][1], at="2026-09-25T12:00:20.500000Z")
        self.rewrite_raw(trace["restarts"][2], at="2026-09-25T12:00:20.600000Z")
        with self.assertRaisesRegex(ValueError, "2/4 common tip window was too short"):
            x01.validate(policy, trace)

    def test_each_node_individually_long_enough_but_common_window_short(self):
        policy, trace = fixture()
        policy["thresholds"]["halt_min_seconds"] = 7
        policy["thresholds"]["halt_tail_min_seconds"] = 3
        for index, sample in enumerate(trace["phases"]["two_of_four"], start=2):
            sample["tip_observed_at"]["node2"] = f"2026-09-25T12:00:{index:02d}.550000Z"
            sample["completed_at"] = f"2026-09-25T12:00:{index:02d}.600000Z"
        self.rewrite_raw(trace["restarts"][1], at="2026-09-25T12:00:09.700000Z")
        self.rewrite_raw(trace["restarts"][2], at="2026-09-25T12:00:09.800000Z")
        with self.assertRaisesRegex(ValueError, "2/4 common tip window was too short"):
            x01.validate(policy, trace)

    def test_tail_common_overlap_is_checked_separately(self):
        policy, trace = fixture()
        policy["thresholds"]["halt_tail_min_seconds"] = 3
        with self.assertRaisesRegex(ValueError, "2/4 common tip window was too short"):
            x01.validate(policy, trace)

    def test_missing_or_late_tip_response_time_is_rejected(self):
        policy, trace = fixture()
        del trace["phases"]["two_of_four"][-1]["tip_observed_at"]["node2"]
        with self.assertRaisesRegex(ValueError, "tip response times"):
            x01.validate(policy, trace)
        policy, trace = fixture()
        trace["phases"]["two_of_four"][-1]["tip_observed_at"]["node2"] = "2026-09-25T12:00:20Z"
        with self.assertRaisesRegex(ValueError, "tip response time outside"):
            x01.validate(policy, trace)

    def test_recovered_node_must_reproduce_halt_full_id(self):
        policy, trace = fixture()
        trace["recovery_halt_checkpoint"]["node4"]["root_hash"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "exact halt checkpoint"):
            x01.validate(policy, trace)

    def test_missing_fault_hit_cannot_pass(self):
        policy, trace = fixture()
        trace["faults"][0]["hit"] = False
        with self.assertRaisesRegex(ValueError, "fault has no raw hit evidence"):
            x01.validate(policy, trace)
        policy, trace = fixture()
        trace["faults"][0]["raw_evidence_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "SHA-256 differs"):
            x01.validate(policy, trace)
        policy, trace = fixture()
        raw = base64.b64decode(trace["faults"][0]["raw_evidence_base64"])
        claim = json.loads(raw)
        claim["running_after"] = True
        raw = json.dumps(claim, sort_keys=True).encode()
        trace["faults"][0]["raw_evidence_base64"] = base64.b64encode(raw).decode()
        trace["faults"][0]["raw_evidence_sha256"] = hashlib.sha256(raw).hexdigest()
        with self.assertRaisesRegex(ValueError, "did not prove a hit"):
            x01.validate(policy, trace)

    def test_prefixed_threshold_and_recovery_are_required(self):
        policy, trace = fixture()
        policy["thresholds"]["three_min_delta"] = 3
        with self.assertRaisesRegex(ValueError, "pre-fixed height delta"):
            x01.validate(policy, trace)
        policy, trace = fixture()
        trace["phases"]["recovery"][-1]["nodes"] = {
            name: block(13) for name in ("node1", "node2", "node3", "node4")}
        with self.assertRaisesRegex(ValueError, "recovery did not meet"):
            x01.validate(policy, trace)
        policy, trace = fixture()
        policy["thresholds"]["halt_tail_min_seconds"] = 4
        with self.assertRaisesRegex(ValueError, "window was too short"):
            x01.validate(policy, trace)

    def test_endpoint_and_zerostate_binding(self):
        policy, trace = fixture()
        policy["nodes"]["node4"]["endpoint"] = policy["nodes"]["node1"]["endpoint"]
        with self.assertRaisesRegex(ValueError, "distinct RPC endpoints"):
            x01.validate(policy, trace)
        policy, trace = fixture()
        policy["nodes"]["node4"]["zerostate"]["root_hash"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "share zerostate"):
            x01.validate(policy, trace)

    def test_stop_after_first_sample_is_rejected(self):
        policy, trace = fixture()
        self.rewrite_raw(trace["faults"][0], at="2026-09-25T13:00:00Z")
        with self.assertRaisesRegex(ValueError, "stop time"):
            x01.validate(policy, trace)

    def test_second_stop_after_halt_samples_is_rejected(self):
        policy, trace = fixture()
        self.rewrite_raw(trace["faults"][1], at="2026-09-25T13:00:00Z")
        with self.assertRaisesRegex(ValueError, "stop time"):
            x01.validate(policy, trace)

    def test_recovery_start_after_sample_is_rejected(self):
        policy, trace = fixture()
        self.rewrite_raw(trace["restarts"][1], at="2026-09-25T13:00:00Z")
        with self.assertRaisesRegex(ValueError, "start time|generation time"):
            x01.validate(policy, trace)

    def test_recovery_wait_before_first_sample_counts_against_window(self):
        policy, trace = fixture()
        policy["thresholds"]["recovery_max_seconds"] = 1
        self.rewrite_raw(trace["restarts"][1], at="2026-09-25T12:00:09.200000Z")
        with self.assertRaisesRegex(ValueError, "start-to-observation"):
            x01.validate(policy, trace)

    def test_slow_rpc_completion_cannot_claim_in_window_progress(self):
        policy, trace = fixture()
        trace["phases"]["three_of_four"][1]["completed_at"] = "2026-09-25T12:02:00Z"
        with self.assertRaisesRegex(ValueError, "pre-fixed window"):
            x01.validate(policy, trace)

    def test_slow_recovery_completion_and_late_halt_overlap_are_rejected(self):
        policy, trace = fixture()
        trace["phases"]["recovery"][-1]["completed_at"] = "2026-09-25T12:02:00Z"
        with self.assertRaisesRegex(ValueError, "start-to-observation|pre-fixed window"):
            x01.validate(policy, trace)
        policy, trace = fixture()
        trace["phases"]["two_of_four"][-1]["completed_at"] = "2026-09-25T12:00:10.500000Z"
        with self.assertRaisesRegex(ValueError, "overlap|start time"):
            x01.validate(policy, trace)

    def test_sample_completion_cannot_precede_start_or_overlap_next_sample(self):
        policy, trace = fixture()
        trace["phases"]["three_of_four"][0]["completed_at"] = "2026-09-25T11:59:59Z"
        with self.assertRaisesRegex(ValueError, "completion precedes"):
            x01.validate(policy, trace)
        policy, trace = fixture()
        trace["phases"]["two_of_four"][0]["completed_at"] = "2026-09-25T12:00:03Z"
        with self.assertRaisesRegex(ValueError, "sample times overlap"):
            x01.validate(policy, trace)

    def test_restart_pid_continuity_is_required(self):
        policy, trace = fixture()
        self.rewrite_raw(trace["restarts"][0], old_pid=9999)
        with self.assertRaisesRegex(ValueError, "PID continuity"):
            x01.validate(policy, trace)

    def test_missing_timestamp_and_raw_proc_identity_are_rejected(self):
        policy, trace = fixture()
        self.rewrite_raw(trace["faults"][0], at=None)
        with self.assertRaisesRegex(ValueError, "timestamp is absent"):
            x01.validate(policy, trace)
        policy, trace = fixture()
        self.rewrite_raw(trace["faults"][0], proc_stat_base64=base64.b64encode(
            stat_bytes(9999).encode()).decode())
        with self.assertRaisesRegex(ValueError, "raw /proc PID evidence disagrees"):
            x01.validate(policy, trace)
        policy, trace = fixture()
        policy["nodes"]["node4"]["node_data_dir"] = policy["nodes"]["node1"]["node_data_dir"]
        with self.assertRaisesRegex(ValueError, "distinct node_data_dir"):
            x01.validate(policy, trace)

    @staticmethod
    def rewrite_raw(row, **updates):
        raw = json.loads(base64.b64decode(row["raw_evidence_base64"]))
        raw.update(updates)
        encoded = json.dumps(raw, sort_keys=True).encode()
        row["raw_evidence_base64"] = base64.b64encode(encoded).decode()
        row["raw_evidence_sha256"] = hashlib.sha256(encoded).hexdigest()


if __name__ == "__main__":
    unittest.main()
