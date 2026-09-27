"""Offline controls for Stage A F01 capture inputs and transition binding."""

import asyncio
import ast
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

from pytosiq_core import Builder


SOURCE = Path(os.environ.get(
    "F01_CAPTURE_SOURCE",
    Path(__file__).resolve().parents[1] / "tostester/src/tostester/f01_stage_a_evidence.py",
))
SPEC = importlib.util.spec_from_file_location("f01_stage_a_evidence", SOURCE)
f01 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(f01)


def response(cell):
    return {"result": {"config": {"bytes": base64.b64encode(cell.to_boc()).decode()}}}


class F01CaptureTests(unittest.IsolatedAsyncioTestCase):
    async def test_full_route_wires_transition_and_raw_log_capture(self):
        route_source = Path(os.environ.get(
            "F01_STAGE_A_SOURCE",
            Path(__file__).resolve().parents[2] / "scripts/validator-election-stage-a.py",
        ))
        tree = ast.parse(route_source.read_text())
        methods = {
            item.name: item
            for node in tree.body if isinstance(node, ast.ClassDef)
            and node.name == "ValidatorElectionRehearsal"
            for item in node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

        def calls(method, name):
            return any(isinstance(item, ast.Call)
                       and isinstance(item.func, ast.Attribute)
                       and item.func.attr == name
                       for item in ast.walk(methods[method]))

        for method in ("run_pq_first_election", "wait_pq_config_activation"):
            self.assertTrue(calls(method, "capture_f01_transition"), method)
        for method in ("restart_node", "verify_three_of_four_liveness",
                       "verify_two_of_four_safe_halt", "verify_live_rejoin"):
            self.assertTrue(calls(method, "preserve_f01_log"), method)
            self.assertTrue(calls(method, "record_f01_process"), method)
        self.assertTrue(calls("write_report", "write_f01_capture"))
        self.assertTrue(calls("execute", "record_f01_process"))
        self.assertIn("node_data_dir", ast.unparse(methods["write_f01_capture"]))
        process_capture = ast.unparse(methods["record_f01_process"])
        self.assertIn("proc / 'cwd'", process_capture)
        self.assertIn("proc_cwd_realpath", process_capture)
        capture = ast.unparse(methods["capture_f01_transition"])
        self.assertIn("height + 1", capture)
        self.assertIn("(height - 1, height, height + 1)", capture)
        self.assertIn("'getBlockHeader'", capture)
        self.assertIn("'getConfigParam'", capture)

    async def test_transition_is_exact_first_new_cell_height(self):
        before = Builder().store_uint(1, 8).end_cell()
        after = Builder().store_uint(2, 8).end_cell()
        seen = []

        async def read(height):
            seen.append(height)
            return response(before if height < 5 else after)

        self.assertEqual(await f01.locate_transition(
            read, 2, 9, before.hash.hex(), after.hash.hex()), 5)
        self.assertIn(4, seen)
        self.assertIn(5, seen)

    async def test_wrong_prior_or_intervening_cell_fails(self):
        before = Builder().store_uint(1, 8).end_cell()
        other = Builder().store_uint(3, 8).end_cell()
        after = Builder().store_uint(2, 8).end_cell()

        async def wrong_lower(height):
            return response(after if height == 2 else before if height < 5 else after)

        with self.assertRaisesRegex(ValueError, "lower bound"):
            await f01.locate_transition(wrong_lower, 2, 9, before.hash.hex(), after.hash.hex())

        async def intermediate(height):
            return response(before if height < 4 else other if height == 4 else after)

        with self.assertRaisesRegex(ValueError, "intervening|neighbors"):
            await f01.locate_transition(intermediate, 2, 9, before.hash.hex(), after.hash.hex())

    async def test_raw_marker_and_distinct_identity_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "node1.log"
            log.write_text("[2026-09-25 10:00:01.000000001] Published event BlockFinalizedInMasterchain{block=(-1,8000000000000000,7):" + "a" * 64 + ":" + "b" * 64 + "}\n")
            extracted = f01.extract_finalized_log(log)
            self.assertEqual(extracted["markers"], 1)
            self.assertEqual(extracted["first"]["height"], 7)
            nodes = []
            for index in range(1, 5):
                node_dir = root / f"node{index}"
                node_dir.mkdir()
                segment = node_dir / "segment.log"
                combined = node_dir / "combined.log"
                segment.write_text(f"node{index} segment\n")
                combined.write_text(f"node{index} combined\n")
                process = {
                    "node_name": f"node{index}", "node_data_dir": str(node_dir),
                    "generation": 0, "pid": 10000 + index,
                    "proc_start_ticks": 20000 + index,
                    "exe_path": "/build/validator-engine", "exe_device": 1,
                    "exe_inode": 5000, "recorded_at": "2026-09-25T10:00:00Z",
                    "proc_cwd_link": str(node_dir),
                    "proc_cwd_realpath": str(node_dir.resolve()),
                    "proc_cwd_device": node_dir.stat().st_dev,
                    "proc_cwd_inode": node_dir.stat().st_ino,
                }
                nodes.append({
                    "node_name": f"node{index}", "node_data_dir": str(node_dir),
                    "controller_id_hex": f"{index:064x}",
                    "pq_validator_id_hex": f"{index + 10:064x}",
                    "pq_key_id_hex": f"{index + 20:064x}",
                    "adnl_id_hex": f"{index + 30:064x}",
                    "rpc_address": f"127.0.0.1:{20000 + index}",
                    "process_generations": [process],
                    "log_segments": [{"path": str(segment),
                                      "sha256": hashlib.sha256(segment.read_bytes()).hexdigest(),
                                      "process": dict(process)}],
                    "combined_log": {"path": str(combined),
                                     "sha256": hashlib.sha256(combined.read_bytes()).hexdigest()},
                })
            target = root / "manifest.json"
            f01.write_manifest(target, source={"source_commit": "a" * 40},
                               nodes=nodes, transitions=[{"height": 7}])
            self.assertEqual(len(json.loads(target.read_text())["validators"]), 4)
            restarted = [dict(node) for node in nodes]
            restarted[0] = dict(restarted[0])
            second = dict(restarted[0]["process_generations"][0],
                          generation=1, pid=20001, proc_start_ticks=30001)
            second_log = root / "node1" / "second-segment.log"
            second_log.write_text("node1 restarted segment\n")
            restarted[0]["process_generations"] = [
                restarted[0]["process_generations"][0], second]
            restarted[0]["log_segments"] = [
                restarted[0]["log_segments"][0],
                {"path": str(second_log),
                 "sha256": hashlib.sha256(second_log.read_bytes()).hexdigest(),
                 "process": dict(second)},
            ]
            f01.write_manifest(target, source={}, nodes=restarted,
                               transitions=[{"height": 7}])
            copied = [dict(node) for node in nodes]
            copied[-1]["process_generations"] = [dict(copied[0]["process_generations"][0])]
            copied[-1]["log_segments"] = [dict(copied[-1]["log_segments"][0],
                                              process=dict(copied[0]["process_generations"][0]))]
            with self.assertRaisesRegex(ValueError, "process generation|aliases a validator process"):
                f01.write_manifest(target, source={}, nodes=copied,
                                   transitions=[{"height": 7}])
            copied = [dict(node) for node in nodes]
            duplicate = dict(copied[-1]["process_generations"][0])
            duplicate["pid"] = copied[0]["process_generations"][0]["pid"]
            duplicate["proc_start_ticks"] = copied[0]["process_generations"][0]["proc_start_ticks"]
            copied[-1]["process_generations"] = [duplicate]
            copied[-1]["log_segments"] = [dict(copied[-1]["log_segments"][0],
                                              process=dict(duplicate))]
            with self.assertRaisesRegex(ValueError, "aliases a validator process"):
                f01.write_manifest(target, source={}, nodes=copied,
                                   transitions=[{"height": 7}])
            copied = [dict(node) for node in nodes]
            duplicate_cwd = dict(copied[-1]["process_generations"][0])
            first_cwd = copied[0]["process_generations"][0]
            for field in ("proc_cwd_link", "proc_cwd_realpath",
                          "proc_cwd_device", "proc_cwd_inode"):
                duplicate_cwd[field] = first_cwd[field]
            copied[-1]["process_generations"] = [duplicate_cwd]
            copied[-1]["log_segments"] = [dict(copied[-1]["log_segments"][0],
                                              process=dict(duplicate_cwd))]
            with self.assertRaisesRegex(ValueError, "process cwd differs|aliases a validator process cwd"):
                f01.write_manifest(target, source={}, nodes=copied,
                                   transitions=[{"height": 7}])
            copied = [dict(node) for node in nodes]
            same_path_wrong_inode = dict(copied[-1]["process_generations"][0])
            same_path_wrong_inode["proc_cwd_inode"] = (
                copied[0]["process_generations"][0]["proc_cwd_inode"])
            copied[-1]["process_generations"] = [same_path_wrong_inode]
            copied[-1]["log_segments"] = [dict(copied[-1]["log_segments"][0],
                                              process=dict(same_path_wrong_inode))]
            with self.assertRaisesRegex(ValueError, "process cwd differs|aliases a validator process cwd"):
                f01.write_manifest(target, source={}, nodes=copied,
                                   transitions=[{"height": 7}])
            for field in ("node_data_dir", "pq_validator_id_hex", "pq_key_id_hex",
                          "adnl_id_hex", "rpc_address"):
                copied = [dict(node) for node in nodes]
                copied[-1][field] = copied[0][field]
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, "aliases"):
                    f01.write_manifest(target, source={}, nodes=copied,
                                       transitions=[{"height": 7}])
            copied = [dict(node) for node in nodes]
            copied[-1]["combined_log"] = copied[0]["combined_log"]
            with self.assertRaisesRegex(ValueError, "aliases raw log paths"):
                f01.write_manifest(target, source={}, nodes=copied,
                                   transitions=[{"height": 7}])
            copied = [dict(node) for node in nodes]
            copied[-1]["combined_log"] = dict(copied[-1]["combined_log"])
            copied[-1]["combined_log"]["sha256"] = copied[0]["combined_log"]["sha256"]
            with self.assertRaisesRegex(ValueError, "differs from bytes"):
                f01.write_manifest(target, source={}, nodes=copied,
                                   transitions=[{"height": 7}])
            Path(copied[-1]["combined_log"]["path"]).write_bytes(
                Path(copied[0]["combined_log"]["path"]).read_bytes())
            with self.assertRaisesRegex(ValueError, "duplicates combined raw log SHA-256"):
                f01.write_manifest(target, source={}, nodes=copied,
                                   transitions=[{"height": 7}])
            nodes[-1]["node_name"] = "node1"
            with self.assertRaisesRegex(ValueError, "distinct"):
                f01.write_manifest(target, source={}, nodes=nodes, transitions=[{"height": 7}])
            log.write_text("height=7 only\n")
            with self.assertRaisesRegex(ValueError, "no native"):
                f01.extract_finalized_log(log)


if __name__ == "__main__":
    unittest.main()
