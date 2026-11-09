"""Offline controls for Stage A F01 capture inputs and transition binding."""

import ast
import asyncio
import base64
import hashlib
import importlib.util
import io
import json
import os
import runpy
import tempfile
import unittest
import urllib.error
import urllib.request
from collections import defaultdict, deque
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from pytosiq_core import Builder

SOURCE = Path(
    os.environ.get(
        "F01_CAPTURE_SOURCE",
        Path(__file__).resolve().parents[1] / "tostester/src/tostester/f01_stage_a_evidence.py",
    )
)
SPEC = importlib.util.spec_from_file_location("f01_stage_a_evidence", SOURCE)
f01 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(f01)


def response(cell):
    return {"result": {"config": {"bytes": base64.b64encode(cell.to_boc()).decode()}}}


class F01CaptureTests(unittest.IsolatedAsyncioTestCase):
    async def test_full_route_wires_transition_and_raw_log_capture(self):
        route_source = Path(
            os.environ.get(
                "F01_STAGE_A_SOURCE",
                Path(__file__).resolve().parents[2] / "scripts/validator-election-stage-a.py",
            )
        )
        tree = ast.parse(route_source.read_text())
        methods = {
            item.name: item
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "ValidatorElectionRehearsal"
            for item in node.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

        def calls(method, name):
            return any(
                isinstance(item, ast.Call)
                and isinstance(item.func, ast.Attribute)
                and item.func.attr == name
                for item in ast.walk(methods[method])
            )

        for method in ("run_pq_first_election", "wait_pq_config_activation"):
            self.assertTrue(calls(method, "capture_f01_transition"), method)
        for method in (
            "restart_node",
            "verify_three_of_four_liveness",
            "verify_two_of_four_safe_halt",
            "verify_live_rejoin",
        ):
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

        self.assertEqual(
            await f01.locate_transition(read, 2, 9, before.hash.hex(), after.hash.hex()), 5
        )
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

    async def test_brief_activation_and_reversion_between_bisection_probes_fails(self):
        before = Builder().store_uint(1, 8).end_cell()
        after = Builder().store_uint(2, 8).end_cell()

        # The final boundary (7, 8, 9) looks valid even with an earlier activation at 1.
        async def read(height):
            return response(after if height == 1 or height >= 8 else before)

        with self.assertRaisesRegex(ValueError, "intervening"):
            await f01.locate_transition(read, 0, 10, before.hash.hex(), after.hash.hex())

    async def test_raw_marker_and_distinct_identity_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "node1.log"
            log.write_text(
                "[2026-09-25 10:00:01.000000001] Published event BlockFinalizedInMasterchain{block=(-1,8000000000000000,7):"
                + "a" * 64
                + ":"
                + "b" * 64
                + "}\n"
            )
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
                    "node_name": f"node{index}",
                    "node_data_dir": str(node_dir),
                    "generation": 0,
                    "pid": 10000 + index,
                    "proc_start_ticks": 20000 + index,
                    "exe_path": "/build/validator-engine",
                    "exe_device": 1,
                    "exe_inode": 5000,
                    "recorded_at": "2026-09-25T10:00:00Z",
                    "proc_cwd_link": str(node_dir),
                    "proc_cwd_realpath": str(node_dir.resolve()),
                    "proc_cwd_device": node_dir.stat().st_dev,
                    "proc_cwd_inode": node_dir.stat().st_ino,
                }
                nodes.append(
                    {
                        "node_name": f"node{index}",
                        "node_data_dir": str(node_dir),
                        "controller_id_hex": f"{index:064x}",
                        "pq_validator_id_hex": f"{index + 10:064x}",
                        "pq_key_id_hex": f"{index + 20:064x}",
                        "adnl_id_hex": f"{index + 30:064x}",
                        "rpc_address": f"127.0.0.1:{20000 + index}",
                        "process_generations": [process],
                        "log_segments": [
                            {
                                "path": str(segment),
                                "sha256": hashlib.sha256(segment.read_bytes()).hexdigest(),
                                "process": dict(process),
                            }
                        ],
                        "combined_log": {
                            "path": str(combined),
                            "sha256": hashlib.sha256(combined.read_bytes()).hexdigest(),
                        },
                    }
                )
            target = root / "manifest.json"
            f01.write_manifest(
                target, source={"source_commit": "a" * 40}, nodes=nodes, transitions=[{"height": 7}]
            )
            self.assertEqual(len(json.loads(target.read_text())["validators"]), 4)
            restarted = [dict(node) for node in nodes]
            restarted[0] = dict(restarted[0])
            second = dict(
                restarted[0]["process_generations"][0],
                generation=1,
                pid=20001,
                proc_start_ticks=30001,
            )
            second_log = root / "node1" / "second-segment.log"
            second_log.write_text("node1 restarted segment\n")
            restarted[0]["process_generations"] = [restarted[0]["process_generations"][0], second]
            restarted[0]["log_segments"] = [
                restarted[0]["log_segments"][0],
                {
                    "path": str(second_log),
                    "sha256": hashlib.sha256(second_log.read_bytes()).hexdigest(),
                    "process": dict(second),
                },
            ]
            f01.write_manifest(target, source={}, nodes=restarted, transitions=[{"height": 7}])
            copied = [dict(node) for node in nodes]
            copied[-1]["process_generations"] = [dict(copied[0]["process_generations"][0])]
            copied[-1]["log_segments"] = [
                dict(
                    copied[-1]["log_segments"][0], process=dict(copied[0]["process_generations"][0])
                )
            ]
            with self.assertRaisesRegex(
                ValueError, "process generation|aliases a validator process"
            ):
                f01.write_manifest(target, source={}, nodes=copied, transitions=[{"height": 7}])
            copied = [dict(node) for node in nodes]
            duplicate = dict(copied[-1]["process_generations"][0])
            duplicate["pid"] = copied[0]["process_generations"][0]["pid"]
            duplicate["proc_start_ticks"] = copied[0]["process_generations"][0]["proc_start_ticks"]
            copied[-1]["process_generations"] = [duplicate]
            copied[-1]["log_segments"] = [
                dict(copied[-1]["log_segments"][0], process=dict(duplicate))
            ]
            with self.assertRaisesRegex(ValueError, "aliases a validator process"):
                f01.write_manifest(target, source={}, nodes=copied, transitions=[{"height": 7}])
            copied = [dict(node) for node in nodes]
            duplicate_cwd = dict(copied[-1]["process_generations"][0])
            first_cwd = copied[0]["process_generations"][0]
            for field in (
                "proc_cwd_link",
                "proc_cwd_realpath",
                "proc_cwd_device",
                "proc_cwd_inode",
            ):
                duplicate_cwd[field] = first_cwd[field]
            copied[-1]["process_generations"] = [duplicate_cwd]
            copied[-1]["log_segments"] = [
                dict(copied[-1]["log_segments"][0], process=dict(duplicate_cwd))
            ]
            with self.assertRaisesRegex(
                ValueError, "process cwd differs|aliases a validator process cwd"
            ):
                f01.write_manifest(target, source={}, nodes=copied, transitions=[{"height": 7}])
            copied = [dict(node) for node in nodes]
            same_path_wrong_inode = dict(copied[-1]["process_generations"][0])
            same_path_wrong_inode["proc_cwd_inode"] = copied[0]["process_generations"][0][
                "proc_cwd_inode"
            ]
            copied[-1]["process_generations"] = [same_path_wrong_inode]
            copied[-1]["log_segments"] = [
                dict(copied[-1]["log_segments"][0], process=dict(same_path_wrong_inode))
            ]
            with self.assertRaisesRegex(
                ValueError, "process cwd differs|aliases a validator process cwd"
            ):
                f01.write_manifest(target, source={}, nodes=copied, transitions=[{"height": 7}])
            for field in (
                "node_data_dir",
                "pq_validator_id_hex",
                "pq_key_id_hex",
                "adnl_id_hex",
                "rpc_address",
            ):
                copied = [dict(node) for node in nodes]
                copied[-1][field] = copied[0][field]
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, "aliases"):
                    f01.write_manifest(target, source={}, nodes=copied, transitions=[{"height": 7}])
            copied = [dict(node) for node in nodes]
            copied[-1]["combined_log"] = copied[0]["combined_log"]
            with self.assertRaisesRegex(ValueError, "aliases raw log paths"):
                f01.write_manifest(target, source={}, nodes=copied, transitions=[{"height": 7}])
            copied = [dict(node) for node in nodes]
            copied[-1]["combined_log"] = dict(copied[-1]["combined_log"])
            copied[-1]["combined_log"]["sha256"] = copied[0]["combined_log"]["sha256"]
            with self.assertRaisesRegex(ValueError, "differs from bytes"):
                f01.write_manifest(target, source={}, nodes=copied, transitions=[{"height": 7}])
            Path(copied[-1]["combined_log"]["path"]).write_bytes(
                Path(copied[0]["combined_log"]["path"]).read_bytes()
            )
            with self.assertRaisesRegex(ValueError, "duplicates combined raw log SHA-256"):
                f01.write_manifest(target, source={}, nodes=copied, transitions=[{"height": 7}])
            nodes[-1]["node_name"] = "node1"
            with self.assertRaisesRegex(ValueError, "distinct"):
                f01.write_manifest(target, source={}, nodes=nodes, transitions=[{"height": 7}])
            log.write_text("height=7 only\n")
            with self.assertRaisesRegex(ValueError, "no native"):
                f01.extract_finalized_log(log)


class F01RpcCaptureTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        scripts = Path(__file__).resolve().parents[2] / "scripts"
        stage = runpy.run_path(
            os.environ.get("F01_STAGE_A_SOURCE", scripts / "validator-election-stage-a.py")
        )
        cls.rehearsal = stage["ValidatorElectionRehearsal"]
        cls.profile = stage["PROFILES"]["a"]
        cls.verify_capture = staticmethod(
            runpy.run_path(str(scripts / "f01_finalized_ids.py"))["verify_capture"]
        )

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.gate = self.rehearsal(
            run_dir=root,
            build_dir=root,
            base_port=20000,
            sample_interval=1.0,
            profile=self.profile,
            pq_election=True,
            pq_full=True,
        )
        self.gate.nodes = [SimpleNamespace(name=f"node-{i + 1}") for i in range(4)]
        self.before = Builder().store_uint(1, 8).end_cell()
        self.after = Builder().store_uint(2, 8).end_cell()
        self.gate.client = SimpleNamespace(get_config_param=AsyncMock(return_value=self.after))
        self.gate.f01_previous_config_hash = self.before.hash.hex()
        self.gate.f01_previous_config_height = 3
        self.upper = 650
        self.activation = 620
        self.gate.masterchain_seqno = AsyncMock(return_value=self.upper)
        self.now = 100.0
        self.budget = defaultdict(deque)
        self.over_budget = 0
        self.injected = []
        self.attempts = []

    @staticmethod
    def block_id(height):
        return {
            "workchain": -1,
            "shard": str(-(1 << 63)),
            "seqno": height,
            "root_hash": base64.b64encode(height.to_bytes(32, "big")).decode(),
            "file_hash": base64.b64encode((height + 1).to_bytes(32, "big")).decode(),
        }

    def urlopen(self, request, timeout):
        payload = json.loads(request.data)
        method = payload["method"]
        height = payload["params"].get("seqno")
        recent = self.budget[request.host]
        while recent and recent[0] < self.now - 10:
            recent.popleft()
        status, code = 200, None
        if len(recent) >= 600:
            self.over_budget += 1
            status, code = 429, -32005
        else:
            recent.append(self.now)
            if method == "getConfigParam" and height == 6:
                self.attempts.append((payload, self.now))
                if self.injected:
                    status, code = self.injected.pop(0)

        if code is not None:
            document = {"error": {"code": code, "message": "injected failure"}}
        elif method == "getConfigParam":
            document = response(self.before if height < self.activation else self.after)
        elif method == "getBlockHeader":
            document = {"result": {"id": self.block_id(height)}}
        else:
            self.assertEqual(method, "getMasterchainInfo")
            document = {"result": {"last": {"seqno": self.upper}}}
        raw = io.BytesIO(json.dumps(document).encode())
        if status != 200:
            raise urllib.error.HTTPError(request.full_url, status, "refused", {}, raw)
        raw.status = status
        return raw

    async def capture(self):
        async def sleep(seconds):
            self.assertGreaterEqual(seconds, 0)
            self.now += seconds

        # Only the rehearsal sees the test clock. The event loop keeps its own clock.
        fake_asyncio = SimpleNamespace(sleep=sleep, to_thread=asyncio.to_thread)
        clock = SimpleNamespace(monotonic=lambda: self.now)
        with patch.dict(
            self.gate.capture_f01_transition.__globals__, time=clock, asyncio=fake_asyncio
        ):
            with patch.object(urllib.request, "urlopen", self.urlopen):
                await self.gate.capture_f01_transition("first PQ set")

    async def test_long_scan_survives_both_rate_limits_and_retains_usable_evidence(self):
        self.injected = [(429, -32005), (200, -32005)]
        await self.capture()
        self.assertEqual(self.over_budget, 0)
        self.assertEqual(len(self.attempts), 3)
        self.assertEqual(len({json.dumps(request) for request, _ in self.attempts}), 1)
        times = [at for _, at in self.attempts]
        self.assertTrue(all(right - left > 10 for left, right in zip(times, times[1:])))
        self.assertEqual(self.gate.f01_previous_config_height, self.activation)
        directory = self.gate.f01_directory
        transcript = directory / "config34-rpc.jsonl"
        rows = [json.loads(line) for line in transcript.read_text().splitlines()]
        scanned = {
            row["request"]["params"]["seqno"]
            for row in rows
            if row["node_index"] == 0 and row["request"]["method"] == "getConfigParam"
        }
        self.assertEqual(scanned, set(range(3, self.upper + 1)))
        refused = [
            json.loads(line)
            for line in (directory / "config34-rpc-throttled.jsonl").read_text().splitlines()
        ]
        self.assertEqual([row["http_status"] for row in refused], [429, 200])
        self.assertEqual([row["request"] for row in refused], [self.attempts[0][0]] * 2)
        for row in refused:
            raw = base64.b64decode(row["response_base64"], validate=True)
            self.assertEqual(json.loads(raw)["error"]["code"], -32005)
        self.verify_transcript(transcript)

    async def test_uncontended_scan_stays_within_the_real_per_ip_budget(self):
        await self.capture()
        self.assertEqual(self.over_budget, 0)
        self.assertEqual(self.gate.f01_previous_config_height, self.activation)

    def verify_transcript(self, transcript):
        heights = list(range(self.activation - 1, self.activation + 2))
        nodes, logs, validators = {}, {}, []
        for i, node in enumerate(self.gate.nodes):
            path = self.gate.f01_directory / f"{node.name}.log"
            path.write_text(node.name)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            logs[node.name] = (path, digest)
            validators.append(
                {
                    "node_name": node.name,
                    "rpc_address": f"127.0.0.1:{20500 + i}",
                    "combined_log": {"path": str(path), "sha256": digest},
                }
            )
            nodes[node.name] = [
                {"height": h, "id": (-1, "8000000000000000", h, f"{h:064x}", f"{h + 1:064x}")}
                for h in heights
            ]
        manifest = transcript.with_name("manifest.json")
        manifest.write_text(
            json.dumps(
                {
                    "schema": "tos.f01.stage-a-capture.v1",
                    "validators": validators,
                    "transitions": self.gate.f01_transitions,
                    "source": {
                        "config34_raw_rpc_transcript": {
                            "path": str(transcript),
                            "sha256": hashlib.sha256(transcript.read_bytes()).hexdigest(),
                        }
                    },
                }
            )
        )
        result = self.verify_capture(
            manifest, nodes, logs, self.activation, self.before.hash.hex(), self.after.hash.hex()
        )
        self.assertEqual(result["raw_header_heights"], heights)

    async def test_non_rate_limit_rpc_error_stops_at_the_failed_height(self):
        self.injected = [(200, -32602)]
        with self.assertRaises(RuntimeError):
            await self.capture()
        self.assertEqual(len(self.attempts), 1)
        self.assertEqual(self.gate.f01_transitions, [])
        self.assertEqual(self.gate.f01_previous_config_height, 3)

    async def test_unrelated_http_error_is_not_retried(self):
        self.injected = [(503, -32603)]
        with self.assertRaises((RuntimeError, urllib.error.HTTPError)):
            await self.capture()
        self.assertEqual(len(self.attempts), 1)
        self.assertEqual(self.gate.f01_transitions, [])
        self.assertEqual(self.gate.f01_previous_config_height, 3)

    async def test_persistent_limit_is_bounded_and_publishes_no_transition(self):
        self.injected = [(429, -32005)] * 4
        with self.assertRaises(RuntimeError):
            await self.capture()
        self.assertEqual(len(self.attempts), 3)
        self.assertEqual(self.gate.f01_transitions, [])
        self.assertEqual(self.gate.f01_previous_config_height, 3)


if __name__ == "__main__":
    unittest.main()
