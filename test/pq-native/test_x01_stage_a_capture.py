"""Offline controls for Stage A X01 capture wiring; no validator is started."""

import ast
import asyncio
import base64
import copy
import json
import os
from pathlib import Path
import unittest
from typing import Any


SOURCE = Path(os.environ.get(
    "X01_STAGE_A_SOURCE", Path(__file__).resolve().parents[2] / "scripts/validator-election-stage-a.py"))


def methods():
    tree = ast.parse(SOURCE.read_text())
    return {item.name: item for node in tree.body if isinstance(node, ast.ClassDef)
            and node.name == "ValidatorElectionRehearsal"
            for item in node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))}


def compiled_method(name):
    method = copy.deepcopy(methods()[name])
    method.decorator_list = []
    namespace = {"Any": Any, "base64": base64, "json": json,
                 "MASTERCHAIN_SHARD_STR": "-9223372036854775808",
                 "utc_now": lambda: "2026-09-25T12:00:00Z"}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])),
                 str(SOURCE), "exec"), namespace)
    return namespace[name]


def raw_id(seqno, root=1):
    return {"workchain": -1, "shard": "-9223372036854775808", "seqno": seqno,
            "root_hash": base64.b64encode(root.to_bytes(32, "big")).decode(),
            "file_hash": base64.b64encode((root + 1).to_bytes(32, "big")).decode()}


class X01StageACaptureTests(unittest.IsolatedAsyncioTestCase):
    async def test_x01_restarts_preserve_f01_process_generations(self):
        body = methods()
        for route in ("verify_three_of_four_liveness", "verify_two_of_four_safe_halt"):
            calls = [node.func.attr for node in ast.walk(body[route])
                     if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)]
            self.assertIn("x01_start", calls)
            self.assertIn("record_f01_process", calls)
            self.assertIn("preserve_f01_log", calls)
        self.assertIn("process_generations", ast.unparse(body["write_f01_capture"]))
        self.assertIn("height + 1", ast.unparse(body["capture_f01_transition"]))

    async def test_retained_route_wires_prefault_policy_stop_start_and_raw_views(self):
        body = methods()
        def calls(name, target):
            return any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                       and node.func.attr == target for node in ast.walk(body[name]))
        self.assertTrue(calls("verify_three_of_four_liveness", "x01_freeze_policy"))
        self.assertTrue(calls("verify_three_of_four_liveness", "x01_stop"))
        self.assertTrue(calls("verify_three_of_four_liveness", "x01_sample"))
        self.assertTrue(calls("verify_three_of_four_liveness", "x01_start"))
        for target in ("x01_stop", "x01_sample", "x01_start", "x01_finish"):
            self.assertTrue(calls("verify_two_of_four_safe_halt", target), target)
        for target in ("getMasterchainInfo", "getBlockHeader"):
            self.assertIn(target, ast.unparse(body["x01_sample"]))
        for target in ("response_base64", "endpoint", "http_status"):
            self.assertIn(target, ast.unparse(body["x01_rpc"]))
        self.assertIn("/proc/", ast.unparse(body["x01_stop"]))
        self.assertIn("/proc/", ast.unparse(body["x01_start"]))
        self.assertTrue(calls("write_report", "write_f01_capture"))
        self.assertIn("x01_capture_manifest", ast.unparse(body["write_report"]))

    async def test_sample_uses_common_height_and_rejects_conflicting_full_ids(self):
        normalizer = compiled_method("x01_block_id")
        sample = compiled_method("x01_sample")
        self.assertEqual(normalizer(raw_id(7))["root_hash"], f"{1:064x}")
        with self.assertRaisesRegex(ValueError, "zero"):
            normalizer(raw_id(7, root=0))

        class Fake:
            nodes = [type("Node", (), {"name": f"node{i}"})() for i in (1, 2)]
            x01_trace = {"phases": {}}
            x01_block_id = staticmethod(normalizer)

            def __init__(self):
                self.calls = []
                self.conflict = False
                self.heights = (12, 10)
                self.later_heights = None
                self.tip_reads = [0, 0]

            async def x01_rpc(self, index, method, params=None):
                self.calls.append((index, method, params))
                if method == "getMasterchainInfo":
                    self.tip_reads[index] += 1
                    height = (self.later_heights[index] if self.later_heights is not None
                              and self.tip_reads[index] > 1 else self.heights[index])
                    return {"last": raw_id(height)}, "2026-09-25T12:00:00.050000Z"
                assert params["seqno"] == min(self.heights)
                return {"id": raw_id(min(self.heights), root=2 if self.conflict and index else 1)}, "2026-09-25T12:00:00.040000Z"

        fake = Fake()
        observed = await sample(fake, "three_of_four", (0, 1))
        self.assertEqual(next(iter(observed["nodes"].values()))["seqno"], 10)
        self.assertEqual(observed["tips"]["node1"]["seqno"], 12)
        self.assertEqual(observed["tips"]["node2"]["seqno"], 10)
        self.assertEqual(set(observed["tip_observed_at"]), {"node1", "node2"})
        self.assertEqual([call[2]["seqno"] for call in fake.calls if call[1] == "getBlockHeader"], [10, 10])
        fake.heights = (12, 20)
        observed = await sample(fake, "two_of_four", (0, 1))
        self.assertEqual({name: row["seqno"] for name, row in observed["nodes"].items()},
                         {"node1": 12, "node2": 12})
        self.assertEqual(observed["tips"]["node2"]["seqno"], 20)
        fake.heights = (12, 12)
        fake.later_heights = (12, 20)
        fake.tip_reads = [0, 0]
        observed = await sample(fake, "two_of_four", (0, 1))
        self.assertEqual(observed["nodes"]["node2"]["seqno"], 12)
        self.assertEqual(observed["tips"]["node2"]["seqno"], 20)
        fake.conflict = True
        with self.assertRaisesRegex(AssertionError, "full IDs conflict"):
            await sample(fake, "three_of_four", (0, 1))


if __name__ == "__main__":
    unittest.main()
