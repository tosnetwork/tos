"""Offline controls for composed-route controller and independent RPC quorum wiring."""

import ast
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


SCRIPT = Path(os.environ.get(
    "E10_SOURCE_PATH",
    Path(__file__).resolve().parents[2] / "scripts/agent-economy-composed-e2e.py",
))
SPEC = importlib.util.spec_from_file_location("e10_composed", SCRIPT)
e10 = importlib.util.module_from_spec(SPEC)
stubs = {name: types.ModuleType(name) for name in (
    "tostester", "tostester.install", "tostester.network",
    "tostester.pq_initial_validator", "contract", "pytosiq_core",
)}
stubs["tostester.install"].Install = object
stubs["tostester.network"].Network = object
stubs["tostester.network"].StartOptions = object
stubs["tostester.pq_initial_validator"].make_deterministic_pq_initial_validator = object
stubs["contract"].tos = object
for name in ("Address", "Cell", "InternalMsgInfo", "MessageAny", "WalletMessage"):
    setattr(stubs["pytosiq_core"], name, object)
with patch.dict(sys.modules, stubs):
    SPEC.loader.exec_module(e10)


class E10ControllerQuorumTests(unittest.TestCase):
    def test_all_agent_account_task_actions_have_unique_stable_ids_and_two_configs(self):
        expected = {
            ("accept", "workflow-happy"), ("result", "workflow-happy"),
            ("accept", "workflow-contested"), ("result", "workflow-contested"),
        }
        found = []
        for node in ast.walk(ast.parse(SCRIPT.read_text())):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id != "tosctl":
                continue
            literals = [arg.value for arg in node.args if isinstance(arg, ast.Constant)]
            if "--via-agent-account" not in literals:
                continue
            expanded = [arg.value for arg in node.args if isinstance(arg, ast.Starred)]
            self.assertEqual(len(expanded), 1)
            call = expanded[0]
            self.assertIsInstance(call, ast.Call)
            self.assertEqual(call.func.id, "controller_task_args")
            operation, name = (arg.value for arg in call.args)
            self.assertEqual(operation, literals[literals.index("--operation") + 1])
            self.assertEqual(name, literals[literals.index("--name") + 1])
            found.append((operation, name))
        self.assertEqual(set(found), expected)
        self.assertEqual(len(found), len(expected))
        ids = set()
        for operation, name in expected:
            args = e10.controller_task_args(operation, name)
            self.assertEqual(args[0], "--controller-action-id")
            self.assertRegex(args[1], r"^[0-9a-f]{64}$")
            self.assertEqual(args[2], "--quorum-config")
            self.assertEqual(args[3:], tuple(map(str, e10.OBSERVER_CONFIGS)))
            self.assertEqual(len(set(args[3:])), 2)
            self.assertTrue(all(Path(value).is_absolute() for value in args[3:]))
            self.assertEqual(args, e10.controller_task_args(operation, name))
            ids.add(args[1])
        self.assertEqual(len(ids), len(expected))

    def test_observer_configs_have_distinct_single_endpoints(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configs = (root / "observer-1.json", root / "observer-2.json")
            with patch.object(e10, "CONFIG", root / "primary.json"), patch.object(
                e10, "OBSERVER_CONFIGS", configs
            ):
                e10.write_config()
            urls = [json.loads(path.read_text())["chain_rpc"]["urls"]
                    for path in (root / "primary.json", *configs)]
            self.assertEqual(urls, [[f"http://{endpoint}/"]
                                    for endpoint in (e10.RPC, *e10.OBSERVER_RPCS)])
            self.assertEqual(len({row[0] for row in urls}), 3)

    def test_observers_must_match_primary_zerostate(self):
        calls = []

        def same_chain(method, *, endpoint=e10.RPC, **params):
            calls.append(endpoint)
            return {"result": {"init": {"root_hash": "same", "file_hash": "same"}}}

        with patch.object(e10, "rpc_call", side_effect=same_chain):
            e10.require_same_zerostate()
        self.assertEqual(calls, [e10.RPC, *e10.OBSERVER_RPCS])

        def different_chain(method, *, endpoint=e10.RPC, **params):
            return {"result": {"init": "wrong" if endpoint == e10.OBSERVER_RPCS[1] else "same"}}

        with patch.object(e10, "rpc_call", side_effect=different_chain):
            with self.assertRaisesRegex(RuntimeError, "different zerostate"):
                e10.require_same_zerostate()

    def test_observer_process_identity_rejects_reused_node(self):
        rows = [
            {"pid": 100 + index, "directory": f"/node{index}", "rpc": endpoint}
            for index, endpoint in enumerate((e10.RPC, *e10.OBSERVER_RPCS))
        ]
        e10.require_independent_processes(rows)
        for key in ("pid", "directory", "rpc"):
            with self.subTest(key=key):
                duplicate = [dict(row) for row in rows]
                duplicate[2][key] = duplicate[1][key]
                with self.assertRaisesRegex(RuntimeError, "not independent"):
                    e10.require_independent_processes(duplicate)

    def test_main_starts_both_observers_and_checks_quorum_before_actions(self):
        tree = ast.parse(SCRIPT.read_text())
        methods = {node.name: node for node in tree.body
                   if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}

        def has_call(method, name):
            return any(isinstance(node, ast.Call)
                       and isinstance(node.func, ast.Name) and node.func.id == name
                       for node in ast.walk(methods[method]))

        self.assertTrue(has_call("main", "write_config"))
        self.assertTrue(has_call("main", "require_independent_processes"))
        self.assertTrue(has_call("run_checks", "require_same_zerostate"))
        self.assertIn("observer.run", SCRIPT.read_text())


if __name__ == "__main__":
    unittest.main()
