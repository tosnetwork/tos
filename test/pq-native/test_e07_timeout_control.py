"""Control-flow checks for the real-chain timeout route; no chain is simulated."""

import asyncio
import ast
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import AsyncMock, patch


SCRIPT = Path(os.environ.get(
    "E07_SOURCE_PATH",
    Path(__file__).resolve().parents[2] / "scripts/agent-task-escrow-e2e.py",
))
SPEC = importlib.util.spec_from_file_location("e07_task_escrow", SCRIPT)
e07 = importlib.util.module_from_spec(SPEC)
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
    SPEC.loader.exec_module(e07)


def header(seqno: int, chain_time: int) -> dict:
    return {"id": {"seqno": seqno}, "gen_utime": chain_time}


def rpc_reply(method: str, **params) -> dict:
    if method == "getAddressInformation":
        return {"result": {"last_transaction_id": {"lt": "10"}}}
    if method == "getTransactions":
        baseline = {"transaction_id": {"lt": "10"}}
        if params["address"] == "0:wallet":
            current = {"transaction_id": {"lt": "11"}, "aborted": False,
                       "compute": {"success": True}, "action": {"success": True},
                       "out_msgs": [{"destination": "0:escrow", "hash": "exact-msg"}]}
        else:
            current = {"transaction_id": {"lt": "11"}, "utime": 108,
                       "aborted": True, "compute": {"exit_code": 109},
                       "in_msg": {"source": "0:wallet", "hash": "exact-msg"}}
        return {"result": [current, baseline]}
    raise AssertionError(method)


class TimeoutControlTests(unittest.TestCase):
    def test_multiple_new_wallet_rows_fail_closed_with_raw_pages_saved(self):
        show = AsyncMock(return_value={"address": "0:escrow", "deadline": 175,
                                       "status": "accepted"})
        send = AsyncMock()

        def extra_wallet_row_rpc(method, **params):
            response = rpc_reply(method, **params)
            if method == "getTransactions" and params["address"] == "0:wallet":
                response["result"].insert(0, {
                    "transaction_id": {"lt": "12"}, "out_msgs": [],
                })
            return response

        with patch.object(e07, "task_show", show), patch.object(
            e07, "finalized_mc_header", side_effect=[header(10, 100)]
        ), patch.object(e07, "norm_addr", side_effect=lambda x: x), patch.object(
            e07, "rpc_call", side_effect=extra_wallet_row_rpc
        ), patch.object(e07, "send_op", send), tempfile.TemporaryDirectory() as directory, patch.object(
            e07, "WORKDIR", Path(directory)
        ):
            with self.assertRaisesRegex(RuntimeError, "multiple new transactions"):
                asyncio.run(e07.premature_timeout_control("e2e-timeout", 175, "0:wallet"))
            evidence = json.loads((Path(directory) / "e07-premature-timeout-ambiguous.json").read_text())
        self.assertEqual(evidence["newer_wallet_count"], 2)
        self.assertEqual(evidence["newer_escrow_count"], 1)
        self.assertEqual(evidence["wallet_baseline_lt"], 10)
        self.assertEqual([row["transaction_id"]["lt"] for row in evidence["wallet_transactions"]],
                         ["12", "11", "10"])
        send.assert_awaited_once()

    def test_controller_actions_have_distinct_ids_and_two_observer_configs(self):
        expected = {
            ("accept", "e2e-controller"), ("result", "e2e-controller"),
            ("claim", "e2e-claim"), ("result", "e2e-claim"),
            ("reject", "e2e-reject"),
        }
        tree = ast.parse(SCRIPT.read_text())
        calls = set()
        for node in ast.walk(tree):
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
            self.assertIsInstance(call.func, ast.Name)
            self.assertEqual(call.func.id, "controller_task_args")
            self.assertEqual(len(call.args), 2)
            operation, name = (arg.value for arg in call.args)
            self.assertEqual(operation, literals[literals.index("--operation") + 1])
            self.assertEqual(name, literals[literals.index("--name") + 1])
            calls.add((operation, name))
        self.assertEqual(calls, expected)
        ids = set()
        for operation, name in expected:
            args = e07.controller_task_args(operation, name)
            self.assertEqual(args[0], "--controller-action-id")
            self.assertRegex(args[1], r"^[0-9a-f]{64}$")
            self.assertEqual(args[2], "--quorum-config")
            self.assertEqual(args[3:], tuple(map(str, e07.OBSERVER_CONFIGS)))
            self.assertEqual(len(set(args[3:])), 2)
            self.assertTrue(all(Path(value).is_absolute() for value in args[3:]))
            ids.add(args[1])
        self.assertEqual(len(ids), len(expected))

    def test_unrelated_aborted_escrow_transaction_cannot_satisfy_control(self):
        show = AsyncMock(return_value={"address": "0:escrow", "deadline": 175,
                                       "status": "accepted"})
        send = AsyncMock()

        def wrong_hash_rpc(method, **params):
            response = rpc_reply(method, **params)
            if method == "getTransactions" and params["address"] == "0:escrow":
                response["result"][0]["in_msg"]["hash"] = "unrelated-msg"
            return response

        with patch.object(e07, "task_show", show), patch.object(
            e07, "finalized_mc_header", side_effect=[header(10, 100), header(11, 108)]
        ), patch.object(e07, "norm_addr", side_effect=lambda x: x), patch.object(
            e07, "rpc_call", side_effect=wrong_hash_rpc
        ), patch.object(e07, "send_op", send), tempfile.TemporaryDirectory() as directory, patch.object(
            e07, "WORKDIR", Path(directory)
        ):
            with self.assertRaisesRegex(RuntimeError, "does not match wallet outbound"):
                asyncio.run(e07.premature_timeout_control("e2e-timeout", 175, "0:wallet"))
        send.assert_awaited_once()

    def test_wrong_vm_exit_does_not_count_as_timeout_refusal(self):
        show = AsyncMock(return_value={"address": "0:escrow", "deadline": 175,
                                       "status": "accepted"})
        send = AsyncMock()

        def wrong_exit_rpc(method, **params):
            response = rpc_reply(method, **params)
            if method == "getTransactions" and params["address"] == "0:escrow":
                response["result"][0]["compute"]["exit_code"] = 110
            return response

        with patch.object(e07, "task_show", show), patch.object(
            e07, "finalized_mc_header", side_effect=[header(10, 100), header(11, 108)]
        ), patch.object(e07, "norm_addr", side_effect=lambda x: x), patch.object(
            e07, "rpc_call", side_effect=wrong_exit_rpc
        ), patch.object(e07, "send_op", send), tempfile.TemporaryDirectory() as directory, patch.object(
            e07, "WORKDIR", Path(directory)
        ):
            with self.assertRaisesRegex(RuntimeError, "not proved"):
                asyncio.run(e07.premature_timeout_control("e2e-timeout", 175, "0:wallet"))
        send.assert_awaited_once()

    def test_elapsed_window_fails_without_sending(self):
        show = AsyncMock(return_value={"address": "0:escrow", "deadline": 175,
                                       "status": "accepted"})
        send = AsyncMock()
        with patch.object(e07, "task_show", show), patch.object(
            e07, "finalized_mc_header", side_effect=[header(10, 170), header(11, 171)]
        ), patch.object(e07, "norm_addr", side_effect=lambda x: x), patch.object(
            e07, "rpc_call", side_effect=rpc_reply
        ), patch.object(e07, "send_op", send):
            with self.assertRaisesRegex(RuntimeError, "window expired"):
                asyncio.run(e07.premature_timeout_control("e2e-timeout", 175, "0:wallet"))
        send.assert_not_awaited()

    def test_normal_window_sends_once_and_requires_accepted_before_deadline(self):
        show = AsyncMock(return_value={"address": "0:escrow", "deadline": 175,
                                       "status": "accepted"})
        send = AsyncMock()
        with patch.object(e07, "task_show", show), patch.object(
            e07, "finalized_mc_header", side_effect=[header(10, 100), header(11, 108)]
        ), patch.object(e07, "norm_addr", side_effect=lambda x: x), patch.object(
            e07, "rpc_call", side_effect=rpc_reply
        ), patch.object(e07, "send_op", send), tempfile.TemporaryDirectory() as directory, patch.object(
            e07, "WORKDIR", Path(directory)
        ):
            asyncio.run(e07.premature_timeout_control("e2e-timeout", 175, "0:wallet"))
        send.assert_awaited_once_with("timeout", "e2e-timeout", "creator")

    def test_post_send_deadline_does_not_count_as_negative_control(self):
        show = AsyncMock(return_value={"address": "0:escrow", "deadline": 175,
                                       "status": "accepted"})
        send = AsyncMock()

        def late_rpc(method, **params):
            response = rpc_reply(method, **params)
            if method == "getTransactions" and params["address"] == "0:escrow":
                response["result"][0]["utime"] = 175
            return response

        with patch.object(e07, "task_show", show), patch.object(
            e07, "finalized_mc_header", side_effect=[header(10, 100), header(11, 180)]
        ), patch.object(e07, "norm_addr", side_effect=lambda x: x), patch.object(
            e07, "rpc_call", side_effect=late_rpc
        ), patch.object(e07, "send_op", send), tempfile.TemporaryDirectory() as directory, patch.object(
            e07, "WORKDIR", Path(directory)
        ):
            with self.assertRaisesRegex(RuntimeError, "not proved"):
                asyncio.run(e07.premature_timeout_control("e2e-timeout", 175, "0:wallet"))
        send.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
