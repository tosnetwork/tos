"""Control-flow checks for the real-chain timeout route; no chain is simulated."""

import asyncio
import importlib.util
import os
from pathlib import Path
import sys
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


def rpc_reply(method: str, **_params) -> dict:
    if method == "getAddressInformation":
        return {"result": {"last_transaction_id": {"lt": "10"}}}
    if method == "getTransactions":
        return {"result": [{"transaction_id": {"lt": "11"},
                            "utime": 108, "aborted": True}]}
    raise AssertionError(method)


class TimeoutControlTests(unittest.TestCase):
    def test_elapsed_window_fails_without_sending(self):
        show = AsyncMock(return_value={"address": "0:abc", "deadline": 175,
                                       "status": "accepted"})
        send = AsyncMock()
        with patch.object(e07, "task_show", show), patch.object(
            e07, "finalized_mc_header", side_effect=[header(10, 170), header(11, 171)]
        ), patch.object(e07, "norm_addr", side_effect=lambda x: x), patch.object(
            e07, "rpc_call", side_effect=lambda method, **kwargs: (
                {"result": [{"transaction_id": {"lt": "11"},
                              "utime": 171, "aborted": True}]}
                if method == "getTransactions" else rpc_reply(method, **kwargs))
        ), patch.object(e07, "send_op", send):
            with self.assertRaisesRegex(RuntimeError, "window expired"):
                asyncio.run(e07.premature_timeout_control("e2e-timeout", 175))
        send.assert_not_awaited()

    def test_normal_window_sends_once_and_requires_accepted_before_deadline(self):
        show = AsyncMock(return_value={"address": "0:abc", "deadline": 175,
                                       "status": "accepted"})
        send = AsyncMock()
        with patch.object(e07, "task_show", show), patch.object(
            e07, "finalized_mc_header", side_effect=[header(10, 100), header(11, 108)]
        ), patch.object(e07, "norm_addr", side_effect=lambda x: x), patch.object(
            e07, "rpc_call", side_effect=rpc_reply
        ), patch.object(e07, "send_op", send):
            asyncio.run(e07.premature_timeout_control("e2e-timeout", 175))
        send.assert_awaited_once_with("timeout", "e2e-timeout", "creator")

    def test_post_send_deadline_does_not_count_as_negative_control(self):
        show = AsyncMock(return_value={"address": "0:abc", "deadline": 175,
                                       "status": "accepted"})
        send = AsyncMock()
        with patch.object(e07, "task_show", show), patch.object(
            e07, "finalized_mc_header", side_effect=[header(10, 100), header(11, 180)]
        ), patch.object(e07, "norm_addr", side_effect=lambda x: x), patch.object(
            e07, "rpc_call", side_effect=lambda method, **kwargs: (
                {"result": [{"transaction_id": {"lt": "11"},
                              "utime": 175, "aborted": True}]}
                if method == "getTransactions" else rpc_reply(method, **kwargs))
        ), patch.object(e07, "send_op", send):
            with self.assertRaisesRegex(RuntimeError, "not proved"):
                asyncio.run(e07.premature_timeout_control("e2e-timeout", 175))
        send.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
