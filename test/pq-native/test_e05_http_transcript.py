"""Retain raw successful and error HTTP replies from the E05 query route."""

import base64
import asyncio
import ast
import importlib.util
import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
from unittest.mock import patch


SCRIPT = Path(os.environ.get(
    "E05_ROUTE_SOURCE",
    Path(__file__).resolve().parents[2] / "scripts/agent-query-api-e2e.py",
))
SPEC = importlib.util.spec_from_file_location("e05_agent_query_api", SCRIPT)
e05 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(e05)


class Response:
    def __init__(self, status: int, raw: bytes):
        self.status = status
        self.raw = raw

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self):
        return self.raw


def task_list_fixture():
    creator = "0:" + "11" * 32
    agent = "0:" + "22" * 32
    open_addr = "0:" + "33" * 32
    settled_addr = "0:" + "44" * 32
    expected = {"q-open": (open_addr, "open"),
                "q-settled": (settled_addr, "settled")}

    def item(name, address, state):
        return {"name": name, "address": address,
                "task": {"address": address, "status": state,
                         "creator": creator, "assigned_agent": agent},
                "error": None, "error_kind": None}

    rows = [item("q-open", open_addr, "open"),
            item("q-settled", settled_addr, "settled")]
    return creator, agent, expected, {"ok": True, "total": 2, "result": rows}


class HttpTranscriptTests(unittest.TestCase):
    def test_detail_must_bind_response_to_requested_address(self):
        requested = "0:" + "11" * 32
        wrong = "0:" + "22" * 32
        self.assertTrue(e05.is_detail_for(
            200, {"ok": True, "result": {"address": requested}}, requested))
        self.assertFalse(e05.is_detail_for(
            200, {"ok": True, "result": {"address": wrong}}, requested))
        self.assertFalse(e05.is_detail_for(
            200, {"ok": True, "result": None}, requested))

    def test_task_list_accepts_complete_exact_entries(self):
        creator, agent, expected, body = task_list_fixture()
        self.assertTrue(e05.task_list_matches(200, body, expected, creator, agent))

    def test_task_list_rejects_named_rpc_error_item(self):
        creator, agent, expected, body = task_list_fixture()
        rows = body["result"]
        error_item = dict(rows[0], task=None, error="RPC failed", error_kind="timeout")
        self.assertFalse(e05.task_list_matches(
            200, dict(body, result=[error_item, rows[1]]), expected, creator, agent))

    def test_task_list_rejects_extra_entry(self):
        creator, agent, expected, body = task_list_fixture()
        extra = {"name": "q-extra", "address": "0:" + "55" * 32,
                 "task": {"address": "0:" + "55" * 32, "status": "open",
                          "creator": creator, "assigned_agent": agent},
                 "error": None, "error_kind": None}
        self.assertFalse(e05.task_list_matches(
            200, dict(body, total=3, result=body["result"] + [extra]),
            expected, creator, agent))

    def test_task_list_rejects_bad_status_and_address(self):
        creator, agent, expected, body = task_list_fixture()
        rows = body["result"]
        self.assertFalse(e05.task_list_matches(500, body, expected, creator, agent))
        self.assertFalse(e05.task_list_matches(
            200, dict(body, result=[rows[0], dict(rows[1], address=rows[0]["address"])]),
            expected, creator, agent))

    def test_not_found_controls_reject_server_error(self):
        not_found = {"ok": False, "error": {"code": 404, "kind": "not_found"}}
        self.assertTrue(e05.is_not_found(404, not_found))
        self.assertFalse(e05.is_not_found(500, not_found))
        self.assertFalse(e05.is_not_found(404, {"ok": False, "error": {
            "code": 404, "kind": "rpc_unavailable"}}))

    def test_records_exact_success_and_error_bodies(self):
        good = b'{"result":{"status":"open"}}'
        bad = b'{"error":{"kind":"invalid_request"}}'
        replies = [Response(200, good), urllib.error.HTTPError(
            "http://127.0.0.1/", 400, "bad request", {}, io.BytesIO(bad))]
        with tempfile.TemporaryDirectory() as directory:
            transcript = Path(directory) / "http.jsonl"
            with patch.object(e05, "HTTP_TRANSCRIPT", transcript), patch.object(
                e05.urllib.request, "urlopen", side_effect=replies
            ):
                self.assertEqual(e05.http_get("/tasks/valid")[0], 200)
                self.assertEqual(e05.http_get("/tasks/invalid")[0], 400)
            rows = [json.loads(line) for line in transcript.read_text().splitlines()]
        self.assertEqual([row["request"]["path"] for row in rows],
                         ["/tasks/valid", "/tasks/invalid"])
        self.assertEqual([row["response"]["status"] for row in rows], [200, 400])
        self.assertEqual([base64.b64decode(row["response"]["body_base64"])
                          for row in rows], [good, bad])


class HttpEventLoopTests(unittest.IsolatedAsyncioTestCase):
    async def test_inverse_filters_reject_ignored_filter_responses(self):
        creator, agent, _, full = task_list_fixture()
        empty = {"ok": True, "total": 0, "result": []}
        expected_paths = [f"/tasks?creator={agent}", f"/tasks?agent={creator}"]
        with patch.object(e05, "failures", []), patch.object(
            e05, "http_get_async", side_effect=[(200, empty), (200, empty)]
        ) as get:
            with redirect_stdout(io.StringIO()):
                await e05.check_task_filter_exclusion(creator, agent)
            self.assertEqual(e05.failures, [])
            self.assertEqual([call.args[0] for call in get.call_args_list], expected_paths)
        with patch.object(e05, "failures", []), patch.object(
            e05, "http_get_async", side_effect=[(200, full), (200, full)]
        ):
            with redirect_stdout(io.StringIO()):
                await e05.check_task_filter_exclusion(creator, agent)
            self.assertEqual(len(e05.failures), 2)

    async def test_real_route_calls_inverse_filter_control(self):
        source = ast.parse(SCRIPT.read_text())
        route = next(node for node in source.body
                     if isinstance(node, ast.AsyncFunctionDef) and node.name == "run_checks")
        self.assertTrue(any(
            isinstance(node, ast.Await)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "check_task_filter_exclusion"
            for node in ast.walk(route)
        ))

    async def test_http_wait_does_not_block_node_log_drain(self):
        released = threading.Event()
        finished = threading.Event()
        released_before_http_return = []

        def delayed_http(_path):
            released_before_http_return.append(released.wait(timeout=0.2))
            finished.set()
            return 200, {"ok": True}

        async def drain_task():
            await asyncio.sleep(0.01)
            released.set()

        with patch.object(e05, "http_get", side_effect=delayed_http):
            result, _ = await asyncio.gather(
                e05.http_get_async("/health"), drain_task())
        self.assertTrue(finished.is_set())
        self.assertEqual(result, (200, {"ok": True}))
        # A direct synchronous call holds the event loop until delayed_http's
        # timeout; the independent log-drain task must release it first.
        self.assertEqual(released_before_http_return, [True])


if __name__ == "__main__":
    unittest.main()
