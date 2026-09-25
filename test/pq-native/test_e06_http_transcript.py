"""Retain exact HTTP success and error replies from the E06 index route."""

import base64
import asyncio
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import types
import unittest
import urllib.error
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/agent-chain-index-e2e.py"
SPEC = importlib.util.spec_from_file_location("e06_agent_chain_index", SCRIPT)
e06 = importlib.util.module_from_spec(SPEC)
stubs = {
    name: types.ModuleType(name) for name in (
        "tostester", "tostester.install", "tostester.network",
        "tostester.pq_initial_validator", "pytosiq_core",
    )
}
stubs["tostester.install"].Install = object
stubs["tostester.network"].Network = object
stubs["tostester.network"].StartOptions = object
stubs["tostester.pq_initial_validator"].make_deterministic_pq_initial_validator = object
for name in ("Address", "Cell", "InternalMsgInfo", "MessageAny", "WalletMessage"):
    setattr(stubs["pytosiq_core"], name, object)
with patch.dict(sys.modules, stubs):
    SPEC.loader.exec_module(e06)


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


class HttpTranscriptTests(unittest.TestCase):
    def test_deployment_anchor_requires_real_index_progress(self):
        self.assertFalse(e06.indexed_through(
            {"result": {"masterchain_indexed": 30}}, 31))
        self.assertTrue(e06.indexed_through(
            {"result": {"masterchain_indexed": 31}}, 31))
        self.assertFalse(e06.indexed_through(
            {"result": {"masterchain_indexed": True}}, 31))
        self.assertFalse(e06.indexed_through({"result": {}}, 31))

    def test_records_exact_success_and_error_bodies(self):
        good = b'{"result":[{"address":"0:abc"}],"ok":true}'
        bad = b'{"error":"invalid query"}\n'
        replies = [Response(200, good), urllib.error.HTTPError(
            "http://127.0.0.1/", 400, "bad request", {}, io.BytesIO(bad))]
        with tempfile.TemporaryDirectory() as directory:
            transcript = Path(directory) / "http.jsonl"
            with patch.object(e06, "HTTP_TRANSCRIPT", transcript), patch.object(
                e06.urllib.request, "urlopen", side_effect=replies
            ) as urlopen:
                self.assertEqual(e06.http_get("/tasks")[0], 200)
                self.assertEqual(e06.http_get("/registry?limit=bad")[0], 400)
            self.assertEqual([call.args[0].get_method() for call in urlopen.call_args_list],
                             ["GET", "GET"])
            rows = [json.loads(line) for line in transcript.read_text().splitlines()]
        self.assertEqual([row["request"] for row in rows], [
            {"method": "GET", "path": "/tasks"},
            {"method": "GET", "path": "/registry?limit=bad"},
        ])
        self.assertEqual([row["response"]["status"] for row in rows], [200, 400])
        self.assertEqual([base64.b64decode(row["response"]["body_base64"])
                          for row in rows], [good, bad])


class HttpEventLoopTests(unittest.IsolatedAsyncioTestCase):
    async def test_http_wait_does_not_block_node_log_drain(self):
        released = threading.Event()
        released_before_http_return = []

        def delayed_http(_path):
            released_before_http_return.append(released.wait(timeout=0.2))
            return 200, {"ok": True}

        async def drain_task():
            await asyncio.sleep(0.01)
            released.set()

        with patch.object(e06, "http_get", side_effect=delayed_http):
            result, _ = await asyncio.gather(
                e06.http_get_async("/health"), drain_task())
        self.assertEqual(result, (200, {"ok": True}))
        self.assertEqual(released_before_http_return, [True])


if __name__ == "__main__":
    unittest.main()
