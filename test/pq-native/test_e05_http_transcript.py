"""Retain raw successful and error HTTP replies from the E05 query route."""

import base64
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/agent-query-api-e2e.py"
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


class HttpTranscriptTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
