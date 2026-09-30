#!/usr/bin/env python3
"""Isolated Unix HTTP controls for the low-rate projection sampler."""

import json
from pathlib import Path
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest


SCRIPT = Path(__file__).with_name("sample-broker-projection.py")
TOKEN = "a" * 64


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        request = b""
        while b"\r\n\r\n" not in request and len(request) <= 4096:
            request += self.request.recv(4096)
        self.server.request_bytes = request
        payload = self.server.payload
        self.request.sendall(
            ("HTTP/1.1 " + str(self.server.code) + " OK\r\nContent-Type: application/json\r\n"
             + "Content-Length: " + str(len(payload)) + "\r\nConnection: close\r\n\r\n").encode()
            + payload
        )


class ProjectionProbeTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="nhm-projection-probe-")
        self.root = Path(self.temporary.name)
        self.token = self.root / "service.token"
        self.token.write_text(TOKEN)
        self.token.chmod(0o600)
        self.sock = self.root / "control.sock"

    def tearDown(self):
        self.temporary.cleanup()

    def run_probe(self, document, code=200):
        expected_token = self.token.read_text().strip()
        server = socketserver.UnixStreamServer(str(self.sock), Handler)
        server.payload = document if isinstance(document, bytes) else json.dumps(document).encode()
        server.code = code
        worker = threading.Thread(target=server.handle_request, daemon=True)
        worker.start()
        try:
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--socket", str(self.sock), "--token-file", str(self.token)],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            worker.join(timeout=1)
            self.assertIn(b"GET /v1/control/projection-health HTTP/1.1", server.request_bytes)
            self.assertIn(("Authorization: Bearer " + expected_token).encode(), server.request_bytes)
            self.assertNotIn(expected_token, result.stdout + result.stderr)
            return result, json.loads(result.stdout)
        finally:
            server.server_close()

    def document(self, **override):
        value = {
            "schema_version": 1,
            "projection_status": "caught_up",
            "manager_conflicted": False,
            "caught_up_at_last_import": True,
            "query_watermark": "17",
            "cursor_global_m_seq": "25",
            "source_global_m_seq": "25",
            "lag_global_m_seq": "0",
            "source_identity_match": True,
        }
        value.update(override)
        return value

    def test_caught_up_and_lag_are_distinct_without_creating_a_grant(self):
        result, output = self.run_probe(self.document())
        self.assertEqual(result.returncode, 0)
        self.assertEqual(output["projection_status"], "caught_up")
        self.assertTrue(output["projection_caught_up"])
        self.assertTrue(output["sample_boottime_ms"].isdecimal())
        self.sock.unlink()
        result, output = self.run_probe(self.document(
            projection_status="lagging", source_global_m_seq="26", lag_global_m_seq="1"
        ))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(output["lag_global_m_seq"], "1")
        self.assertTrue(output["probe_ok"])
        self.assertFalse(output["projection_caught_up"])
        self.assertTrue(output["sample_boottime_ms"].isdecimal())

    def test_false_caught_up_and_oversize_are_refused_without_secret_output(self):
        result, output = self.run_probe(self.document(source_global_m_seq="26", lag_global_m_seq="1"))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(output["error_kind"], "ValueError")
        self.sock.unlink()
        result, output = self.run_probe(self.document(projection_status="transition"))
        self.assertEqual(result.returncode, 1, "transition must not be HTTP 200")
        self.assertEqual(output["error_kind"], "ValueError")
        self.sock.unlink()
        missing = self.document()
        del missing["cursor_global_m_seq"]
        result, output = self.run_probe(missing)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(output["error_kind"], "ValueError")
        self.sock.unlink()
        result, output = self.run_probe(b"{" + b" " * 4096 + b"}")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(output["error_kind"], "ValueError")

    def test_conflict_and_private_file_permissions(self):
        result, output = self.run_probe(self.document(projection_status="conflict", manager_conflicted=True), 503)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(output["manager_conflicted"])
        self.assertFalse(output["projection_caught_up"])
        self.sock.unlink()
        result, output = self.run_probe(self.document(projection_status="transition"), 503)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(output["probe_ok"])
        self.assertFalse(output["projection_caught_up"])
        self.token.chmod(0o644)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--socket", str(self.sock), "--token-file", str(self.token)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["error_kind"], "ValueError")
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_service_token_rotation_matches_running_broker_parser(self):
        # The Rust service trims surrounding whitespace, accepts ASCII graphic
        # bytes, and caps the raw private file at 4096 bytes.
        rotated = "Z" * 300 + "-._~!"
        self.token.write_text(rotated + "\n")
        result, output = self.run_probe(self.document())
        self.assertEqual(result.returncode, 0)
        self.assertEqual(output["projection_status"], "caught_up")
        self.sock.unlink()
        # The raw-file cap is inclusive. A trailing newline is trimmed by
        # Rust secret(path), leaving 4095 valid graphic bytes.
        self.token.write_text("-" * 4095 + "\n")
        result, output = self.run_probe(self.document())
        self.assertEqual(result.returncode, 0)
        self.assertEqual(output["projection_status"], "caught_up")
        self.sock.unlink()
        self.token.write_text("a" * 4097)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--socket", str(self.sock), "--token-file", str(self.token)],
            capture_output=True, text=True, timeout=5, check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["error_kind"], "ValueError")


if __name__ == "__main__":
    unittest.main()
