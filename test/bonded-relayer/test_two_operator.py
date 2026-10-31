"""A/B composition with independent processes and real HTTP/SQLite, fake chain."""

import dataclasses
import socket
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/bonded-relayer"))
from relay_client import ClientError, SubmissionUnknown  # noqa: E402
from relay_core import encode  # noqa: E402
from two_operator_harness import Operator, candidate  # noqa: E402


class TwoOperatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.a, self.b = Operator(root / "alice", 3), Operator(root / "bob", 4)
        self.addCleanup(self.a.stop)
        self.addCleanup(self.b.stop)

    def test_two_distinct_processes_receive_independent_quotes_and_fees(self):
        self.assertNotEqual(self.a.pid, self.b.pid)
        self.assertNotEqual(self.a.release.scope, self.b.release.scope)
        for operator in (self.a, self.b):
            quote = operator.client.quote()
            self.assertEqual(quote.terms["note_index"], 0)
            request = candidate(operator, quote)
            result = operator.client.submit(request, quote)
            self.assertEqual(result["status"], "broadcast")
            self.assertIsNone(result["finality"])
            operator.control("settings", outcome="executed")
            self.assertEqual(operator.control("tick")["unavailable"], 0)
            result = operator.client.status(request.identity, quote.status_token)
            self.assertEqual(result["status"], "executed")
            self.assertTrue(result["requires_independent_verification"])
            self.assertEqual(operator.control("counts"), {"prepare": 1, "broadcast": 1})

    def test_crash_after_ambiguous_write_never_resigns_or_resubmits(self):
        quote = self.a.client.quote()
        request = candidate(self.a, quote)
        self.a.control("settings", broadcast_error=True)
        self.assertEqual(self.a.client.submit(request, quote)["status"], "unknown")
        old_pid = self.a.pid
        self.a.restart()
        self.assertNotEqual(old_pid, self.a.pid)
        for _ in range(3):
            self.a.control("tick")
            self.assertEqual(self.a.client.submit(request, quote)["status"], "unknown")
        self.assertEqual(self.a.control("counts"), {"prepare": 1, "broadcast": 1})
        self.a.control("settings", outcome="executed")
        self.a.control("tick")
        self.assertEqual(
            self.a.client.status(request.identity, quote.status_token)["status"], "executed"
        )

    def test_crash_after_preparation_resumes_exact_persisted_message(self):
        quote = self.a.client.quote()
        request = candidate(self.a, quote)
        prepared = self.a.control("prepare_only", request=dataclasses.asdict(request))
        self.assertEqual(self.a.control("counts"), {"prepare": 1, "broadcast": 0})
        self.a.restart()
        self.a.control("tick")
        result = self.a.client.status(request.identity, quote.status_token)
        self.assertEqual(result["status"], "broadcast")
        self.assertEqual(result["message_hash"], prepared["message_hash"])
        self.assertEqual(self.a.control("counts"), {"prepare": 1, "broadcast": 1})

    def test_foreign_quote_is_rejected_before_either_operator_signs(self):
        quote = self.a.client.quote()
        request = candidate(self.a, quote)
        with self.assertRaises(ClientError):
            self.b.client.submit(request, quote)
        self.assertEqual(self.a.control("counts"), {"prepare": 0, "broadcast": 0})
        self.assertEqual(self.b.control("counts"), {"prepare": 0, "broadcast": 0})

    def test_bad_proof_with_fee_shaped_output_never_prepares(self):
        quote = self.a.client.quote()
        request = candidate(self.a, quote)
        self.a.control("settings", invalid=True)
        with self.assertRaises(SubmissionUnknown):
            self.a.client.submit(request, quote)
        self.assertEqual(self.a.control("counts"), {"prepare": 0, "broadcast": 0})

    def test_concurrent_duplicate_requests_have_one_broadcast(self):
        quote = self.a.client.quote()
        request = candidate(self.a, quote)

        def submit():
            try:
                return self.a.client.submit(request, quote)["status"]
            except SubmissionUnknown:
                return "unavailable"

        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda _: submit(), range(3)))
        self.assertIn("broadcast", results)
        self.assertEqual(self.a.control("counts"), {"prepare": 1, "broadcast": 1})

    def test_destination_refusal_has_no_fee_credit_or_false_success(self):
        quote = self.a.client.quote()
        request = candidate(self.a, quote)
        self.a.client.submit(request, quote)
        self.a.control("settings", outcome="rejected")
        self.a.control("tick")
        self.assertEqual(
            self.a.client.status(request.identity, quote.status_token)["status"], "rejected"
        )

    def test_unrelated_receipt_cannot_finalize_a_request(self):
        quote = self.a.client.quote()
        request = candidate(self.a, quote)
        self.a.client.submit(request, quote)
        self.a.control("settings", outcome="executed", bad_receipt=True)
        self.assertEqual(self.a.control("tick")["unavailable"], 1)
        self.assertEqual(
            self.a.client.status(request.identity, quote.status_token)["status"], "broadcast"
        )

    def test_lost_http_acknowledgement_is_recoverable_by_identity(self):
        quote = self.a.client.quote()
        request = candidate(self.a, quote)
        body = encode({"request": dataclasses.asdict(request), "status_token": quote.status_token})
        with socket.create_connection(("127.0.0.1", self.a.port), timeout=2) as sock:
            sock.sendall(
                f"POST /v1/submit HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n".encode()
                + body
            )
            sock.shutdown(socket.SHUT_WR)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self.a.control("counts")["broadcast"] == 1:
                break
            time.sleep(0.02)
        result = self.a.client.status(request.identity, quote.status_token)
        self.assertEqual(result["status"], "broadcast")
        self.assertEqual(self.a.client.submit(request, quote)["status"], "broadcast")
        self.assertEqual(self.a.control("counts"), {"prepare": 1, "broadcast": 1})


if __name__ == "__main__":
    unittest.main()
