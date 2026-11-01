"""Real HTTP and SQLite tests with the explicit TEST-ONLY authority fixture."""

import dataclasses
import errno
import json
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/bonded-relayer"))
from _service_fixture import FixtureAuthority, candidate, h, profile, submission  # noqa: E402
from relay_client import Client, ClientError, SubmissionUnknown  # noqa: E402
from relay_core import Engine, Journal, Refused, encode  # noqa: E402
from relay_http import HTTPRefused, receive  # noqa: E402
from relay_service import BODY_LIMIT, RelayServer, Service  # noqa: E402


class HTTPBoundTests(unittest.TestCase):
    def test_content_length_bound_is_not_an_unrelated_parse_failure(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        left.sendall(
            b"POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 5\r\nContent-Type: application/json\r\n\r\n12345"
        )
        with self.assertRaisesRegex(HTTPRefused, "HTTP body too large"):
            receive(right, 4, time.monotonic() + 1)


class ServiceFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.profile = profile()
        self.path = Path(self.tmp.name) / "journal.sqlite"
        self.journal = Journal(self.path, self.profile, max_pending=8, require_quotes=True)
        self.addCleanup(self.journal.close)
        self.authority = FixtureAuthority(self.journal)
        self.now = 1000
        self.engine = Engine(self.journal, self.authority, clock=lambda: self.now)
        self.service = Service(self.engine, fee=7, funding_cap=100, enabled=True)
        self.token = "ef" * 32

    def quote(self):
        status, result = self.service.handle(
            "POST", "/v1/quote", encode({"slot": 2, "lifetime": 100, "status_token": self.token})
        )
        self.assertEqual(status, 200, result)
        return result


class ServiceTests(ServiceFixture):
    def test_server_restarts_after_active_close_without_sharing_listener(self):
        server = RelayServer(self.service, ("127.0.0.1", 0))
        address = server.server_address
        self.addCleanup(server.server_close)
        with socket.socket() as competitor:
            competitor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            with self.assertRaises(OSError) as refused:
                competitor.bind(address)
            self.assertEqual(refused.exception.errno, errno.EADDRINUSE)
        worker = threading.Thread(target=server.handle_request)
        worker.start()
        with socket.create_connection(address, timeout=3) as client:
            client.sendall(b"GET /v1/health HTTP/1.1\r\nHost: local\r\n\r\n")
            response = bytearray()
            while chunk := client.recv(4096):
                response.extend(chunk)
        worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertIn(b"200", response.split(b"\r\n", 1)[0])
        server.server_close()
        replacement = RelayServer(self.service, address)
        replacement.server_close()

    def test_disabled_is_default_and_is_not_production_approval(self):
        service = Service(self.engine, fee=7, funding_cap=100)
        self.assertEqual(service.handle("POST", "/v1/quote", b"{}")[0], 503)
        code, body = service.handle("GET", "/v1/health", b"")
        self.assertEqual(code, 503)
        self.assertFalse(body["ready"])
        self.assertFalse(body["production_approved"])
        self.assertEqual(self.journal.db.execute("SELECT COUNT(*) FROM quotes").fetchone()[0], 0)

    def test_unauthenticated_journal_is_not_a_service(self):
        path = Path(self.tmp.name) / "unquoted.sqlite"
        journal = Journal(path, self.profile)
        self.addCleanup(journal.close)
        with self.assertRaisesRegex(Refused, "local quote"):
            Service(Engine(journal, self.authority), fee=7, funding_cap=100, enabled=True)

    def test_quote_allocation_is_durable_and_token_never_persisted(self):
        first, second = self.quote(), self.quote()
        self.assertEqual(first["quote"]["terms"]["note_index"], 0)
        self.assertEqual(second["quote"]["terms"]["note_index"], 1)
        self.assertNotEqual(first["quote_id"], second["quote_id"])
        for path in Path(self.tmp.name).iterdir():
            if path.is_file():
                self.assertNotIn(self.token.encode(), path.read_bytes())

    def test_signing_failure_does_not_recycle_receiving_index(self):
        self.authority.bad_quote = True
        status, _ = self.service.handle(
            "POST", "/v1/quote", encode({"slot": 2, "lifetime": 100, "status_token": self.token})
        )
        self.assertEqual(status, 422)
        self.authority.bad_quote = False
        self.assertEqual(self.quote()["quote"]["terms"]["note_index"], 1)

    def test_caller_cannot_set_fee_or_send_seed(self):
        for data in (
            {"slot": 2, "lifetime": 100, "status_token": self.token, "amount": 1},
            {"mnemonic": "not-a-real-secret"},
        ):
            self.assertEqual(self.service.handle("POST", "/v1/quote", encode(data))[0], 422)
        self.assertEqual(self.journal.db.execute("SELECT COUNT(*) FROM quotes").fetchone()[0], 0)

    def test_quote_count_limit_is_enforced(self):
        self.journal.max_quotes = 2
        self.quote()
        self.quote()
        self.assertEqual(
            self.service.handle(
                "POST",
                "/v1/quote",
                encode({"slot": 2, "lifetime": 100, "status_token": self.token}),
            )[0],
            422,
        )
        self.assertEqual(self.journal.db.execute("SELECT COUNT(*) FROM quotes").fetchone()[0], 2)

    def test_submit_status_and_duplicate_use_one_signature_and_write(self):
        quote = self.quote()
        request = candidate(self.profile, quote)
        for _ in range(3):
            code, value = self.service.handle("POST", "/v1/submit", submission(request, self.token))
            self.assertEqual((code, value["status"]), (202, "broadcast"))
            self.assertIsNone(value["finality"])
            self.assertTrue(value["requires_independent_verification"])
        self.assertEqual((self.authority.prepares, len(self.authority.writes)), (1, 1))
        code, value = self.service.handle(
            "POST",
            "/v1/status",
            encode({"request_id": request.identity, "status_token": self.token}),
        )
        self.assertEqual(code, 200)
        self.assertIn("acceptance_b64", value)
        self.assertNotIn("request", value)
        self.assertNotIn("body_b64", value)

    def test_capability_and_quote_mismatch_refuse_before_proof_work(self):
        request = candidate(self.profile, self.quote())
        self.assertEqual(
            self.service.handle("POST", "/v1/submit", submission(request, "ad" * 32))[0], 422
        )
        for altered in (
            dataclasses.replace(request, fee_slot=1),
            dataclasses.replace(request, fee_note_index=2),
            dataclasses.replace(request, funding_cap=101),
            dataclasses.replace(request, valid_until=1101),
        ):
            self.assertEqual(
                self.service.handle("POST", "/v1/submit", submission(altered, self.token))[0], 422
            )
        self.assertEqual(self.authority.preflights, 0)
        self.assertEqual(self.authority.prepares, 0)

    def test_bad_proof_with_valid_looking_fee_never_signs(self):
        request = candidate(self.profile, self.quote())
        self.authority.invalid_proof = True
        self.assertEqual(
            self.service.handle("POST", "/v1/submit", submission(request, self.token))[0], 422
        )
        self.assertEqual(self.authority.preflights, 1)
        self.assertEqual(self.authority.prepares, 0)
        self.assertEqual(self.journal.pending(), [])

    def test_ambiguous_write_survives_recovery_without_rebroadcast(self):
        request = candidate(self.profile, self.quote())
        self.authority.ambiguous = True
        _, result = self.service.handle("POST", "/v1/submit", submission(request, self.token))
        self.assertEqual(result["status"], "unknown")
        for _ in range(3):
            self.service.tick()
        self.assertEqual(len(self.authority.writes), 1)
        self.assertEqual(self.authority.prepares, 1)
        self.authority.outcome = "executed"
        self.service.tick()
        self.assertEqual(self.journal.get(request.identity)["state"], "executed")

    def test_reserved_only_expiry_cancellation_does_not_reuse_slot(self):
        request = candidate(self.profile, self.quote())
        self.journal.reserve(request, 10, 1000)
        self.now = 1101
        self.service.tick()
        self.assertEqual(self.journal.get(request.identity)["state"], "cancelled")
        self.assertEqual(
            self.journal.db.execute("SELECT value FROM metadata WHERE key='next_slot'").fetchone()[
                0
            ],
            "2",
        )
        self.assertEqual(self.authority.prepares, 0)

    def test_failed_prepare_is_not_automatically_signed_again(self):
        request = candidate(self.profile, self.quote())
        self.authority.bad_prepare = True
        self.assertEqual(
            self.service.handle("POST", "/v1/submit", submission(request, self.token))[0], 422
        )
        self.assertEqual(self.authority.prepares, 1)
        self.service.tick()
        self.service.handle("POST", "/v1/submit", submission(request, self.token))
        self.assertEqual(self.authority.prepares, 1)
        self.assertEqual(self.authority.writes, [])

    def test_status_cannot_supply_evidence_or_trigger_reconciliation(self):
        request = candidate(self.profile, self.quote())
        self.service.handle("POST", "/v1/submit", submission(request, self.token))
        self.authority.outcome = "executed"
        _, value = self.service.handle(
            "POST",
            "/v1/status",
            encode({"request_id": request.identity, "status_token": self.token}),
        )
        self.assertEqual(value["status"], "broadcast")
        for path in ("/v1/evidence", "/v1/reconcile", "/v1/retire", "/v1/admin"):
            self.assertEqual(self.service.handle("POST", path, b"{}")[0], 404)
        self.assertEqual(self.journal.get(request.identity)["state"], "broadcast")

    def test_busy_service_refuses_without_a_wait_queue(self):
        self.service._busy.acquire()
        try:
            self.assertEqual(self.service.handle("POST", "/v1/quote", b"{}")[0], 429)
        finally:
            self.service._busy.release()

    def test_unknown_and_unauthorized_status_are_indistinguishable(self):
        request = candidate(self.profile, self.quote())
        self.service.handle("POST", "/v1/submit", submission(request, self.token))
        result = self.service.handle(
            "POST",
            "/v1/status",
            encode({"request_id": request.identity, "status_token": "ab" * 32}),
        )
        missing = self.service.handle(
            "POST", "/v1/status", encode({"request_id": h(999), "status_token": self.token})
        )
        self.assertEqual(result, (404, {"error": "status_unavailable"}))
        self.assertEqual(result, missing)

    def test_health_recovers_only_after_capability_probe(self):
        with patch.object(
            self.authority, "check_capabilities", side_effect=RuntimeError("offline")
        ):
            self.assertEqual(self.service.tick(), {"processed": 0, "unavailable": 1})
        self.assertEqual(self.service.handle("GET", "/v1/health", b"")[0], 503)
        self.service.tick()
        self.assertEqual(self.service.handle("GET", "/v1/health", b"")[0], 200)

    def test_native_exceptions_are_not_reflected_into_responses(self):
        with patch.object(
            self.authority, "descriptor", side_effect=RuntimeError("SECRET/private/path")
        ):
            result = self.service.handle(
                "POST",
                "/v1/quote",
                encode({"slot": 2, "lifetime": 100, "status_token": self.token}),
            )
        self.assertEqual(result, (503, {"error": "backend_unavailable"}))
        self.assertNotIn("SECRET", json.dumps(result))


class HTTPTests(ServiceFixture):
    def setUp(self):
        super().setUp()
        self.server = RelayServer(self.service, ("127.0.0.1", 0))
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}
        )
        self.thread.start()

        def stop():
            self.server.shutdown()
            self.thread.join(timeout=2)
            self.server.server_close()

        self.addCleanup(stop)
        self.client = Client(
            f"http://127.0.0.1:{self.server.server_address[1]}",
            self.profile.scope,
            self.authority.verify_quote,
            allow_loopback=True,
            clock=lambda: self.now,
        )

    def test_modified_quote_object_is_reverified_before_submission(self):
        quote = self.client.quote(lifetime=100, token=self.token)
        request = candidate(
            self.profile, {"quote_id": quote.identity, "quote": {"terms": quote.terms}}
        )
        altered = dataclasses.replace(quote, terms={**quote.terms, "amount": 1})
        with patch.object(self.client, "_request") as transport:
            with self.assertRaisesRegex(ClientError, "not authenticated"):
                self.client.submit(request, altered)
            transport.assert_not_called()

    def test_bind_failure_releases_owner_lock(self):
        other = Journal(Path(self.tmp.name) / "other.sqlite", self.profile, require_quotes=True)
        self.addCleanup(other.close)
        service = Service(Engine(other, self.authority), fee=7, funding_cap=100)
        with self.assertRaises(OSError):
            RelayServer(service, self.server.server_address)
        replacement = RelayServer(service, ("127.0.0.1", 0))
        replacement.server_close()
        replacement.server_close()

    def test_real_http_client_quote_submit_status(self):
        quote = self.client.quote(lifetime=100, token=self.token)
        raw = {"quote_id": quote.identity, "quote": {"terms": quote.terms}}
        request = candidate(self.profile, raw)
        value = self.client.submit(request, quote)
        self.assertEqual(value["status"], "broadcast")
        self.assertEqual(self.client.status(request.identity, self.token)["status"], "broadcast")
        self.authority.outcome = "executed"
        self.service.tick()
        self.assertEqual(self.client.status(request.identity, self.token)["status"], "executed")

    def test_http_framing_and_body_bounds(self):
        for header in (
            b"Content-Length: 0\r\nContent-Length: 0\r\n",
            b"Content-Length: 0\r\nTransfer-Encoding: chunked\r\n",
            b"Content-Length: +0\r\n",
            b"Content-Length: 00\r\n",
            f"Content-Length: {BODY_LIMIT + 1}\r\n".encode(),
            b"Content-Length: 0\r\n Folded: no\r\n",
        ):
            with (
                self.subTest(header=header),
                socket.create_connection(self.server.server_address, timeout=2) as connection,
            ):
                connection.sendall(
                    b"POST /v1/submit HTTP/1.1\r\nHost: localhost\r\n" + header + b"\r\n"
                )
                start, _, _ = receive(connection, 4096, time.monotonic() + 2)
                self.assertTrue(start.startswith("HTTP/1.1 400"), start)
        self.assertEqual(self.authority.prepares, 0)

    def test_listener_never_binds_publicly(self):
        with self.assertRaisesRegex(Refused, "loopback"):
            RelayServer(self.service, ("0.0.0.0", 0))

    def test_same_journal_cannot_have_two_service_owners(self):
        with self.assertRaises(BlockingIOError):
            RelayServer(self.service, ("127.0.0.1", 0))

    def test_connections_are_bounded_before_thread_creation(self):
        connections = [
            socket.create_connection(self.server.server_address, timeout=2) for _ in range(4)
        ]
        try:
            for _ in range(100):
                if self.server._connections._value == 0:
                    break
                time.sleep(0.01)
            self.assertEqual(self.server._connections._value, 0)
            with socket.create_connection(self.server.server_address, timeout=2) as connection:
                start, _, _ = receive(connection, 4096, time.monotonic() + 2)
                self.assertTrue(start.startswith("HTTP/1.1 429"))
        finally:
            for connection in connections:
                connection.close()

    def test_client_has_no_automatic_submission_retry(self):
        quote = self.client.quote(lifetime=100, token=self.token)
        request = candidate(
            self.profile, {"quote_id": quote.identity, "quote": {"terms": quote.terms}}
        )
        with patch.object(
            self.client, "_request", side_effect=ClientError("response lost")
        ) as call:
            with self.assertRaises(SubmissionUnknown) as caught:
                self.client.submit(request, quote)
            self.assertEqual(call.call_count, 1)
            self.assertEqual(caught.exception.request_id, request.identity)

    def test_client_rejects_unverified_quotes_and_insecure_remote_origins(self):
        client = Client("https://example.invalid", self.profile.scope, None)
        with self.assertRaisesRegex(ClientError, "local pinned"):
            client.quote()
        for endpoint in (
            "http://example.invalid",
            "https://u:p@example.invalid",
            "https://example.invalid/evil",
            "https://example.invalid/#fragment",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(ClientError):
                Client(endpoint, self.profile.scope, self.authority.verify_quote)


class DeadlineTests(unittest.TestCase):
    def test_slow_header_has_one_deadline_not_per_byte_timeout(self):
        reader, writer = socket.socketpair()
        stop = threading.Event()

        def drip():
            try:
                while not stop.wait(0.02):
                    writer.sendall(b"x")
            except OSError:
                pass

        thread = threading.Thread(target=drip)
        thread.start()
        try:
            start = time.monotonic()
            with self.assertRaises((TimeoutError, HTTPRefused)):
                receive(reader, 1024, start + 0.15)
            self.assertLess(time.monotonic() - start, 1)
        finally:
            stop.set()
            reader.close()
            writer.close()
            thread.join(timeout=1)


if __name__ == "__main__":
    unittest.main()
