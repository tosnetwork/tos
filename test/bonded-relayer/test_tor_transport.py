"""Real sockets and journals; SOCKS and signing peers here are explicit test doubles."""

import contextlib
import io
import json
import socket
import socketserver
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/bonded-relayer"))
from _service_fixture import candidate  # noqa: E402
from native_process import NativeRPC  # noqa: E402
from relay_client import Client, ClientError, SubmissionUnknown  # noqa: E402
from relay_core import Refused  # noqa: E402
from relay_http import receive, respond  # noqa: E402
from relay_service import RelayServer  # noqa: E402
from test_relay_service import ServiceFixture  # noqa: E402
from tor_transport import OnionEndpoint, TorProxy  # noqa: E402

ONION = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"
ORIGIN = "http://" + ONION


def read_exact(sock, count):
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise EOFError("test peer disconnected")
        result.extend(part)
    return bytes(result)


class SocksPeer(socketserver.ThreadingTCPServer):
    """Test-only SOCKS server forwarding to a fixed local BR1 listener."""

    daemon_threads = False

    def __init__(self, target):
        self.target = target
        self.credentials, self.targets, self.paths, self.errors = [], [], [], []
        self.method = b"\x05\x02"
        self.auth = b"\x01\x00"
        self.reply = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        self.drop_submit = self.redirect = False
        super().__init__(("127.0.0.1", 0), SocksHandler)

    def handle_error(self, request, client_address):
        self.errors.append(sys.exception())


class SocksHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            if read_exact(self.request, 3) != b"\x05\x01\x02":
                raise AssertionError("client did not require SOCKS authentication")
            self.request.sendall(self.server.method)
            if self.server.method != b"\x05\x02":
                return
            if read_exact(self.request, 1) != b"\x01":
                raise AssertionError("wrong authentication version")
            user = read_exact(self.request, read_exact(self.request, 1)[0])
            password = read_exact(self.request, read_exact(self.request, 1)[0])
            self.server.credentials.append((user, password))
            self.request.sendall(self.server.auth)
            if self.server.auth != b"\x01\x00":
                return
            if read_exact(self.request, 4) != b"\x05\x01\x00\x03":
                raise AssertionError("client resolved destination instead of sending domain")
            host = read_exact(self.request, read_exact(self.request, 1)[0])
            port = int.from_bytes(read_exact(self.request, 2), "big")
            self.server.targets.append((host.decode(), port))
            # Fragment replies to exercise exact framing, including the bound address.
            for byte in self.server.reply:
                self.request.sendall(bytes([byte]))
            if self.server.reply[:3] != b"\x05\x00\x00" or self.server.reply[3] not in (1, 3, 4):
                return
            start, headers, body = receive(self.request, 512 * 1024, time.monotonic() + 3)
            self.server.paths.append(start.split(" ")[1])
            if self.server.redirect:
                self.request.sendall(
                    b"HTTP/1.1 302 Found\r\nLocation: https://example.invalid\r\nContent-Length: 0\r\n\r\n"
                )
                return
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with upstream:
                upstream.settimeout(3)
                upstream.connect(self.server.target)
                wire = (
                    start + "\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
                )
                upstream.sendall(wire.encode() + body)
                line, _, result = receive(upstream, 65536, time.monotonic() + 3)
            if self.server.drop_submit and start.startswith("POST /v1/submit "):
                return
            respond(self.request, int(line.split(" ")[1]), json.loads(result), time.monotonic() + 3)
        except (EOFError, BrokenPipeError, ConnectionResetError):
            pass


def start_server(test, server):
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()

    def close():
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        test.assertFalse(thread.is_alive())

    test.addCleanup(close)


class OnionEncodingTests(unittest.TestCase):
    def test_canonical_v3_origin_and_checksum(self):
        self.assertEqual(OnionEndpoint.parse(ORIGIN).authority, ONION)
        self.assertEqual(OnionEndpoint.parse(ORIGIN + ":8080").port, 8080)
        for bad in (
            ORIGIN + "/",
            ORIGIN + ":80",
            ORIGIN + ":080",
            ORIGIN + ":65536",
            ORIGIN + "?",
            ORIGIN + "#",
            ORIGIN.replace("http:", "https:"),
            ORIGIN.upper(),
            "http://user@" + ONION,
            "http://example.com",
            "http://127.0.0.1",
            "http://" + "a" * 56 + ".onion",
            "http://" + ONION[:-7] + "a.onion",
            ORIGIN + "\n",
            "\t" + ORIGIN,
        ):
            with self.subTest(bad=bad), self.assertRaises(Refused):
                OnionEndpoint.parse(bad)

    def test_proxy_port_is_local_and_bounded(self):
        for port in (0, 80, 65536, True, "9050"):
            with self.subTest(port=port), self.assertRaises(Refused):
                TorProxy(port)


class OnionHTTPTests(ServiceFixture):
    def setUp(self):
        super().setUp()
        self.server = RelayServer(self.service, ("127.0.0.1", 0), onion_endpoint=ORIGIN)
        start_server(self, self.server)
        self.socks = SocksPeer(self.server.server_address)
        start_server(self, self.socks)
        self.proxy = TorProxy(self.socks.server_address[1])
        self.client = Client(
            ORIGIN,
            self.profile.scope,
            self.authority.verify_quote,
            tor=self.proxy,
            timeout=3,
            clock=lambda: self.now,
        )

    def request(self):
        quote = self.client.quote(token=self.token)
        req = candidate(self.profile, {"quote_id": quote.identity, "quote": {"terms": quote.terms}})
        return quote, req

    def test_quote_submit_status_use_only_socks_no_dns_or_environment_proxy(self):
        with (
            patch("socket.getaddrinfo", side_effect=AssertionError("DNS leak")),
            patch.dict(
                "os.environ",
                {"HTTP_PROXY": "http://example.invalid", "ALL_PROXY": "http://example.invalid"},
            ),
        ):
            quote, req = self.request()
            self.assertEqual(quote.terms["valid_until"] - self.now, 300)
            self.assertEqual(self.client.submit(req, quote)["status"], "broadcast")
            self.assertEqual(self.client.status(req.identity, self.token)["status"], "broadcast")
        self.assertEqual(self.socks.targets, [(ONION, 80)] * 3)
        self.assertEqual(self.authority.prepares, 1)
        self.assertEqual(len(self.authority.writes), 1)
        self.assertEqual(self.socks.errors, [])

    def test_isolation_is_stable_for_session_and_distinct_for_another(self):
        self.client.quote()
        self.client.quote()
        other = Client(
            ORIGIN,
            self.profile.scope,
            self.authority.verify_quote,
            tor=TorProxy(self.proxy.port),
            clock=lambda: self.now,
        )
        other.quote()
        first, second, third = self.socks.credentials
        self.assertEqual(first, second)
        self.assertNotEqual(first, third)
        self.assertNotIn(self.token.encode(), first)

    def test_no_method_downgrade_auth_failure_or_connect_failure_fallback(self):
        for field, value, expected_targets in (
            ("method", b"\x05\x00", 0),
            ("auth", b"\x01\x01", 0),
            ("reply", b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00", 1),
            ("reply", b"\x05\x00\x00\x09", 1),
        ):
            with self.subTest(field=field, value=value):
                old = getattr(self.socks, field)
                setattr(self.socks, field, value)
                count = len(self.socks.targets)
                try:
                    with patch(
                        "socket.create_connection", side_effect=AssertionError("direct fallback")
                    ):
                        with self.assertRaisesRegex(ClientError, "response unavailable"):
                            self.client.quote()
                    self.assertEqual(len(self.socks.targets) - count, expected_targets)
                finally:
                    setattr(self.socks, field, old)
        self.assertEqual(self.authority.prepares, 0)

    def test_authentication_downgrade_has_specific_refusal(self):
        self.socks.method = b"\x05\x00"
        with self.assertRaisesRegex(Refused, "isolation authentication required"):
            self.proxy.connect(OnionEndpoint.parse(ORIGIN), time.monotonic() + 2)
        self.assertEqual(self.socks.targets, [])

    def test_wallet_factory_uses_local_authenticated_bond_endpoint(self):
        rpc = Mock(spec=NativeRPC)
        identity = {
            "scope": self.profile.scope,
            "endpoint": ORIGIN,
            "worker_key_hash": self.profile.worker_key_hash,
        }
        rpc.call.return_value = identity
        client = Client.from_bond(self.profile, b"public-test-init", rpc, tor=self.proxy)
        self.assertEqual(client.onion.origin, ORIGIN)
        self.assertEqual(rpc.call.call_args.args[0], "client_identity")
        self.assertEqual(rpc.call.call_args.args[1]["release"]["bond"], self.profile.bond)
        # Exercise the callback through quote(), so it must authenticate actual terms.
        client.clock = lambda: self.now
        rpc.call.side_effect = lambda operation, payload: {
            "terms": self.authority.verify_quote(json.dumps(payload["envelope"]).encode())
        }
        quote = client.quote(token=self.token)
        self.assertEqual(quote.terms["amount"], 7)
        self.assertEqual(rpc.call.call_args.args[0], "client_quote")
        for changed in (
            {**identity, "scope": "aa" * 32},
            {**identity, "worker_key_hash": "aa" * 32},
            {**identity, "endpoint": "https://example.invalid"},
        ):
            rpc.call.side_effect = None
            rpc.call.return_value = changed
            with self.assertRaises(Refused):
                Client.from_bond(self.profile, b"public-test-init", rpc, tor=self.proxy)
        self.assertEqual(len(self.socks.targets), 1)
        with self.assertRaisesRegex(ClientError, "pinned local native"):
            Client.from_bond(self.profile, b"public-test-init", object(), tor=self.proxy)

    def test_socks_ipv6_and_domain_bound_reply_are_consumed(self):
        for reply in (b"\x05\x00\x00\x04" + b"\x00" * 18, b"\x05\x00\x00\x03\x03abc\x00\x00"):
            self.socks.reply = reply
            self.assertEqual(self.client.quote().terms["amount"], 7)

    def test_unavailable_tor_never_opens_direct_destination(self):
        with (
            patch("socket.socket.connect", side_effect=ConnectionRefusedError),
            patch("socket.create_connection", side_effect=AssertionError("direct fallback")),
        ):
            with self.assertRaisesRegex(ClientError, "response unavailable"):
                self.client.quote()
        self.assertEqual(self.socks.targets, [])

    def test_onion_cannot_be_used_without_tor_or_with_loopback_mode(self):
        for endpoint, kwargs in (
            (ORIGIN, {}),
            (ORIGIN.replace("http:", "https:"), {}),
            # A fully qualified name keeps its trailing dot in urlparse's hostname, so a
            # suffix test on ".onion" alone would let the OS resolver look the name up.
            (ORIGIN.replace("http:", "https:").replace(".onion", ".onion."), {}),
            (ORIGIN, {"tor": self.proxy, "allow_loopback": True}),
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(ClientError):
                Client(endpoint, self.profile.scope, self.authority.verify_quote, **kwargs)

    def test_redirect_is_refused_without_following_location(self):
        self.socks.redirect = True
        with self.assertRaises(ClientError):
            self.client.quote()
        self.assertEqual(len(self.socks.targets), 1)
        self.assertEqual(self.authority.prepares, 0)

    def test_lost_submit_reply_reconciles_original_without_resigning(self):
        quote, req = self.request()
        self.socks.drop_submit = True
        with self.assertRaises(SubmissionUnknown) as caught:
            self.client.submit(req, quote)
        self.assertEqual(caught.exception.request_id, req.identity)
        self.assertEqual(self.client.status(req.identity, self.token)["status"], "broadcast")
        self.assertEqual(self.socks.paths.count("/v1/submit"), 1)
        self.assertEqual(self.authority.prepares, 1)
        self.assertEqual(len(self.authority.writes), 1)

    def test_host_pin_refuses_before_quote_allocation_and_does_not_log(self):
        output = io.StringIO()
        with (
            contextlib.redirect_stderr(output),
            socket.create_connection(self.server.server_address) as sock,
        ):
            sock.sendall(
                b"POST /v1/quote HTTP/1.1\r\nHost: wrong.onion\r\nContent-Length: 0\r\n\r\n"
            )
            start, _, _ = receive(sock, 4096, time.monotonic() + 2)
        self.assertEqual(start, "HTTP/1.1 400 Bad Request")
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(self.journal.db.execute("SELECT COUNT(*) FROM quotes").fetchone()[0], 0)
        self.assertEqual(self.server.read_timeout, 30)
        self.assertEqual(self.server.write_timeout, 10)

    def test_onion_connection_cap_still_refuses_fifth_connection(self):
        sockets = [socket.create_connection(self.server.server_address) for _ in range(4)]
        try:
            deadline = time.monotonic() + 2
            while self.server._connections._value and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(self.server._connections._value, 0)
            with socket.create_connection(self.server.server_address) as sock:
                start, _, _ = receive(sock, 4096, time.monotonic() + 2)
            self.assertEqual(start, "HTTP/1.1 429 Too Many Requests")
        finally:
            for sock in sockets:
                sock.close()


class SocksDeadlineTests(unittest.TestCase):
    def test_one_deadline_across_fragmented_socks_handshake(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        self.addCleanup(listener.close)
        stop = threading.Event()

        def peer():
            with listener.accept()[0] as sock:
                read_exact(sock, 3)
                sock.sendall(b"\x05")
                stop.wait(1)

        thread = threading.Thread(target=peer)
        thread.start()
        start = time.monotonic()
        try:
            with self.assertRaises(TimeoutError):
                TorProxy(listener.getsockname()[1]).connect(
                    OnionEndpoint.parse(ORIGIN), start + 0.1
                )
            self.assertLess(time.monotonic() - start, 0.8)
        finally:
            stop.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
