#!/usr/bin/env python3
"""
tos-rpc-proxy.py — tiny JSON-RPC HTTP forwarder for the Hive proxy mode.

Used by tos.cmd when TOS_PROXY_UPSTREAM is set.  The Hive simulator hits us
on 127.0.0.1:8545; we forward each POST verbatim to the upstream TOS RPC
endpoint (the live testnet, typically reachable via host.docker.internal
or a hard-coded host IP).

Why this exists:
  The full single-node TOS bootstrap inside a fresh container is several
  engineer-days of work (zerostate generation, key gen, DHT bootstrapping,
  consensus topology).  The proxy mode lets us validate the Hive harness
  end-to-end against an existing TOS chain in the meantime.

Stdlib-only on purpose — keeps the runtime image small and avoids pip in
the Dockerfile.
"""

from __future__ import annotations

import argparse
import http.server
import socketserver
import sys
import urllib.error
import urllib.request


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    upstream_url: str = ""
    ready_marker: str = ""
    _ready_logged: bool = False

    def log_message(self, fmt: str, *args) -> None:  # noqa: ANN001
        # Quieter than the default per-request log.
        sys.stderr.write("[tos-rpc-proxy] %s\n" % (fmt % args))

    def _forward(self, body: bytes) -> tuple[int, bytes, str]:
        req = urllib.request.Request(
            self.upstream_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, resp.read(), resp.headers.get("Content-Type", "application/json")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read() or b"", exc.headers.get("Content-Type", "application/json")
        except urllib.error.URLError as exc:
            payload = (
                b'{"jsonrpc":"2.0","id":null,"error":{"code":-32603,'
                b'"message":"upstream unreachable: ' + str(exc).encode() + b'"}}'
            )
            return 502, payload, "application/json"

    def do_GET(self) -> None:
        # Hive only POSTs JSON-RPC, but a GET on /readyz / / is handy.
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"tos-rpc-proxy: ok\n")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length > 0 else b""
        status, response, ctype = self._forward(body)
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)
        if not ProxyHandler._ready_logged and self.ready_marker:
            sys.stderr.write("[tos-rpc-proxy] %s\n" % self.ready_marker)
            ProxyHandler._ready_logged = True


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--listen", required=True, help="bind addr, e.g. 0.0.0.0:8545")
    p.add_argument("--upstream", required=True, help="upstream addr, e.g. host.docker.internal:8011")
    p.add_argument("--ready-marker", default="", help="line to log on first request")
    args = p.parse_args()

    host, port = args.listen.rsplit(":", 1)
    upstream = args.upstream
    if not upstream.startswith("http"):
        upstream = "http://" + upstream

    ProxyHandler.upstream_url = upstream
    ProxyHandler.ready_marker = args.ready_marker

    sys.stderr.write(
        "[tos-rpc-proxy] listening on %s:%s -> %s\n" % (host, port, upstream)
    )
    # Log the ready marker before any request lands so Hive's TCP probe and
    # operator log-greppers both see it immediately.
    if args.ready_marker:
        sys.stderr.write("[tos-rpc-proxy] %s\n" % args.ready_marker)
        ProxyHandler._ready_logged = True

    # SO_REUSEADDR must be set as a class attribute before binding.
    class _Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    with _Server((host, int(port)), ProxyHandler) as srv:
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
