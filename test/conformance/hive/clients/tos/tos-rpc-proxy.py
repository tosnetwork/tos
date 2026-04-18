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
import json
import socketserver
import sys
import urllib.error
import urllib.request


# Methods that announce the chain identity. When --override-chain-id is set
# we short-circuit these locally with the override value rather than asking
# the upstream (which is hard-coded to 0x544f53 on the live testnet).
# Note: this only patches the announced chain id — receipts, txs, and other
# state from the upstream still belong to the real chain. That's fine for
# Hive's rpc-compat: the dominant failure class is "wrong chain id" and
# "no seeded state", and we cannot fix the latter from a proxy anyway.
_CHAIN_ID_METHODS = ("eth_chainId", "net_version")


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    upstream_url: str = ""
    ready_marker: str = ""
    override_chain_id: int | None = None  # set if Hive demands a non-default chain id
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

    def _maybe_override(self, body: bytes) -> bytes | None:
        """Return a synthesised JSON-RPC response when the request asks for
        chain identity AND --override-chain-id was passed, else None.

        Handles both single-call objects and JSON-RPC batches transparently
        so a Hive client doing `[eth_chainId, eth_blockNumber]` falls back
        to upstream for the latter half.
        """
        if ProxyHandler.override_chain_id is None:
            return None
        try:
            payload = json.loads(body or b"null")
        except json.JSONDecodeError:
            return None  # malformed; let upstream answer (it'll error)

        def make_one(call: dict) -> dict | None:
            method = call.get("method")
            req_id = call.get("id", None)
            if method == "eth_chainId":
                return {"jsonrpc": "2.0", "id": req_id,
                        "result": "0x%x" % ProxyHandler.override_chain_id}
            if method == "net_version":
                return {"jsonrpc": "2.0", "id": req_id,
                        "result": str(ProxyHandler.override_chain_id)}
            return None

        if isinstance(payload, dict):
            replaced = make_one(payload)
            return json.dumps(replaced).encode("utf-8") if replaced else None

        if isinstance(payload, list) and payload and \
                all(isinstance(c, dict) for c in payload) and \
                all(c.get("method") in _CHAIN_ID_METHODS for c in payload):
            # Whole-batch override only; mixed batches go upstream as-is so
            # we don't mis-order responses vs requests.
            return json.dumps([make_one(c) for c in payload]).encode("utf-8")

        return None

    def do_GET(self) -> None:
        # Hive only POSTs JSON-RPC, but a GET on /readyz / / is handy.
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"tos-rpc-proxy: ok\n")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length > 0 else b""

        override = self._maybe_override(body)
        if override is not None:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(override)))
            self.end_headers()
            self.wfile.write(override)
        else:
            status, response, ctype = self._forward(body)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        if not ProxyHandler._ready_logged and self.ready_marker:
            sys.stderr.write("[tos-rpc-proxy] %s\n" % self.ready_marker)
            ProxyHandler._ready_logged = True


def _parse_chain_id(s: str) -> int:
    """Accept "0x..." hex or decimal."""
    s = s.strip()
    if not s:
        raise ValueError("empty chain id")
    return int(s, 0)  # int's base=0 handles 0x / decimal


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--listen", required=True, help="bind addr, e.g. 0.0.0.0:8545")
    p.add_argument("--upstream", required=True, help="upstream addr, e.g. host.docker.internal:8011")
    p.add_argument("--ready-marker", default="", help="line to log on first request")
    p.add_argument(
        "--override-chain-id",
        default="",
        help=(
            "If set, eth_chainId / net_version are answered locally with "
            "this value (decimal or 0x-hex). Used by Hive when the spec's "
            "chain id (0xc72dd9d5e883e) differs from the upstream's "
            "(0x544f53)."
        ),
    )
    args = p.parse_args()

    host, port = args.listen.rsplit(":", 1)
    upstream = args.upstream
    if not upstream.startswith("http"):
        upstream = "http://" + upstream

    ProxyHandler.upstream_url = upstream
    ProxyHandler.ready_marker = args.ready_marker
    if args.override_chain_id:
        try:
            ProxyHandler.override_chain_id = _parse_chain_id(args.override_chain_id)
        except ValueError as e:
            sys.stderr.write("[tos-rpc-proxy] bad --override-chain-id %r: %s\n"
                             % (args.override_chain_id, e))
            return 2
        sys.stderr.write("[tos-rpc-proxy] chain id override: 0x%x (%d)\n"
                         % (ProxyHandler.override_chain_id,
                            ProxyHandler.override_chain_id))

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
