#!/usr/bin/env python3
"""
normalize-proxy.py — Blockscout-facing JSON-RPC compatibility shim for TOS.

Blockscout's `EthereumJSONRPC` library expects a strict JSON-RPC 2.0 wire
contract that the TOS validator does not yet fully honour. Two specific
gaps prevent the indexer from making any progress against TOS:

  P-6 BUG #1 — Error-object shape (spec violation):
    TOS sends      {"ok":false,"jsonrpc":"2.0","id":1,
                    "error":"<message string>","code":-32601}
    spec demands   {"jsonrpc":"2.0","id":1,
                    "error":{"code":-32601,"message":"<message string>"}}
    Blockscout's `standardize_error/1` only matches the spec form and
    raises `FunctionClauseError` on anything else, killing the indexer
    GenServer (Indexer.Block.Catchup.MissingRangesCollector).

  P-6 BUG #2 — Batch JSON-RPC unsupported:
    TOS replies to a batch (a JSON array request) with the single-error
    shape from BUG #1 plus message "Batch requests are not supported".
    Blockscout always batches its block-catchup fetch (10–50 calls per
    HTTP roundtrip) so this is a hard blocker, not a perf hint.

This proxy exists so the rest of P-6 can be exercised — it is NOT a
permanent fix. The real fix is to teach the TOS RPC server to honour
both, tracked in the BUG entries above. Run with --upstream pointed at
the validator and listen on a port the bridge-net containers can reach
via host-gateway.

Why stdlib-only:
  Matches the policy of test/conformance/hive/clients/tos/tos-rpc-proxy.py
  (no pip in container images for the conformance harness).
"""

from __future__ import annotations

import argparse
import json
import socketserver
import sys
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


# ---------------------------------------------------------------------------
# Shape normalisation
# ---------------------------------------------------------------------------

def _bump_method_counter(method: str | None, err_msg: str | None) -> None:
    if not method:
        return
    if err_msg is None:
        NormalizingHandler.method_ok[method] = (
            NormalizingHandler.method_ok.get(method, 0) + 1
        )
    else:
        per = NormalizingHandler.method_err.setdefault(method, {})
        per[err_msg] = per.get(err_msg, 0) + 1


def _normalize_response(resp: Any) -> Any:
    """Coerce a single TOS RPC response into JSON-RPC 2.0 spec shape.

    Tolerates the four shapes seen in TOS responses today:

      A. {"jsonrpc":"2.0","id":N,"result": ...}                  # already OK
      B. {"jsonrpc":"2.0","id":N,"error":{...}}                  # already OK
      C. {"ok":false,"jsonrpc":"2.0","id":N,
          "error":"<msg>","code":<int>}                          # BUG #1
      D. arrays / non-dicts                                      # pass through

    Returns the response with the `ok` key dropped and `error` reshaped
    when needed, leaving `result` payloads untouched.
    """
    if not isinstance(resp, dict):
        return resp

    out = {k: v for k, v in resp.items() if k != "ok"}
    err = out.get("error")

    # Case C: error is a bare string with a peer "code" int.
    if isinstance(err, str):
        code = out.pop("code", -32603)
        if not isinstance(code, int):
            try:
                code = int(code)
            except (TypeError, ValueError):
                code = -32603
        out["error"] = {"code": code, "message": err}

    return out


# ---------------------------------------------------------------------------
# Upstream forwarder
# ---------------------------------------------------------------------------

class Upstream:
    def __init__(self, url: str, timeout: float = 30.0) -> None:
        self.url = url
        self.timeout = timeout

    def call(self, payload: bytes) -> bytes:
        req = urllib.request.Request(
            self.url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            return exc.read() or b""
        except urllib.error.URLError as exc:
            return (
                b'{"jsonrpc":"2.0","id":null,"error":{"code":-32603,'
                b'"message":"upstream unreachable: '
                + str(exc).encode("utf-8", "replace")
                + b'"}}'
            )


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

class NormalizingHandler(BaseHTTPRequestHandler):
    upstream: Upstream = None  # type: ignore[assignment]
    fanout: ThreadPoolExecutor = None  # type: ignore[assignment]
    log_lock = threading.Lock()
    counter_lock = threading.Lock()
    counters: dict[str, int] = {
        "single": 0,
        "batch": 0,
        "fanned_calls": 0,
        "errors_normalized": 0,
    }
    # Per-method success / error counters (helps spot which RPC Blockscout
    # is hammering and which keep returning -32601 / etc.)
    method_ok: dict[str, int] = {}
    method_err: dict[str, dict[str, int]] = {}  # method -> {message: count}

    # Quieter than BaseHTTPRequestHandler's default per-line log.
    def log_message(self, fmt: str, *args) -> None:  # noqa: ANN001
        with NormalizingHandler.log_lock:
            sys.stderr.write("[normalize-proxy] " + (fmt % args) + "\n")

    def _send_json(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length > 0 else b""

        try:
            payload = json.loads(body or b"null")
        except json.JSONDecodeError:
            # Malformed; just forward and let upstream complain.
            raw = self.upstream.call(body)
            self._send_json(200, raw)
            return

        if isinstance(payload, list):
            # BUG #2 workaround: fan out into single requests.
            self._handle_batch(payload)
        elif isinstance(payload, dict):
            self._handle_single(payload)
        else:
            raw = self.upstream.call(body)
            self._send_json(200, raw)

    def _handle_single(self, call: dict) -> None:
        with NormalizingHandler.counter_lock:
            NormalizingHandler.counters["single"] += 1
        raw = self.upstream.call(json.dumps(call).encode("utf-8"))
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError:
            self._send_json(200, raw)
            return
        normalized = _normalize_response(decoded)
        method = call.get("method") if isinstance(call, dict) else None
        err_msg = None
        if isinstance(decoded, dict) and decoded.get("ok") is False:
            with NormalizingHandler.counter_lock:
                NormalizingHandler.counters["errors_normalized"] += 1
            err_msg = str(decoded.get("error"))[:120]
        elif isinstance(decoded, dict) and isinstance(decoded.get("error"), dict):
            err_msg = str(decoded["error"].get("message"))[:120]
        with NormalizingHandler.counter_lock:
            _bump_method_counter(method, err_msg)
        self._send_json(200, json.dumps(normalized).encode("utf-8"))

    def _handle_batch(self, calls: list) -> None:
        with NormalizingHandler.counter_lock:
            NormalizingHandler.counters["batch"] += 1
            NormalizingHandler.counters["fanned_calls"] += len(calls)

        def _one(call: Any) -> Any:
            if not isinstance(call, dict):
                return call
            raw = self.upstream.call(json.dumps(call).encode("utf-8"))
            try:
                decoded = json.loads(raw)
            except json.JSONDecodeError:
                return {"jsonrpc": "2.0", "id": call.get("id"),
                        "error": {"code": -32603,
                                  "message": "upstream returned non-json"}}
            method = call.get("method")
            err_msg = None
            if isinstance(decoded, dict) and decoded.get("ok") is False:
                with NormalizingHandler.counter_lock:
                    NormalizingHandler.counters["errors_normalized"] += 1
                err_msg = str(decoded.get("error"))[:120]
            elif isinstance(decoded, dict) and isinstance(decoded.get("error"), dict):
                err_msg = str(decoded["error"].get("message"))[:120]
            with NormalizingHandler.counter_lock:
                _bump_method_counter(method, err_msg)
            return _normalize_response(decoded)

        results = list(self.fanout.map(_one, calls))
        self._send_json(200, json.dumps(results).encode("utf-8"))


def _stats_dumper() -> None:
    """Periodically dump counter snapshots to stderr — useful for spotting
    which methods Blockscout is hammering and how many errors we coerced."""
    import time
    while True:
        time.sleep(15)
        with NormalizingHandler.counter_lock:
            snap = dict(NormalizingHandler.counters)
            method_ok = dict(NormalizingHandler.method_ok)
            method_err = {m: dict(d) for m, d in NormalizingHandler.method_err.items()}
        sys.stderr.write(
            "[normalize-proxy] stats single=%d batch=%d fanned_calls=%d "
            "errors_normalized=%d\n"
            % (snap["single"], snap["batch"], snap["fanned_calls"],
               snap["errors_normalized"])
        )
        if method_ok or method_err:
            sys.stderr.write("[normalize-proxy] per-method (ok / errors):\n")
            all_methods = sorted(set(method_ok) | set(method_err))
            for m in all_methods:
                ok = method_ok.get(m, 0)
                errs = method_err.get(m, {})
                err_total = sum(errs.values())
                if err_total == 0:
                    sys.stderr.write("  %-40s ok=%d\n" % (m, ok))
                else:
                    err_summary = ", ".join(
                        f'"{msg}"={cnt}' for msg, cnt in sorted(
                            errs.items(), key=lambda kv: -kv[1])[:3])
                    sys.stderr.write(
                        "  %-40s ok=%d err=%d [%s]\n"
                        % (m, ok, err_total, err_summary)
                    )
        sys.stderr.flush()


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--listen", default="0.0.0.0:9545",
                   help="host:port to listen on (default 0.0.0.0:9545)")
    p.add_argument("--upstream", required=True,
                   help="upstream RPC URL, e.g. http://127.0.0.1:18011")
    p.add_argument("--fanout-concurrency", type=int, default=16,
                   help="parallel single-call requests when splitting batches")
    args = p.parse_args()

    host, port_s = args.listen.rsplit(":", 1)
    port = int(port_s)

    NormalizingHandler.upstream = Upstream(args.upstream)
    NormalizingHandler.fanout = ThreadPoolExecutor(
        max_workers=args.fanout_concurrency,
        thread_name_prefix="normalize-fanout",
    )

    threading.Thread(target=_stats_dumper, daemon=True,
                     name="stats-dumper").start()

    sys.stderr.write(
        "[normalize-proxy] listening on %s:%d, upstream=%s, fanout=%d\n"
        % (host, port, args.upstream, args.fanout_concurrency)
    )
    sys.stderr.flush()

    server = ThreadingHTTPServer((host, port), NormalizingHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
