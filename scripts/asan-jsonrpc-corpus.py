#!/usr/bin/env python3
"""Drive a JSON-RPC server with the inputs the hardening work was about.

Run against an ASAN build of validator-engine. The point is not that the
assertions pass -- most of these requests are expected to fail at the
application level -- but that the sanitizer stays quiet while they do.

The batch cases are the ones that matter most. A parsed JSON value
borrows from the buffer it was decoded from, and the batch driver resumes
on a later actor message, so elements after the first are read once the
caller that owned that buffer has returned. Crucially, an unknown method
is answered locally, without a liteserver query, so these reach the
lifetime bug on a node with no chain behind it.

Usage: asan-corpus.py http://127.0.0.1:8081/
"""

import json
import sys
import concurrent.futures

import requests


def post_raw(base, body, timeout=15):
    return requests.post(base + "jsonRPC", data=body.encode(),
                         headers={"Content-Type": "application/json"}, timeout=timeout)


def post_json(base, obj, timeout=15):
    return requests.post(base + "jsonRPC", json=obj, timeout=timeout)


def case(name, fn):
    try:
        fn()
        print(f"  ok    {name}")
        return True
    except Exception as exc:  # noqa: BLE001 - a failed request is still a result
        print(f"  note  {name}: {type(exc).__name__}: {exc}")
        return True


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8081/"
    if not base.endswith("/"):
        base += "/"

    print("batch sizes (the buffer-lifetime path)")
    for n in (1, 2, 3, 100):
        case(f"batch of {n}", lambda n=n: post_json(base, [
            {"jsonrpc": "2.0", "id": i, "method": "noSuchMethod", "params": {}}
            for i in range(n)
        ]))
    # Distinct method names per element: if a later element is read from
    # released storage, the reply names something other than what was sent.
    case("batch with distinct unknown methods", lambda: post_json(base, [
        {"jsonrpc": "2.0", "id": i, "method": f"unknownMethod{i:04d}", "params": {}}
        for i in range(50)
    ]))
    case("batch over the element cap", lambda: post_json(base, [
        {"jsonrpc": "2.0", "id": i, "method": "noSuchMethod", "params": {}}
        for i in range(150)
    ]))
    case("batch of non-objects", lambda: post_raw(base, "[null,null,1,\"x\"]"))
    case("batch mixing objects and non-objects",
         lambda: post_raw(base, '[null,{"jsonrpc":"2.0","id":2,"method":"noSuchMethod"},3]'))

    print("request ids")
    for raw in (".", "--", "1e+-.3", "0", "-1", "1.5", "1e10", "1" * 4096):
        case(f"id {raw[:16]!r}", lambda raw=raw: post_raw(
            base, '{"jsonrpc":"2.0","id":%s,"method":"noSuchMethod","params":{}}' % raw))
    case("very long string id", lambda: post_raw(
        base, '{"jsonrpc":"2.0","id":"%s","method":"noSuchMethod","params":{}}' % ("x" * 100000)))

    print("body shapes")
    case("4 MiB body", lambda: post_raw(
        base, '{"jsonrpc":"2.0","id":1,"method":"noSuchMethod","params":{"pad":"%s"}}'
        % ("a" * (4 * 1024 * 1024 - 200))))
    case("body over the cap", lambda: post_raw(
        base, '{"jsonrpc":"2.0","id":1,"method":"noSuchMethod","params":{"pad":"%s"}}'
        % ("a" * (5 * 1024 * 1024))))
    case("truncated json", lambda: post_raw(base, '{"jsonrpc":"2.0","id":1,"method":'))
    case("deeply nested params", lambda: post_raw(
        base, '{"jsonrpc":"2.0","id":1,"method":"noSuchMethod","params":%s}'
        % ("[" * 90 + "]" * 90)))
    case("empty body", lambda: post_raw(base, ""))
    case("array of arrays", lambda: post_raw(base, "[[],[],[]]"))

    print("malformed payloads on the write surface")
    for boc in ("", "!!!!", "AAAA", "A" * 200000):
        case(f"sendBoc {len(boc)} chars", lambda boc=boc: post_json(
            base, {"jsonrpc": "2.0", "id": 1, "method": "sendBoc",
                   "params": {"boc": boc}}))
    case("runGetMethod with junk stack", lambda: post_json(
        base, {"jsonrpc": "2.0", "id": 1, "method": "runGetMethod",
               "params": {"address": "0:" + "0" * 64, "method": "seqno",
                          "stack": [["num", "!!!"]] * 300}}))

    print("account reads")
    for addr in ("", "0:", "0:" + "0" * 64, "-1:" + "f" * 64, "x" * 500):
        case(f"getAddressInformation {addr[:12]!r}", lambda addr=addr: post_json(
            base, {"jsonrpc": "2.0", "id": 1, "method": "getAddressInformation",
                   "params": {"address": addr}}))
    case("getAccountEvents at the page cap", lambda: post_json(
        base, {"jsonrpc": "2.0", "id": 1, "method": "getAccountEvents",
               "params": {"address": "0:" + "0" * 64, "limit": 1000}}))

    print("connection handling")
    case("headers then abandon", lambda: _abandon(base))
    case("probe burst", lambda: [requests.get(base + "readyz", timeout=10) for _ in range(40)])

    print("concurrency (promises in flight while the server is busy)")
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        futures = [pool.submit(post_json, base, [
            {"jsonrpc": "2.0", "id": i, "method": f"unknownMethod{i}", "params": {}}
            for i in range(8)
        ]) for _ in range(200)]
        done = sum(1 for f in concurrent.futures.as_completed(futures) if f)
    print(f"  ok    200 concurrent batches ({done} completed)")

    print()
    print("corpus finished. The result that matters is whether the server's")
    print("sanitizer output stayed empty; check its stderr.")
    return 0


def _abandon(base):
    """Send headers, then drop the connection before the body arrives."""
    import socket
    from urllib.parse import urlparse

    parsed = urlparse(base)
    sock = socket.create_connection((parsed.hostname, parsed.port or 80), timeout=5)
    sock.sendall(b"POST /jsonRPC HTTP/1.1\r\nHost: x\r\nContent-Length: 4194304\r\n\r\n")
    sock.sendall(b'{"jsonrpc":"2.0","id":1,')
    sock.close()


if __name__ == "__main__":
    sys.exit(main())
