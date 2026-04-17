#!/usr/bin/env python3
"""
execution-apis conformance runner for the TOS EVM workchain.

Reads every `.io` file under `execution-apis/tests/`, posts the request
to our RPC, and classifies the response:

  - METHOD_NOT_FOUND  — RPC method doesn't exist on our node (hard fail)
  - SHAPE_OK          — our response has the same top-level shape as the
                        official expected response (same JSON schema
                        family: `error` vs `result`, same top-level keys
                        if result is an object, etc.). Values obviously
                        diverge because our chain state is not the test
                        suite's seeded chain.
  - SHAPE_MISMATCH    — success on both sides but result shape differs
                        (missing fields, extra fields, type skew)
  - BOTH_ERROR        — both responses are errors; the tests file itself
                        expected an error. Usually a pass.
  - OUR_ERROR         — our node returned an error where the spec
                        expected a result. Needs investigation.
  - SPEC_ERROR        — spec expected an error but we returned a result.
                        Often OK if the spec expected "block not found"
                        and we happen to have a block at that height;
                        worth recording separately.

Since we can't match actual values (different chainId/genesis/state),
this is a *method + schema* conformance check, not a replay check.
"""

import glob
import json
import os
import sys
import urllib.request
from collections import defaultdict

RPC = os.environ.get("RPC", "http://127.0.0.1:8011")
ROOT = os.path.dirname(os.path.abspath(__file__))
TESTS_DIR = os.path.join(ROOT, "execution-apis", "tests")


def post(payload, timeout=5):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        RPC, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as f:
            return json.loads(f.read())
    except Exception as e:
        return {"__transport_error__": str(e)}


def parse_io(path):
    """Extract (request, expected_response) from a `.io` file."""
    req, resp = None, None
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith(">>"):
                req = json.loads(line[2:].strip())
            elif line.startswith("<<"):
                resp = json.loads(line[2:].strip())
    return req, resp


def shape(v):
    """Structural fingerprint: types only, not values."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, str):
        return "str"
    if isinstance(v, list):
        if not v:
            return "list[]"
        return f"list<{shape(v[0])}>"
    if isinstance(v, dict):
        return "{" + ",".join(f"{k}:{shape(val)}" for k, val in sorted(v.items())) + "}"
    return type(v).__name__


def compare(ours, theirs):
    """Return (status, detail)."""
    if "__transport_error__" in ours:
        return "TRANSPORT_ERROR", ours["__transport_error__"]
    our_err = "error" in ours
    their_err = "error" in theirs

    # Method-not-found on our side
    if our_err:
        code = ours["error"].get("code")
        msg = ours["error"].get("message", "")
        if code == -32601 or "method not found" in msg.lower() or "unsupported" in msg.lower() or "unknown method" in msg.lower():
            return "METHOD_NOT_FOUND", msg
        if their_err:
            return "BOTH_ERROR", f"ours={msg}, spec-error"
        return "OUR_ERROR", msg

    if their_err:
        return "SPEC_ERROR", "we returned result, spec expected error"

    # Both succeeded — compare shape
    if "result" not in ours:
        return "MALFORMED", json.dumps(ours)[:200]

    our_shape = shape(ours["result"])
    their_shape = shape(theirs["result"])
    if our_shape == their_shape:
        return "SHAPE_OK", None
    return "SHAPE_MISMATCH", f"ours={our_shape[:300]}\n    spec={their_shape[:300]}"


def main():
    io_files = sorted(glob.glob(os.path.join(TESTS_DIR, "*", "*.io")))
    if not io_files:
        print("no .io files found", file=sys.stderr)
        return 1

    # Sanity-check RPC is up
    r = post({"jsonrpc": "2.0", "id": 0, "method": "eth_chainId"})
    if "result" not in r:
        print(f"RPC sanity check failed at {RPC}: {r}", file=sys.stderr)
        return 2
    print(f"RPC alive, chainId={r['result']}")

    by_method = defaultdict(lambda: defaultdict(int))
    details = defaultdict(list)
    total = 0

    # Known crashers — skip unless SKIP_CRASHERS=0 is in the env.
    # See CONFORMANCE-FINDINGS.md for the bug each file flags.
    crashers = set()
    if os.environ.get("SKIP_CRASHERS", "1") != "0":
        crashers.add("execution-apis/tests/eth_sendRawTransaction/send-access-list-transaction.io")
        crashers.add("execution-apis/tests/eth_sendRawTransaction/send-blob-tx.io")
        crashers.add("execution-apis/tests/eth_sendRawTransaction/send-dynamic-fee-access-list-transaction.io")
        crashers.add("execution-apis/tests/eth_sendRawTransaction/send-dynamic-fee-transaction.io")
        crashers.add("execution-apis/tests/eth_sendRawTransaction/send-legacy-transaction.io")

    for io in io_files:
        rel = os.path.relpath(io, ROOT)
        if rel in crashers:
            by_method[parse_io(io)[0].get("method", "<none>")]["SKIPPED_CRASHER"] += 1
            continue
        req, expected = parse_io(io)
        if req is None or expected is None:
            continue
        method = req.get("method", "<none>")
        # strip our id, reuse request's
        ours = post(req)
        status, detail = compare(ours, expected)
        by_method[method][status] += 1
        details[(method, status)].append((os.path.relpath(io, ROOT), detail))
        total += 1

    print()
    print(f"total tests: {total}")
    print()
    print(f"{'METHOD':<48} {'OK':>4} {'MISMATCH':>8} {'MNF':>4} {'OUR_ERR':>7} {'SPEC_ERR':>8} {'BOTH_ERR':>8} {'OTHER':>5}")
    print("-" * 100)

    methods_with_mnf = []
    methods_with_shape_mismatch = []
    methods_with_our_err = []
    for method in sorted(by_method):
        s = by_method[method]
        ok = s["SHAPE_OK"]
        mm = s["SHAPE_MISMATCH"]
        mnf = s["METHOD_NOT_FOUND"]
        oe = s["OUR_ERROR"]
        se = s["SPEC_ERROR"]
        be = s["BOTH_ERROR"]
        other = sum(s[k] for k in s if k not in {"SHAPE_OK", "SHAPE_MISMATCH", "METHOD_NOT_FOUND", "OUR_ERROR", "SPEC_ERROR", "BOTH_ERROR"})
        print(f"{method:<48} {ok:>4} {mm:>8} {mnf:>4} {oe:>7} {se:>8} {be:>8} {other:>5}")
        if mnf > 0:
            methods_with_mnf.append(method)
        if mm > 0:
            methods_with_shape_mismatch.append(method)
        if oe > 0:
            methods_with_our_err.append(method)

    print()
    print(f"methods with METHOD_NOT_FOUND ({len(methods_with_mnf)}):")
    for m in methods_with_mnf:
        print(f"  - {m}")
    print()
    print(f"methods with SHAPE_MISMATCH ({len(methods_with_shape_mismatch)}):")
    for m in methods_with_shape_mismatch:
        for path, detail in details[(m, "SHAPE_MISMATCH")][:1]:
            print(f"  - {m} ({path})")
            print(f"      {detail}")
    print()
    print(f"methods with OUR_ERROR ({len(methods_with_our_err)}):")
    for m in methods_with_our_err:
        for path, detail in details[(m, "OUR_ERROR")][:1]:
            print(f"  - {m}: {detail[:120]}")

    # Any OTHER statuses
    other_statuses = set()
    for method, sts in by_method.items():
        for k in sts:
            if k not in {"SHAPE_OK", "SHAPE_MISMATCH", "METHOD_NOT_FOUND", "OUR_ERROR", "SPEC_ERROR", "BOTH_ERROR"}:
                other_statuses.add(k)
    if other_statuses:
        print()
        print(f"uncategorized statuses encountered: {other_statuses}")
        for s in other_statuses:
            print(f"  {s}:")
            for (m, st), rows in details.items():
                if st == s:
                    for path, detail in rows[:1]:
                        print(f"    - {m} ({path}): {str(detail)[:120]}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
