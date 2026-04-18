#!/usr/bin/env python3
"""
Manual sanity-test runner for RPC methods that the upstream
execution-apis conformance suite doesn't cover.

Reads every `.io` file under `manual-rpc/`, posts each request to our
RPC, and compares the response to the expected one.

File format (each line):
  // optional comment
  >> {request json}
  << {expected response json}

A file MAY contain multiple `>> / <<` pairs — we treat them as a
sequential chain. The token "${RESULT_N}" anywhere in a later request
expands to the JSON-encoded "result" of the Nth (0-indexed) prior step
in the same file. (For string results, that's the unquoted string;
e.g. a filter ID "0x1" becomes literally "0x1" inside the params.)

Comparison is shape+value-aware:
  - For deterministic methods (web3_sha3, etc.) the expected `result`
    is matched exactly.
  - For non-deterministic methods, we fall back to a structural shape
    fingerprint (same JSON types, same dict keys recursively).
  - "Determinism" is decided per-step: if the expected `result` is
    null, bool, list[], a fixed-position numeric like "0x0", or "true"
    (eth_uninstallFilter), exact match is required. Otherwise shape.

Each `.io` file passes if every step in it passes. The script exits 0
iff every file passes.
"""

import glob
import json
import os
import re
import sys
import urllib.request

RPC = os.environ.get("RPC", "http://127.0.0.1:8011")
ROOT = os.path.dirname(os.path.abspath(__file__))
TESTS_DIR = os.path.join(ROOT, "manual-rpc")

# Methods whose result must match the expected exactly.
EXACT_METHODS = {
    "eth_blobBaseFee",
    "eth_coinbase",
    "eth_protocolVersion",
    "eth_hashrate",
    "eth_getUncleCountByBlockHash",
    "eth_getUncleCountByBlockNumber",
    "eth_getUncleByBlockHashAndIndex",
    "eth_getUncleByBlockNumberAndIndex",
    "eth_getRawTransactionByHash",
    "web3_sha3",
    "net_listening",
    "eth_uninstallFilter",
    "eth_getFilterChanges",  # always [] on this idle chain
}

# Methods whose value drifts but shape is fixed.
SHAPE_METHODS = {
    "eth_maxPriorityFeePerGas",
    "web3_clientVersion",
    "net_peerCount",
    "eth_newFilter",
    "eth_newBlockFilter",
    "eth_newPendingTransactionFilter",
    # debug_getRaw* return chain-state-dependent RLP whose exact bytes
    # change every block; we only assert the response is a non-null hex
    # string (or list of them).
    "debug_getRawBlock",
    "debug_getRawHeader",
    "debug_getRawReceipts",
    "debug_getRawTransaction",
}


def post(payload, timeout=5):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        RPC, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as f:
            body = f.read()
            status = f.status
            # Batch responses (JSON arrays), HTTP 204 with empty body, and
            # all-notification batches all need to round-trip through this
            # function unscathed.  We always return a dict shape so the
            # comparator can inspect it uniformly.
            if not body:
                return {"__http_status__": status, "__empty_body__": True}
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                return {"__http_status__": status,
                        "__raw_body__": body.decode("utf-8", "replace")}
            if isinstance(parsed, list):
                # Batch response — wrap in a sentinel dict so callers know.
                return {"__http_status__": status, "__batch__": parsed}
            if isinstance(parsed, dict):
                parsed["__http_status__"] = status
                return parsed
            return {"__http_status__": status, "__raw_body__": parsed}
    except Exception as e:
        return {"__transport_error__": str(e)}


def parse_io(path):
    """Extract a list of (request, expected_response) steps from a `.io` file."""
    steps = []
    pending_req = None
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("//"):
                continue
            if line.startswith(">>"):
                pending_req = json.loads(line[2:].strip())
            elif line.startswith("<<"):
                resp = json.loads(line[2:].strip())
                if pending_req is None:
                    raise ValueError(f"{path}: << without preceding >>")
                # Wrap a raw list expected-response in the batch sentinel
                # so compare_step's batch path is taken.  Authors can also
                # write `{"__batch__": [...]}` explicitly if they want to
                # also assert on __http_status__.
                if isinstance(resp, list):
                    resp = {"__http_status__": 200, "__batch__": resp}
                steps.append((pending_req, resp))
                pending_req = None
    return steps


def shape(v):
    """Structural fingerprint: types only, recursive into dicts and lists."""
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


_PLACEHOLDER = re.compile(r"\$\{RESULT_(\d+)\}")


def substitute(obj, prior_results):
    """Recursively replace ${RESULT_N} tokens inside string values."""
    if isinstance(obj, str):
        def repl(m):
            i = int(m.group(1))
            if i >= len(prior_results):
                raise ValueError(f"unknown RESULT_{i}")
            v = prior_results[i]
            if isinstance(v, str):
                return v
            return json.dumps(v)
        return _PLACEHOLDER.sub(repl, obj)
    if isinstance(obj, list):
        return [substitute(x, prior_results) for x in obj]
    if isinstance(obj, dict):
        return {k: substitute(v, prior_results) for k, v in obj.items()}
    return obj


def compare_step(method, ours, expected):
    """Return (ok: bool, detail: str)."""
    if "__transport_error__" in ours:
        return False, f"transport error: {ours['__transport_error__']}"

    # Special: HTTP-status-only assertions (e.g. 204 No Content for an
    # all-notification batch).  When the expected payload includes
    # __http_status__ we match it against the actual status code rather
    # than against a JSON body.
    if "__http_status__" in expected:
        exp_status = expected["__http_status__"]
        our_status = ours.get("__http_status__")
        if our_status != exp_status:
            return False, f"HTTP status differs: ours={our_status} expected={exp_status}"
        if expected.get("__empty_body__"):
            if not ours.get("__empty_body__"):
                return False, f"expected empty body, got: {json.dumps(ours)[:200]}"
            return True, None
        # Fall through to normal comparison if more keys are set.

    # Special: batch (JSON array) response.  Compare element-by-element.
    if "__batch__" in expected:
        if "__batch__" not in ours:
            return False, f"expected batch (JSON array) response, got: {json.dumps(ours)[:200]}"
        ob, eb = ours["__batch__"], expected["__batch__"]
        if len(ob) != len(eb):
            return False, f"batch length differs: ours={len(ob)} expected={len(eb)}"
        for i, (o, e) in enumerate(zip(ob, eb)):
            ok, detail = compare_step(method, o, e)
            if not ok:
                return False, f"batch[{i}]: {detail}"
        return True, None

    if "error" in ours and "error" not in expected:
        return False, f"unexpected error: {ours['error']}"
    if "error" in expected and "error" not in ours:
        return False, "expected error, got result"
    if "error" in ours and "error" in expected:
        # Match error code if expected has one.
        oc = ours["error"].get("code") if isinstance(ours["error"], dict) else None
        ec = expected["error"].get("code") if isinstance(expected["error"], dict) else None
        if ec is not None and oc != ec:
            return False, f"error code differs: ours={oc} expected={ec}"
        return True, None
    if "result" not in ours:
        return False, f"malformed response: {json.dumps(ours)[:200]}"

    our_result = ours["result"]
    exp_result = expected["result"]

    if method in EXACT_METHODS:
        if our_result != exp_result:
            return False, (
                f"value mismatch for {method}\n"
                f"      ours={json.dumps(our_result)[:200]}\n"
                f"      expected={json.dumps(exp_result)[:200]}"
            )
        return True, None

    if method in SHAPE_METHODS:
        os_ = shape(our_result)
        es_ = shape(exp_result)
        if os_ != es_:
            return False, f"shape mismatch for {method}: ours={os_} expected={es_}"
        return True, None

    # Default to exact comparison for any unclassified method.
    if our_result != exp_result:
        return False, (
            f"unclassified method {method}, default exact compare failed\n"
            f"      ours={json.dumps(our_result)[:200]}\n"
            f"      expected={json.dumps(exp_result)[:200]}"
        )
    return True, None


def run_file(path):
    """Run all steps in a single .io file. Returns (ok, [(method, ok, detail)])."""
    steps = parse_io(path)
    if not steps:
        return False, [("<empty>", False, "no >>/<< steps parsed")]
    prior_results = []
    rows = []
    file_ok = True
    for req, expected in steps:
        req = substitute(req, prior_results)
        if isinstance(req, list):
            # Batch — synthesize a method label from the first element.
            method = "batch:" + ",".join(
                e.get("method", "<none>") if isinstance(e, dict) else "<non-obj>"
                for e in req[:3])
            if len(req) > 3:
                method += "..."
        else:
            method = req.get("method", "<none>")
        ours = post(req)
        ok, detail = compare_step(method, ours, expected)
        rows.append((method, ok, detail))
        if not ok:
            file_ok = False
            # Don't keep chaining if a step blew up — later RESULT_N
            # references would be meaningless.
            prior_results.append(None)
        else:
            prior_results.append(ours.get("result"))
    return file_ok, rows


def main():
    io_files = sorted(glob.glob(os.path.join(TESTS_DIR, "*", "*.io")))
    if not io_files:
        print(f"no .io files found under {TESTS_DIR}", file=sys.stderr)
        return 1

    # Sanity-check RPC is up.
    r = post({"jsonrpc": "2.0", "id": 0, "method": "eth_chainId"})
    if "result" not in r:
        print(f"RPC sanity check failed at {RPC}: {r}", file=sys.stderr)
        return 2
    print(f"RPC alive at {RPC}, chainId={r['result']}")
    print()

    total = 0
    passed = 0
    failed = 0
    fail_details = []

    for io in io_files:
        rel = os.path.relpath(io, ROOT)
        total += 1
        try:
            file_ok, rows = run_file(io)
        except Exception as e:
            file_ok = False
            rows = [("<parse>", False, f"exception: {e}")]
        if file_ok:
            passed += 1
            method = rows[0][0] if rows else "<none>"
            extra = f" ({len(rows)} steps)" if len(rows) > 1 else ""
            print(f"PASS  {rel:<60} [{method}{extra}]")
        else:
            failed += 1
            print(f"FAIL  {rel}")
            for method, ok, detail in rows:
                marker = "  ok " if ok else "  !! "
                print(f"{marker}{method}: {detail if detail else ''}")
            fail_details.append(rel)

    print()
    print(f"total: {total}   pass: {passed}   fail: {failed}")
    if failed:
        print()
        print("failed files:")
        for r in fail_details:
            print(f"  - {r}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
