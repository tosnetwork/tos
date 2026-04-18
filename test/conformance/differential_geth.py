#!/usr/bin/env python3
"""
Differential RPC test: hit the same set of methods on our node and a
local geth dev chain, compare response shapes.

This is a *shape* check, not a value check. The two chains have
different chainIds (0x544f53 vs 0x539) and different state, so value
equality is impossible. But the JSON structure of the response should
match.

Any method where geth returns a populated object and we return null/[]
is usually a false positive (our chain lacks that block/tx), as
verified in the execution-apis conformance suite. We surface those
so a human can eyeball them.

Usage:
  python3 differential_geth.py
  OURS=http://127.0.0.1:8011 GETH=http://127.0.0.1:8545 python3 differential_geth.py
"""

import json
import os
import sys
import urllib.request

OURS = os.environ.get("OURS", "http://127.0.0.1:8011")
GETH = os.environ.get("GETH", "http://127.0.0.1:8545")


def post(url, payload, timeout=10):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as f:
            return json.loads(f.read())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read())
        except Exception:
            return {"__http_error__": str(e.code)}
    except Exception as e:
        return {"__transport_error__": str(e)}


def shape(v):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float"
    if isinstance(v, str):
        return "str"
    if isinstance(v, list):
        if not v:
            return "list[]"
        return f"list<{shape(v[0])}>"
    if isinstance(v, dict):
        return "{" + ",".join(f"{k}:{shape(val)}" for k, val in sorted(v.items())) + "}"
    return type(v).__name__


CASES = [
    # id, method, params, tolerate_empty (True = it's OK if ours is null / [])
    ("net_version", "net_version", [], False),
    ("web3_clientVersion", "web3_clientVersion", [], False),
    ("eth_chainId", "eth_chainId", [], False),
    ("eth_blockNumber", "eth_blockNumber", [], False),
    ("eth_gasPrice", "eth_gasPrice", [], False),
    ("eth_blobBaseFee", "eth_blobBaseFee", [], False),
    ("eth_maxPriorityFeePerGas", "eth_maxPriorityFeePerGas", [], False),
    ("eth_mining", "eth_mining", [], False),
    ("eth_syncing", "eth_syncing", [], False),
    ("eth_accounts", "eth_accounts", [], False),
    ("eth_getBalance_zero", "eth_getBalance", ["0x0000000000000000000000000000000000000000", "latest"], False),
    ("eth_getTransactionCount_zero", "eth_getTransactionCount", ["0x0000000000000000000000000000000000000000", "latest"], False),
    ("eth_getCode_zero", "eth_getCode", ["0x0000000000000000000000000000000000000000", "latest"], False),
    ("eth_getStorageAt_zero", "eth_getStorageAt",
     ["0x0000000000000000000000000000000000000000", "0x0", "latest"], False),
    ("eth_getBlockByNumber_latest", "eth_getBlockByNumber", ["latest", False], False),
    ("eth_getBlockByNumber_latest_full", "eth_getBlockByNumber", ["latest", True], False),
    ("eth_getBlockByNumber_earliest", "eth_getBlockByNumber", ["earliest", False], False),
    ("eth_getBlockTransactionCountByNumber_0", "eth_getBlockTransactionCountByNumber", ["0x0"], False),
    ("eth_feeHistory_5", "eth_feeHistory", ["0x5", "latest", [25, 50, 75]], False),
    ("eth_getLogs_empty", "eth_getLogs", [{"fromBlock": "0x0", "toBlock": "0x0"}], True),
    # eth_call against a zero address (empty code) — should return 0x on both
    ("eth_call_to_empty", "eth_call", [{"to": "0x0000000000000000000000000000000000000001", "data": "0x"}, "latest"], False),
    # eth_estimateGas a plain transfer
    ("eth_estimateGas_transfer", "eth_estimateGas",
     [{"from": "0x0000000000000000000000000000000000000001",
       "to": "0x0000000000000000000000000000000000000002",
       "value": "0x1"}], False),
    # eth_getProof for zero address with no slots
    ("eth_getProof_zero_empty", "eth_getProof", ["0x0000000000000000000000000000000000000000", [], "latest"], False),
    ("eth_getProof_zero_one_slot", "eth_getProof",
     ["0x0000000000000000000000000000000000000000", ["0x0"], "latest"], False),
    # eth_createAccessList
    ("eth_createAccessList_transfer", "eth_createAccessList",
     [{"from": "0x0000000000000000000000000000000000000001",
       "to": "0x0000000000000000000000000000000000000002"}], False),
]


def main():
    print(f"ours={OURS}  geth={GETH}")
    print()

    # Sanity
    r = post(OURS, {"jsonrpc": "2.0", "id": 0, "method": "eth_chainId"})
    if "result" not in r:
        print(f"OURS not responding: {r}", file=sys.stderr); return 2
    print(f"  ours chainId = {r['result']}")
    r = post(GETH, {"jsonrpc": "2.0", "id": 0, "method": "eth_chainId"})
    if "result" not in r:
        print(f"GETH not responding: {r}", file=sys.stderr); return 2
    print(f"  geth chainId = {r['result']}")
    print()

    ok = 0
    mismatch = 0
    rows = []
    for name, method, params, tolerate_empty in CASES:
        req = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ours = post(OURS, req)
        theirs = post(GETH, req)

        def classify(resp):
            if "__transport_error__" in resp or "__http_error__" in resp:
                return "TRANSPORT", str(resp)[:80]
            if "error" in resp:
                err = resp["error"]
                if isinstance(err, dict):
                    return "ERR", f"{err.get('code')}:{err.get('message','')[:60]}"
                return "ERR", str(err)[:80]
            return "OK", shape(resp.get("result"))

        o_status, o_info = classify(ours)
        t_status, t_info = classify(theirs)

        if o_status == t_status == "OK":
            # Both returned; compare shape
            if o_info == t_info:
                rows.append(("OK", name, method, None))
                ok += 1
            else:
                # Empty-on-ours is usually a false positive (our chain is mostly
                # empty). Flag but don't count as hard failure.
                if tolerate_empty and o_info in {"null", "list[]"}:
                    rows.append(("EMPTY_ON_OURS", name, method, None))
                    ok += 1
                else:
                    rows.append(("SHAPE_DIFF", name, method, f"ours={o_info}\n    geth={t_info}"))
                    mismatch += 1
        elif o_status == t_status:
            rows.append((f"BOTH_{o_status}", name, method, f"ours={o_info} / geth={t_info}"))
            ok += 1
        else:
            rows.append((f"DIVERGE", name, method, f"ours={o_status}({o_info}) / geth={t_status}({t_info})"))
            mismatch += 1

    print(f"{'status':<18} {'name':<40} method")
    print("-" * 100)
    for status, name, method, detail in rows:
        print(f"{status:<18} {name:<40} {method}")
        if detail:
            for line in detail.splitlines():
                print(f"    {line}")

    print()
    print(f"total: {ok + mismatch}, ok/emptyOK: {ok}, mismatches/diverges: {mismatch}")
    return 0 if mismatch == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
