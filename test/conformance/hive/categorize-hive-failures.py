#!/usr/bin/env python3
"""
Categorize each Hive rpc-compat failure into one of:
  CHAIN_STATE — spec expects block/tx/contract that doesn't exist on our chain
  MISSING_METHOD — we return -32601 / Method not found (unimplemented)
  BLOB_TYPE3 — request involves blob (type-3) tx (we reject by design pre-Cancun)
  TRANSPORT — HTTP error / network
  REAL_BUG — anything else (warrants investigation)
"""
import json, os, re, subprocess, sys, time, urllib.request

RPC = os.environ.get("RPC", "http://127.0.0.1:8011")
TESTS_ROOT = "test/conformance/execution-apis/tests"

def post(req, retry=3):
    data = json.dumps(req).encode()
    for attempt in range(retry):
        rq = urllib.request.Request(RPC, data=data, headers={"Content-Type":"application/json"})
        try:
            with urllib.request.urlopen(rq, timeout=10) as f:
                resp = json.loads(f.read())
            # Back off on rate-limit
            err = resp.get("error") if isinstance(resp, dict) else None
            if err and err.get("code") == -32005:
                time.sleep(0.5 * (attempt + 1))
                continue
            time.sleep(0.05)  # gentle throttle between requests
            return resp
        except Exception as e:
            time.sleep(0.5 * (attempt + 1))
            if attempt == retry - 1:
                return {"__transport__": str(e)}
    return {"__transport__": "rate-limited after retries"}

def parse_io(p):
    req = exp = None
    with open(p) as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith(">>"): req = json.loads(line[2:].strip())
            elif line.startswith("<<"): exp = json.loads(line[2:].strip())
    return req, exp

def categorize(req, exp, ours):
    method = req.get("method", "")
    params = req.get("params", []) or []
    if "__transport__" in ours:
        return "TRANSPORT", ours["__transport__"][:80]
    err = ours.get("error")
    if err:
        msg = (err.get("message") or "").lower()
        code = err.get("code")
        if code == -32601:
            return "MISSING_METHOD", method
        # eth_sendRawTransaction with spec chainId
        if "invalid chain id" in msg:
            return "CHAIN_STATE_CHAINID", f"signed with spec chainId, our chainId differs"
        # eth_simulateV1 block-numbers-must-be-in-order: our head is post-spec-end
        if "block numbers must be in order" in msg:
            return "CHAIN_STATE_HEAD", f"our head exceeds simulated block number"
        if code == -32005:
            return "RATE_LIMIT", "transient — retry the test"
        # gas fee error or similar: treat as REAL_BUG
        return "REAL_BUG", f"{method}: error code {code} msg={msg[:100]}"
    if "blob" in method.lower():
        return "BLOB_TYPE3", method
    # eth_chainId / eth_blockNumber: scalar values, but chain-divergent
    if method == "eth_chainId":
        return "CHAIN_STATE_CHAINID", f"spec={exp.get('result')} ours={ours.get('result')}"
    if method == "eth_blockNumber":
        return "CHAIN_STATE_HEAD", f"spec={exp.get('result')} ours={ours.get('result')}"
    # eth_getBlockByNumber latest/safe/finalized: chain-divergent
    if method == "eth_getBlockByNumber" and params and isinstance(params[0], str) and params[0] in ("latest", "safe", "finalized", "pending", "earliest"):
        # spec has different chain head with different content
        return "CHAIN_STATE_HEAD_BLOCK", f"chain heads diverge: spec block != ours"
    # eth_getBlockReceipts latest/safe/etc.
    if method == "eth_getBlockReceipts" and params and isinstance(params[0], str) and params[0] in ("latest", "safe", "finalized", "earliest", "pending"):
        return "CHAIN_STATE_HEAD_BLOCK", f"chain heads diverge: spec block != ours"
    # eth_getLogs querying spec contract addresses
    if method == "eth_getLogs":
        spec_logs = exp.get("result") if exp else None
        our_logs = ours.get("result")
        if isinstance(spec_logs, list) and spec_logs and isinstance(our_logs, list) and not our_logs:
            return "CHAIN_STATE_ADDR", f"spec has logs from contracts we don't host; we return []"
    # eth_simulateV1 with spec contracts deploying via stateOverrides
    if method == "eth_simulateV1":
        # spec result and our result both succeed but content differs heavily — chain state
        return "CHAIN_STATE_SIMV1", f"sim against spec-seeded chain vs ours"
    # Look for spec block/tx hashes in params
    def is_spec_hash(s):
        if not isinstance(s, str): return False
        if not s.startswith("0x"): return False
        if len(s) != 66: return False
        # Real on-chain hash (block or tx) — check if our chain has it
        return True
    # Check param 0 for a 32-byte hash (block hash or tx hash)
    if params and is_spec_hash(params[0]):
        target = params[0]
        # Try eth_getBlockByHash and eth_getTransactionByHash
        for probe_method in ["eth_getBlockByHash", "eth_getTransactionByHash"]:
            r = post({"jsonrpc":"2.0","id":99,"method":probe_method,"params":[target,False] if probe_method=="eth_getBlockByHash" else [target]})
            if r.get("result") not in (None, "null"):
                return "REAL_BUG", f"{method}: hash {target[:18]}... exists on our chain but fixture failed"
        return "CHAIN_STATE_HASH", f"hash {target[:18]}... not on our chain"
    # Check for a block-number param like "0x4" / "0x5" (small spec block)
    if params and isinstance(params[0], str) and re.match(r"^0x[0-9a-fA-F]{1,4}$", params[0]):
        bn = int(params[0], 16)
        # Query eth_getBlockByNumber to see if we have it
        r = post({"jsonrpc":"2.0","id":99,"method":"eth_getBlockByNumber","params":[params[0], False]})
        bh = (r.get("result") or {}).get("hash") if isinstance(r.get("result"), dict) else None
        # Our placeholder for unknown blocks is all-zeros
        if bh is None or bh == "0x" + "0"*64:
            return "CHAIN_STATE_BN", f"block {params[0]} (= {bn}) not on our chain"
    # Check for contract address in params (debug_storageRange, eth_call to spec contracts)
    addr_re = re.compile(r"0x[0-9a-fA-F]{40}")
    for p in params:
        if isinstance(p, dict) and "to" in p and isinstance(p["to"], str):
            r = post({"jsonrpc":"2.0","id":99,"method":"eth_getCode","params":[p["to"],"latest"]})
            code = r.get("result", "0x")
            if code == "0x" or code == "":
                return "CHAIN_STATE_ADDR", f"contract {p['to'][:18]}... has no code on our chain"
        if isinstance(p, str) and addr_re.fullmatch(p):
            r = post({"jsonrpc":"2.0","id":99,"method":"eth_getCode","params":[p,"latest"]})
            code = r.get("result", "0x")
            if code == "0x" or code == "":
                return "CHAIN_STATE_ADDR", f"contract {p[:18]}... has no code on our chain"
    # Default: needs investigation
    return "REAL_BUG", f"{method}: spec={json.dumps(exp.get('result'))[:80] if exp else '?'} ours={json.dumps(ours.get('result',ours.get('error')))[:80]}"

def main():
    # Read failure list from /tmp/hive-run.log
    failures = []
    with open("/tmp/hive-run.log") as f:
        for line in f:
            m = re.match(r"^  FAIL (\S+)", line)
            if m:
                failures.append(m.group(1))
    # Dedup keeping first occurrence
    seen = set()
    failures = [f for f in failures if not (f in seen or seen.add(f))]
    print(f"# {len(failures)} unique failing fixtures")

    cats = {}
    samples = {}
    for fx in failures:
        path = os.path.join(TESTS_ROOT, fx + ".io")
        if not os.path.exists(path):
            cats.setdefault("PARSE_ERROR", 0)
            cats["PARSE_ERROR"] += 1
            samples.setdefault("PARSE_ERROR", []).append(fx)
            continue
        req, exp = parse_io(path)
        if req is None:
            cats.setdefault("PARSE_ERROR", 0)
            cats["PARSE_ERROR"] += 1
            samples.setdefault("PARSE_ERROR", []).append(fx)
            continue
        ours = post(req)
        cat, detail = categorize(req, exp, ours)
        cats.setdefault(cat, 0)
        cats[cat] += 1
        samples.setdefault(cat, []).append((fx, detail))

    print("\n## Category counts")
    for cat in sorted(cats.keys(), key=lambda k: -cats[k]):
        print(f"  {cat:24} {cats[cat]:4d}")

    print("\n## Sample (up to 10 per category)")
    for cat in sorted(cats.keys()):
        print(f"\n### {cat} ({cats[cat]} total)")
        for entry in samples[cat][:10]:
            if isinstance(entry, tuple):
                print(f"  - {entry[0]:60} {entry[1]}")
            else:
                print(f"  - {entry}")

    # Report all REAL_BUGs in full detail
    if "REAL_BUG" in samples:
        print(f"\n## REAL_BUG full list ({cats['REAL_BUG']} entries)")
        for entry in samples["REAL_BUG"]:
            print(f"  - {entry[0]}: {entry[1]}")

if __name__ == "__main__":
    main()
