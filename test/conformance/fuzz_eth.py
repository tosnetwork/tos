#!/usr/bin/env python3
"""
Phase G.5 fuzz harness for the TOS EVM workchain RPC.

Probes `eth_sendRawTransaction` and `eth_call` with malformed inputs and
reports validator crashes, hangs, or error-response regressions.

Strategy:
  1. Build a seed corpus of 10 well-formed signed txs (legacy / EIP-2930 /
     EIP-1559 / EIP-4844 blob-stripped, various sizes) via a short ethers
     subprocess -- this is the only subprocess we spawn, and only once.
  2. Mutate each seed (bit-flip, byte-drop, byte-dup, truncate, junk
     prepend/append, chainId swap) and POST as eth_sendRawTransaction.
  3. Also fuzz eth_call with mutations of a valid call-object corpus.
  4. Classify each response:
       clean_error  -- JSON-RPC error with sensible code  (good)
       http_5xx     -- HTTP 500 from server               (yellow)
       timeout      -- urllib timeout                     (yellow; possible hang)
       node_death   -- connection refused OR async health failure (red; STOP)
  5. Every 100 mutations, run a health check (eth_chainId). If it fails we
     treat the preceding payload as having crashed the validator.
  6. Run for DURATION_SECONDS (default 300, i.e. 5 minutes).

Exit codes:
   0  -- completed with zero node_deaths
   1  -- testnet not reachable at startup, or seed generation failed
   2  -- detected a validator crash; payload is printed to stderr
"""

import collections
import json
import os
import random
import subprocess
import sys
import time
import urllib.error
import urllib.request

RPC = os.environ.get("RPC", "http://127.0.0.1:8011")
DURATION = int(os.environ.get("DURATION_SECONDS", "300"))
CHAIN_ID_HEX = "0x544f53"
HARDHAT_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
HARDHAT_ADDR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

# Seed generation uses ethers in a local subprocess. This directory is
# where ethers has been installed on dev hosts; override via ETHERS_DIR.
ETHERS_DIR = os.environ.get("ETHERS_DIR", "/home/tomi/openfox")


# -------------- RPC helpers --------------------------------------------------

def post(payload, timeout=5):
    """Return (kind, body) where kind is one of clean / http_5xx / timeout /
    refused / other."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        RPC, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as f:
            body = f.read()
            try:
                return "clean", json.loads(body)
            except Exception:
                return "other", body[:256]
    except urllib.error.HTTPError as e:
        code = e.code
        try:
            body = json.loads(e.read())
        except Exception:
            body = None
        if 500 <= code < 600:
            return "http_5xx", body
        return "clean", body or {"error": {"code": code}}
    except urllib.error.URLError as e:
        reason = str(e.reason).lower()
        if "refused" in reason or "reset" in reason or "broken pipe" in reason:
            return "refused", reason
        if "timed out" in reason or "timeout" in reason:
            return "timeout", reason
        return "other", reason
    except TimeoutError:
        return "timeout", "socket timeout"
    except Exception as e:
        return "other", str(e)


def health_check():
    """Return True iff the node responds to eth_chainId with expected value."""
    kind, body = post(
        {"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 0},
        timeout=5)
    if kind != "clean" or not isinstance(body, dict):
        return False
    return body.get("result") == CHAIN_ID_HEX


# -------------- Seed corpus --------------------------------------------------

SEED_GEN_JS = r"""
const { ethers } = require("ethers");
const key = process.env.KEY;
const chainId = BigInt(process.env.CHAIN_ID);
const w = new ethers.Wallet(key);

function code(n) {  // n bytes of deterministic junk EVM code
  const buf = Buffer.alloc(n);
  for (let i = 0; i < n; i++) buf[i] = (i * 13 + 7) & 0xff;
  return "0x" + buf.toString("hex");
}

const bases = [
  // legacy transfer
  { type: 0, nonce: 100, gasPrice: 1_000_000_000n, gasLimit: 21000n,
    to: "0x0000000000000000000000000000000000000001", value: 1n, data: "0x",
    chainId },
  // legacy contract deploy (~64 B code)
  { type: 0, nonce: 101, gasPrice: 1_000_000_000n, gasLimit: 400000n,
    value: 0n, data: code(64), chainId },
  // EIP-2930 transfer
  { type: 1, nonce: 102, gasPrice: 1_500_000_000n, gasLimit: 21000n,
    to: "0x0000000000000000000000000000000000000002", value: 2n, data: "0x",
    accessList: [], chainId },
  // EIP-2930 with access list entry
  { type: 1, nonce: 103, gasPrice: 1_500_000_000n, gasLimit: 50000n,
    to: "0x0000000000000000000000000000000000000003", value: 0n, data: "0x",
    accessList: [{ address: "0x0000000000000000000000000000000000000004",
                   storageKeys: ["0x" + "00".repeat(32)] }],
    chainId },
  // EIP-1559 transfer
  { type: 2, nonce: 104, maxFeePerGas: 2_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n, gasLimit: 21000n,
    to: "0x0000000000000000000000000000000000000005", value: 3n, data: "0x",
    chainId },
  // EIP-1559 contract deploy with ~1 KB code
  { type: 2, nonce: 105, maxFeePerGas: 2_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n, gasLimit: 2_000_000n,
    value: 0n, data: code(1024), chainId },
  // EIP-1559 contract deploy with ~4 KB code
  { type: 2, nonce: 106, maxFeePerGas: 2_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n, gasLimit: 8_000_000n,
    value: 0n, data: code(4096), chainId },
  // EIP-1559 with access list
  { type: 2, nonce: 107, maxFeePerGas: 2_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n, gasLimit: 100000n,
    to: "0x0000000000000000000000000000000000000006", value: 0n, data: "0xdeadbeef",
    accessList: [{ address: "0x0000000000000000000000000000000000000007",
                   storageKeys: [] }],
    chainId },
  // EIP-1559, max-gas transfer
  { type: 2, nonce: 108, maxFeePerGas: 50_000_000_000n,
    maxPriorityFeePerGas: 2_000_000_000n, gasLimit: 30_000_000n,
    to: "0x0000000000000000000000000000000000000008", value: 0n, data: "0x",
    chainId },
  // EIP-4844-shaped tx (blob tx) -- we sign it as EIP-1559 because our
  // devnet rejects blobs; this keeps the raw bytes realistic.
  { type: 2, nonce: 109, maxFeePerGas: 3_000_000_000n,
    maxPriorityFeePerGas: 1_000_000_000n, gasLimit: 200000n,
    to: "0x0000000000000000000000000000000000000009", value: 0n,
    data: code(256), chainId },
];

(async () => {
  const out = [];
  for (const tx of bases) out.push(await w.signTransaction(tx));
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(2); });
"""


def build_seed_corpus():
    """Run ethers in a subprocess to produce 10 valid signed tx hex strings."""
    env = dict(os.environ)
    env["KEY"] = HARDHAT_KEY
    env["CHAIN_ID"] = str(int(CHAIN_ID_HEX, 16))
    try:
        out = subprocess.check_output(
            ["node", "-e", SEED_GEN_JS],
            cwd=ETHERS_DIR, env=env, timeout=30)
        seeds = json.loads(out)
        assert isinstance(seeds, list) and len(seeds) == 10
        return seeds
    except Exception as e:
        sys.stderr.write(
            f"ERROR: failed to build seed corpus via ethers at {ETHERS_DIR}: {e}\n"
            f"  Set ETHERS_DIR to a directory where `node -e \"require('ethers')\"` works.\n")
        sys.exit(1)


# -------------- Mutation operators ------------------------------------------

def mut_bit_flip(b):
    if not b:
        return b
    i = random.randrange(len(b))
    bit = 1 << random.randrange(8)
    return b[:i] + bytes([b[i] ^ bit]) + b[i+1:]


def mut_byte_drop(b):
    if len(b) < 5:
        return b
    n = random.randint(1, 4)
    for _ in range(n):
        if len(b) <= 1:
            break
        i = random.randrange(len(b))
        b = b[:i] + b[i+1:]
    return b


def mut_byte_dup(b):
    if not b:
        return b
    n = random.randint(1, 4)
    for _ in range(n):
        i = random.randrange(len(b))
        b = b[:i] + bytes([b[i]]) + b[i:]
    return b


def mut_truncate(b):
    if len(b) < 2:
        return b
    k = random.randint(1, len(b) - 1)
    return b[:k]


def mut_junk_prepend(b):
    n = random.randint(1, 256)
    return random.randbytes(n) + b


def mut_junk_append(b):
    n = random.randint(1, 256)
    return b + random.randbytes(n)


# The tx-type byte on typed envelopes (0x01, 0x02, 0x03) lives at byte 0 for
# non-legacy. Swapping it produces a realistic but wrong envelope.
def mut_type_swap(b):
    if not b:
        return b
    if b[0] in (0x01, 0x02, 0x03):
        new = random.choice([0x00, 0x04, 0x7f])  # 0 = invalid envelope
        return bytes([new]) + b[1:]
    return mut_bit_flip(b)


# Scan for the chainId bytes (the testnet uses 0x544f53, a 3-byte value) and
# swap them for another plausible chainId.
_PLAUSIBLE_CHAINIDS = [b"\x01", b"\x05", b"\x89", b"\xaa\x36\xa7", b"\x27\x10"]


def mut_chainid_swap(b):
    target = b"\x54\x4f\x53"
    i = b.find(target)
    if i < 0:
        return mut_bit_flip(b)
    repl = random.choice(_PLAUSIBLE_CHAINIDS)
    return b[:i] + repl + b[i+len(target):]


TX_MUTATORS = [
    mut_bit_flip, mut_byte_drop, mut_byte_dup, mut_truncate,
    mut_junk_prepend, mut_junk_append, mut_type_swap, mut_chainid_swap,
]


def mutate_raw_tx(hex_str):
    raw = bytes.fromhex(hex_str[2:] if hex_str.startswith("0x") else hex_str)
    op = random.choice(TX_MUTATORS)
    mutated = op(raw)
    # occasionally stack two mutations
    if random.random() < 0.2:
        mutated = random.choice(TX_MUTATORS)(mutated)
    return "0x" + mutated.hex()


# -------------- eth_call corpus + mutation ----------------------------------

CALL_SEEDS = [
    {"from": HARDHAT_ADDR, "to": "0x0000000000000000000000000000000000000001",
     "gas": "0x5208", "value": "0x0", "data": "0x"},
    {"to": "0x0000000000000000000000000000000000000002",
     "data": "0x70a08231" + "00" * 12 + HARDHAT_ADDR[2:]},
    {"from": HARDHAT_ADDR, "to": "0x0000000000000000000000000000000000000004",
     "gasPrice": "0x3b9aca00", "value": "0x1", "data": "0xdeadbeef"},
    {"from": HARDHAT_ADDR, "to": HARDHAT_ADDR,
     "maxFeePerGas": "0x77359400", "maxPriorityFeePerGas": "0x3b9aca00",
     "gas": "0x186a0", "value": "0x0", "data": "0x" + "ab" * 128},
    {"to": "0x0000000000000000000000000000000000000006", "data": "0x" + "cd" * 2048},
]

JSON_WEIRD_VALUES = [
    None, True, False, 0, -1, 1, 2**63, 2**256, 1.5,
    "", "0x", "0xZZ", "0x" + "ff" * 65536,
    "not-hex", "0xgg", "0xdeadbeef" * 100,
    [], [1, 2], {}, {"nested": {"x": "y"}},
]

CALL_FIELDS = ["from", "to", "gas", "gasPrice", "value", "data", "input",
               "maxFeePerGas", "maxPriorityFeePerGas", "chainId", "type",
               "accessList", "nonce"]


def mutate_call_object(seed):
    obj = dict(seed)
    choice = random.random()
    if choice < 0.25:
        # replace a field with a weird value
        f = random.choice(CALL_FIELDS)
        obj[f] = random.choice(JSON_WEIRD_VALUES)
    elif choice < 0.45:
        # delete a random field
        if obj:
            del obj[random.choice(list(obj.keys()))]
    elif choice < 0.6:
        # inject an unexpected field
        obj["__fuzz_" + str(random.randrange(1000))] = random.choice(JSON_WEIRD_VALUES)
    elif choice < 0.75:
        # corrupt the data hex
        if "data" in obj and isinstance(obj["data"], str) and obj["data"].startswith("0x"):
            raw = bytes.fromhex(obj["data"][2:])
            if raw:
                op = random.choice(TX_MUTATORS)
                obj["data"] = "0x" + op(raw).hex()
        else:
            obj["data"] = random.choice(["0xZZ", "notahex", "0x" + "f" * 33])
    elif choice < 0.9:
        # swap an address field to garbage
        f = random.choice(["from", "to"])
        obj[f] = random.choice(["0x1", "0x" + "gg" * 20, "not-an-address", 42])
    else:
        # replace the whole object with something weird
        return random.choice(JSON_WEIRD_VALUES)
    return obj


# -------------- Classification + main loop ----------------------------------

def classify_rpc_error(body):
    """True if body looks like a well-formed JSON-RPC error."""
    if not isinstance(body, dict):
        return False
    err = body.get("error")
    if not isinstance(err, dict):
        # might be a success result -- unexpected for malformed input but fine
        return "result" in body
    return "code" in err


def run_fuzz(seed_txs, deadline):
    stats = {
        "raw_tx": {"attempts": 0, "clean_errors": 0, "http_5xx": 0,
                   "timeouts": 0, "node_deaths": 0, "other": 0, "accepted": 0},
        "call":   {"attempts": 0, "clean_errors": 0, "http_5xx": 0,
                   "timeouts": 0, "node_deaths": 0, "other": 0, "accepted": 0},
    }
    last_payload = None
    # Ring buffer of recent payloads so a post-mortem can replay the
    # preceding traffic to bisect which specific request triggered a crash.
    recent = collections.deque(maxlen=32)
    total_since_health = 0
    rpc_id = 1

    while time.time() < deadline:
        # Alternate between sendRawTransaction (~80%) and eth_call (~20%)
        is_call = random.random() < 0.2

        if is_call:
            seed = random.choice(CALL_SEEDS)
            obj = mutate_call_object(seed)
            params = [obj, random.choice(["latest", "earliest", "pending", "0x1",
                                          {"blockNumber": "0x1"}, None])]
            payload = {"jsonrpc": "2.0", "method": "eth_call",
                       "params": params, "id": rpc_id}
            key = "call"
        else:
            seed = random.choice(seed_txs)
            mutated = mutate_raw_tx(seed)
            payload = {"jsonrpc": "2.0", "method": "eth_sendRawTransaction",
                       "params": [mutated], "id": rpc_id}
            key = "raw_tx"

        rpc_id += 1
        stats[key]["attempts"] += 1
        last_payload = payload
        recent.append(payload)
        kind, body = post(payload, timeout=5)

        if kind == "clean":
            if classify_rpc_error(body):
                if isinstance(body, dict) and "result" in body:
                    stats[key]["accepted"] += 1
                else:
                    stats[key]["clean_errors"] += 1
            else:
                stats[key]["other"] += 1
        elif kind == "http_5xx":
            stats[key]["http_5xx"] += 1
        elif kind == "timeout":
            stats[key]["timeouts"] += 1
        elif kind == "refused":
            # Strong signal: node is down.
            sys.stderr.write("\n!!! CONNECTION REFUSED -- node may have died !!!\n")
            sys.stderr.write(f"offending payload: {json.dumps(payload)[:2000]}\n")
            sys.stderr.write(f"--- preceding {len(recent)} payloads (newest last) ---\n")
            for p in recent:
                sys.stderr.write(json.dumps(p)[:1000] + "\n")
            stats[key]["node_deaths"] += 1
            return stats, last_payload
        else:
            stats[key]["other"] += 1

        total_since_health += 1

        # Health check every 100 mutations.
        if total_since_health >= 100:
            total_since_health = 0
            ok = health_check()
            if not ok:
                # Give the node one follow-up probe with a longer timeout in case
                # it's just transiently loaded.
                time.sleep(1.0)
                ok = health_check()
            if not ok:
                sys.stderr.write(
                    "\n!!! HEALTH CHECK FAILED after mutation -- node may have died !!!\n")
                sys.stderr.write(f"last payload: {json.dumps(last_payload)[:2000]}\n")
                sys.stderr.write(f"--- preceding {len(recent)} payloads (newest last) ---\n")
                for p in recent:
                    sys.stderr.write(json.dumps(p)[:1000] + "\n")
                stats[key]["node_deaths"] += 1
                return stats, last_payload

            total = stats["raw_tx"]["attempts"] + stats["call"]["attempts"]
            remaining = max(0, int(deadline - time.time()))
            sys.stdout.write(
                f"[fuzz] {total:>6} muts | raw_tx clean={stats['raw_tx']['clean_errors']} "
                f"5xx={stats['raw_tx']['http_5xx']} to={stats['raw_tx']['timeouts']} "
                f"| call clean={stats['call']['clean_errors']} "
                f"5xx={stats['call']['http_5xx']} to={stats['call']['timeouts']} "
                f"| {remaining}s left\n")
            sys.stdout.flush()

    return stats, last_payload


def print_summary(stats, duration):
    sys.stdout.write("\n=== Phase G.5 fuzz summary ===\n")
    sys.stdout.write(f"duration: {duration}s\n")
    for method, label in [("raw_tx", "eth_sendRawTransaction"),
                          ("call",   "eth_call")]:
        s = stats[method]
        sys.stdout.write(f"{label} attempts: {s['attempts']}\n")
        sys.stdout.write(f"  clean_errors: {s['clean_errors']}\n")
        sys.stdout.write(f"  accepted:     {s['accepted']}\n")
        sys.stdout.write(f"  http_5xx:     {s['http_5xx']}\n")
        sys.stdout.write(f"  timeouts:     {s['timeouts']}\n")
        sys.stdout.write(f"  other:        {s['other']}\n")
        sys.stdout.write(f"  node_deaths:  {s['node_deaths']}\n")
    total_deaths = stats["raw_tx"]["node_deaths"] + stats["call"]["node_deaths"]
    verdict = "PASS" if total_deaths == 0 else "FAIL"
    sys.stdout.write(f"{verdict}\n")
    sys.stdout.flush()


def main():
    random.seed(os.environ.get("FUZZ_SEED", time.time()))

    # Pre-flight: is the testnet reachable?
    if not health_check():
        sys.stderr.write(
            f"ERROR: testnet RPC at {RPC} not reachable or wrong chainId.\n"
            f"  Expected eth_chainId={CHAIN_ID_HEX}. Bring up the testnet first.\n")
        return 1

    sys.stdout.write(f"[fuzz] RPC={RPC} duration={DURATION}s -- building seed corpus...\n")
    sys.stdout.flush()
    seeds = build_seed_corpus()
    sys.stdout.write(f"[fuzz] built {len(seeds)} seed txs (lengths: "
                     f"{[len(bytes.fromhex(s[2:])) for s in seeds]})\n")
    sys.stdout.flush()

    start = time.time()
    deadline = start + DURATION
    stats, last_payload = run_fuzz(seeds, deadline)
    actual = int(time.time() - start)
    print_summary(stats, actual)

    total_deaths = stats["raw_tx"]["node_deaths"] + stats["call"]["node_deaths"]
    if total_deaths > 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
