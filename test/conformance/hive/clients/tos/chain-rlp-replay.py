#!/usr/bin/env python3
"""
chain-rlp-replay.py — replay a Hive `chain.rlp` into a TOS RPC endpoint.

Hive's `rpc-compat` simulator drops a `/chain.rlp` file in the client
container. The file is a CONCATENATION of RLP-encoded geth-format blocks
(NOT a single outer list — see test/conformance/execution-apis/tests/chain.rlp
which is 45 top-level items totalling 54 KB). For each block we extract its
transactions and re-broadcast them via `eth_sendRawTransaction`, then poll
`eth_blockNumber` until the chain advances by one block.

Used by tos.cmd in the (TODO) single-validator-in-container mode after the
fresh chain comes up. For the proxy mode against the live testnet, this
script is **not** invoked because the txs are signed for chain id
`0xc72dd9d5e883e` and our live testnet uses `0x544f53` — every tx would be
rejected with bad signature, and we cannot rewrite the chain id without
re-signing (which requires the private key, which the spec doesn't ship).

Stdlib-only on purpose.

Usage:
    chain-rlp-replay.py --chain /chain.rlp --rpc http://127.0.0.1:8545 \\
                        [--expected-chain-id 0xc72dd9d5e883e] \\
                        [--start-block 1] [--max-block 99]

Exit codes:
    0  all txs broadcast OK and chain reached expected height
    1  RPC error (network / 5xx)
    2  one or more txs rejected (invalid signature / chain id mismatch /
       insufficient balance / ...)
    3  block production stalled (chain didn't advance after timeout)
    4  malformed chain.rlp
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request


# -----------------------------------------------------------------------------
# Minimal RLP decoder. Just enough to walk a list-of-blocks and extract the
# transactions array (block[1]).  Returns parsed nested Python lists/bytes.
# -----------------------------------------------------------------------------

def _decode_length(buf: bytes, off: int) -> tuple[int, int, int, str]:
    """Returns (payload_len, payload_start, item_end, kind) where kind is
    'item' (single byte / short string / long string) or 'list'."""
    b = buf[off]
    if b < 0x80:
        return 1, off, off + 1, "item"
    if b < 0xb8:
        l = b - 0x80
        return l, off + 1, off + 1 + l, "item"
    if b < 0xc0:
        n = b - 0xb7
        l = int.from_bytes(buf[off + 1: off + 1 + n], "big")
        return l, off + 1 + n, off + 1 + n + l, "item"
    if b < 0xf8:
        l = b - 0xc0
        return l, off + 1, off + 1 + l, "list"
    n = b - 0xf7
    l = int.from_bytes(buf[off + 1: off + 1 + n], "big")
    return l, off + 1 + n, off + 1 + n + l, "list"


def split_top_level_blocks(buf: bytes) -> list[bytes]:
    """A Hive chain.rlp is a concatenation of top-level RLP-encoded blocks.
    Walk the file at top level and return each block's raw bytes."""
    out: list[bytes] = []
    off = 0
    while off < len(buf):
        _, _, end, _ = _decode_length(buf, off)
        out.append(buf[off:end])
        off = end
    return out


def list_items(list_bytes: bytes) -> list[tuple[int, int]]:
    """Given the raw bytes of a single RLP list, return the (start, end)
    offsets of each child item (relative to list_bytes)."""
    plen, pstart, pend, kind = _decode_length(list_bytes, 0)
    if kind != "list":
        raise ValueError("not a list")
    items: list[tuple[int, int]] = []
    off = pstart
    while off < pend:
        _, _, end, _ = _decode_length(list_bytes, off)
        items.append((off, end))
        off = end
    return items


def block_txs_raw(block_bytes: bytes) -> list[bytes]:
    """A geth Block in RLP is [Header, Transactions, Uncles, Withdrawals?].
    Return each Transaction as its raw RLP bytes (suitable for direct
    eth_sendRawTransaction)."""
    items = list_items(block_bytes)
    if len(items) < 2:
        raise ValueError("block has no Transactions field")
    txs_off, txs_end = items[1]
    txs_list_bytes = block_bytes[txs_off:txs_end]
    plen, pstart, pend, kind = _decode_length(txs_list_bytes, 0)
    if kind != "list":
        raise ValueError("Transactions field is not a list")
    raw_txs: list[bytes] = []
    off = pstart
    while off < pend:
        _, _, end, _ = _decode_length(txs_list_bytes, off)
        raw_txs.append(txs_list_bytes[off:end])
        off = end
    return raw_txs


# -----------------------------------------------------------------------------
# JSON-RPC helpers
# -----------------------------------------------------------------------------

def rpc(url: str, method: str, params: list, *, req_id: int = 1, timeout: float = 30.0) -> dict:
    body = json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def rpc_block_number(url: str) -> int:
    r = rpc(url, "eth_blockNumber", [])
    return int(r["result"], 16)


def rpc_chain_id(url: str) -> int:
    r = rpc(url, "eth_chainId", [])
    return int(r["result"], 16)


def rpc_send_raw(url: str, raw_tx_hex: str) -> dict:
    return rpc(url, "eth_sendRawTransaction", [raw_tx_hex], timeout=60.0)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--chain", required=True, help="path to chain.rlp")
    p.add_argument("--rpc", required=True, help="JSON-RPC endpoint, eg http://127.0.0.1:8545")
    p.add_argument("--expected-chain-id", type=lambda s: int(s, 0), default=None,
                   help="Sanity-check upstream chain id matches this (decimal or 0x-hex).")
    p.add_argument("--start-block", type=int, default=0,
                   help=("Skip the first N entries in chain.rlp. Note: chain.rlp "
                         "in execution-apis starts at block 1 (genesis is "
                         "implicit), so the default 0 is correct."))
    p.add_argument("--max-block", type=int, default=None,
                   help="Stop after replaying up to this many blocks.")
    p.add_argument("--block-wait-secs", type=float, default=10.0,
                   help="Per-block timeout waiting for the chain to advance.")
    p.add_argument("--dry-run", action="store_true",
                   help="Decode and report tx counts without sending anything.")
    args = p.parse_args()

    try:
        data = open(args.chain, "rb").read()
    except OSError as e:
        sys.stderr.write(f"[chain-rlp-replay] cannot read chain.rlp: {e}\n")
        return 4

    try:
        blocks = split_top_level_blocks(data)
    except Exception as e:
        sys.stderr.write(f"[chain-rlp-replay] malformed chain.rlp: {e}\n")
        return 4
    sys.stderr.write(f"[chain-rlp-replay] decoded {len(blocks)} blocks "
                     f"({len(data)} bytes)\n")

    # Pre-decode all block tx lists so we can fail fast on shape errors.
    block_txs: list[list[bytes]] = []
    total_txs = 0
    for i, b in enumerate(blocks):
        try:
            txs = block_txs_raw(b)
        except Exception as e:
            sys.stderr.write(f"[chain-rlp-replay] block {i} malformed: {e}\n")
            return 4
        block_txs.append(txs)
        total_txs += len(txs)
    sys.stderr.write(f"[chain-rlp-replay] total {total_txs} transactions across "
                     f"{len(blocks)} blocks\n")

    if args.dry_run:
        for i, txs in enumerate(block_txs):
            sys.stderr.write(f"  block {i}: {len(txs)} tx(s)\n")
        return 0

    # Sanity check the upstream chain id.
    if args.expected_chain_id is not None:
        try:
            actual = rpc_chain_id(args.rpc)
        except Exception as e:
            sys.stderr.write(f"[chain-rlp-replay] cannot read chain id: {e}\n")
            return 1
        if actual != args.expected_chain_id:
            sys.stderr.write(
                f"[chain-rlp-replay] CHAIN ID MISMATCH — upstream={hex(actual)} "
                f"expected={hex(args.expected_chain_id)}.\n"
                f"All transactions in chain.rlp are signed with chain id "
                f"{hex(args.expected_chain_id)}; sending them to a chain "
                f"reporting {hex(actual)} will be rejected with bad signature. "
                f"Set TOS_EVM_CHAIN_ID before launching the validator.\n"
            )
            return 2

    # Replay each block: send all its txs, then wait for the chain to advance.
    rejected = 0
    last_block = args.max_block if args.max_block is not None else len(block_txs) - 1
    try:
        head_before = rpc_block_number(args.rpc)
    except Exception as e:
        sys.stderr.write(f"[chain-rlp-replay] cannot read eth_blockNumber: {e}\n")
        return 1

    sys.stderr.write(f"[chain-rlp-replay] head before replay: {head_before}\n")

    for i in range(args.start_block, last_block + 1):
        if i >= len(block_txs):
            break
        txs = block_txs[i]
        if not txs:
            sys.stderr.write(f"  block {i}: empty (skipping send)\n")
            continue
        sys.stderr.write(f"  block {i}: sending {len(txs)} tx(s)\n")
        for j, raw_tx in enumerate(txs):
            try:
                resp = rpc_send_raw(args.rpc, "0x" + raw_tx.hex())
                if "error" in resp:
                    sys.stderr.write(f"    tx {j}: REJECTED — {resp['error']}\n")
                    rejected += 1
                else:
                    sys.stderr.write(f"    tx {j}: ok hash={resp.get('result','?')}\n")
            except urllib.error.URLError as e:
                sys.stderr.write(f"    tx {j}: RPC error {e}\n")
                return 1

        # Wait for our collator to seal a new block before sending the next one.
        target = head_before + (i - args.start_block + 1)
        deadline = time.time() + args.block_wait_secs
        while time.time() < deadline:
            try:
                cur = rpc_block_number(args.rpc)
            except Exception:
                cur = None
            if cur is not None and cur >= target:
                break
            time.sleep(0.5)
        else:
            sys.stderr.write(f"  block {i}: chain stalled at {rpc_block_number(args.rpc)} "
                             f"(target {target})\n")
            return 3

    sys.stderr.write(f"[chain-rlp-replay] done. rejected={rejected}, "
                     f"final head={rpc_block_number(args.rpc)}\n")
    return 2 if rejected > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
