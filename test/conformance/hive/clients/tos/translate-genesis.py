#!/usr/bin/env python3
# =============================================================================
# translate-genesis.py — Hive `/genesis.json` -> Fift include for tos-create-state
# =============================================================================
#
# Reads a geth-format Hive `/genesis.json` (the file the simulator drops into
# the container before launch) and emits two artifacts the container
# bootstrap consumes:
#
#   1. /tmp/chain_id.txt    — decimal chain id. Production validators ignore
#                              TOS_EVM_CHAIN_ID; devnet-only validator builds
#                              may opt into that env override for Hive.
#
#   2. /tmp/genesis-alloc.fif — Fift include file that pushes a tuple-of-
#                                tuples onto the stack and calls
#                                `evm-zerostate-from-alloc`. The result is a
#                                ShardAccounts cell suitable to be wrapped
#                                into the wc=1 ShardState.
#
# Each allocation is encoded as a 5-tuple matching the C++ word's contract
# (see `interpret_evm_zerostate_from_alloc` in crypto/block/create-state.cpp):
#
#   ( addr_int, balance_int, nonce_int, code_bytes, storage_pairs_tuple )
#
# Stdlib only. No third-party deps. Runs on Python 3.10+.
#
# Usage:
#   translate-genesis.py [--genesis /genesis.json] [--out-fif /tmp/genesis-alloc.fif]
#                        [--out-chain-id /tmp/chain_id.txt]
#                        [--print-summary]
#
# Exit codes:
#   0  ok
#   1  malformed genesis.json
#   2  missing required fields (chainId, alloc)
#
# Hive genesis.json shape (subset):
#   {
#     "config": {"chainId": 0xc72dd9d5e883e, ... },
#     "alloc": {
#       "<20-hex-addr>": {
#         "balance": "0x<hex>" | "<dec>",
#         "nonce":   "0x<hex>" | "<dec>",          (optional)
#         "code":    "0x<hex>",                    (optional)
#         "storage": { "0x<32-hex>": "0x<32-hex>" } (optional)
#       }
#     }
#   }
#
# Reference implementation: ethereum/hive/simulators/ethereum/rpc-compat/main.go
# and the geth Genesis JSON parser at github.com/ethereum/go-ethereum/core/genesis.go.
# =============================================================================

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def parse_int_field(v: Any, *, name: str) -> int:
    """Accept hex (0x...), decimal string, or int.  Returns non-negative int."""
    if v is None:
        return 0
    if isinstance(v, int):
        if v < 0:
            raise ValueError(f"{name}: negative not allowed ({v})")
        return v
    if not isinstance(v, str):
        raise ValueError(f"{name}: expected string or int, got {type(v).__name__}")
    s = v.strip()
    if not s:
        return 0
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s, 10)
    except ValueError as e:
        raise ValueError(f"{name}: cannot parse {v!r} as int") from e


def parse_hex_bytes(v: Any, *, name: str) -> bytes:
    """Accept '0x...' or plain hex string.  Returns raw bytes (possibly empty)."""
    if v is None:
        return b""
    if not isinstance(v, str):
        raise ValueError(f"{name}: expected hex string, got {type(v).__name__}")
    s = v.strip()
    if not s:
        return b""
    if s.lower().startswith("0x"):
        s = s[2:]
    if len(s) % 2 != 0:
        s = "0" + s  # tolerate odd-length hex strings
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise ValueError(f"{name}: invalid hex {v!r}") from e


def parse_address(addr: str) -> int:
    """Parse a 20-byte EVM address (with or without 0x prefix) as an int."""
    s = addr.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    if len(s) != 40:
        raise ValueError(f"address {addr!r} is not 20 bytes (40 hex chars)")
    try:
        return int(s, 16)
    except ValueError as e:
        raise ValueError(f"address {addr!r} is not valid hex") from e


def emit_fift_bytes(b: bytes) -> str:
    """Render `bytes` as a Fift expression that produces an equivalent Bytes
    value on the stack. Empty -> `B{}`; otherwise `"<hex>" x>B`.

    `B{}` is the literal Fift bytes constant (zero length); for non-empty
    we go via the hex string + `x>B` (defined in fift/words.cpp:3144). This
    avoids the `B{...}` literal form whose grammar varies across Fift
    forks; the string-based path is exactly what `crypto/smartcont/auto/`
    uses for embedded byte blobs.
    """
    if not b:
        return "B{}"
    return f'"{b.hex()}" x>B'


def emit_fift_storage_pairs(storage: dict[str, str]) -> str:
    """Render a {slot_hex: value_hex} dict as a Fift expression that produces
    a tuple of [slot:int, value:int] 2-tuples.  Empty dict -> `0 tuple`.

    Slots are sorted by integer value so the output is deterministic across
    Python dict iteration orders (CPython preserves insertion order, but
    test fixtures may scramble the JSON; sorting keeps cell hashes stable).
    """
    pairs: list[tuple[int, int]] = []
    for slot_str, val_str in storage.items():
        slot = parse_int_field(slot_str, name=f"storage[{slot_str}].key")
        val = parse_int_field(val_str, name=f"storage[{slot_str}].value")
        pairs.append((slot, val))
    pairs.sort(key=lambda kv: kv[0])

    if not pairs:
        return "0 tuple"
    body = " ".join(f"0x{slot:x} 0x{val:x} 2 tuple" for slot, val in pairs)
    return f"{body} {len(pairs)} tuple"


def emit_fift_alloc(genesis: dict[str, Any]) -> tuple[str, int, int]:
    """Build the Fift snippet that pushes the alloc tuple onto the stack and
    calls `evm-zerostate-from-alloc`. Returns (fift_text, chain_id, alloc_count).
    """
    if "config" not in genesis or not isinstance(genesis["config"], dict):
        raise ValueError("genesis.json missing 'config' object")
    config = genesis["config"]
    if "chainId" not in config:
        raise ValueError("genesis.json:config missing 'chainId'")
    chain_id = parse_int_field(config["chainId"], name="config.chainId")

    if "alloc" not in genesis or not isinstance(genesis["alloc"], dict):
        # An empty alloc is technically legal — the C++ word handles a 0-tuple
        # and produces an executor-only zerostate. We still emit the call
        # so the Fift include is always self-contained.
        alloc = {}
    else:
        alloc = genesis["alloc"]

    # Sort allocations by address (numeric) for deterministic output. Hive's
    # genesis JSON uses dicts so order is not guaranteed; sorting makes the
    # resulting zerostate cell hash reproducible across translator invocations.
    items: list[tuple[int, dict[str, Any]]] = []
    for addr_str, fields in alloc.items():
        if not isinstance(fields, dict):
            raise ValueError(f"alloc[{addr_str}] must be an object")
        addr_int = parse_address(addr_str)
        items.append((addr_int, fields))
    items.sort(key=lambda kv: kv[0])

    lines: list[str] = []
    lines.append("// Auto-generated by translate-genesis.py — DO NOT EDIT BY HAND.")
    lines.append("// Source: Hive /genesis.json -> evm-zerostate-from-alloc tuple.")
    lines.append(f"// chainId = {chain_id} (0x{chain_id:x})")
    lines.append(f"// alloc count = {len(items)}")
    lines.append("")

    if not items:
        # Push an empty tuple and call the word so the surrounding template
        # always sees a single accounts cell on the stack.
        lines.append("0 tuple")
        lines.append("evm-zerostate-from-alloc")
    else:
        for addr_int, fields in items:
            balance = parse_int_field(fields.get("balance"), name=f"alloc[0x{addr_int:040x}].balance")
            nonce = parse_int_field(fields.get("nonce"), name=f"alloc[0x{addr_int:040x}].nonce")
            code = parse_hex_bytes(fields.get("code"), name=f"alloc[0x{addr_int:040x}].code")
            storage = fields.get("storage") or {}
            if not isinstance(storage, dict):
                raise ValueError(f"alloc[0x{addr_int:040x}].storage must be an object")

            code_fift = emit_fift_bytes(code)
            storage_fift = emit_fift_storage_pairs(storage)

            lines.append(
                f"0x{addr_int:x} 0x{balance:x} {nonce} {code_fift} {storage_fift} 5 tuple"
                f"  // 0x{addr_int:040x}"
            )

        lines.append(f"{len(items)} tuple")
        lines.append("evm-zerostate-from-alloc")

    return "\n".join(lines) + "\n", chain_id, len(items)


def main() -> int:
    p = argparse.ArgumentParser(description="Translate Hive /genesis.json into a Fift include for tos-create-state.")
    p.add_argument("--genesis", default="/genesis.json", help="Input geth-format genesis JSON file (default: /genesis.json)")
    p.add_argument("--out-fif", default="/tmp/genesis-alloc.fif", help="Output Fift include file")
    p.add_argument("--out-chain-id", default="/tmp/chain_id.txt", help="Output chain id text file (decimal)")
    p.add_argument("--print-summary", action="store_true", help="Print a summary to stdout")
    args = p.parse_args()

    src = Path(args.genesis)
    if not src.is_file():
        print(f"[translate-genesis] ERROR: genesis file not found: {src}", file=sys.stderr)
        return 2

    try:
        with src.open("r") as f:
            genesis = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[translate-genesis] ERROR: invalid JSON in {src}: {e}", file=sys.stderr)
        return 1

    try:
        fift_text, chain_id, alloc_count = emit_fift_alloc(genesis)
    except ValueError as e:
        print(f"[translate-genesis] ERROR: {e}", file=sys.stderr)
        return 2

    out_fif = Path(args.out_fif)
    out_fif.parent.mkdir(parents=True, exist_ok=True)
    out_fif.write_text(fift_text)

    out_chain_id = Path(args.out_chain_id)
    out_chain_id.parent.mkdir(parents=True, exist_ok=True)
    out_chain_id.write_text(f"{chain_id}\n")

    if args.print_summary:
        print(f"[translate-genesis] chainId = {chain_id} (0x{chain_id:x})")
        print(f"[translate-genesis] alloc   = {alloc_count} accounts")
        print(f"[translate-genesis] -> {out_fif}")
        print(f"[translate-genesis] -> {out_chain_id}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
