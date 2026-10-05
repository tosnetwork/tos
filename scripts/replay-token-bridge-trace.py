#!/usr/bin/env python3
"""Replay the token-bridge sandbox's transactions in the native transaction engine.

The sandbox suite (tosctl/src/node-control/contracts/tests/token_bridge_sandbox.rs)
runs on the Rust executor. Run with TOKEN_BRIDGE_TRACE_DIR set, it records every
transaction it executes: the account before, the incoming message, the
configuration and the outcome. This replays each one through libemulator, the
production C++ engine, and requires the same outcome: compute exit code,
abort, action-phase result, bounce, every outgoing message with its value and
forwarding fee, and the account's balance and data afterwards.

The bridge's completion guarantees rest on fee arithmetic and on the bounce
and action-failure rules of send modes 1, 2, 16 and 64; a difference between
the two engines in any of them would make the sandbox evidence describe the
wrong chain.

Usage: replay-token-bridge-trace.py <trace-dir> [--emulator path/to/libemulator.so]
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
from cells import Cell, from_boc, make_dict, read_dict  # noqa: E402

DEFAULT_CONFIG = ROOT / "tosctl/src/executor/real_boc/default_config.boc"


def complete_config(recorded: str) -> bytes:
    """The recorded parameters over a complete configuration.

    The sandbox's configuration holds only the parameters its executor reads
    (prices, limits, workchains, global version and id, the bridge's own); the
    native engine requires every mandatory parameter. Every recorded parameter
    is kept as recorded, so all prices come from the recording.
    """
    fixture = from_boc(DEFAULT_CONFIG.read_bytes())
    entries = read_dict(fixture.refs[0], 32)
    entries[0] = Cell().ref(Cell().uint(int(fixture.bits, 2), 256))
    entries.update(read_dict(from_boc(base64.b64decode(recorded)), 32))
    return make_dict(entries, 32).b64()


class Engine:
    def __init__(self, library: Path):
        self.lib = ctypes.CDLL(str(library))
        self.lib.transaction_emulator_create.argtypes = [ctypes.c_char_p, ctypes.c_int]
        self.lib.transaction_emulator_create.restype = ctypes.c_void_p
        self.lib.transaction_emulator_emulate_transaction.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        self.lib.transaction_emulator_emulate_transaction.restype = ctypes.c_void_p
        self.lib.string_destroy.argtypes = [ctypes.c_void_p]
        self.lib.transaction_emulator_destroy.argtypes = [ctypes.c_void_p]
        self.lib.transaction_emulator_set_unixtime.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.lib.transaction_emulator_set_lt.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        self.lib.emulator_set_verbosity_level(0)
        self.emulators: dict[str, int] = {}

    def run(self, config: str, unixtime: int, shard_account: str, message: str) -> dict:
        if config not in self.emulators:
            ptr = self.lib.transaction_emulator_create(complete_config(config), 0)
            if not ptr:
                raise AssertionError("the native engine refused the recorded configuration")
            self.emulators[config] = ptr
        ptr = self.emulators[config]
        self.lib.transaction_emulator_set_unixtime(ptr, unixtime)
        self.lib.transaction_emulator_set_lt(ptr, 2_000_000_000)
        out = self.lib.transaction_emulator_emulate_transaction(
            ptr, shard_account.encode(), message.encode()
        )
        if not out:
            raise AssertionError("the native engine returned nothing")
        try:
            return json.loads(ctypes.string_at(out))
        finally:
            self.lib.string_destroy(out)


def coins(s) -> int:
    return s.coins()


def skip_currency_collection(s) -> int:
    value = s.coins()
    s.maybe()  # extra currencies
    return value


def read_int_address(s) -> str:
    tag = s.uint(2)
    if tag == 0:
        return ""
    assert tag == 2, "only standard addresses are expected"
    assert s.uint(1) == 0, "no anycast"
    wc = s.sint(8)
    return f"{wc}:{s.uint(256):064x}"


def body_hash(s) -> str:
    if s.uint(1):
        return s.ref().hash.hex()
    return Cell(s.bits, list(s.refs)).hash.hex()


def skip_init(s) -> None:
    if not s.uint(1):
        return
    if s.uint(1):
        s.ref()
        return
    if s.uint(1):
        s.uint(5)
    if s.uint(1):
        s.uint(2)
    s.maybe()
    s.maybe()
    s.maybe()


def outgoing(tx: Cell) -> list[dict]:
    s = tx.refs[0].slice()
    s.maybe()  # incoming
    found = []
    for _, holder in sorted(read_dict(s.maybe(), 15).items()):
        m = holder.refs[0].slice()
        if m.uint(1) == 0:
            m.uint(1)  # ihr_disabled
            bounce = bool(m.uint(1))
            bounced = bool(m.uint(1))
            read_int_address(m)
            dst = read_int_address(m)
            value = skip_currency_collection(m)
            m.coins()  # ihr fee / extra flags
            fwd_fee = m.coins()
            m.uint(64)
            m.uint(32)
            skip_init(m)
            found.append(
                {
                    "kind": "internal",
                    "dst": dst,
                    "value": str(value),
                    "bounce": bounce,
                    "bounced": bounced,
                    "fwd_fee": str(fwd_fee),
                    "body": body_hash(m),
                }
            )
        else:
            assert m.uint(1) == 1, "an outgoing external message"
            read_int_address(m)
            assert m.uint(2) == 1, "an external destination"
            length = m.uint(9)
            topic = f"{m.uint(length):0{length // 4}x}"
            m.uint(64)
            m.uint(32)
            skip_init(m)
            found.append({"kind": "external", "topic": topic, "body": body_hash(m)})
    return found


def description(tx: Cell) -> dict:
    c = tx.refs[2].slice()
    assert c.uint(4) == 0, "an ordinary transaction"
    c.uint(1)  # credit_first
    if c.uint(1):  # storage phase
        c.coins()
        if c.uint(1):
            c.coins()
        if c.uint(1):
            c.uint(1)
    if c.uint(1):  # credit phase
        if c.uint(1):
            c.coins()
        c.coins()
        c.maybe()
    exit_code, skipped, gas_used = None, True, None
    if c.uint(1):
        skipped = False
        c.uint(1)  # success
        c.uint(2)
        c.coins()
        vm = c.ref().slice()
        gas_used = vm.varuint(7)
        vm.varuint(7)
        if vm.uint(1):
            vm.varuint(3)
        vm.sint(8)
        exit_code = vm.sint(32)
    else:
        c.uint(2)  # skip reason
    action_cell = c.maybe()
    aborted = bool(c.uint(1))
    bounce = "none"
    if c.uint(1):
        bounce = "ok" if c.uint(1) else ("nofunds" if c.uint(1) else "negfunds")
    action = None
    if action_cell is not None:
        a = action_cell.slice()
        success = bool(a.uint(1))
        a.uint(2)
        if a.uint(1):
            a.uint(1)
        if a.uint(1):
            a.coins()
        if a.uint(1):
            a.coins()
        result_code = a.sint(32)
        if a.uint(1):
            a.sint(32)
        a.uint(16)
        a.uint(16)
        action = {"success": success, "result_code": result_code, "skipped": a.uint(16)}
    return {
        "gas_used": gas_used,
        "aborted": aborted,
        "exit_code": exit_code,
        "compute_skipped": skipped,
        "action": action,
        "bounce": bounce,
    }


def read_state_init(s) -> tuple[str | None, str | None]:
    """The code and data hashes of an inline StateInit."""
    if s.uint(1):
        s.uint(5)
    if s.uint(1):
        s.uint(2)
    code = s.maybe()
    data = s.maybe()
    s.maybe()
    return (
        code.hash.hex() if code is not None else None,
        data.hash.hex() if data is not None else None,
    )


def read_account(shard_account: Cell) -> dict:
    """An account's state, balance, and code and data hashes."""
    s = shard_account.refs[0].slice()
    if not s.uint(1):
        return {"state": "none", "balance": None, "code": None, "data": None}
    read_int_address(s)
    s.varuint(7)
    s.varuint(7)
    if s.uint(3) == 1:
        s.uint(256)
    s.uint(32)
    if s.uint(1):
        s.coins()
    s.uint(64)
    balance = str(skip_currency_collection(s))
    if s.uint(1) == 0:
        state = "frozen" if s.uint(1) else "uninit"
        return {"state": state, "balance": balance, "code": None, "data": None}
    code, data = read_state_init(s)
    return {"state": "active", "balance": balance, "code": code, "data": data}


def message_init(message: Cell) -> tuple[str | None, str | None] | None:
    """The StateInit an internal message carries, as code and data hashes."""
    s = message.slice()
    if s.uint(1) != 0:
        return None
    s.uint(3)
    read_int_address(s)
    read_int_address(s)
    skip_currency_collection(s)
    s.coins()
    s.coins()
    s.uint(64)
    s.uint(32)
    if not s.uint(1):
        return None
    if s.uint(1):
        return read_state_init(s.ref().slice())
    return read_state_init(s)


def failed_deployment_kept_by_rust(expect: dict, got: dict, before: dict, init) -> bool:
    """A deployment refused in its compute phase, which bounced everything.

    The native engine leaves no account behind; the Rust executor keeps the
    account active, holding nothing, with the deployed code and data. Only that
    exact shape is set apart: an account that did not exist or held no code
    before, a message carrying the StateInit, a compute phase that ran and
    failed with no action phase, a bounce, and code and data equal to the
    StateInit's. Every other field of the transaction must still agree.
    """
    return (
        before["state"] in ("none", "uninit")
        and init is not None
        and got["balance"] is None
        and got["data"] is None
        and got["code"] is None
        and expect["balance"] == "0"
        and (expect["code"], expect["data"]) == init
        and expect["aborted"]
        and got["aborted"]
        and not expect["compute_skipped"]
        and not got["compute_skipped"]
        and expect["exit_code"] == got["exit_code"]
        and expect["exit_code"] not in (0, 1)
        and expect["action"] is None
        and got["action"] is None
        and expect["bounce"] == got["bounce"] == "ok"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("trace_dir", type=Path)
    parser.add_argument("--emulator", type=Path, default=ROOT / "build/emulator/libemulator.so")
    args = parser.parse_args()

    engine = Engine(args.emulator)
    records = sorted(args.trace_dir.rglob("*.json"))
    if not records:
        print(f"no trace records under {args.trace_dir}", file=sys.stderr)
        return 2
    differences = []
    kept_deployments = []
    for path in records:
        record = json.loads(path.read_text())
        result = engine.run(
            record["config"], record["unixtime"], record["shard_account"], record["message"]
        )
        expect = record["expect"]
        if not result.get("success"):
            differences.append(
                f"{path}: the native engine did not execute it: {result.get('error')}"
            )
            continue
        tx = from_boc(base64.b64decode(result["transaction"]))
        got = description(tx)
        got["out"] = outgoing(tx)
        after = read_account(from_boc(base64.b64decode(result["shard_account"])))
        got["balance"], got["data"], got["code"] = after["balance"], after["data"], after["code"]
        before = read_account(from_boc(base64.b64decode(record["shard_account"])))
        init = message_init(from_boc(base64.b64decode(record["message"])))
        if failed_deployment_kept_by_rust(expect, got, before, init):
            kept_deployments.append(str(path.relative_to(args.trace_dir)))
            got["balance"], got["data"], got["code"] = (
                expect["balance"],
                expect["data"],
                expect["code"],
            )
        keys = ["gas_used"] if "gas_used" in expect else []
        for key in keys + [
            "aborted",
            "exit_code",
            "compute_skipped",
            "action",
            "bounce",
            "out",
            "balance",
            "data",
            "code",
        ]:
            if got[key] != expect[key]:
                differences.append(
                    f"{path.relative_to(args.trace_dir)}: {key}: Rust {expect[key]} native {got[key]}"
                )
    print(f"replayed {len(records)} transactions in the native engine; {len(differences)} differ")
    if kept_deployments:
        print(
            f"{len(kept_deployments)} failed deployments that the Rust executor keeps as an empty "
            "active account and the native engine does not create (an executor difference, "
            "reported, not a contract one):"
        )
        for line in kept_deployments:
            print("  " + line)
    for line in differences:
        print(line)
    return 1 if differences else 0


if __name__ == "__main__":
    sys.exit(main())
