#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Turn the Rust node's exported executor rows into txn-harness contexts and check the C++ fill.

    txnfam_rtos.py contexts <export.tsv> <frozen.tsv> <work dir> --family <name> [--tick-rule R]
        <export.tsv> is what a Rust executor test writes with its RTOS_<X>_EXPORT variable: per row
        the inputs, then the Rust transaction and Account hashes. <frozen.tsv> is the family's frozen
        C++ result file (``name<TAB>transaction hash<TAB>account hash``, ``#`` comment lines). Writes
        all.jsonl / native.jsonl / unique.jsonl / summary.json like txnfam_convert.py; native.jsonl
        holds the frozen C++ hashes (the ShardAccount hash is not part of those files).
    txnfam_rtos.py check <work dir> <target>
        Run every context through ``<target> txn``; the effect must carry the frozen C++ outcome and
        hashes. Exit 1 on any difference.

Input columns, in order (absent trailing columns take the defaults the C++ filler used):
name, now, lt, configuration (ConfigParams wrapper: address and dictionary), Account, inbound
message or ``-`` (tick/tock), global libraries or ``-``, special flag, workchain, address. The C++
filler (an out-of-tree driver over emulator::TransactionEmulator) wrapped the Account in a ShardAccount
with zero last transaction hash and lt, used a zero rand seed, no previous blocks, signature checks on,
and passed ``now``/``lt`` to emulate_transaction; those are exactly the txn context fields. The
emulator derives specialness from CP31 (and the configuration address) for masterchain accounts; a row
whose special flag differs from that is not expressible and is listed instead.
"""

from __future__ import annotations

import argparse
import base64
import importlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parents[1] / "auth-extensions")]
# Sibling and test-helper modules are loaded by name: they live outside the type checker's import roots.
_convert = importlib.import_module("txnfam_convert")
_cells = importlib.import_module("cells")
from_boc = _convert.from_boc
read_jsonl = _convert.read_jsonl
run_target = _convert.run_target
write_jsonl = _convert.write_jsonl
Cell = _cells.Cell
read_dict = _cells.read_dict

Json = dict[str, Any]
ZERO_SEED = "0" * 64
_CONFIGS: dict[str, tuple[str, int | None, set[int], int | None]] = {}


def b64(cell: Cell) -> str:
    return base64.b64encode(cell.boc()).decode("ascii")


def configuration(wrapper_hex: str) -> tuple[str, int | None, set[int], int | None]:
    """(dictionary BOC, global version, CP31 addresses, configuration address) of a wrapper."""
    if wrapper_hex not in _CONFIGS:
        wrapper = from_boc(bytes.fromhex(wrapper_hex), allow_library=True)
        if len(wrapper.bits) != 256 or len(wrapper.refs) != 1:
            raise ValueError("configuration must be the ConfigParams wrapper")
        dictionary = wrapper.refs[0]
        entries = read_dict(dictionary, 32)
        version = None
        if 8 in entries and entries[8].refs:
            p8 = entries[8].refs[0].bits
            if p8[:8] == f"{0xC4:08b}":
                version = int(p8[8:40], 2)
        special: set[int] = set()
        if 31 in entries and entries[31].refs:
            p31 = entries[31].refs[0]
            if p31.bits[:1] == "1" and p31.refs:
                special = set(read_dict(p31.refs[0], 256))
        address = None
        if 0 in entries and entries[0].refs and len(entries[0].refs[0].bits) == 256:
            address = int(entries[0].refs[0].bits, 2)
        _CONFIGS[wrapper_hex] = (b64(dictionary), version, special, address)
    return _CONFIGS[wrapper_hex]


def context(fields: list[str], tick_tock: str | None = None) -> tuple[Json | None, str | None]:
    """A tick_tock kind given by the family rule wins over the row's message column."""
    if len(fields) < 6:
        return None, f"{len(fields)} input columns, at least 6 required"
    config, version, special_set, config_address = configuration(fields[3])
    account = from_boc(bytes.fromhex(fields[4]), allow_library=True)
    shard = Cell("0" * 320, [account])
    ctx: Json = {
        "config": config,
        "shard_account": b64(shard),
        "now": int(fields[1]),
        "lt": int(fields[2]),
        "rand_seed": ZERO_SEED,
    }
    if tick_tock is not None:
        ctx["tick_tock"] = tick_tock
    elif fields[5] != "-":
        ctx["message"] = base64.b64encode(bytes.fromhex(fields[5])).decode("ascii")
    else:
        return None, "no inbound message and no tick/tock kind"
    if len(fields) > 6 and fields[6] != "-":
        ctx["libraries"] = base64.b64encode(bytes.fromhex(fields[6])).decode("ascii")
    if len(fields) > 9:
        flagged = fields[7] == "1"
        workchain = int(fields[8])
        address = int(fields[9], 16)
        derived = workchain == -1 and (address in special_set or address == config_address)
        if flagged != derived:
            return None, (
                f"special={int(flagged)} for workchain {workchain}, the emulator derives {int(derived)}"
            )
    ctx["_version"] = version
    return ctx, None


def frozen(path: Path) -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        rows[fields[0]] = fields[1:]
    return rows


def expected(values: list[str]) -> Json:
    """The effect a frozen C++ row stands for.

    ``ERROR`` rows (8f083dc fillers) are printed when the emulator returns no transaction; a hard
    emulation error aborts those fillers, so ERROR is an external message the account did not accept.
    ``error`` rows (8812403 fillers) carry a reason column: ``not-success`` is a refusal (no
    transaction without an error status), every other reason is an emulation error. An ``error`` row without a reason (filler not
    retained) is only known to produce no transaction. ``ext-rejected`` is an emulation error status
    whose message says the account rejected the message, so it stays an error.
    """
    if values[0] == "ERROR":
        return {"outcome": "rejected"}
    if values[0] == "error":
        if len(values) < 3:
            return {"_outcomes": ["rejected", "error"]}
        if values[2] == "not-success":
            return {"outcome": "rejected"}
        return {"outcome": "error"}
    return {
        "outcome": "accepted",
        "transaction_hash": values[0].upper(),
        "account_hash": values[1].upper(),
    }


def agrees(want: Json, got: Json) -> bool:
    for key, value in want.items():
        if key == "_outcomes":
            if got.get("outcome") not in value:
                return False
        elif got.get(key) != value:
            return False
    return True


def tick_kind(name: str, rule: str) -> str | None:
    """Tick/tock kind of a row, decided as that family's C++ filler decided it."""
    if rule == "name":
        kinds = [k for k in ("tick", "tock") if f"-{k}-" in f"-{name}-"]
        return kinds[0] if len(kinds) == 1 else None
    if rule == "dash-message":
        return None  # decided in context(): a row without a message is tick, or tock by name
    if rule == "tick-address-prefix":
        if not name.startswith("tick-address-"):
            return None
        return "tock" if "-tock-" in name else "tick"
    return None


def command_contexts(export: Path, frozen_path: Path, work: Path, family: str, rule: str) -> int:
    work.mkdir(parents=True, exist_ok=True)
    reference = frozen(frozen_path)
    every: list[Json] = []
    native: list[Json] = []
    unique: list[Json] = []
    seen: set[str] = set()
    skipped: list[Json] = []
    versions: dict[str, int] = {}
    names: set[str] = set()
    with export.open() as handle:
        for number, line in enumerate(handle, 1):
            fields = line.rstrip("\n").split("\t")
            name = fields[0]
            fixture_id = f"{family}-{number:05d}"
            inputs = fields[:-2]
            if name not in reference:
                skipped.append(
                    {"fixture_id": fixture_id, "name": name, "reason": "no frozen C++ row"}
                )
                continue
            kind = tick_kind(name, rule)
            if rule == "dash-message" and len(inputs) > 5 and inputs[5] == "-":
                kind = "tock" if "-tock-" in name else "tick"
            ctx, reason = context(inputs, kind)
            if ctx is None:
                skipped.append({"fixture_id": fixture_id, "name": name, "reason": reason})
                continue
            version = ctx.pop("_version")
            versions[str(version)] = versions.get(str(version), 0) + 1
            names.add(name)
            entry = {
                "fixture_id": fixture_id,
                "note": f"{name} (global version {version})",
                "context": ctx,
            }
            every.append(entry)
            native.append({"fixture_id": fixture_id, "effects": expected(reference[name])})
            key = json.dumps(ctx, sort_keys=True)
            if key not in seen:
                seen.add(key)
                unique.append(entry)
    write_jsonl(work / "all.jsonl", every)
    write_jsonl(work / "native.jsonl", native)
    write_jsonl(work / "unique.jsonl", unique)
    summary = {
        "family": family,
        "export_rows": len(every) + len(skipped),
        "frozen_rows": len(reference),
        "frozen_rows_without_export": sorted(set(reference) - names)[:50],
        "converted": len(every),
        "unique": len(unique),
        "versions": versions,
        "not_convertible": skipped[:200],
        "not_convertible_count": len(skipped),
    }
    (work / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(
        f"{family}: {summary['export_rows']} rows, {len(every)} converted ({len(unique)} unique), "
        f"{len(skipped)} not convertible, frozen {len(reference)}, versions {versions}"
    )
    return 0


def command_check(work: Path, target: str) -> int:
    entries = read_jsonl(work / "all.jsonl")
    native = read_jsonl(work / "native.jsonl")
    effects = run_target(target, [e["context"] for e in entries])
    write_jsonl(work / "harness.jsonl", effects)
    differences = 0
    for entry, want, got in zip(entries, native, effects, strict=True):
        if not agrees(want["effects"], got):
            differences += 1
            if differences <= 20:
                print(
                    f"DIFF {entry['fixture_id']} {entry['note']}: C++ {want['effects']} harness {got}"
                )
    print(f"checked {len(entries)} rows against the frozen C++ results, {differences} differences")
    return 1 if differences else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    contexts = sub.add_parser("contexts")
    contexts.add_argument("export", type=Path)
    contexts.add_argument("frozen", type=Path)
    contexts.add_argument("work", type=Path)
    contexts.add_argument("--family", required=True)
    contexts.add_argument(
        "--tick-rule",
        choices=("none", "name", "dash-message", "tick-address-prefix"),
        default="none",
        help="how the family's C++ filler chose tick/tock rows",
    )
    check = sub.add_parser("check")
    check.add_argument("work", type=Path)
    check.add_argument("target")
    args = parser.parse_args(argv)
    if args.command == "contexts":
        return command_contexts(args.export, args.frozen, args.work, args.family, args.tick_rule)
    return command_check(args.work, args.target)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
