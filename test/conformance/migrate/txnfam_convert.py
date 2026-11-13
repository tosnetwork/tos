#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Turn recorded native emulator calls of a transaction family into txn-harness contexts and check them.

    txnfam_convert.py contexts <capture dir> <work dir> --family <name>
        Read the records txnfam_capture.py wrote while the unchanged family ran, in call order, and
        write <work>/all.jsonl (every call as a context), <work>/native.jsonl (the effect the family's
        own native result implies, row for row), <work>/unique.jsonl (input for ``create``: each
        distinct context once) and <work>/summary.json. A call the harness cannot express is listed
        in the summary with its reason and left out of the context files.
    txnfam_convert.py check <work dir> <target>
        Run every recorded call through ``<target> txn`` and require the effect the native result
        implies: same outcome, Transaction, Account and ShardAccount hashes, VM exit code of a
        rejection. Exit 1 on any difference.
    txnfam_convert.py fixtures <work dir> <family.jsonl>
        Require the frozen fixtures to carry exactly those native effects (the reference fill and the
        family's native results agree fixture for fixture).

The expected effect of a call comes from its native response alone: hashes of the returned
Transaction root, of the ShardAccount's Account reference and of the ShardAccount root; for a refused
external message its VM exit code; otherwise ``error``. Context fields are the caller's own arguments;
settings the caller never made are the emulator's documented defaults: rand seed zero, and lt the
first aligned lt after the input ShardAccount's last_trans_lt (TransactionEmulator::emulate_transaction).
"""

from __future__ import annotations

import argparse
import base64
import importlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT / "test/executor-parity"), str(ROOT / "test/auth-extensions")]
# Sibling and test-helper modules are loaded by name: they live outside the type checker's import roots.
from_boc = importlib.import_module("root_cells").from_boc

Json = dict[str, Any]
LT_ALIGN = 1_000_000
ZERO_SEED = "0" * 64
MAX_CAPTURE_LINE = 64 << 20


def cell_hash(b64: str) -> str:
    return from_boc(base64.b64decode(b64), allow_library=True).hash.hex().upper()


def native_effect(response: Json) -> Json:
    """The txn effect a native emulator response stands for (same rules as ref/harness-txn.cpp)."""
    if response.get("success") is True:
        shard = from_boc(base64.b64decode(response["shard_account"]), allow_library=True)
        if len(shard.refs) < 1:
            raise SystemExit("native ShardAccount without an Account reference")
        return {
            "outcome": "accepted",
            "transaction_hash": cell_hash(response["transaction"]),
            "account_hash": shard.refs[0].hash.hex().upper(),
            "shard_account_hash": shard.hash.hex().upper(),
        }
    if response.get("external_not_accepted") is True:
        return {"outcome": "rejected", "vm_exit_code": int(response["vm_exit_code"])}
    return {"outcome": "error"}


def last_trans_lt(shard_account_b64: str) -> int:
    root = from_boc(base64.b64decode(shard_account_b64), allow_library=True)
    if len(root.bits) != 320:
        raise ValueError("ShardAccount root must be 320 bits")
    return int(root.bits[256:320], 2)


def records(capture: Path) -> list[Json]:
    found: list[Json] = []
    for path in sorted(capture.glob("*.jsonl")):
        with path.open("rb") as handle:
            for raw in handle:
                if len(raw) > MAX_CAPTURE_LINE:
                    raise SystemExit(f"{path}: capture line too long")
                found.append(json.loads(raw))
    found.sort(key=lambda r: (r["ns"], r["pid"], r["seq"]))
    return found


def to_context(record: Json) -> tuple[Json | None, list[str], str | None]:
    """(context, defaults applied, reason it is not expressible)."""
    state = record["state"]
    defaults: list[str] = []
    if state.get("refused_settings"):
        return None, defaults, "emulator refused a setting: " + ",".join(state["refused_settings"])
    if state.get("ignore_chksig"):
        return None, defaults, "ignore_chksig=true (the harness always verifies signatures)"
    if not state.get("config"):
        return None, defaults, "no configuration recorded"
    if state.get("now") is None:
        return None, defaults, "unixtime never set (the emulator would read the wall clock)"
    ctx: Json = {
        "config": state["config"],
        "shard_account": record["shard_account"],
        "now": int(state["now"]),
    }
    if state.get("lt") is None:
        lt = (last_trans_lt(record["shard_account"]) // LT_ALIGN + 1) * LT_ALIGN
        defaults.append("lt")
    else:
        lt = int(state["lt"])
    ctx["lt"] = lt
    if state.get("rand_seed") is None:
        ctx["rand_seed"] = ZERO_SEED
        defaults.append("rand_seed")
    else:
        ctx["rand_seed"] = state["rand_seed"]
    if "message" in record:
        ctx["message"] = record["message"]
    else:
        ctx["tick_tock"] = record["tick_tock"]
    if state.get("libraries"):
        ctx["libraries"] = state["libraries"]
    if state.get("prev_blocks"):
        ctx["prev_blocks"] = state["prev_blocks"]
    if state.get("debug_enabled"):
        defaults.append("debug_enabled-ignored")
    return ctx, defaults, None


def write_jsonl(path: Path, items: list[Json]) -> None:
    path.write_text("".join(json.dumps(i, separators=(",", ":")) + "\n" for i in items))


def read_jsonl(path: Path) -> list[Json]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def command_contexts(capture: Path, work: Path, family: str) -> int:
    work.mkdir(parents=True, exist_ok=True)
    every: list[Json] = []
    native: list[Json] = []
    unique: list[Json] = []
    seen: dict[str, str] = {}
    skipped: list[Json] = []
    problems: list[Json] = []
    defaults: dict[str, int] = {}
    outcomes: dict[str, int] = {}
    number = 0
    for record in records(capture):
        if record.get("kind") != "call":
            problems.append(record)
            continue
        number += 1
        fixture_id = f"{family}-{number:05d}"
        if record.get("response") is None:
            skipped.append({"fixture_id": fixture_id, "reason": "no native response recorded"})
            continue
        ctx, applied, reason = to_context(record)
        if ctx is None:
            skipped.append({"fixture_id": fixture_id, "reason": reason, "caller": record["caller"]})
            continue
        for name in applied:
            defaults[name] = defaults.get(name, 0) + 1
        effect = native_effect(record["response"])
        outcomes[effect["outcome"]] = outcomes.get(effect["outcome"], 0) + 1
        note = "native call " + " < ".join(reversed(record["caller"][-3:]))
        entry = {"fixture_id": fixture_id, "note": note, "context": ctx}
        every.append(entry)
        native.append({"fixture_id": fixture_id, "effects": effect})
        key = json.dumps(ctx, sort_keys=True)
        if key in seen:
            continue
        seen[key] = fixture_id
        unique.append(entry)
    write_jsonl(work / "all.jsonl", every)
    write_jsonl(work / "native.jsonl", native)
    write_jsonl(work / "unique.jsonl", unique)
    summary = {
        "family": family,
        "native_calls": number,
        "converted": len(every),
        "unique": len(unique),
        "outcomes": outcomes,
        "defaults_applied": defaults,
        "not_convertible": skipped,
        "capture_problems": problems,
    }
    (work / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(
        f"{family}: {number} native calls, {len(every)} converted ({len(unique)} unique), "
        f"{len(skipped)} not convertible, {len(problems)} capture problems, outcomes {outcomes}, "
        f"defaults {defaults}"
    )
    return 1 if problems else 0


def run_target(target: str, contexts: list[Json]) -> list[Json]:
    stdin = "".join(json.dumps(c, separators=(",", ":")) + "\n" for c in contexts)
    done = subprocess.run(
        [target, "txn"], input=stdin, capture_output=True, text=True, timeout=7200, check=False
    )
    if done.returncode != 0:
        raise SystemExit(f"{target} txn exited {done.returncode}: {done.stderr[-2000:]}")
    lines = done.stdout.splitlines()
    if len(lines) != len(contexts):
        raise SystemExit(f"{len(lines)} responses for {len(contexts)} contexts")
    return [json.loads(line) for line in lines]


def command_check(work: Path, target: str) -> int:
    entries = read_jsonl(work / "all.jsonl")
    native = read_jsonl(work / "native.jsonl")
    if not entries or len(entries) != len(native):
        raise SystemExit("all.jsonl and native.jsonl must be non-empty and of equal length")
    effects = run_target(target, [e["context"] for e in entries])
    write_jsonl(work / "harness.jsonl", effects)
    differences = 0
    for entry, want, got in zip(entries, native, effects, strict=True):
        if want["fixture_id"] != entry["fixture_id"]:
            raise SystemExit("all.jsonl and native.jsonl are out of order")
        if got != want["effects"]:
            differences += 1
            if differences <= 20:
                print(f"DIFF {entry['fixture_id']}: native {want['effects']} harness {got}")
    print(f"checked {len(entries)} native calls against {target}, {differences} differences")
    return 1 if differences else 0


def command_fixtures(work: Path, fixture_file: Path) -> int:
    native = {n["fixture_id"]: n["effects"] for n in read_jsonl(work / "native.jsonl")}
    unique = [u["fixture_id"] for u in read_jsonl(work / "unique.jsonl")]
    fixtures = read_jsonl(fixture_file)
    ids = [f["metadata"]["fixture_id"] for f in fixtures]
    differences = 0
    if ids != unique:
        differences += 1
        print(f"fixture ids differ from the converted contexts ({len(ids)} vs {len(unique)})")
    for fixture in fixtures:
        fixture_id = fixture["metadata"]["fixture_id"]
        if native.get(fixture_id) != fixture["effects"]:
            differences += 1
            if differences <= 20:
                print(
                    f"DIFF {fixture_id}: native {native.get(fixture_id)} fixture {fixture['effects']}"
                )
    print(f"compared {len(fixtures)} fixtures with native results, {differences} differences")
    return 1 if differences else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    contexts = sub.add_parser("contexts")
    contexts.add_argument("capture", type=Path)
    contexts.add_argument("work", type=Path)
    contexts.add_argument("--family", required=True)
    check = sub.add_parser("check")
    check.add_argument("work", type=Path)
    check.add_argument("target")
    fixtures = sub.add_parser("fixtures")
    fixtures.add_argument("work", type=Path)
    fixtures.add_argument("fixture_file", type=Path)
    args = parser.parse_args(argv)
    if args.command == "contexts":
        return command_contexts(args.capture, args.work, args.family)
    if args.command == "check":
        return command_check(args.work, args.target)
    return command_fixtures(args.work, args.fixture_file)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
