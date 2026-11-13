#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Cross-check converted txn contexts against the records a transaction family itself retained.

    txnfam_artifacts.py <work dir> <family output dir> [<committed fixture>...]

``<work dir>`` is a ``txnfam_convert.py`` directory after ``check`` (all.jsonl, harness.jsonl). The
family output directory and the committed files are read for every per-transaction record a family
writes, independently of the call recorder:

- ``*-roots.tsv`` (``#pq-tx-roots-v1``: name, now, lt, ShardAccount, message, seed, libraries,
  previous blocks, ignore-signatures) with ``*-root-expected.tsv`` and the configuration beside it;
- per-case dumps ``<name>.json`` (raw native response) with ``<name>{.,-}{shard,message,config}.boc``;
- JSON reports with rows of ``input_shard``/``account``, ``message``, ``now``, ``lt``, configuration
  and the recorded transaction/account/ShardAccount hashes (storage carry and deployment families).

Every record must match a converted context (same ShardAccount, message or tick/tock, configuration
when the record names one, now and lt when it gives them), and the harness effect of that context
must carry the record's outcome and hashes. A record without a match is a difference. The record's
name is added to the note of the matched contexts in unique.jsonl.
"""

from __future__ import annotations

import base64
import importlib
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Sibling and test-helper modules are loaded by name: they live outside the type checker's import roots.
_convert = importlib.import_module("txnfam_convert")
from_boc = _convert.from_boc
native_effect = _convert.native_effect
read_jsonl = _convert.read_jsonl
write_jsonl = _convert.write_jsonl

Json = dict[str, Any]
_HASHES: dict[bytes, str] = {}


def boc_hash(data: bytes) -> str:
    if data not in _HASHES:
        _HASHES[data] = from_boc(data, allow_library=True).hash.hex()
    return _HASHES[data]


def config_hash(data: bytes) -> str:
    """Dictionary root of a configuration given either as the dictionary or as the full wrapper."""
    cell = from_boc(data, allow_library=True)
    if len(cell.bits) == 256 and len(cell.refs) == 1:
        return cell.refs[0].hash.hex()
    return cell.hash.hex()


def account_hash(data: bytes) -> str | None:
    cell = from_boc(data, allow_library=True)
    return cell.refs[0].hash.hex() if cell.refs else None


def b64_bytes(text: str) -> bytes:
    return base64.b64decode(text)


def record(
    name: str,
    shard: bytes,
    message: bytes | None,
    expect: Json,
    *,
    config: bytes | None = None,
    now: int | None = None,
    lt: int | None = None,
    tick_tock: str | None = None,
    account_only: bool = False,
) -> Json:
    return {
        "name": name,
        "index": "account" if account_only else "shard",
        "shard": boc_hash(shard),
        "message": None if message is None else boc_hash(message),
        "tick_tock": tick_tock,
        "config": None if config is None else config_hash(config),
        "now": now,
        "lt": lt,
        "expect": expect,
    }


def roots_records(output: Path) -> list[Json]:
    found: list[Json] = []
    for inputs in sorted(output.rglob("*-roots.tsv")):
        lines = inputs.read_text().splitlines()
        if not lines or lines[0] != "#pq-tx-roots-v1":
            continue
        label = inputs.name.removesuffix("-roots.tsv")
        expected_path = inputs.with_name(f"{label}-root-expected.tsv")
        expected = [line.split("\t") for line in expected_path.read_text().splitlines()]
        rows = [line.split("\t") for line in lines[1:]]
        if len(expected) != len(rows):
            raise SystemExit(f"{inputs}: {len(rows)} rows, {len(expected)} expected")
        config = None
        for candidate in (inputs.with_name(f"{label}-config.boc"), inputs.with_name("config.boc")):
            if candidate.exists():
                config = candidate.read_bytes()
                break
        for index, (fields, want) in enumerate(zip(rows, expected, strict=True)):
            if want[1] == "accepted":
                expect = {
                    "outcome": "accepted",
                    "transaction_hash": want[2].upper(),
                    "account_hash": want[3].upper(),
                    "shard_account_hash": want[4].upper(),
                }
            elif want[1] == "rejected":
                expect = {"outcome": "rejected", "vm_exit_code": int(want[2])}
            else:
                expect = {"outcome": "error"}
            found.append(
                record(
                    f"{inputs.relative_to(output)}:{index + 1}:{fields[0]}",
                    bytes.fromhex(fields[3]),
                    bytes.fromhex(fields[4]),
                    expect,
                    config=config,
                    now=int(fields[1]),
                    lt=int(fields[2]),
                )
            )
    return found


def transcript_records(output: Path) -> list[Json]:
    """Six-field scenario rows (name, now, lt, Account, message, libraries) and native transcripts.

    A transcript gives no roots: a refused external message is ``name exit 0 - -``, any other line
    is an executed transaction, so only the outcome class is compared.
    """
    found: list[Json] = []
    for scenarios in sorted(output.rglob("scenarios.tsv")):
        transcripts = scenarios.with_name("native.tsv")
        if not transcripts.exists():
            continue
        rows = [line.split("\t") for line in scenarios.read_text().splitlines() if line]
        lines = [line.split("\t") for line in transcripts.read_text().splitlines() if line]
        if len(rows) != len(lines) or any(len(r) != 6 for r in rows):
            continue
        for fields, native in zip(rows, lines, strict=True):
            if native[0] != fields[0]:
                raise SystemExit(f"{transcripts}: {native[0]} for scenario {fields[0]}")
            if len(native) == 5 and native[3:] == ["-", "-"]:
                expect: Json = {"outcome": "rejected", "vm_exit_code": int(native[1])}
            else:
                expect = {"outcome": "accepted"}
            found.append(
                record(
                    f"{scenarios.relative_to(output)}:{fields[0]}",
                    bytes.fromhex(fields[3]),
                    bytes.fromhex(fields[4]),
                    expect,
                    now=int(fields[1]),
                    lt=int(fields[2]),
                    account_only=True,
                )
            )
    return found


def sibling(result: Path, stem: str, kind: str) -> Path | None:
    for separator in (".", "-"):
        path = result.with_name(f"{stem}{separator}{kind}.boc")
        if path.exists():
            return path
    return None


def dump_records(output: Path) -> list[Json]:
    found: list[Json] = []
    for result in sorted(output.rglob("*.json")):
        if "rust" in result.relative_to(output).parts:
            continue
        stem = result.name.removesuffix(".json")
        shard = sibling(result, stem, "shard")
        if shard is None:
            continue
        response = json.loads(result.read_text())
        if not isinstance(response, dict) or "success" not in response:
            continue
        message = sibling(result, stem, "message")
        config = sibling(result, stem, "config")
        # A tick/tock case also dumps the placeholder message it never sends.
        tick_tock = next((k for k in ("tick", "tock") if stem.startswith(k + "-")), None)
        if tick_tock is not None:
            message = None
        found.append(
            record(
                str(result.relative_to(output)),
                shard.read_bytes(),
                None if message is None else message.read_bytes(),
                native_effect(response),
                config=None if config is None else config.read_bytes(),
                tick_tock=tick_tock,
            )
        )
    return found


def report_rows(path: Path) -> list[Json]:
    data = json.loads(path.read_text())
    found: list[Json] = []
    if isinstance(data, dict) and "cases" in data and isinstance(data["cases"], list):
        groups = [
            (c.get("name", str(i)), c["config_boc"], c["rows"]) for i, c in enumerate(data["cases"])
        ]
    elif isinstance(data, dict) and "rows" in data:
        groups = [("", data["config_boc"], data["rows"])]
    elif isinstance(data, list):
        groups = [("", None, data)]
    else:
        raise SystemExit(f"{path}: unknown report shape")
    for group, config_hex, rows in groups:
        for index, row in enumerate(rows):
            # Deployment rows give the Account, not its ShardAccount wrapper.
            account_only = "input_shard" not in row
            shard_hex = row["input_shard"] if not account_only else row["account"]
            config = bytes.fromhex(config_hex if config_hex is not None else row["config"])
            expect: Json = {}
            for source, target in (
                ("transaction_hash", "transaction_hash"),
                ("tx_hash", "transaction_hash"),
                ("account_hash", "account_hash"),
                ("shard_hash", "shard_account_hash"),
            ):
                if source in row:
                    expect[target] = row[source].upper()
            if expect:
                expect["outcome"] = "accepted"
            elif "rejected_exit" in row:
                expect = {"outcome": "rejected", "vm_exit_code": int(row["rejected_exit"])}
            tick = None
            if "is_tock" in row:
                tick = "tock" if row["is_tock"] else "tick"
            message = row.get("message")
            found.append(
                record(
                    f"{path.name}:{group}:{row.get('name', index + 1)}",
                    bytes.fromhex(shard_hex),
                    None if not message else bytes.fromhex(message),
                    expect,
                    config=config,
                    now=row.get("now"),
                    lt=row.get("lt"),
                    tick_tock=tick,
                    account_only=account_only,
                )
            )
    return found


def context_key(ctx: Json) -> Json:
    return {
        "shard": boc_hash(b64_bytes(ctx["shard_account"])),
        "account": account_hash(b64_bytes(ctx["shard_account"])),
        "message": boc_hash(b64_bytes(ctx["message"])) if "message" in ctx else None,
        "tick_tock": ctx.get("tick_tock"),
        "config": config_hash(b64_bytes(ctx["config"])),
        "now": ctx["now"],
        "lt": ctx["lt"],
    }


def matches(rec: Json, key: Json) -> bool:
    if rec["shard"] != key[rec["index"]]:
        return False
    if rec["message"] is not None and rec["message"] != key["message"]:
        return False
    if rec["tick_tock"] is not None and rec["tick_tock"] != key["tick_tock"]:
        return False
    return all(rec[field] is None or rec[field] == key[field] for field in ("config", "now", "lt"))


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    work, output = Path(argv[0]), Path(argv[1])
    entries = read_jsonl(work / "all.jsonl")
    effects = read_jsonl(work / "harness.jsonl")
    if len(entries) != len(effects):
        raise SystemExit("run txnfam_convert.py check first")
    keys = [context_key(e["context"]) for e in entries]
    index: dict[str, list[int]] = {}
    for i, key in enumerate(keys):
        index.setdefault(key["shard"], []).append(i)
        if key["account"] is not None:
            index.setdefault(key["account"], []).append(i)
    found = roots_records(output) + dump_records(output) + transcript_records(output)
    for extra in argv[2:]:
        found += report_rows(Path(extra))
    differences = 0
    names: dict[str, list[str]] = {}
    for rec in found:
        candidates = sorted({i for i in index.get(rec["shard"], []) if matches(rec, keys[i])})
        if not candidates:
            differences += 1
            if differences <= 20:
                print(f"UNMATCHED {rec['name']}")
            continue
        good = [
            i
            for i in candidates
            if all(effects[i].get(k) == v for k, v in rec["expect"].items())
            and (not rec["expect"] or effects[i]["outcome"] == rec["expect"]["outcome"])
        ]
        if not good:
            differences += 1
            if differences <= 20:
                print(
                    f"DIFF {rec['name']}: record {rec['expect']} harness {effects[candidates[0]]}"
                )
            continue
        for i in good:
            names.setdefault(entries[i]["fixture_id"], []).append(rec["name"])
    unique = read_jsonl(work / "unique.jsonl")
    for entry in unique:
        if entry["fixture_id"] in names:
            label = sorted(set(names[entry["fixture_id"]]))[0]
            entry["note"] = f"{label}; {entry['note'].split('; ')[-1]}"
    write_jsonl(work / "unique.jsonl", unique)
    covered = len(names)
    summary = {
        "records": len(found),
        "differences": differences,
        "contexts_with_record": covered,
        "contexts": len(entries),
    }
    (work / "artifacts.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(
        f"{len(found)} family records, {differences} differences; "
        f"{covered} of {len(entries)} converted calls carry a family record"
    )
    return 1 if differences or not found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
