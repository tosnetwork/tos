#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Conformance runner: fill fixtures from the C++ reference, compare targets, regenerate, validate.

A target is any program with the line protocol of conformance-ref-cli (see ../README.md):
``<program> <harness>`` reads one context JSON per stdin line and writes one effects JSON per
stdout line, in order. ``<program> --info`` prints the build identity.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

HARNESSES = ("vm", "txn")
HARNESS_VERSION = 1
TARGET_TIMEOUT_SECONDS = 3600
MAX_FIXTURE_LINE_BYTES = 16 << 20

Json = dict[str, Any]


class FixtureError(Exception):
    """A fixture, context or target response does not have the required shape."""


# ---------------------------------------------------------------------------------------------
# Structural validation. Mirrors schema/fixture-v1.schema.json; test_conformance.py checks that the
# required/allowed key sets below match the schema file.

BOC_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
HASH_RE = re.compile(r"^[0-9A-F]{64}$")
SEED_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
FIXTURE_ID_RE = re.compile(r"^[A-Za-z0-9._:/+-]{1,200}$")
FAMILY_RE = re.compile(r"^[a-z0-9-]{1,64}$")
SOURCE_RE = re.compile(r"^(authored|fuzz|replay|migrated:[a-z0-9_./-]+)$")
INT_TEXT_RE = re.compile(r"^-?[0-9]{1,80}$")

METADATA_REQUIRED = {
    "harness",
    "harness_version",
    "fixture_id",
    "family",
    "source",
    "reference_commit",
}
METADATA_ALLOWED = METADATA_REQUIRED | {"note"}
VM_CONTEXT_REQUIRED = {"code", "global_version", "gas", "stack"}
VM_CONTEXT_ALLOWED = VM_CONTEXT_REQUIRED | {"data", "c7", "flags", "libraries"}
VM_EFFECTS_REQUIRED = {"exit_code", "gas_used", "steps", "committed", "c4_hash", "c5_hash", "stack"}
TXN_CONTEXT_REQUIRED = {"config", "shard_account", "now", "lt", "rand_seed"}
TXN_CONTEXT_ALLOWED = TXN_CONTEXT_REQUIRED | {"message", "tick_tock", "libraries", "prev_blocks"}
TXN_EFFECTS_KEYS = {
    "accepted": {"outcome", "transaction_hash", "account_hash", "shard_account_hash"},
    "rejected": {"outcome", "vm_exit_code"},
    "error": {"outcome"},
}


def _keys(obj: Mapping[str, Any], required: set[str], allowed: set[str], where: str) -> None:
    missing = required - obj.keys()
    extra = obj.keys() - allowed
    if missing:
        raise FixtureError(f"{where}: missing {sorted(missing)}")
    if extra:
        raise FixtureError(f"{where}: unexpected {sorted(extra)}")


def _int(value: object, where: str, low: int | None = None, high: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise FixtureError(f"{where}: integer required")
    if (low is not None and value < low) or (high is not None and value > high):
        raise FixtureError(f"{where}: {value} out of range")
    return value


def _str(value: object, pattern: re.Pattern[str], where: str) -> str:
    if not isinstance(value, str) or not pattern.match(value):
        raise FixtureError(f"{where}: invalid value")
    return value


def _obj(value: object, where: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise FixtureError(f"{where}: object required")
    return cast(Mapping[str, Any], value)


def _list(value: object, where: str, max_items: int | None = None) -> list[Any]:
    if not isinstance(value, list):
        raise FixtureError(f"{where}: array required")
    items = cast(list[Any], value)
    if max_items is not None and len(items) > max_items:
        raise FixtureError(f"{where}: more than {max_items} items")
    return items


def validate_stack_item(value: object, where: str, depth: int = 0) -> None:
    if depth > 32:
        raise FixtureError(f"{where}: nesting too deep")
    item = _obj(value, where)
    kind = item.get("type")
    if kind in ("null", "nan"):
        _keys(item, {"type"}, {"type"}, where)
    elif kind == "int":
        _keys(item, {"type", "value"}, {"type", "value"}, where)
        _str(item["value"], INT_TEXT_RE, f"{where}.value")
    elif kind in ("cell", "slice"):
        _keys(item, {"type", "boc"}, {"type", "boc"}, where)
        _str(item["boc"], BOC_RE, f"{where}.boc")
    elif kind == "tuple":
        _keys(item, {"type", "items"}, {"type", "items"}, where)
        for i, sub in enumerate(_list(item["items"], f"{where}.items", 255)):
            validate_stack_item(sub, f"{where}.items[{i}]", depth + 1)
    else:
        raise FixtureError(f"{where}: unknown stack item type {kind!r}")


def validate_context(harness: str, value: object, where: str = "context") -> None:
    ctx = _obj(value, where)
    if harness == "vm":
        _keys(ctx, VM_CONTEXT_REQUIRED, VM_CONTEXT_ALLOWED, where)
        _str(ctx["code"], BOC_RE, f"{where}.code")
        _int(ctx["global_version"], f"{where}.global_version", 0, 255)
        if "flags" in ctx:
            _int(ctx["flags"], f"{where}.flags", 0, 255)
        if "data" in ctx:
            _str(ctx["data"], BOC_RE, f"{where}.data")
        if "c7" in ctx:
            validate_stack_item(ctx["c7"], f"{where}.c7")
            if _obj(ctx["c7"], f"{where}.c7").get("type") != "tuple":
                raise FixtureError(f"{where}.c7: tuple required")
        gas = _obj(ctx["gas"], f"{where}.gas")
        _keys(gas, {"limit", "max"}, {"limit", "max", "credit"}, f"{where}.gas")
        for key in gas:
            _int(gas[key], f"{where}.gas.{key}", 0)
        for i, item in enumerate(_list(ctx["stack"], f"{where}.stack", 255)):
            validate_stack_item(item, f"{where}.stack[{i}]")
        for i, lib in enumerate(_list(ctx.get("libraries", []), f"{where}.libraries", 4)):
            _str(lib, BOC_RE, f"{where}.libraries[{i}]")
    elif harness == "txn":
        _keys(ctx, TXN_CONTEXT_REQUIRED, TXN_CONTEXT_ALLOWED, where)
        for key in ("config", "shard_account", "message", "libraries", "prev_blocks"):
            if key in ctx:
                _str(ctx[key], BOC_RE, f"{where}.{key}")
        if ("message" in ctx) == ("tick_tock" in ctx):
            raise FixtureError(f"{where}: exactly one of message and tick_tock")
        if "tick_tock" in ctx and ctx["tick_tock"] not in ("tick", "tock"):
            raise FixtureError(f"{where}.tick_tock: tick or tock")
        _int(ctx["now"], f"{where}.now", 1, 0xFFFFFFFF)
        _int(ctx["lt"], f"{where}.lt", 1)
        _str(ctx["rand_seed"], SEED_RE, f"{where}.rand_seed")
    else:
        raise FixtureError(f"{where}: unknown harness {harness!r}")


def validate_effects(harness: str, value: object, where: str = "effects") -> None:
    eff = _obj(value, where)
    if harness == "vm":
        _keys(eff, VM_EFFECTS_REQUIRED, VM_EFFECTS_REQUIRED, where)
        for key in ("exit_code", "gas_used", "steps"):
            _int(eff[key], f"{where}.{key}")
        if not isinstance(eff["committed"], bool):
            raise FixtureError(f"{where}.committed: boolean required")
        for key in ("c4_hash", "c5_hash"):
            if eff[key] is not None:
                _str(eff[key], HASH_RE, f"{where}.{key}")
        for i, item in enumerate(_list(eff["stack"], f"{where}.stack")):
            if not isinstance(item, str):
                raise FixtureError(f"{where}.stack[{i}]: string required")
    elif harness == "txn":
        outcome = eff.get("outcome")
        if outcome not in TXN_EFFECTS_KEYS:
            raise FixtureError(f"{where}.outcome: invalid {outcome!r}")
        keys = TXN_EFFECTS_KEYS[outcome]
        _keys(eff, keys, keys, where)
        for key in ("transaction_hash", "account_hash", "shard_account_hash"):
            if key in eff:
                _str(eff[key], HASH_RE, f"{where}.{key}")
        if "vm_exit_code" in eff:
            _int(eff["vm_exit_code"], f"{where}.vm_exit_code")
    else:
        raise FixtureError(f"{where}: unknown harness {harness!r}")


def validate_fixture(value: object, where: str) -> Json:
    fixture = _obj(value, where)
    _keys(fixture, {"metadata", "context", "effects"}, {"metadata", "context", "effects"}, where)
    meta = _obj(fixture["metadata"], f"{where}.metadata")
    _keys(meta, METADATA_REQUIRED, METADATA_ALLOWED, f"{where}.metadata")
    harness = meta["harness"]
    if harness not in HARNESSES:
        raise FixtureError(f"{where}.metadata.harness: unknown {harness!r}")
    if meta["harness_version"] != HARNESS_VERSION:
        raise FixtureError(f"{where}.metadata.harness_version: {HARNESS_VERSION} required")
    _str(meta["fixture_id"], FIXTURE_ID_RE, f"{where}.metadata.fixture_id")
    _str(meta["family"], FAMILY_RE, f"{where}.metadata.family")
    _str(meta["source"], SOURCE_RE, f"{where}.metadata.source")
    _str(meta["reference_commit"], COMMIT_RE, f"{where}.metadata.reference_commit")
    if "note" in meta and not isinstance(meta["note"], str):
        raise FixtureError(f"{where}.metadata.note: string required")
    validate_context(harness, fixture["context"], f"{where}.context")
    validate_effects(harness, fixture["effects"], f"{where}.effects")
    return dict(fixture)


# ---------------------------------------------------------------------------------------------
# Fixture files


@dataclass
class FamilyFile:
    path: Path
    harness: str
    family: str
    fixtures: list[Json] = field(default_factory=lambda: [])


def read_jsonl(path: Path) -> list[Json]:
    records: list[Json] = []
    with path.open("rb") as handle:
        for number, raw in enumerate(handle, 1):
            if len(raw) > MAX_FIXTURE_LINE_BYTES:
                raise FixtureError(f"{path}:{number}: line too long")
            line = raw.decode("utf-8").rstrip("\n")
            if not line:
                raise FixtureError(f"{path}:{number}: empty line")
            value = json.loads(line)
            if not isinstance(value, dict):
                raise FixtureError(f"{path}:{number}: object required")
            records.append(cast(Json, value))
    return records


def write_jsonl(path: Path, records: Iterable[Mapping[str, Any]]) -> None:
    text = "".join(
        json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n" for record in records
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def family_files(paths: Sequence[Path]) -> list[Path]:
    found: list[Path] = []
    for path in paths:
        if path.is_dir():
            found.extend(sorted(path.rglob("*.jsonl")))
        elif path.is_file():
            found.append(path)
        else:
            raise FixtureError(f"{path}: no such file or directory")
    if not found:
        raise FixtureError("no fixture files found")
    return found


def load_family(path: Path) -> FamilyFile:
    records = read_jsonl(path)
    if not records:
        raise FixtureError(f"{path}: no fixtures")
    fixtures = [validate_fixture(record, f"{path}:{i + 1}") for i, record in enumerate(records)]
    harness = fixtures[0]["metadata"]["harness"]
    family = fixtures[0]["metadata"]["family"]
    seen: set[str] = set()
    for i, fixture in enumerate(fixtures):
        meta = fixture["metadata"]
        if meta["harness"] != harness or meta["family"] != family:
            raise FixtureError(f"{path}:{i + 1}: one harness and family per file")
        if meta["fixture_id"] in seen:
            raise FixtureError(f"{path}:{i + 1}: duplicate fixture_id {meta['fixture_id']}")
        seen.add(meta["fixture_id"])
    if (
        path.name != f"{family}.jsonl"
        or path.parent.name != "fixtures"
        or path.parent.parent.name != harness
    ):
        raise FixtureError(
            f"{path}: expected <harness>/fixtures/<family>.jsonl for {harness}/{family}"
        )
    return FamilyFile(path, harness, family, fixtures)


# ---------------------------------------------------------------------------------------------
# Targets


def target_info(program: str) -> Json:
    done = subprocess.run(
        [program, "--info"], capture_output=True, text=True, timeout=60, check=False
    )
    if done.returncode != 0:
        raise FixtureError(f"{program} --info failed: {done.stderr.strip()}")
    info = json.loads(done.stdout)
    if not isinstance(info, dict):
        raise FixtureError(f"{program} --info: object required")
    return cast(Json, info)


def run_target(program: str, harness: str, contexts: Sequence[Mapping[str, Any]]) -> list[Json]:
    """Run one batch through a target; exactly one response object per context, in order."""
    stdin = "".join(json.dumps(ctx, separators=(",", ":")) + "\n" for ctx in contexts)
    done = subprocess.run(
        [program, harness],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=TARGET_TIMEOUT_SECONDS,
        check=False,
    )
    if done.returncode != 0:
        raise FixtureError(
            f"{program} {harness} exited {done.returncode}: {done.stderr.strip()[-2000:]}"
        )
    lines = done.stdout.splitlines()
    if len(lines) != len(contexts):
        raise FixtureError(
            f"{program} {harness}: {len(lines)} responses for {len(contexts)} contexts"
        )
    responses: list[Json] = []
    for i, line in enumerate(lines):
        value = json.loads(line)
        if not isinstance(value, dict):
            raise FixtureError(f"{program} {harness}: response {i + 1} is not an object")
        responses.append(cast(Json, value))
    return responses


def is_refusal(response: Mapping[str, Any]) -> bool:
    return set(response) == {"harness_error"}


# ---------------------------------------------------------------------------------------------
# Commands


@dataclass
class Tally:
    compared: int = 0
    equal: int = 0
    mismatched: int = 0
    refused: int = 0
    skipped: int = 0
    details: list[str] = field(default_factory=lambda: [])

    def line(self) -> str:
        return (
            f"compared {self.compared}, equal {self.equal}, mismatched {self.mismatched}, "
            f"refused {self.refused}, skipped {self.skipped}"
        )

    def ok(self) -> bool:
        return (
            self.compared > 0
            and self.equal == self.compared
            and not (self.mismatched or self.refused or self.skipped)
        )


def diff_fields(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> list[str]:
    keys = sorted(set(expected) | set(actual))
    return [
        f"{key}: expected {json.dumps(expected.get(key))} got {json.dumps(actual.get(key))}"
        for key in keys
        if expected.get(key) != actual.get(key)
    ]


def compare_family(
    family: FamilyFile, responses: Sequence[Mapping[str, Any]], tally: Tally
) -> None:
    for fixture, response in zip(family.fixtures, responses, strict=True):
        fixture_id = f"{family.harness}/{family.family}/{fixture['metadata']['fixture_id']}"
        tally.compared += 1
        if is_refusal(response):
            tally.refused += 1
            tally.details.append(f"REFUSED {fixture_id}: {response['harness_error']}")
            continue
        try:
            validate_effects(family.harness, response, "response")
        except FixtureError as exc:
            tally.mismatched += 1
            tally.details.append(f"MISMATCH {fixture_id}: malformed response: {exc}")
            continue
        if response == fixture["effects"]:
            tally.equal += 1
        else:
            tally.mismatched += 1
            tally.details.append(
                f"MISMATCH {fixture_id}: " + "; ".join(diff_fields(fixture["effects"], response))
            )


def command_run(target: str, paths: Sequence[Path], harnesses: set[str] | None = None) -> Tally:
    tally = Tally()
    for path in family_files(paths):
        family = load_family(path)
        if harnesses is not None and family.harness not in harnesses:
            tally.skipped += len(family.fixtures)
            tally.details.append(
                f"SKIPPED {path}: harness {family.harness} not provided by the target"
            )
            continue
        responses = run_target(target, family.harness, [f["context"] for f in family.fixtures])
        compare_family(family, responses, tally)
    return tally


def reference_commit(reference: str, allow_dirty: bool) -> str:
    info = target_info(reference)
    commit = info.get("reference_commit")
    if not isinstance(commit, str) or not COMMIT_RE.match(commit):
        raise FixtureError(f"{reference}: no reference commit in --info")
    if info.get("dirty") is not False and not allow_dirty:
        raise FixtureError(
            f"{reference}: built from a tree with uncommitted changes; refusing to fill"
        )
    return commit


def command_create(
    reference: str,
    harness: str,
    family: str,
    source: str,
    contexts_path: Path,
    out: Path,
    allow_dirty: bool = False,
) -> int:
    if harness not in HARNESSES:
        raise FixtureError(f"unknown harness {harness!r}")
    _str(family, FAMILY_RE, "family")
    _str(source, SOURCE_RE, "source")
    commit = reference_commit(reference, allow_dirty)
    entries = read_jsonl(contexts_path)
    if not entries:
        raise FixtureError(f"{contexts_path}: no contexts")
    seen: set[str] = set()
    for i, entry in enumerate(entries):
        where = f"{contexts_path}:{i + 1}"
        _keys(entry, {"fixture_id", "context"}, {"fixture_id", "context", "note"}, where)
        _str(entry["fixture_id"], FIXTURE_ID_RE, f"{where}.fixture_id")
        if entry["fixture_id"] in seen:
            raise FixtureError(f"{where}: duplicate fixture_id {entry['fixture_id']}")
        seen.add(entry["fixture_id"])
        validate_context(harness, entry["context"], f"{where}.context")
    responses = run_target(reference, harness, [e["context"] for e in entries])
    refusals = [
        f"{e['fixture_id']}: {r['harness_error']}"
        for e, r in zip(entries, responses, strict=True)
        if is_refusal(r)
    ]
    if refusals:
        raise FixtureError("reference refused contexts:\n  " + "\n  ".join(refusals))
    fixtures: list[Json] = []
    for entry, response in zip(entries, responses, strict=True):
        validate_effects(harness, response, f"effects of {entry['fixture_id']}")
        meta: Json = {
            "harness": harness,
            "harness_version": HARNESS_VERSION,
            "fixture_id": entry["fixture_id"],
            "family": family,
            "source": source,
            "reference_commit": commit,
        }
        if "note" in entry:
            meta["note"] = entry["note"]
        fixtures.append({"metadata": meta, "context": entry["context"], "effects": response})
    write_jsonl(out, fixtures)
    load_family(out)
    print(f"created {len(fixtures)} fixtures in {out} from {commit}")
    return len(fixtures)


def command_regenerate(
    reference: str, paths: Sequence[Path], write: bool, allow_dirty: bool = False
) -> list[str]:
    """Refill every fixture with ``reference``; return the ids whose effects changed."""
    commit = reference_commit(reference, allow_dirty or not write)
    changed: list[str] = []
    for path in family_files(paths):
        family = load_family(path)
        responses = run_target(reference, family.harness, [f["context"] for f in family.fixtures])
        updated: list[Json] = []
        for fixture, response in zip(family.fixtures, responses, strict=True):
            fixture_id = f"{family.harness}/{family.family}/{fixture['metadata']['fixture_id']}"
            if is_refusal(response):
                raise FixtureError(
                    f"{fixture_id}: reference refused the context: {response['harness_error']}"
                )
            validate_effects(family.harness, response, fixture_id)
            if response != fixture["effects"]:
                changed.append(
                    fixture_id + ": " + "; ".join(diff_fields(fixture["effects"], response))
                )
            meta = dict(fixture["metadata"])
            meta["reference_commit"] = commit
            updated.append({"metadata": meta, "context": fixture["context"], "effects": response})
        if write:
            write_jsonl(path, updated)
    return changed


def command_validate(paths: Sequence[Path]) -> int:
    total = 0
    for path in family_files(paths):
        total += len(load_family(path).fixtures)
    return total


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="fill effects from the C++ reference")
    create.add_argument("--reference", required=True)
    create.add_argument("--harness", required=True, choices=HARNESSES)
    create.add_argument("--family", required=True)
    create.add_argument("--source", required=True)
    create.add_argument(
        "--allow-dirty", action="store_true", help="tests only: accept a dirty reference build"
    )
    create.add_argument("contexts", type=Path)
    create.add_argument("out", type=Path)

    run = sub.add_parser("run", help="compare a target with frozen fixtures")
    run.add_argument("--target", required=True)
    run.add_argument(
        "--harness", action="append", choices=HARNESSES, help="harnesses the target provides"
    )
    run.add_argument("paths", type=Path, nargs="+")

    regenerate = sub.add_parser("regenerate", help="refill fixtures with a new reference build")
    regenerate.add_argument("--reference", required=True)
    regenerate.add_argument("--write", action="store_true", help="rewrite the fixture files")
    regenerate.add_argument(
        "--allow-dirty", action="store_true", help="tests only: accept a dirty reference build"
    )
    regenerate.add_argument("paths", type=Path, nargs="+")

    validate = sub.add_parser("validate", help="check fixture files")
    validate.add_argument("paths", type=Path, nargs="+")

    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            command_create(
                args.reference,
                args.harness,
                args.family,
                args.source,
                args.contexts,
                args.out,
                args.allow_dirty,
            )
            return 0
        if args.command == "run":
            harnesses = set(cast(list[str], args.harness)) if args.harness else None
            tally = command_run(args.target, args.paths, harnesses)
            for detail in tally.details:
                print(detail)
            print(tally.line())
            return 0 if tally.ok() else 1
        if args.command == "regenerate":
            changed = command_regenerate(args.reference, args.paths, args.write, args.allow_dirty)
            for line in changed:
                print(f"CHANGED {line}")
            print(f"changed {len(changed)}")
            return 0
        count = command_validate(args.paths)
        print(f"valid {count} fixtures")
        return 0
    except (FixtureError, json.JSONDecodeError, subprocess.TimeoutExpired, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
