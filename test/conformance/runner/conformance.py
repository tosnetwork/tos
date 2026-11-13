#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Conformance runner: fill fixtures from the C++ reference, compare targets, regenerate, validate.

A target is any program with the line protocol of conformance-ref-cli (see ../README.md):
``<program> <harness>`` reads one context JSON per stdin line and writes one effects JSON per
stdout line, in order. ``<program> --info`` prints the build identity and the harnesses it provides.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import subprocess
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixture_types as t  # noqa: E402
from harnesses import HARNESSES  # noqa: E402

FixtureError = t.FixtureError
Json = t.Json
HARNESS_VERSION = 1
TARGET_TIMEOUT_SECONDS = 3600
MAX_FIXTURE_LINE_BYTES = 16 << 20
DEFAULT_BLOB_THRESHOLD = 2048

METADATA_REQUIRED = {
    "harness",
    "harness_version",
    "fixture_id",
    "family",
    "source",
    "reference_commit",
}
METADATA_ALLOWED = METADATA_REQUIRED | {"note"}


def harness_module(name: object, where: str) -> Any:
    if not isinstance(name, str) or name not in HARNESSES:
        raise FixtureError(f"{where}: unknown harness {name!r}")
    return HARNESSES[name]


def validate_context(harness: str, value: object, where: str = "context") -> None:
    harness_module(harness, where).validate_context(t.obj(value, where), where)


def validate_effects(harness: str, value: object, where: str = "effects") -> None:
    harness_module(harness, where).validate_effects(t.obj(value, where), where)


def validate_fixture(value: object, where: str) -> Json:
    fixture = t.obj(value, where)
    t.keys(fixture, {"metadata", "context", "effects"}, {"metadata", "context", "effects"}, where)
    meta = t.obj(fixture["metadata"], f"{where}.metadata")
    t.keys(meta, METADATA_REQUIRED, METADATA_ALLOWED, f"{where}.metadata")
    harness = meta["harness"]
    harness_module(harness, f"{where}.metadata.harness")
    if meta["harness_version"] != HARNESS_VERSION:
        raise FixtureError(f"{where}.metadata.harness_version: {HARNESS_VERSION} required")
    t.text(meta["fixture_id"], t.FIXTURE_ID_RE, f"{where}.metadata.fixture_id")
    t.text(meta["family"], t.FAMILY_RE, f"{where}.metadata.family")
    t.text(meta["source"], t.SOURCE_RE, f"{where}.metadata.source")
    t.text(meta["reference_commit"], t.COMMIT_RE, f"{where}.metadata.reference_commit")
    if "note" in meta:
        t.any_text(meta["note"], f"{where}.metadata.note")
    validate_context(harness, fixture["context"], f"{where}.context")
    validate_effects(harness, fixture["effects"], f"{where}.effects")
    return dict(fixture)


# ---------------------------------------------------------------------------------------------
# Blobs: large BOCs shared by many fixtures are stored once per family in <family>.blobs.json
# ({"<sha256 of the BOC bytes>": "<base64>"}) and referenced as {"blob": "<sha256>"}.


def blob_digest(b64: str) -> str:
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise FixtureError(f"blob is not base64: {exc}") from exc
    return hashlib.sha256(raw).hexdigest()


def is_blob_ref(value: object) -> bool:
    return isinstance(value, dict) and set(cast(dict[str, Any], value)) == {"blob"}


def blob_refs(value: object, out: set[str]) -> set[str]:
    if is_blob_ref(value):
        out.add(cast(dict[str, str], value)["blob"])
    elif isinstance(value, dict):
        for item in cast(dict[str, Any], value).values():
            blob_refs(item, out)
    elif isinstance(value, list):
        for item in cast(list[Any], value):
            blob_refs(item, out)
    return out


def resolve(value: Any, blobs: Mapping[str, str]) -> Any:
    if is_blob_ref(value):
        digest = cast(dict[str, str], value)["blob"]
        if digest not in blobs:
            raise FixtureError(f"unresolved blob {digest}")
        return blobs[digest]
    if isinstance(value, dict):
        return {k: resolve(v, blobs) for k, v in cast(dict[str, Any], value).items()}
    if isinstance(value, list):
        return [resolve(v, blobs) for v in cast(list[Any], value)]
    return value


def externalize(value: Any, blobs: dict[str, str], threshold: int) -> Any:
    """Move every base64 BOC string longer than threshold into blobs, replacing it by a reference."""
    if isinstance(value, str) and len(value) > threshold and t.BOC_RE.match(value):
        digest = blob_digest(value)
        blobs[digest] = value
        return {"blob": digest}
    if isinstance(value, dict):
        return {k: externalize(v, blobs, threshold) for k, v in cast(dict[str, Any], value).items()}
    if isinstance(value, list):
        return [externalize(v, blobs, threshold) for v in cast(list[Any], value)]
    return value


def blobs_path(family_path: Path) -> Path:
    return family_path.with_name(family_path.stem + ".blobs.json")


def load_blobs(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    data = t.obj(json.loads(path.read_text()), str(path))
    blobs: dict[str, str] = {}
    for digest, b64 in data.items():
        t.text(digest, t.BLOB_RE, f"{path}: key")
        t.text(b64, t.BOC_RE, f"{path}: {digest}")
        if blob_digest(b64) != digest:
            raise FixtureError(f"{path}: blob {digest} does not match its content")
        blobs[digest] = b64
    return blobs


def write_blobs(path: Path, blobs: Mapping[str, str]) -> None:
    if blobs:
        path.write_text(
            json.dumps(dict(sorted(blobs.items())), indent=0, separators=(",", ":")) + "\n"
        )
    elif path.exists():
        path.unlink()


# ---------------------------------------------------------------------------------------------
# Fixture files


@dataclass
class FamilyFile:
    path: Path
    harness: str
    family: str
    fixtures: list[Json] = field(default_factory=lambda: [])
    blobs: dict[str, str] = field(default_factory=lambda: {})

    def contexts(self) -> list[Json]:
        return [cast(Json, resolve(f["context"], self.blobs)) for f in self.fixtures]


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
    blobs = load_blobs(blobs_path(path))
    refs: set[str] = set()
    for fixture in fixtures:
        blob_refs(fixture["context"], refs)
    if refs - blobs.keys():
        raise FixtureError(f"{path}: unresolved blobs {sorted(refs - blobs.keys())[:3]}")
    if blobs.keys() - refs:
        raise FixtureError(f"{path}: unreferenced blobs {sorted(blobs.keys() - refs)[:3]}")
    return FamilyFile(path, harness, family, fixtures, blobs)


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


def target_harnesses(program: str) -> set[str] | None:
    harnesses = target_info(program).get("harnesses")
    if harnesses is None:
        return None
    return {
        h for h in cast(list[Any], t.array(harnesses, "--info harnesses")) if isinstance(h, str)
    }


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
    if harnesses is None:
        harnesses = target_harnesses(target)
    tally = Tally()
    for path in family_files(paths):
        family = load_family(path)
        if harnesses is not None and family.harness not in harnesses:
            tally.skipped += len(family.fixtures)
            tally.details.append(
                f"SKIPPED {path}: harness {family.harness} not provided by the target"
            )
            continue
        responses = run_target(target, family.harness, family.contexts())
        compare_family(family, responses, tally)
    return tally


def reference_commit(reference: str, allow_dirty: bool) -> str:
    info = target_info(reference)
    commit = info.get("reference_commit")
    if not isinstance(commit, str) or not t.COMMIT_RE.match(commit):
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
    blob_threshold: int = DEFAULT_BLOB_THRESHOLD,
) -> int:
    harness_module(harness, "harness")
    t.text(family, t.FAMILY_RE, "family")
    t.text(source, t.SOURCE_RE, "source")
    commit = reference_commit(reference, allow_dirty)
    entries = read_jsonl(contexts_path)
    if not entries:
        raise FixtureError(f"{contexts_path}: no contexts")
    seen: set[str] = set()
    for i, entry in enumerate(entries):
        where = f"{contexts_path}:{i + 1}"
        t.keys(entry, {"fixture_id", "context"}, {"fixture_id", "context", "note"}, where)
        t.text(entry["fixture_id"], t.FIXTURE_ID_RE, f"{where}.fixture_id")
        if entry["fixture_id"] in seen:
            raise FixtureError(f"{where}: duplicate fixture_id {entry['fixture_id']}")
        seen.add(entry["fixture_id"])
        validate_context(harness, entry["context"], f"{where}.context")
        if blob_refs(entry["context"], set()):
            raise FixtureError(f"{where}: contexts given to create must be inline")
    responses = run_target(reference, harness, [e["context"] for e in entries])
    refusals = [
        f"{e['fixture_id']}: {r['harness_error']}"
        for e, r in zip(entries, responses, strict=True)
        if is_refusal(r)
    ]
    if refusals:
        raise FixtureError("reference refused contexts:\n  " + "\n  ".join(refusals[:20]))
    blobs: dict[str, str] = {}
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
        context = externalize(entry["context"], blobs, blob_threshold)
        fixtures.append({"metadata": meta, "context": context, "effects": response})
    write_jsonl(out, fixtures)
    write_blobs(blobs_path(out), blobs)
    load_family(out)
    print(f"created {len(fixtures)} fixtures ({len(blobs)} blobs) in {out} from {commit}")
    return len(fixtures)


def command_regenerate(
    reference: str, paths: Sequence[Path], write: bool, allow_dirty: bool = False
) -> list[str]:
    """Refill every fixture with ``reference``; return the ids whose effects changed."""
    commit = reference_commit(reference, allow_dirty or not write)
    changed: list[str] = []
    for path in family_files(paths):
        family = load_family(path)
        responses = run_target(reference, family.harness, family.contexts())
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
    names = sorted(HARNESSES)

    create = sub.add_parser("create", help="fill effects from the C++ reference")
    create.add_argument("--reference", required=True)
    create.add_argument("--harness", required=True, choices=names)
    create.add_argument("--family", required=True)
    create.add_argument("--source", required=True)
    create.add_argument("--blob-threshold", type=int, default=DEFAULT_BLOB_THRESHOLD)
    create.add_argument(
        "--allow-dirty", action="store_true", help="tests only: accept a dirty reference build"
    )
    create.add_argument("contexts", type=Path)
    create.add_argument("out", type=Path)

    run = sub.add_parser("run", help="compare a target with frozen fixtures")
    run.add_argument("--target", required=True)
    run.add_argument(
        "--harness", action="append", choices=names, help="harnesses the target provides"
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
                args.blob_threshold,
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
