#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Process-level differential fuzzing for targets that are command-line programs (docs/fuzz.md).

    fuzz_process.py run --generator <conformance-fuzz> --harness vm --reference <cli> --target <cli>
        [--seeds <path>]... [--cases N] [--seed S] [--start K] [--batch B] [--out <vectors dir>]
        [--max-files M] [--expect-mismatch] [--same-mismatches-as <dir>]
    fuzz_process.py rel02-seeds <test-epoch-replay> <corpus dir> <out.jsonl>

``run`` takes the contexts from the in-process driver's ``--emit`` mode, so case i of seed S is the same
context in both drivers, sends them in batches through both programs over the line protocol of
conformance-ref-cli and writes every mismatch in the in-process driver's layout:
``<out>/<harness>/inputs/fuzz-mismatches/<lineage>/<sha256 of the canonical context>.json``.
``--same-mismatches-as`` requires the mismatch files under ``--out`` to be the ones under another directory
(same names, contexts and effects), which checks the two drivers against each other.

``rel02-seeds`` exports the REL-02 corpus as txn contexts to seed txn campaigns.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parent))

import conformance as c  # noqa: E402

Json = dict[str, Any]
FORMAT = "fuzz-mismatch-v1"
GENERATOR_TIMEOUT_SECONDS = 3600
REL02 = Path(__file__).resolve().parent.parent / "migrate" / "rel02.py"


def canonical(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def digest(context: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical(context).encode("utf-8")).hexdigest()


def emit(
    generator: str, harness: str, seeds: Sequence[str], seed: int, start: int, cases: int
) -> list[Json]:
    command = [
        generator,
        "--harness",
        harness,
        "--emit",
        "--cases",
        str(cases),
        "--seed",
        str(seed),
    ]
    command += ["--start", str(start)]
    for path in seeds:
        command += ["--seeds", path]
    done = subprocess.run(
        command, capture_output=True, text=True, timeout=GENERATOR_TIMEOUT_SECONDS, check=False
    )
    if done.returncode != 0:
        raise c.FixtureError(f"generator exited {done.returncode}: {done.stderr.strip()[-2000:]}")
    records = [cast(Json, json.loads(line)) for line in done.stdout.splitlines()]
    if len(records) != cases:
        raise c.FixtureError(f"generator emitted {len(records)} cases for {cases}")
    return records


def mismatch_document(
    harness: str,
    record: Mapping[str, Any],
    seed: int,
    names: tuple[str, str],
    effects: tuple[Any, Any],
) -> Json:
    return {
        "format": FORMAT,
        "harness": harness,
        "lineage": record["lineage"],
        "seed": seed,
        "index": record["index"],
        "reference": names[0],
        "target": names[1],
        "context": record["context"],
        "effects": {"reference": effects[0], "target": effects[1]},
    }


def mismatch_path(root: Path, harness: str, lineage: str, context: Mapping[str, Any]) -> Path:
    return root / harness / "inputs" / "fuzz-mismatches" / lineage / f"{digest(context)}.json"


def agree(reference: Mapping[str, Any], target: Mapping[str, Any]) -> str:
    """ "equal", "both-refused" or "mismatch", with the in-process driver's rules."""
    ref_refused, target_refused = c.is_refusal(reference), c.is_refusal(target)
    if ref_refused and target_refused:
        return "both-refused"
    if ref_refused or target_refused:
        return "mismatch"
    return "equal" if dict(reference) == dict(target) else "mismatch"


def campaign(args: argparse.Namespace) -> Json:
    names = (Path(args.reference).name, Path(args.target).name)
    out = Path(args.out) if args.out else None
    tally: Json = {
        "harness": args.harness,
        "seed": args.seed,
        "cases": 0,
        "equal": 0,
        "both_refused": 0,
        "mismatched": 0,
        "generator_errors": 0,
        "files_written": 0,
        "lineages": {},
    }
    began = time.monotonic()
    for start in range(args.start, args.start + args.cases, args.batch):
        count = min(args.batch, args.start + args.cases - start)
        records = emit(args.generator, args.harness, args.seeds, args.seed, start, count)
        tally["cases"] += count
        usable = [r for r in records if "context" in r]
        tally["generator_errors"] += count - len(usable)
        contexts = [cast(Json, r["context"]) for r in usable]
        reference = c.run_target(args.reference, args.harness, contexts)
        target = c.run_target(args.target, args.harness, contexts)
        for record, ref_effects, target_effects in zip(usable, reference, target, strict=True):
            lineage = tally["lineages"].setdefault(record["lineage"], {"cases": 0, "mismatched": 0})
            lineage["cases"] += 1
            verdict = agree(ref_effects, target_effects)
            if verdict == "equal":
                tally["equal"] += 1
                continue
            if verdict == "both-refused":
                tally["both_refused"] += 1
                continue
            tally["mismatched"] += 1
            lineage["mismatched"] += 1
            if out is not None and tally["files_written"] < args.max_files:
                path = mismatch_path(out, args.harness, record["lineage"], record["context"])
                path.parent.mkdir(parents=True, exist_ok=True)
                document = mismatch_document(
                    args.harness, record, args.seed, names, (ref_effects, target_effects)
                )
                path.write_text(canonical(document) + "\n")
                tally["files_written"] += 1
    seconds = time.monotonic() - began
    tally["milliseconds"] = int(seconds * 1000)
    tally["cases_per_second"] = int(tally["cases"] / seconds) if seconds > 0 else 0
    return tally


def mismatch_files(root: Path) -> dict[str, Json]:
    found: dict[str, Json] = {}
    for path in sorted(root.rglob("*.json")):
        if "fuzz-mismatches" in path.parts:
            found[str(path.relative_to(root))] = cast(Json, json.loads(path.read_text()))
    return found


def same_mismatches(ours: Path, theirs: Path) -> list[str]:
    """Differences between two mismatch trees, ignoring which program names each side carries."""
    a, b = mismatch_files(ours), mismatch_files(theirs)
    problems = [f"only in {ours}: {name}" for name in sorted(a.keys() - b.keys())]
    problems += [f"only in {theirs}: {name}" for name in sorted(b.keys() - a.keys())]
    for name in sorted(a.keys() & b.keys()):
        for key in ("format", "harness", "lineage", "seed", "index", "context", "effects"):
            if a[name].get(key) != b[name].get(key):
                problems.append(f"{name}: {key} differs")
    if not a and not b:
        problems.append("no mismatch files on either side")
    return problems


def load_rel02() -> Any:
    """migrate/rel02.py, whose row-to-context conversion the REL-02 chain check also uses."""
    spec = importlib.util.spec_from_file_location("rel02", REL02)
    if spec is None or spec.loader is None:
        raise c.FixtureError(f"cannot load {REL02}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rel02_seeds(replay: Path, corpus: Path, out: Path) -> int:
    rel02 = load_rel02()

    manifest = json.loads((corpus / "manifest.json").read_text())
    with tempfile.TemporaryDirectory(prefix="conformance-fuzz-rel02-") as directory:
        work = Path(directory)
        lists: list[str] = []
        for name in ("blocks", "supplements"):
            listing = work / name
            listing.write_text("".join(str(corpus / p) + "\n" for p in manifest[name]))
            lists.append(str(listing))
        dump = work / "dump.tsv"
        done = subprocess.run(
            [str(replay), "--dump", *lists, str(dump)],
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )
        if done.returncode != 0:
            raise c.FixtureError(f"replay export failed: {done.stderr.strip()[-2000:]}")
        entries = rel02.contexts(dump)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(canonical({"context": e["context"]}) + "\n" for e in entries))
    print(f"{len(entries)} txn seed contexts in {out}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="differential campaign over two command-line targets")
    run.add_argument(
        "--generator", required=True, help="conformance-fuzz (its --emit mode is used)"
    )
    run.add_argument("--harness", required=True, choices=sorted(c.HARNESSES))
    run.add_argument("--reference", required=True)
    run.add_argument("--target", required=True)
    run.add_argument("--seeds", action="append", default=[])
    run.add_argument("--cases", type=int, default=1000)
    run.add_argument("--seed", type=int, default=1)
    run.add_argument("--start", type=int, default=0)
    run.add_argument("--batch", type=int, default=2000)
    run.add_argument("--out")
    run.add_argument("--max-files", type=int, default=1000)
    run.add_argument("--expect-mismatch", action="store_true")
    run.add_argument("--same-mismatches-as")
    seeds = sub.add_parser("rel02-seeds", help="export the REL-02 corpus as txn seed contexts")
    seeds.add_argument("replay", type=Path)
    seeds.add_argument("corpus", type=Path)
    seeds.add_argument("out", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "rel02-seeds":
            return rel02_seeds(args.replay, args.corpus, args.out)
        if args.cases < 1 or args.batch < 1 or args.seed < 0 or args.start < 0:
            parser.error("--cases and --batch must be positive, --seed and --start non-negative")
        if args.same_mismatches_as and not args.out:
            parser.error("--same-mismatches-as needs --out")
        tally = campaign(args)
        print(canonical(tally))
        if tally["cases"] == tally["generator_errors"]:
            print("error: no case was compared", file=sys.stderr)
            return 1
        if args.same_mismatches_as:
            problems = same_mismatches(Path(args.out), Path(args.same_mismatches_as))
            for problem in problems[:20]:
                print(f"DIFFERENT {problem}", file=sys.stderr)
            if problems:
                return 1
        if args.expect_mismatch:
            return 0 if tally["mismatched"] > 0 else 1
        return 0 if tally["mismatched"] == 0 else 1
    except (c.FixtureError, json.JSONDecodeError, subprocess.TimeoutExpired, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
