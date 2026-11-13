#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""validate harness contexts from archived history (docs/validate.md).

    validate_families.py families <conformance-validate-export> <conformance-ref-cli> <vectors dir>
                         --epoch5 ROOT=SHA256LIST --epoch6 ROOT=SHA256LIST --inputs DIR --corpus DIR
        Export and fill the frozen families: rel02-chain (every REL-02 corpus block that has complete
        history), epoch6-slice (EPOCH6_RANGES of the epoch-6 network) and rel02-negative (MUTATIONS of
        two corpus blocks). The positive contexts must be accepted by the exporter before they are
        filled; ``conformance.py create`` then fills every effect from the reference.
    validate_families.py slice <conformance-validate-export> <target> <work dir>
                         --packs ROOT=SHA256LIST --zerostate MC.boc --basestate BASE.boc --mc-limit N
        Export every block of masterchain 1..N (and the shard blocks referencing them) of one archived
        network, run ``<target> validate`` on them and require every one to be accepted: the chain is
        the oracle. Exits 77 (a visible ctest skip) when an input does not exist on this host.

Packages are checked against their SHA-256 lists first (migrate/archive.py).
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "runner"))

archive: Any = importlib.import_module("archive")
c: Any = importlib.import_module("conformance")

Json = dict[str, Any]
SKIP = 77
HARNESS = "validate"
# The epoch-5 packages of the node that holds history from genesis end at masterchain 242,333; later
# REL-02 blocks have no complete previous state (docs/archive.md, "Full runs").
EPOCH5_HISTORY_END = 242_333
# The genesis of the epoch-6 network and a window deeper in its history.
EPOCH6_RANGES = ("1-100", "250001-250020")
# Authored defects: (workchain, seqno, mutation) of REL-02 corpus blocks (migrate/validate-export.cpp).
MC_BLOCK, BASE_BLOCK, OUT_MSG_BLOCK = 117_752, 118_284, 151_331
MUTATIONS: tuple[tuple[int, int, str], ...] = (
    *(
        (-1, MC_BLOCK, m)
        for m in (
            "prev_state_altered",
            "prev_block_other",
            "fees_collected_plus_one",
            "transaction_fees_plus_one",
            "account_block_removed",
            "transaction_duplicated",
            "gen_utime_earlier",
            "gen_utime_header_only",
            "gen_utime_ms_mismatch",
            "start_lt_unaligned",
            "lt_delta_oversize",
            "state_update_noop",
            "candidate_file_hash",
            "candidate_shard_other",
            "created_by_other",
        )
    ),
    *(
        (0, BASE_BLOCK, m)
        for m in (
            "prev_state_altered",
            "prev_block_other",
            "mc_state_missing",
            "fees_collected_plus_one",
            "transaction_fees_plus_one",
            "account_block_removed",
            "transaction_duplicated",
            "gen_utime_earlier",
            "start_lt_unaligned",
            "lt_delta_oversize",
            "state_update_noop",
            "candidate_shard_other",
        )
    ),
    (-1, OUT_MSG_BLOCK, "out_msg_removed"),
)
CORPUS_BLOCK = re.compile(r"^blocks/(-?\d+)-(\d+)\.boc$")


class ExportError(Exception):
    """The exporter or a target failed, or an archived block was not accepted."""


def corpus_blocks(corpus: Path) -> list[tuple[int, int]]:
    manifest = cast(Json, json.loads((corpus / "manifest.json").read_text()))
    blocks: list[tuple[int, int]] = []
    for path in cast(list[str], manifest["blocks"]):
        match = CORPUS_BLOCK.match(path)
        if match is None:
            raise ExportError(f"corpus block path {path!r}")
        blocks.append((int(match.group(1)), int(match.group(2))))
    return blocks


def rel02_targets(corpus: Path) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    """Corpus blocks with complete history, and those without (a masterchain block past the end)."""
    covered: list[tuple[int, int]] = []
    excluded: list[tuple[int, int]] = []
    for wc, seqno in corpus_blocks(corpus):
        (excluded if wc == -1 and seqno > EPOCH5_HISTORY_END else covered).append((wc, seqno))
    return covered, excluded


def export(
    exporter: str,
    packs: list[Path],
    zerostate: Path,
    basestate: Path,
    work: Path,
    name: str,
    targets: tuple[tuple[int, int], ...] = (),
    mutations: tuple[tuple[int, int, str], ...] = (),
    ranges: tuple[str, ...] = (),
) -> list[Json]:
    args = [exporter, "--packs", str(archive.write_list(work / f"{name}.packs", packs))]
    args += ["--zerostate", str(zerostate), "--basestate", str(basestate)]
    if targets:
        listing = work / f"{name}.targets"
        listing.write_text("".join(f"{wc} {seqno}\n" for wc, seqno in targets))
        args += ["--targets", str(listing)]
    if mutations:
        listing = work / f"{name}.mutations"
        listing.write_text("".join(f"{wc} {seqno} {m}\n" for wc, seqno, m in mutations))
        args += ["--mutations", str(listing)]
    for r in ranges:
        args += ["--range", r]
    out = work / f"{name}.jsonl"
    done = subprocess.run(
        [*args, "--out", str(out)], capture_output=True, text=True, timeout=3600, check=False
    )
    if done.returncode != 0:
        raise ExportError(f"{name}: exporter failed: {done.stderr.strip()[-2000:]}")
    return [cast(Json, json.loads(line)) for line in out.read_text().splitlines()]


def require_accepted_by_exporter(entries: list[Json], name: str) -> None:
    refused = [e["fixture_id"] for e in entries if "exporter: accepted" not in e["note"]]
    if refused:
        raise ExportError(f"{name}: archived blocks not accepted: {refused[:10]}")


def create_family(
    reference: str, vectors: Path, family: str, source: str, entries: list[Json]
) -> None:
    out = vectors / HARNESS / "fixtures" / f"{family}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="conformance-validate-") as directory:
        contexts = Path(directory) / "contexts.jsonl"
        contexts.write_text("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in entries))
        c.command_create(reference, HARNESS, family, source, contexts, out)


def families(args: argparse.Namespace) -> int:
    inputs = Path(args.inputs)
    covered, excluded = rel02_targets(Path(args.corpus))
    print(
        f"REL-02: {len(covered)} blocks with complete history, {len(excluded)} without: {excluded}"
    )
    with tempfile.TemporaryDirectory(prefix="conformance-validate-") as directory:
        work = Path(directory)
        e5_packs, _ = archive.verified_packs(args.epoch5, True, EPOCH5_HISTORY_END)
        e5 = (inputs / "epoch-5" / "zerostate.boc", inputs / "epoch-5" / "basestate0.boc")
        rel02 = export(args.exporter, e5_packs, *e5, work, "rel02-chain", targets=tuple(covered))
        require_accepted_by_exporter(rel02, "rel02-chain")
        negative = export(args.exporter, e5_packs, *e5, work, "rel02-negative", mutations=MUTATIONS)
        last = max(int(r.split("-")[1]) for r in EPOCH6_RANGES)
        e6_packs, _ = archive.verified_packs(args.epoch6, True, last + 101)
        e6 = (inputs / "epoch-6" / "zerostate.boc", inputs / "epoch-6" / "basestate0.boc")
        slice6 = export(args.exporter, e6_packs, *e6, work, "epoch6-slice", ranges=EPOCH6_RANGES)
        require_accepted_by_exporter(slice6, "epoch6-slice")
    vectors = Path(args.vectors)
    create_family(args.reference, vectors, "rel02-chain", "replay", rel02)
    create_family(args.reference, vectors, "epoch6-slice", "replay", slice6)
    create_family(args.reference, vectors, "rel02-negative", "authored", negative)
    return 0


def slice_test(args: argparse.Namespace) -> int:
    spec_paths = [p for p in args.packs.split("=")[:2]]
    missing = [p for p in (args.zerostate, args.basestate, *spec_paths) if not os.path.exists(p)]
    if missing:
        print(f"SKIP: archive inputs not present on this host: {missing}")
        return SKIP
    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    packs, _ = archive.verified_packs(args.packs, True, args.mc_limit + 101)
    entries = export(
        args.exporter,
        packs,
        Path(args.zerostate),
        Path(args.basestate),
        work,
        "slice",
        ranges=(f"1-{args.mc_limit}",),
    )
    stdin = "".join(json.dumps(e["context"], separators=(",", ":")) + "\n" for e in entries)
    done = subprocess.run(
        [args.target, HARNESS],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=3600,
        check=False,
    )
    if done.returncode != 0:
        raise ExportError(f"{args.target} {HARNESS} failed: {done.stderr.strip()[-2000:]}")
    effects = [cast(Json, json.loads(line)) for line in done.stdout.splitlines()]
    return check_accepted(entries, effects, args.mc_limit)


def check_accepted(entries: list[Json], effects: list[Json], mc_limit: int) -> int:
    """Every archived block must be accepted, and masterchain 1..mc_limit must all be there."""
    if len(effects) != len(entries):
        raise ExportError(f"{len(effects)} effects for {len(entries)} contexts")
    differences = 0
    for entry, effect in zip(entries, effects, strict=True):
        if effect.get("outcome") != "accepted":
            differences += 1
            print(f"NOT ACCEPTED {entry['fixture_id']}: {json.dumps(effect)}")
    mc = {str(e["fixture_id"]) for e in entries if str(e["fixture_id"]).startswith("mc-")}
    print(
        f"validated {len(entries)} archived blocks ({len(mc)} masterchain, {len(entries) - len(mc)} "
        f"shard), {differences} not accepted"
    )
    if mc != {f"mc-{s}" for s in range(1, mc_limit + 1)}:
        print(f"FAIL {len(mc)} masterchain blocks for masterchain 1..{mc_limit}")
        return 1
    return 1 if differences else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    fam = sub.add_parser("families")
    fam.add_argument("exporter")
    fam.add_argument("reference")
    fam.add_argument("vectors")
    fam.add_argument("--epoch5", required=True)
    fam.add_argument("--epoch6", required=True)
    fam.add_argument("--inputs", required=True)
    fam.add_argument("--corpus", required=True)
    sl = sub.add_parser("slice")
    sl.add_argument("exporter")
    sl.add_argument("target")
    sl.add_argument("work")
    sl.add_argument("--packs", required=True)
    sl.add_argument("--zerostate", required=True)
    sl.add_argument("--basestate", required=True)
    sl.add_argument("--mc-limit", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        return families(args) if args.command == "families" else slice_test(args)
    except (ExportError, c.FixtureError) as exc:
        print(f"validate families: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
