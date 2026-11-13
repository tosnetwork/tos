#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Build the frozen block and get_method families from the REL-02 corpus.

    block_families.py contexts <conformance-block-export> <corpus dir> <out dir>
        Write one context file per family into <out dir> (see FAMILIES).
    block_families.py create <conformance-block-export> <reference> <corpus dir> <vectors dir>
        Write the contexts to a temporary directory and fill every family with
        ``conformance.py create`` from the reference (a clean-tree build) into <vectors dir>.

Families:
    block/rel02-negative           authored defects of corpus blocks (conformance-block-export negatives)
    get_method/rel02-getters       elector, config and other getters on corpus account states
    get_method/rust-get-context, rust-get-history-context, rust-get-method-id-context
                                   the Rust node's getter-context test families, rebuilt
    get_method/c7-shape            the rows of test/validator/data/getter-c7-shape.tsv

The positive block cases are not frozen: block_chain.py checks every corpus block against the chain.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple, cast

RUNNER = Path(__file__).resolve().parent.parent / "runner" / "conformance.py"
# Small snapshots and accounts recur across many contexts of a family; store them once.
BLOB_THRESHOLD = 512


class Family(NamedTuple):
    harness: str
    name: str
    source: str
    command: str  # conformance-block-export command that writes the contexts


FAMILIES = (
    Family("block", "rel02-negative", "authored", "negatives"),
    Family("get_method", "rel02-getters", "replay", "getters"),
    Family("get_method", "rust-get-context", "migrated:rust-node/get-context", "rust-families"),
    Family(
        "get_method",
        "rust-get-history-context",
        "migrated:rust-node/get-history-context",
        "rust-families",
    ),
    Family(
        "get_method",
        "rust-get-method-id-context",
        "migrated:rust-node/get-method-id-context",
        "rust-families",
    ),
    Family("get_method", "c7-shape", "migrated:validator/getter-c7-shape", "rust-families"),
)


def run(command: list[str]) -> None:
    done = subprocess.run(command, capture_output=True, text=True, timeout=1800, check=False)
    if done.returncode != 0:
        raise SystemExit(f"{command[0]} failed: {(done.stderr or done.stdout).strip()[-2000:]}")
    if done.stderr.strip():
        print(done.stderr.strip())


def contexts(exporter: Path, corpus: Path, out: Path) -> dict[str, Path]:
    manifest = cast(dict[str, list[str]], json.loads((corpus / "manifest.json").read_text()))
    out.mkdir(parents=True, exist_ok=True)
    lists: list[str] = []
    for name in ("blocks", "supplements"):
        listing = out / f"{name}.list"
        listing.write_text("".join(str(corpus / p) + "\n" for p in manifest[name]))
        lists.append(str(listing))
    files: dict[str, Path] = {}
    for family in FAMILIES:
        files[family.name] = out / f"{family.name}.jsonl"
    run([str(exporter), "negatives", *lists, str(files["rel02-negative"])])
    run([str(exporter), "getters", *lists, str(files["rel02-getters"])])
    run([str(exporter), "rust-families", *lists, str(out)])
    for family in FAMILIES:
        if not files[family.name].is_file():
            raise SystemExit(f"the export wrote no {files[family.name].name}")
    return files


def create(exporter: Path, reference: Path, corpus: Path, vectors: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="conformance-block-families-") as directory:
        files = contexts(exporter, corpus, Path(directory))
        for family in FAMILIES:
            target = vectors / family.harness / "fixtures" / f"{family.name}.jsonl"
            target.parent.mkdir(parents=True, exist_ok=True)
            run(
                [
                    sys.executable,
                    str(RUNNER),
                    "create",
                    "--reference",
                    str(reference),
                    "--harness",
                    family.harness,
                    "--family",
                    family.name,
                    "--source",
                    family.source,
                    "--blob-threshold",
                    str(BLOB_THRESHOLD),
                    str(files[family.name]),
                    str(target),
                ]
            )


def main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[0] == "contexts":
        contexts(Path(argv[1]), Path(argv[2]), Path(argv[3]))
        return 0
    if len(argv) == 5 and argv[0] == "create":
        create(Path(argv[1]), Path(argv[2]), Path(argv[3]), Path(argv[4]))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
