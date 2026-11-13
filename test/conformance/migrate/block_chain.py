#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Apply every REL-02 corpus block through the block harness and check the result against the chain.

    block_chain.py chain <conformance-block-export> <target> <corpus dir>
        Export one block context per corpus block, run ``<target> block`` on them and require each
        effect to be ``accepted`` with the on-chain block root hash, new state hash and the ordered
        on-chain transaction and new account hashes.
    block_chain.py check <corpus dir> <contexts.jsonl> <effects.jsonl>
        The check alone, for contexts exported with ``conformance-block-export blocks``.

The expected values are the corpus manifest's ``expected`` records, decoded from the original block
and transaction BOCs independently of the transaction emulator: the chain is the oracle, so neither
implementation supplies them. These contexts are not frozen as fixtures (about 29 MB of states):
the corpus already in the tree is the input.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

Json = dict[str, Any]


class ChainError(Exception):
    """The corpus manifest or a harness response has an unexpected shape."""


def chain_records(corpus: Path) -> dict[str, Json]:
    """Per block root hash: the block's new state hash and its transactions in replay order."""
    manifest = cast(Json, json.loads((corpus / "manifest.json").read_text()))
    by_root: dict[str, Json] = {}
    current: Json | None = None
    for record in cast(list[Json], manifest["expected"]):
        if record["kind"] == "block":
            current = {
                "block_root_hash": record["root_hash"],
                "new_state_hash": record["new_state_hash"],
                "transactions": [],
            }
            if record["root_hash"] in by_root:
                raise ChainError(f"block {record['root_hash']} listed twice")
            by_root[record["root_hash"]] = current
        elif record["kind"] == "transaction":
            if current is None:
                raise ChainError("transaction record before any block record")
            cast(list[Json], current["transactions"]).append(
                {"transaction_hash": record["result_hash"], "account_hash": record["account_hash"]}
            )
        else:
            raise ChainError(f"unknown expected record kind {record['kind']!r}")
    if len(by_root) != len(cast(list[Any], manifest["blocks"])):
        raise ChainError(
            f"{len(by_root)} expected blocks for {len(manifest['blocks'])} corpus blocks"
        )
    return by_root


def check(corpus: Path, contexts: Path, effects_path: Path) -> int:
    expected = chain_records(corpus)
    entries = [cast(Json, json.loads(line)) for line in contexts.read_text().splitlines()]
    effects = [cast(Json, json.loads(line)) for line in effects_path.read_text().splitlines()]
    if len(entries) != len(expected) or len(effects) != len(entries):
        raise ChainError(
            f"{len(entries)} contexts and {len(effects)} effects for {len(expected)} blocks"
        )
    differences = 0
    transactions = 0
    seen: set[str] = set()
    for entry, effect in zip(entries, effects, strict=True):
        note = cast(str, entry["note"])
        root = note.rsplit(" ", 1)[-1]
        if root not in expected or root in seen:
            raise ChainError(f"{entry['fixture_id']}: block {root} not in the manifest once")
        seen.add(root)
        want: Json = {"outcome": "accepted", **expected[root]}
        transactions += len(cast(list[Any], want["transactions"]))
        if effect != want:
            differences += 1
            print(
                f"DIFF {entry['fixture_id']}: chain {json.dumps(want)} harness {json.dumps(effect)}"
            )
    print(
        f"checked {len(entries)} blocks and {transactions} transactions against the chain, "
        f"{differences} differences"
    )
    return 1 if differences else 0


def chain(exporter: Path, target: Path, corpus: Path) -> int:
    manifest = cast(Json, json.loads((corpus / "manifest.json").read_text()))
    with tempfile.TemporaryDirectory(prefix="conformance-block-") as directory:
        work = Path(directory)
        lists: list[str] = []
        for name in ("blocks", "supplements"):
            listing = work / name
            listing.write_text(
                "".join(str(corpus / p) + "\n" for p in cast(list[str], manifest[name]))
            )
            lists.append(str(listing))
        contexts = work / "contexts.jsonl"
        exported = subprocess.run(
            [str(exporter), "blocks", *lists, str(contexts)],
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )
        if exported.returncode != 0:
            raise ChainError(f"block export failed: {exported.stderr.strip()[-2000:]}")
        stdin = "".join(
            json.dumps(json.loads(line)["context"], separators=(",", ":")) + "\n"
            for line in contexts.read_text().splitlines()
        )
        executed = subprocess.run(
            [str(target), "block"],
            input=stdin,
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )
        if executed.returncode != 0:
            raise ChainError(f"{target} block failed: {executed.stderr.strip()[-2000:]}")
        effects = work / "effects.jsonl"
        effects.write_text(executed.stdout)
        return check(corpus, contexts, effects)


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 4 and argv[0] == "chain":
            return chain(Path(argv[1]), Path(argv[2]), Path(argv[3]))
        if len(argv) == 4 and argv[0] == "check":
            return check(Path(argv[1]), Path(argv[2]), Path(argv[3]))
    except (ChainError, KeyError, ValueError) as exc:
        print(f"block chain check: {exc}", file=sys.stderr)
        return 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
