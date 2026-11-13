#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Turn the REL-02 per-transaction export into txn-harness contexts and check them against the chain.

    rel02.py contexts <dump.tsv> <contexts.jsonl>
        Convert the 18-field ``#rel02-v2`` rows of ``test-epoch-replay --dump`` into contexts.
    rel02.py check <dump.tsv> <effects.jsonl>
        Require every effect to be an accepted transaction whose transaction and account hashes are
        the on-chain ones recorded in the same row. The chain is the oracle: neither implementation
        supplies the expected values.
    rel02.py chain <test-epoch-replay> <target> <corpus dir>
        Both steps in a temporary directory: export the corpus, run ``<target> txn``, check.

Row fields (emulator/test/epoch-replay.cpp): type (1 ordinary, 3 tick, 4 tock), now, lt, seed,
input ShardAccount, inbound message, config, global libraries, previous blocks, on-chain
transaction hash, on-chain new account hash, original transaction, workchain, shard, block
seqno, block root hash, source file hash, post-account depth. Cells are hex BOCs, ``-`` for none.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

Json = dict[str, Any]
TICK_TOCK = {"3": "tick", "4": "tock"}


def b64(hex_boc: str) -> str:
    return base64.b64encode(bytes.fromhex(hex_boc)).decode("ascii")


def rows(dump: Path) -> list[list[str]]:
    lines = dump.read_text().splitlines()
    if not lines or lines[0] != "#rel02-v2":
        raise SystemExit(f"{dump}: #rel02-v2 header required")
    out = [line.split("\t") for line in lines[1:]]
    for number, fields in enumerate(out, 2):
        if len(fields) != 18:
            raise SystemExit(f"{dump}:{number}: 18 fields required, got {len(fields)}")
    if not out:
        raise SystemExit(f"{dump}: no rows")
    return out


def context(fields: list[str]) -> Json:
    ctx: Json = {
        "config": b64(fields[6]),
        "shard_account": b64(fields[4]),
        "now": int(fields[1]),
        "lt": int(fields[2]),
        "rand_seed": fields[3].lower(),
    }
    if fields[0] == "1":
        if fields[5] == "-":
            raise SystemExit(f"ordinary transaction {fields[9]} without an inbound message")
        ctx["message"] = b64(fields[5])
    elif fields[0] in TICK_TOCK:
        ctx["tick_tock"] = TICK_TOCK[fields[0]]
    else:
        raise SystemExit(f"transaction {fields[9]}: unsupported type {fields[0]}")
    if fields[7] != "-":
        ctx["libraries"] = b64(fields[7])
    if fields[8] != "-":
        ctx["prev_blocks"] = b64(fields[8])
    return ctx


def contexts(dump: Path) -> list[Json]:
    return [
        {
            "fixture_id": f"{f[12]}:{f[13]}:{f[14]}:{f[9].upper()[:16]}",
            "note": f"block {f[15].upper()} transaction {f[9].upper()}",
            "context": context(f),
        }
        for f in rows(dump)
    ]


def check(dump: Path, effects_path: Path) -> int:
    expected = rows(dump)
    effects = [json.loads(line) for line in effects_path.read_text().splitlines()]
    if len(effects) != len(expected):
        raise SystemExit(f"{len(effects)} effects for {len(expected)} transactions")
    differences = 0
    for fields, effect in zip(expected, effects, strict=True):
        want = {
            "outcome": "accepted",
            "transaction_hash": fields[9].upper(),
            "account_hash": fields[10].upper(),
        }
        got = {key: effect.get(key) for key in want}
        if got != want:
            differences += 1
            print(f"DIFF {fields[9]}: chain {want} harness {effect}")
    print(f"checked {len(expected)} transactions against the chain, {differences} differences")
    return 1 if differences else 0


def chain(replay: Path, target: Path, corpus: Path) -> int:
    """Export the corpus with the replay tool, run ``target`` on every context, check the chain."""
    manifest = json.loads((corpus / "manifest.json").read_text())
    with tempfile.TemporaryDirectory(prefix="conformance-rel02-") as directory:
        work = Path(directory)
        lists: list[str] = []
        for name in ("blocks", "supplements"):
            listing = work / name
            listing.write_text("".join(str(corpus / p) + "\n" for p in manifest[name]))
            lists.append(str(listing))
        dump = work / "dump.tsv"
        exported = subprocess.run(
            [str(replay), "--dump", *lists, str(dump)],
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )
        if exported.returncode != 0:
            raise SystemExit(f"replay export failed: {exported.stderr.strip()[-2000:]}")
        entries = contexts(dump)
        stdin = "".join(json.dumps(e["context"], separators=(",", ":")) + "\n" for e in entries)
        executed = subprocess.run(
            [str(target), "txn"],
            input=stdin,
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )
        if executed.returncode != 0:
            raise SystemExit(f"{target} txn failed: {executed.stderr.strip()[-2000:]}")
        effects = work / "effects.jsonl"
        effects.write_text(executed.stdout)
        return check(dump, effects)


def main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[0] == "chain":
        return chain(Path(argv[1]), Path(argv[2]), Path(argv[3]))
    if len(argv) == 3 and argv[0] == "contexts":
        entries = contexts(Path(argv[1]))
        Path(argv[2]).write_text(
            "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in entries)
        )
        print(f"{len(entries)} contexts")
        return 0
    if len(argv) == 3 and argv[0] == "check":
        return check(Path(argv[1]), Path(argv[2]))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
