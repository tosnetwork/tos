#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Tests of the archive replay driver (migrate/archive.py). Each check is shown to fail on a defect."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib
import io
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "migrate"))

# The driver lives outside the runner directory, so it is loaded by path.
archive: Any = importlib.import_module("archive")

CODE = "te6ccgEBAQEAAwAAAXA="
SEED = "0" * 64
TX = "A" * 64
ACCOUNT = "B" * 64

# A stand-in for a target CLI: answers each context by its lt from a JSON map.
FAKE_TARGET = r"""
import json, os, sys
answers = json.loads(open(os.environ["ARCHIVE_FAKE_ANSWERS"]).read())
for line in sys.stdin.read().splitlines():
    print(json.dumps(answers[str(json.loads(line)["lt"])]))
"""


def context(lt: int, config: Any = CODE) -> dict[str, Any]:
    return {
        "config": config,
        "shard_account": CODE,
        "now": 1,
        "lt": lt,
        "rand_seed": SEED,
        "tick_tock": "tick",
    }


class ArchiveDriverTests(unittest.TestCase):
    # Placeholders; setUp assigns every one of them before a test runs.
    dir: Path = Path()
    target: str = ""
    answers: Path = Path()

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        target = self.dir / "target"
        target.write_text(f"#!{sys.executable}\n{FAKE_TARGET}")
        target.chmod(target.stat().st_mode | stat.S_IEXEC)
        self.target = str(target)
        self.answers = self.dir / "answers.json"

    def export(self, lines: list[dict[str, Any]], blobs: dict[str, str] | None = None) -> Path:
        out = self.dir / "export"
        out.mkdir(exist_ok=True)
        (out / "contexts.jsonl").write_text("".join(json.dumps(x) + "\n" for x in lines))
        (out / "contexts.blobs.json").write_text(json.dumps(blobs or {}))
        return out

    def run_chain(self, answers: dict[str, Any], export: Path) -> int:
        self.answers.write_text(json.dumps(answers))
        with mock.patch.dict("os.environ", {"ARCHIVE_FAKE_ANSWERS": str(self.answers)}):
            with contextlib.redirect_stdout(io.StringIO()):
                return archive.chain(self.target, export)

    def line(self, lt: int, config: Any = CODE) -> dict[str, Any]:
        return {
            "fixture_id": f"0:1:{lt}",
            "note": "",
            "context": context(lt, config),
            "chain": {"transaction_hash": TX, "account_hash": ACCOUNT},
        }

    def accepted(self, tx: str = TX) -> dict[str, Any]:
        return {
            "outcome": "accepted",
            "transaction_hash": tx,
            "account_hash": ACCOUNT,
            "shard_account_hash": TX,
        }

    def test_chain_accepts_the_chain_hashes(self) -> None:
        export = self.export([self.line(1), self.line(2)])
        self.assertEqual(self.run_chain({"1": self.accepted(), "2": self.accepted()}, export), 0)

    def test_chain_reports_a_differing_transaction(self) -> None:
        # Control: one target answer differs from the chain.
        export = self.export([self.line(1), self.line(2)])
        self.assertEqual(
            self.run_chain({"1": self.accepted(), "2": self.accepted("C" * 64)}, export), 1
        )

    def test_chain_reports_a_refusal_and_a_rejection(self) -> None:
        export = self.export([self.line(1), self.line(2)])
        answers = {"1": {"harness_error": "no"}, "2": {"outcome": "rejected", "vm_exit_code": 0}}
        self.assertEqual(self.run_chain(answers, export), 1)

    def test_chain_resolves_blobs_and_refuses_a_corrupt_blob(self) -> None:
        digest = hashlib.sha256(base64.b64decode(CODE)).hexdigest()
        export = self.export([self.line(1, {"blob": digest})], {digest: CODE})
        self.assertEqual(self.run_chain({"1": self.accepted()}, export), 0)
        # Control: a blob whose digest does not match its content is refused before any target runs.
        export = self.export([self.line(1, {"blob": "0" * 64})], {"0" * 64: CODE})
        with self.assertRaises(archive.c.FixtureError):
            self.run_chain({"1": self.accepted()}, export)

    def test_packages_are_checked_against_their_list(self) -> None:
        root = self.dir / "packs"
        (root / "arch0000").mkdir(parents=True)
        pack = root / "arch0000" / "archive.00000.pack"
        pack.write_bytes(b"package")
        listing = self.dir / "SHA256SUMS"
        good = hashlib.sha256(b"package").hexdigest()
        listing.write_text(f"{good}  ./arch0000/archive.00000.pack\n")
        paths, info = archive.verified_packs(f"{root}={listing}", True)
        self.assertEqual((paths, info["packages"], info["bytes"]), ([pack], 1, 7))
        # Controls: a differing package, an unlisted package, a listed package that is absent.
        pack.write_bytes(b"changed")
        with self.assertRaisesRegex(SystemExit, "differ"):
            archive.verified_packs(f"{root}={listing}", True)
        pack.write_bytes(b"package")
        extra = root / "arch0000" / "archive.00100.pack"
        extra.write_bytes(b"x")
        with self.assertRaisesRegex(SystemExit, "1 packages not listed"):
            archive.verified_packs(f"{root}={listing}", True)
        # The base filter keeps only the slice's packages, so the unlisted later package is outside it.
        self.assertEqual(archive.verified_packs(f"{root}={listing}", True, 100)[0], [pack])
        extra.unlink()
        pack.unlink()
        with self.assertRaisesRegex(SystemExit, "1 listed but absent"):
            archive.verified_packs(f"{root}={listing}", True)

    def test_a_package_listed_twice_is_refused(self) -> None:
        listing = self.dir / "SHA256SUMS"
        line = f"{'0' * 64}  ./archive.00000.pack\n"
        listing.write_text(line + line)
        with self.assertRaisesRegex(SystemExit, "listed twice"):
            archive.read_sha_list(listing)


if __name__ == "__main__":
    unittest.main()
