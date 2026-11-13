#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Tests of the codec, tl and fee validators and of the codec migration helpers.

Each check is shown to fail on a controlled defect: a malformed context or effect, a tampered fixture.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixture_types as t  # noqa: E402
from harnesses import HARNESSES  # noqa: E402

CONFORMANCE = Path(__file__).resolve().parent.parent
HASH = "B" * 64
DIGEST = "c" * 64


def load_migration() -> Any:
    spec = importlib.util.spec_from_file_location(
        "codec_migration", CONFORMANCE / "migrate/codec.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CodecValidatorTests(unittest.TestCase):
    harness = HARNESSES["codec"]

    def accepts(self, ctx: dict[str, Any]) -> None:
        self.harness.validate_context(ctx, "ctx")

    def refuses(self, ctx: dict[str, Any]) -> None:
        with self.assertRaises(t.FixtureError):
            self.harness.validate_context(ctx, "ctx")

    def test_contexts(self) -> None:
        self.accepts({"type": "cell", "boc": "te6ccgEBAQEAAwAAAXA=", "mode": 3})
        self.accepts({"type": "VarUInteger", "n": 16, "bits": "0000"})
        self.accepts({"type": "VarUInteger", "n": 32, "op": "write", "value": "-5"})
        self.accepts({"type": "Block", "bits": "0", "path": [0, 3], "max_cells": 5})
        self.accepts({"type": "config", "bits": "0", "address": "5" * 64})

    def test_bad_contexts(self) -> None:
        self.refuses({"type": "Nothing", "bits": ""})
        self.refuses({"type": "Account", "bits": "0", "boc": "te6ccgEBAQEAAwAAAXA="})
        self.refuses({"type": "Account"})
        self.refuses({"type": "Account", "bits": "2"})
        self.refuses({"type": "Account", "bits": "0", "path": [4]})
        self.refuses({"type": "cell", "bits": "0", "path": [0]})
        self.refuses({"type": "VarUInteger", "n": 33, "bits": ""})
        self.refuses({"type": "VarUInteger", "n": 16, "op": "write", "bits": ""})
        self.refuses({"type": "config", "bits": "0"})
        self.refuses({"type": "ConfigParam", "bits": "0", "n": 1 << 32})
        self.refuses({"type": "account_storage", "bits": "0"})

    def test_effects(self) -> None:
        accepted = {
            "outcome": "accepted",
            "root_hashes": [HASH],
            "reserialized_sha256": DIGEST,
            "facts": {"a": [HASH], "b": None},
        }
        self.harness.validate_effects(accepted, "eff")
        rejected = {
            "outcome": "rejected",
            "reason": "tlb",
            "root_hashes": [],
            "facts": {"gen": False},
        }
        self.harness.validate_effects(rejected, "eff")
        for bad in (
            dict(rejected, reason="because"),
            dict(rejected, facts={"x": {"nested": 1}}),
            dict(accepted, root_hashes=[HASH.lower()]),
            dict(accepted, reserialized_sha256=DIGEST.upper()),
            {k: v for k, v in accepted.items() if k != "facts"},
        ):
            with self.subTest(bad=bad), self.assertRaises(t.FixtureError):
                self.harness.validate_effects(bad, "eff")


class TlValidatorTests(unittest.TestCase):
    harness = HARNESSES["tl"]

    def test_contexts(self) -> None:
        self.harness.validate_context(
            {"schema": "tos_api", "kind": "function", "bytes": "2522ad59"}, "ctx"
        )
        for bad in (
            {"schema": "toslib_api", "kind": "function", "bytes": ""},
            {"schema": "other_api", "kind": "object", "bytes": ""},
            {"schema": "tos_api", "kind": "object", "bytes": "ABCD"},
            {"schema": "tos_api", "kind": "object", "bytes": "abc"},
        ):
            with self.subTest(bad=bad), self.assertRaises(t.FixtureError):
                self.harness.validate_context(bad, "ctx")

    def test_effects(self) -> None:
        self.harness.validate_effects(
            {"outcome": "accepted", "constructor": -1, "bytes": "00"}, "eff"
        )
        for bad in (
            {"outcome": "accepted", "constructor": 1 << 31, "bytes": "00"},
            {"outcome": "rejected", "reason": "Not enough data to read"},
            {"outcome": "rejected", "reason": "truncated", "bytes": "00"},
        ):
            with self.subTest(bad=bad), self.assertRaises(t.FixtureError):
                self.harness.validate_effects(bad, "eff")


class FeeValidatorTests(unittest.TestCase):
    harness = HARNESSES["fee"]
    period = {
        "since": 0,
        "bit_price": "1",
        "cell_price": "2",
        "mc_bit_price": "3",
        "mc_cell_price": "4",
    }
    storage = {
        "kind": "storage",
        "now": 1,
        "last_paid": 0,
        "cells": "1",
        "bits": "1",
        "special": False,
        "masterchain": False,
        "periods": [period],
    }

    def test_contexts(self) -> None:
        self.harness.validate_context(self.storage, "ctx")
        for bad in (
            dict(self.storage, cells=str(1 << 64)),
            dict(self.storage, cells="01"),
            dict(self.storage, now=-1),
            dict(self.storage, periods=[{"since": 0}]),
            dict(self.storage, gas_price="1"),
            {"kind": "gas_purchase", "gas_price": "1"},
        ):
            with self.subTest(bad=bad), self.assertRaises(t.FixtureError):
                self.harness.validate_context(bad, "ctx")

    def test_effects(self) -> None:
        self.harness.validate_effects({"outcome": "storage", "fee": None}, "eff")
        self.harness.validate_effects({"outcome": "storage", "fee": "-3"}, "eff")
        for bad in (
            {"outcome": "storage", "fee": 3},
            {
                "outcome": "gas_purchase",
                "threshold": "1",
                "gas_bought": "1",
                "fee": None,
                "simple_fee": "1",
            },
            {"outcome": "forward", "fwd_fee": "1"},
        ):
            with self.subTest(bad=bad), self.assertRaises(t.FixtureError):
                self.harness.validate_effects(bad, "eff")


class MigrationHelperTests(unittest.TestCase):
    migration = load_migration()

    def test_dictionary_labels_follow_the_node(self) -> None:
        label = self.migration.label_bits
        self.assertEqual(label("", 32), "00")
        self.assertEqual(label("1", 32), "0101")
        self.assertEqual(label("1" * 10, 32), "111" + "001010")
        self.assertEqual(label("0101010101", 32), "10" + "001010" + "0101010101")
        self.assertEqual(label("01", 32), "0110" + "01")

    def test_lz4_block_round_trip_of_literals(self) -> None:
        data = b"conformance"
        block = len(data).to_bytes(4, "little") + bytes([len(data) << 4]) + data
        self.assertEqual(self.migration.lz4_block(block), data)
        with self.assertRaises(SystemExit):
            self.migration.lz4_block((len(data) + 1).to_bytes(4, "little") + block[4:])

    def test_storage_fee_check_finds_a_tampered_fixture(self) -> None:
        source = CONFORMANCE / "vectors/fee/fixtures/storage-fee-vectors.jsonl"
        if not source.exists():
            self.skipTest("storage-fee-vectors not frozen yet")
        with tempfile.TemporaryDirectory() as directory:
            vectors = Path(directory)
            target = vectors / "fee/fixtures/storage-fee-vectors.jsonl"
            target.parent.mkdir(parents=True)
            target.write_text(source.read_text())
            tally = self.migration.Tally()
            self.migration.check_storage_fee(vectors, tally)
            self.assertEqual(tally.differences, 0)
            self.assertGreater(tally.rows, 0)
            records = [json.loads(line) for line in source.read_text().splitlines()]
            records[0]["effects"]["fee"] = str(int(records[0]["effects"]["fee"]) + 1)
            target.write_text("".join(json.dumps(r) + "\n" for r in records))
            tally = self.migration.Tally()
            self.migration.check_storage_fee(vectors, tally)
            self.assertEqual(tally.differences, 1)


if __name__ == "__main__":
    unittest.main()
