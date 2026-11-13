#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Tests of the block harness validator, its frozen negative family and the block chain check."""

from __future__ import annotations

import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "migrate"))

import conformance as c  # noqa: E402
import fixture_types as t  # noqa: E402

# migrate/ is not on the type checker's import path; the module is loaded by name at run time.
block_chain: Any = importlib.import_module("block_chain")
VECTORS = Path(__file__).resolve().parent.parent / "vectors"
HASH = "A" * 64
BOC = "te6ccgEBAQEAAwAAAXA="

# The reason class each authored defect must produce (checked against the C++ fill). An incomplete
# previous state fails where the first pruned cell is read: the masterchain configuration of a
# masterchain block, an account of a basechain block.
EXPECTED_REASONS = {
    "wrong-prev-state": {"prev_state_mismatch"},
    "pruned-prev-state": {"pruned_state", "config_unavailable"},
    "foreign-update": {"state_update_invalid"},
    "reversed-update": {"state_update_invalid"},
    "tx-fees": {"transaction_mismatch"},
    "tx-time": {"transaction_context_mismatch"},
    "wrong-master-state": {"master_context_mismatch"},
    "no-master": {"master_context_mismatch"},
}


def accepted(transactions: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "outcome": "accepted",
        "block_root_hash": HASH,
        "new_state_hash": HASH,
        "transactions": transactions,
    }


class ValidatorTests(unittest.TestCase):
    def test_context_shapes(self) -> None:
        c.validate_context("block", {"block": BOC, "prev_state": BOC})
        c.validate_context(
            "block", {"block": BOC, "prev_state": BOC, "master_block": BOC, "master_state": BOC}
        )
        for bad in (
            {"block": BOC},
            {"block": BOC, "prev_state": BOC, "master_block": BOC},
            {"block": BOC, "prev_state": BOC, "extra": BOC},
            {"block": "not base64!", "prev_state": BOC},
        ):
            with self.subTest(context=bad), self.assertRaises(t.FixtureError):
                c.validate_context("block", bad)

    def test_effect_shapes(self) -> None:
        c.validate_effects("block", accepted([{"transaction_hash": HASH, "account_hash": HASH}]))
        c.validate_effects("block", {"outcome": "rejected", "reason": "prev_state_mismatch"})
        for bad in (
            {"outcome": "rejected", "reason": "something else"},
            {"outcome": "rejected"},
            accepted([{"transaction_hash": HASH.lower(), "account_hash": HASH}]),
            accepted([{"transaction_hash": HASH}]),
            {**accepted([]), "reason": "prev_state_mismatch"},
        ):
            with self.subTest(effects=bad), self.assertRaises(t.FixtureError):
                c.validate_effects("block", bad)


class NegativeFamilyTests(unittest.TestCase):
    """Authored assertions on the C++ fill of block/rel02-negative."""

    def test_every_defect_is_rejected_for_its_reason(self) -> None:
        family = c.load_family(VECTORS / "block" / "fixtures" / "rel02-negative.jsonl")
        kinds: set[str] = set()
        for fixture in family.fixtures:
            fixture_id = cast(str, fixture["metadata"]["fixture_id"])
            kind = fixture_id.split(":", 2)[2]
            kinds.add(kind)
            with self.subTest(fixture=fixture_id):
                effects = cast(dict[str, Any], fixture["effects"])
                self.assertEqual(effects["outcome"], "rejected")
                self.assertIn(effects["reason"], EXPECTED_REASONS[kind])
        self.assertEqual(kinds, set(EXPECTED_REASONS))


class ChainCheckTests(unittest.TestCase):
    """block_chain.check compares harness effects with the manifest's on-chain records."""

    # Placeholders; setUp assigns every one of them before a test runs.
    dir: Path = Path()
    contexts: Path = Path()
    effects: list[dict[str, Any]] = []  # noqa: RUF012

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        roots = ("1" * 64, "2" * 64)
        manifest = {
            "blocks": ["blocks/a.boc", "blocks/b.boc"],
            "expected": [
                {"kind": "block", "root_hash": roots[0], "new_state_hash": "3" * 64},
                {"kind": "transaction", "result_hash": "4" * 64, "account_hash": "5" * 64},
                {"kind": "transaction", "result_hash": "6" * 64, "account_hash": "7" * 64},
                {"kind": "block", "root_hash": roots[1], "new_state_hash": "8" * 64},
            ],
        }
        (self.dir / "manifest.json").write_text(json.dumps(manifest))
        self.contexts = self.dir / "contexts.jsonl"
        self.contexts.write_text(
            "".join(
                json.dumps({"fixture_id": f"b{i}", "note": f"corpus block {root}", "context": {}})
                + "\n"
                for i, root in enumerate(roots)
            )
        )
        self.effects: list[dict[str, Any]] = [
            {
                "outcome": "accepted",
                "block_root_hash": roots[0],
                "new_state_hash": "3" * 64,
                "transactions": [
                    {"transaction_hash": "4" * 64, "account_hash": "5" * 64},
                    {"transaction_hash": "6" * 64, "account_hash": "7" * 64},
                ],
            },
            {
                "outcome": "accepted",
                "block_root_hash": roots[1],
                "new_state_hash": "8" * 64,
                "transactions": [],
            },
        ]

    def check(self) -> int:
        path = self.dir / "effects.jsonl"
        path.write_text("".join(json.dumps(e) + "\n" for e in self.effects))
        return block_chain.check(self.dir, self.contexts, path)

    def test_chain_equal_passes(self) -> None:
        self.assertEqual(self.check(), 0)

    def test_changed_transaction_hash_fails(self) -> None:
        self.effects[0]["transactions"][1]["transaction_hash"] = "9" * 64
        self.assertEqual(self.check(), 1)

    def test_reordered_transactions_fail(self) -> None:
        self.effects[0]["transactions"].reverse()
        self.assertEqual(self.check(), 1)

    def test_changed_state_hash_fails(self) -> None:
        self.effects[1]["new_state_hash"] = "9" * 64
        self.assertEqual(self.check(), 1)

    def test_rejected_block_fails(self) -> None:
        self.effects[1] = {"outcome": "rejected", "reason": "pruned_state"}
        self.assertEqual(self.check(), 1)

    def test_missing_effect_is_an_error(self) -> None:
        self.effects.pop()
        with self.assertRaises(block_chain.ChainError):
            self.check()


if __name__ == "__main__":
    unittest.main()
