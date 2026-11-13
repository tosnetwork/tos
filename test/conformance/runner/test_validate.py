#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Tests of the validate harness validator, its frozen families and the archive slice check."""

from __future__ import annotations

import base64
import importlib
import json
import re
import sys
import unittest
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "migrate"))

import conformance as c  # noqa: E402
import fixture_types as t  # noqa: E402
from harnesses import validate as h  # noqa: E402

# migrate/ is not on the type checker's import path; the module is loaded by name at run time.
families: Any = importlib.import_module("validate_families")
ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "vectors" / "validate" / "fixtures"
CORPUS = ROOT.parent / "rel02" / "corpus"
HASH = "A" * 64
BOC = "te6ccgEBAQEAAwAAAXA="
BLOCK_ID = {
    "workchain": -1,
    "shard": "8000000000000000",
    "seqno": 5,
    "root_hash": HASH,
    "file_hash": HASH,
}

# The outcome and reason class each authored defect must produce (checked against the C++ fill).
EXPECTED = {
    "prev_state_altered": ("rejected", "prev_state_mismatch"),
    "prev_block_other": ("rejected", "prev_block_mismatch"),
    "mc_state_missing": ("error", "input_unavailable"),
    "fees_collected_plus_one": ("rejected", "value_flow_invalid"),
    "transaction_fees_plus_one": ("rejected", "transaction_invalid"),
    "account_block_removed": ("rejected", "account_update_invalid"),
    "transaction_duplicated": ("rejected", "transaction_invalid"),
    "gen_utime_earlier": ("rejected", "utime_lt_invalid"),
    "gen_utime_header_only": ("rejected", "new_state_mismatch"),
    "gen_utime_ms_mismatch": ("rejected", "utime_lt_invalid"),
    "start_lt_unaligned": ("rejected", "utime_lt_invalid"),
    "lt_delta_oversize": ("rejected", "limit_exceeded"),
    "state_update_noop": ("rejected", "new_state_mismatch"),
    "candidate_file_hash": ("rejected", "candidate_id_mismatch"),
    "candidate_shard_other": ("rejected", "shard_mismatch"),
    "created_by_other": ("rejected", "creator_mismatch"),
    "out_msg_removed": ("rejected", "message_invalid"),
}


def context(**changes: Any) -> dict[str, Any]:
    ctx: dict[str, Any] = {
        "block_id": BLOCK_ID,
        "block": BOC,
        "collated_data": BOC,
        "created_by": HASH,
        "prev": [BLOCK_ID],
        "min_masterchain": BLOCK_ID,
        "top_masterchain": BLOCK_ID,
        "validator_set_from": BLOCK_ID,
        "skip_shard_signatures": False,
        "states": [{"block": BLOCK_ID, "state": BOC}],
    }
    ctx.update(changes)
    return ctx


class ValidatorTests(unittest.TestCase):
    def test_context_shapes(self) -> None:
        c.validate_context("validate", context())
        minimal = context()
        del minimal["collated_data"], minimal["skip_shard_signatures"]
        c.validate_context("validate", minimal)
        for bad in (
            context(prev=[]),
            context(prev=[BLOCK_ID, BLOCK_ID, BLOCK_ID]),
            context(block_id={**BLOCK_ID, "shard": "8000"}),
            context(block_id={**BLOCK_ID, "root_hash": HASH.lower()}),
            context(created_by="00"),
            context(states=[{"block": BLOCK_ID}]),
            context(states=[{"block": BLOCK_ID, "state": BOC}] * 33),
            context(skip_shard_signatures=1),
            context(extra=1),
        ):
            with self.subTest(context=bad), self.assertRaises(t.FixtureError):
                c.validate_context("validate", bad)

    def test_effect_shapes(self) -> None:
        c.validate_effects("validate", {"outcome": "accepted", "ok_from_utime_ms": 1})
        c.validate_effects("validate", {"outcome": "rejected", "reason": "unclassified"})
        c.validate_effects("validate", {"outcome": "error", "reason": "input_unavailable"})
        for bad in (
            {"outcome": "accepted"},
            {"outcome": "accepted", "ok_from_utime_ms": -1},
            {"outcome": "rejected", "reason": "something else"},
            {"outcome": "error"},
            {"outcome": "refused", "reason": "unclassified"},
        ):
            with self.subTest(effects=bad), self.assertRaises(t.FixtureError):
                c.validate_effects("validate", bad)


class ReasonTableTests(unittest.TestCase):
    """The validator, the schema and the C++ classification table name the same classes."""

    def test_schema_enum(self) -> None:
        schema = json.loads((ROOT / "schema" / "harness" / "validate-v1.schema.json").read_text())
        self.assertEqual(set(schema["$defs"]["reason"]["enum"]), set(h.REASONS))

    def test_cpp_table(self) -> None:
        source = (ROOT / "ref" / "validate-offline.cpp").read_text()
        table = source[source.index("const Pattern kPatterns[] = {") :]
        table = table[: table.index("};")]
        classes = set(re.findall(r'\{"[^"]+", "([a-z_]+)"\}', table))
        self.assertEqual(classes | {"unclassified"}, set(h.REASONS))


def family(name: str) -> c.FamilyFile:
    return c.load_family(VECTORS / f"{name}.jsonl")


class PositiveFamilyTests(unittest.TestCase):
    """Archived blocks are accepted: the chain is the oracle."""

    def test_rel02_chain_is_every_corpus_block_with_history(self) -> None:
        fam = family("rel02-chain")
        covered, excluded = families.rel02_targets(CORPUS)
        self.assertEqual(len(covered) + len(excluded), 366)
        expected = {f"{'mc' if wc == -1 else 'base'}-{seqno}" for wc, seqno in covered}
        ids = {cast(str, f["metadata"]["fixture_id"]) for f in fam.fixtures}
        self.assertEqual(ids, expected)
        for fixture in fam.fixtures:
            with self.subTest(fixture=fixture["metadata"]["fixture_id"]):
                self.assertEqual(cast(dict[str, Any], fixture["effects"])["outcome"], "accepted")

    def test_rel02_chain_blocks_are_the_corpus_bytes(self) -> None:
        fam = family("rel02-chain")
        for fixture, ctx in zip(fam.fixtures, fam.contexts(), strict=True):
            fixture_id = cast(str, fixture["metadata"]["fixture_id"])
            kind, seqno = fixture_id.split("-")
            path = CORPUS / "blocks" / f"{-1 if kind == 'mc' else 0}-{seqno}.boc"
            with self.subTest(fixture=fixture_id):
                self.assertEqual(base64.b64decode(ctx["block"]), path.read_bytes())

    def test_epoch6_slice_is_accepted(self) -> None:
        fam = family("epoch6-slice")
        lo, hi = (tuple(map(int, r.split("-"))) for r in families.EPOCH6_RANGES)
        mc = {f"mc-{s}" for r in (lo, hi) for s in range(r[0], r[1] + 1)}
        ids = {cast(str, f["metadata"]["fixture_id"]) for f in fam.fixtures}
        self.assertEqual({i for i in ids if i.startswith("mc-")}, mc)
        self.assertGreater(len(ids - mc), 0)
        for fixture in fam.fixtures:
            with self.subTest(fixture=fixture["metadata"]["fixture_id"]):
                self.assertEqual(cast(dict[str, Any], fixture["effects"])["outcome"], "accepted")


class NegativeFamilyTests(unittest.TestCase):
    """Authored assertions on the C++ fill of validate/rel02-negative."""

    def test_every_defect_has_its_class(self) -> None:
        fam = family("rel02-negative")
        ids = {cast(str, f["metadata"]["fixture_id"]) for f in fam.fixtures}
        wanted = {
            f"{'mc' if wc == -1 else 'base'}-{seqno}:{m}" for wc, seqno, m in families.MUTATIONS
        }
        self.assertEqual(ids, wanted)
        for fixture in fam.fixtures:
            fixture_id = cast(str, fixture["metadata"]["fixture_id"])
            kind = fixture_id.split(":", 1)[1]
            with self.subTest(fixture=fixture_id):
                effects = cast(dict[str, Any], fixture["effects"])
                self.assertEqual((effects["outcome"], effects["reason"]), EXPECTED[kind])
        self.assertEqual({m for _, _, m in families.MUTATIONS}, set(EXPECTED))


class SliceCheckTests(unittest.TestCase):
    """validate_families.check_accepted, the archive slice gate."""

    # Placeholders; setUp assigns both before a test runs.
    entries: list[dict[str, Any]] = []  # noqa: RUF012
    effects: list[dict[str, Any]] = []  # noqa: RUF012

    def setUp(self) -> None:
        self.entries = [{"fixture_id": i} for i in ("mc-1", "base-1", "mc-2", "base-2")]
        self.effects = [{"outcome": "accepted", "ok_from_utime_ms": 1} for _ in self.entries]

    def test_all_accepted_passes(self) -> None:
        self.assertEqual(families.check_accepted(self.entries, self.effects, 2), 0)

    def test_rejected_block_fails(self) -> None:
        self.effects[1] = {"outcome": "rejected", "reason": "unclassified"}
        self.assertEqual(families.check_accepted(self.entries, self.effects, 2), 1)

    def test_error_fails(self) -> None:
        self.effects[2] = {"outcome": "error", "reason": "input_unavailable"}
        self.assertEqual(families.check_accepted(self.entries, self.effects, 2), 1)

    def test_missing_masterchain_block_fails(self) -> None:
        self.assertEqual(families.check_accepted(self.entries, self.effects, 3), 1)

    def test_missing_effect_is_an_error(self) -> None:
        with self.assertRaises(families.ExportError):
            families.check_accepted(self.entries, self.effects[:-1], 2)


if __name__ == "__main__":
    unittest.main()
