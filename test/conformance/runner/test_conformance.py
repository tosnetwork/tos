#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Tests of the conformance runner. Each check is shown to fail on a controlled defect."""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parent))

import conformance as c  # noqa: E402

SCHEMA = Path(__file__).resolve().parent.parent / "schema" / "fixture-v1.schema.json"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
HASH = "A" * 64
CODE = "te6ccgEBAQEAAwAAAXA="

FAKE_TARGET = r"""
import json, os, sys
mode = os.environ.get("FAKE_MODE", "exact")
if sys.argv[1] == "--info":
    print(json.dumps({"reference_commit": os.environ["FAKE_COMMIT"], "dirty": mode == "dirty"}))
    sys.exit(0)
answers = json.loads(open(os.environ["FAKE_ANSWERS"]).read())
lines = sys.stdin.read().splitlines()
out = []
for i, line in enumerate(lines):
    effects = dict(answers[json.loads(line)["code"]])
    if mode == "mutate" and i == 0:
        effects["gas_used"] += 1
    if mode == "refuse" and i == 0:
        effects = {"harness_error": "refused for the test"}
    if mode == "extra-field" and i == 0:
        effects["unexpected"] = 1
    out.append(json.dumps(effects))
if mode == "drop":
    out = out[:-1]
print("\n".join(out))
"""


def vm_effects(gas: int) -> dict[str, Any]:
    return {
        "exit_code": 0,
        "gas_used": gas,
        "steps": 2,
        "committed": True,
        "c4_hash": HASH,
        "c5_hash": HASH,
        "stack": ["7"],
    }


def vm_context(code: str) -> dict[str, Any]:
    return {"code": code, "global_version": 16, "gas": {"limit": 100, "max": 100}, "stack": []}


class Fixture(unittest.TestCase):
    # Placeholders; setUp assigns every one of them before a test runs.
    dir: Path = Path()
    codes: tuple[str, ...] = ()
    target: str = ""
    contexts: Path = Path()
    vectors: Path = Path()
    family: Path = Path()

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.codes = (CODE, "te6ccgEBAQEAAwAAAXE=")
        answers = {code: vm_effects(10 + i) for i, code in enumerate(self.codes)}
        (self.dir / "answers.json").write_text(json.dumps(answers))
        target = self.dir / "fake-target"
        target.write_text(f"#!{sys.executable}\n{FAKE_TARGET}")
        target.chmod(target.stat().st_mode | stat.S_IEXEC)
        self.target = str(target)
        os.environ["FAKE_ANSWERS"] = str(self.dir / "answers.json")
        os.environ["FAKE_COMMIT"] = COMMIT
        os.environ["FAKE_MODE"] = "exact"
        self.contexts = self.dir / "contexts.jsonl"
        self.contexts.write_text(
            "".join(
                json.dumps({"fixture_id": f"case-{i}", "context": vm_context(code)}) + "\n"
                for i, code in enumerate(self.codes)
            )
        )
        self.vectors = self.dir / "vectors"
        self.family = self.vectors / "vm" / "fixtures" / "sample.jsonl"

    def create(self) -> None:
        c.command_create(self.target, "vm", "sample", "authored", self.contexts, self.family)

    def mode(self, mode: str) -> None:
        os.environ["FAKE_MODE"] = mode


class RunTests(Fixture):
    def test_equal_fixtures_pass(self) -> None:
        self.create()
        tally = c.command_run(self.target, [self.vectors])
        self.assertTrue(tally.ok(), tally.details)
        self.assertEqual((tally.compared, tally.equal), (2, 2))

    def test_changed_effect_is_a_mismatch(self) -> None:
        self.create()
        self.mode("mutate")
        tally = c.command_run(self.target, [self.vectors])
        self.assertFalse(tally.ok())
        self.assertEqual(tally.mismatched, 1)
        self.assertIn("gas_used", tally.details[0])

    def test_extra_response_field_is_a_mismatch(self) -> None:
        self.create()
        self.mode("extra-field")
        tally = c.command_run(self.target, [self.vectors])
        self.assertEqual(tally.mismatched, 1)

    def test_refusal_is_counted_and_fails(self) -> None:
        self.create()
        self.mode("refuse")
        tally = c.command_run(self.target, [self.vectors])
        self.assertFalse(tally.ok())
        self.assertEqual((tally.refused, tally.equal), (1, 1))

    def test_missing_response_line_stops_the_run(self) -> None:
        self.create()
        self.mode("drop")
        with self.assertRaises(c.FixtureError):
            c.command_run(self.target, [self.vectors])

    def test_skipped_harness_fails(self) -> None:
        self.create()
        tally = c.command_run(self.target, [self.vectors], {"txn"})
        self.assertFalse(tally.ok())
        self.assertEqual((tally.compared, tally.skipped), (0, 2))

    def test_any_skip_fails_even_when_the_rest_is_equal(self) -> None:
        self.assertTrue(c.Tally(compared=2, equal=2).ok())
        self.assertFalse(c.Tally(compared=2, equal=2, skipped=1).ok())
        self.assertFalse(c.Tally(compared=2, equal=1, refused=1).ok())
        self.assertFalse(c.Tally().ok())

    def test_no_fixtures_is_an_error(self) -> None:
        self.vectors.mkdir()
        with self.assertRaises(c.FixtureError):
            c.command_run(self.target, [self.vectors])


class CreateTests(Fixture):
    def test_dirty_reference_is_refused(self) -> None:
        self.mode("dirty")
        with self.assertRaises(c.FixtureError):
            self.create()
        c.command_create(
            self.target, "vm", "sample", "authored", self.contexts, self.family, allow_dirty=True
        )
        self.assertTrue(self.family.exists())

    def test_provenance_is_recorded(self) -> None:
        self.create()
        meta = c.read_jsonl(self.family)[0]["metadata"]
        self.assertEqual(meta["reference_commit"], COMMIT)
        self.assertEqual(meta["harness_version"], 1)

    def test_refused_context_is_not_frozen(self) -> None:
        self.mode("refuse")
        with self.assertRaises(c.FixtureError):
            self.create()
        self.assertFalse(self.family.exists())

    def test_duplicate_fixture_id_is_refused(self) -> None:
        line = json.dumps({"fixture_id": "same", "context": vm_context(CODE)}) + "\n"
        self.contexts.write_text(line + line)
        with self.assertRaises(c.FixtureError):
            self.create()


class RegenerateTests(Fixture):
    def test_changed_effects_are_reported_and_written(self) -> None:
        self.create()
        self.assertEqual(c.command_regenerate(self.target, [self.vectors], write=False), [])
        self.mode("mutate")
        changed = c.command_regenerate(self.target, [self.vectors], write=True)
        self.assertEqual(len(changed), 1)
        self.assertIn("vm/sample/case-0", changed[0])
        self.assertEqual(c.read_jsonl(self.family)[0]["effects"]["gas_used"], 11)


class ValidateTests(Fixture):
    def fixture(self) -> dict[str, Any]:
        self.create()
        return c.read_jsonl(self.family)[0]

    def rewrite(self, record: dict[str, Any]) -> None:
        c.write_jsonl(self.family, [record])

    def test_valid_family(self) -> None:
        self.create()
        self.assertEqual(c.command_validate([self.vectors]), 2)

    def test_unknown_context_key_is_rejected(self) -> None:
        record = self.fixture()
        record["context"]["librarys"] = []
        self.rewrite(record)
        with self.assertRaises(c.FixtureError):
            c.command_validate([self.vectors])

    def test_lowercase_hash_is_rejected(self) -> None:
        record = self.fixture()
        record["effects"]["c4_hash"] = "a" * 64
        self.rewrite(record)
        with self.assertRaises(c.FixtureError):
            c.command_validate([self.vectors])

    def test_family_file_must_sit_under_its_harness(self) -> None:
        self.create()
        moved = self.vectors / "txn" / "fixtures" / "sample.jsonl"
        moved.parent.mkdir(parents=True)
        self.family.rename(moved)
        with self.assertRaises(c.FixtureError):
            c.command_validate([self.vectors])

    def test_duplicate_ids_in_a_family_are_rejected(self) -> None:
        record = self.fixture()
        c.write_jsonl(self.family, [record, record])
        with self.assertRaises(c.FixtureError):
            c.command_validate([self.vectors])

    def test_txn_context_needs_exactly_one_of_message_and_tick_tock(self) -> None:
        base = {"config": CODE, "shard_account": CODE, "now": 1, "lt": 1, "rand_seed": "0" * 64}
        c.validate_context("txn", {**base, "message": CODE})
        c.validate_context("txn", {**base, "tick_tock": "tock"})
        for bad in (base, {**base, "message": CODE, "tick_tock": "tick"}):
            with self.assertRaises(c.FixtureError):
                c.validate_context("txn", bad)

    def test_txn_effects_by_outcome(self) -> None:
        c.validate_effects("txn", {"outcome": "rejected", "vm_exit_code": 33})
        with self.assertRaises(c.FixtureError):
            c.validate_effects(
                "txn", {"outcome": "rejected", "vm_exit_code": 33, "transaction_hash": HASH}
            )
        with self.assertRaises(c.FixtureError):
            c.validate_effects("txn", {"outcome": "error", "detail": "text"})


class SchemaAgreementTests(unittest.TestCase):
    """The hand-written validator and the JSON Schema document must describe the same keys."""

    schema: dict[str, Any] = {}  # noqa: RUF012 - replaced in setUp
    defs: dict[str, Any] = {}  # noqa: RUF012 - replaced in setUp

    def setUp(self) -> None:
        self.schema = cast(dict[str, Any], json.loads(SCHEMA.read_text()))
        self.defs = cast(dict[str, Any], self.schema["$defs"])

    def keys(self, node: dict[str, Any]) -> tuple[set[str], set[str]]:
        return set(cast(list[str], node.get("required", []))), set(
            cast(dict[str, Any], node["properties"])
        )

    def test_metadata(self) -> None:
        meta = cast(dict[str, Any], self.schema["properties"]["metadata"])
        self.assertEqual(self.keys(meta), (c.METADATA_REQUIRED, c.METADATA_ALLOWED))
        self.assertEqual(
            set(cast(list[str], meta["properties"]["harness"]["enum"])), set(c.HARNESSES)
        )

    def test_contexts(self) -> None:
        self.assertEqual(
            self.keys(self.defs["vm_context"]), (c.VM_CONTEXT_REQUIRED, c.VM_CONTEXT_ALLOWED)
        )
        self.assertEqual(
            self.keys(self.defs["txn_context"]), (c.TXN_CONTEXT_REQUIRED, c.TXN_CONTEXT_ALLOWED)
        )

    def test_effects(self) -> None:
        self.assertEqual(
            self.keys(self.defs["vm_effects"]), (c.VM_EFFECTS_REQUIRED, c.VM_EFFECTS_REQUIRED)
        )
        variants = cast(list[dict[str, Any]], self.defs["txn_effects"]["oneOf"])
        by_outcome = {v["properties"]["outcome"]["const"]: self.keys(v) for v in variants}
        self.assertEqual(by_outcome, {k: (v, v) for k, v in c.TXN_EFFECTS_KEYS.items()})

    def test_patterns(self) -> None:
        self.assertEqual(self.defs["hash"]["pattern"], c.HASH_RE.pattern)
        self.assertEqual(self.defs["boc"]["pattern"], c.BOC_RE.pattern)


if __name__ == "__main__":
    unittest.main()
