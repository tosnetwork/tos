#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Tests of the transaction-family migration tools (migrate/txnfam_*.py); each check fails on a defect."""

from __future__ import annotations

import base64
import importlib
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent / "migrate")]
# The migration modules and the cell helpers live outside this directory's import roots.
artifacts = importlib.import_module("txnfam_artifacts")
convert = importlib.import_module("txnfam_convert")
rtos = importlib.import_module("txnfam_rtos")
Cell = importlib.import_module("cells").Cell
make_dict = importlib.import_module("cells").make_dict

FAKE_TARGET = r"""
import json, os, sys
mode = os.environ.get("TXNFAM_FAKE_MODE", "exact")
answers = json.loads(open(os.environ["TXNFAM_FAKE_ANSWERS"]).read())
out = []
for i, line in enumerate(sys.stdin.read().splitlines()):
    effects = dict(answers[json.loads(line)["shard_account"]])
    if mode == "mutate" and i == 0:
        effects["transaction_hash"] = "0" * 64
    out.append(json.dumps(effects))
print("\n".join(out))
"""


def text(cell: Any) -> str:
    return cell.b64().decode("ascii")


def shard_account(marker: int, last_lt: int = 5_000_123) -> Any:
    account = Cell().uint(1, 1).uint(marker, 16)
    return Cell().uint(marker, 256).uint(last_lt, 64).ref(account)


CONFIG = make_dict({8: Cell().ref(Cell().uint(0xC4, 8).uint(16, 32).uint(0, 64))}, 32)
MESSAGE = Cell().uint(4, 4).uint(7, 8)


def call(shard: Any, **state: Any) -> dict[str, Any]:
    transaction = Cell().uint(0x7, 4).uint(int.from_bytes(shard.hash[:4], "big"), 32)
    after = Cell().uint(1, 256).uint(9, 64).ref(Cell().uint(3, 8))
    base: dict[str, Any] = {
        "config": text(CONFIG),
        "now": 1_780_000_000,
        "lt": 2_000_000,
        "rand_seed": None,
        "ignore_chksig": False,
        "libraries": None,
        "prev_blocks": None,
    }
    base.update(state)
    return {
        "kind": "call",
        "state": base,
        "caller": ["family.py:case:1"],
        "shard_account": text(shard),
        "message": text(MESSAGE),
        "response": {
            "success": True,
            "transaction": text(transaction),
            "shard_account": text(after),
        },
        "seq": 1,
        "pid": 1,
        "ns": 1,
    }


class Workspace(unittest.TestCase):
    dir: Path = Path()

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        (self.dir / "capture").mkdir()

    def capture(self, records: list[dict[str, Any]]) -> None:
        for number, record in enumerate(records):
            record["seq"] = record["ns"] = number + 1
        lines = "".join(json.dumps(r) + "\n" for r in records)
        (self.dir / "capture" / "1-1.jsonl").write_text(lines)

    def contexts(self) -> dict[str, Any]:
        convert.command_contexts(self.dir / "capture", self.dir / "work", "sample")
        return json.loads((self.dir / "work" / "summary.json").read_text())

    def fake_target(self) -> str:
        entries = convert.read_jsonl(self.dir / "work" / "all.jsonl")
        native = convert.read_jsonl(self.dir / "work" / "native.jsonl")
        answers = {
            e["context"]["shard_account"]: n["effects"]
            for e, n in zip(entries, native, strict=True)
        }
        (self.dir / "answers.json").write_text(json.dumps(answers))
        target = self.dir / "fake-target"
        target.write_text(f"#!{sys.executable}\n{FAKE_TARGET}")
        target.chmod(target.stat().st_mode | stat.S_IEXEC)
        os.environ["TXNFAM_FAKE_ANSWERS"] = str(self.dir / "answers.json")
        os.environ["TXNFAM_FAKE_MODE"] = "exact"
        return str(target)


class ContextTests(Workspace):
    def test_caller_arguments_become_the_context(self) -> None:
        shard = shard_account(1)
        self.capture([call(shard, rand_seed="ab" * 32, libraries=text(CONFIG))])
        summary = self.contexts()
        self.assertEqual((summary["converted"], summary["not_convertible"]), (1, []))
        ctx = convert.read_jsonl(self.dir / "work" / "all.jsonl")[0]["context"]
        self.assertEqual(ctx["shard_account"], text(shard))
        self.assertEqual(
            (ctx["now"], ctx["lt"], ctx["rand_seed"]), (1_780_000_000, 2_000_000, "ab" * 32)
        )
        self.assertEqual(ctx["libraries"], text(CONFIG))
        self.assertNotIn("prev_blocks", ctx)

    def test_unset_lt_and_seed_take_the_emulator_defaults(self) -> None:
        self.capture([call(shard_account(2, last_lt=5_000_123), lt=None)])
        summary = self.contexts()
        ctx = convert.read_jsonl(self.dir / "work" / "all.jsonl")[0]["context"]
        self.assertEqual((ctx["lt"], ctx["rand_seed"]), (6_000_000, "0" * 64))
        self.assertEqual(summary["defaults_applied"], {"lt": 1, "rand_seed": 1})

    def test_inexpressible_calls_are_listed_not_converted(self) -> None:
        self.capture(
            [
                call(shard_account(3), ignore_chksig=True),
                call(shard_account(4), now=None),
                call(shard_account(5)),
            ]
        )
        summary = self.contexts()
        self.assertEqual(summary["converted"], 1)
        reasons = sorted(s["reason"].split(" ")[0] for s in summary["not_convertible"])
        self.assertEqual(reasons, ["ignore_chksig=true", "unixtime"])

    def test_duplicate_contexts_are_frozen_once(self) -> None:
        shard = shard_account(6)
        self.capture([call(shard), call(shard)])
        summary = self.contexts()
        self.assertEqual((summary["converted"], summary["unique"]), (2, 1))

    def test_native_rejection_and_error_effects(self) -> None:
        self.assertEqual(
            convert.native_effect(
                {"success": False, "external_not_accepted": True, "vm_exit_code": -14}
            ),
            {"outcome": "rejected", "vm_exit_code": -14},
        )
        self.assertEqual(
            convert.native_effect({"success": False, "error": "x"}), {"outcome": "error"}
        )


class CheckTests(Workspace):
    target: str = ""

    def setUp(self) -> None:
        super().setUp()
        self.capture([call(shard_account(7)), call(shard_account(8))])
        self.contexts()
        self.target = self.fake_target()

    def test_matching_target_passes(self) -> None:
        self.assertEqual(convert.command_check(self.dir / "work", self.target), 0)

    def test_red_control_changed_effect_fails(self) -> None:
        os.environ["TXNFAM_FAKE_MODE"] = "mutate"
        self.assertEqual(convert.command_check(self.dir / "work", self.target), 1)

    def test_red_control_tampered_fixture_fails(self) -> None:
        native = convert.read_jsonl(self.dir / "work" / "native.jsonl")
        fixtures = [
            {"metadata": {"fixture_id": n["fixture_id"]}, "effects": dict(n["effects"])}
            for n in native
        ]
        path = self.dir / "fixtures.jsonl"
        convert.write_jsonl(path, fixtures)
        self.assertEqual(convert.command_fixtures(self.dir / "work", path), 0)
        fixtures[1]["effects"]["account_hash"] = "1" * 64
        convert.write_jsonl(path, fixtures)
        self.assertEqual(convert.command_fixtures(self.dir / "work", path), 1)


class ArtifactTests(Workspace):
    # Placeholders; setUp assigns every one of them before a test runs.
    shard: Any = None
    effect: Any = None
    output: Path = Path()

    def setUp(self) -> None:
        super().setUp()
        self.shard = shard_account(9)
        self.capture([call(self.shard)])
        self.contexts()
        convert.command_check(self.dir / "work", self.fake_target())
        self.effect = convert.read_jsonl(self.dir / "work" / "harness.jsonl")[0]
        self.output = self.dir / "family"
        self.output.mkdir()

    def roots(self, transaction_hash: str, now: int = 1_780_000_000) -> int:
        row = [
            "case",
            str(now),
            "2000000",
            self.shard.boc().hex(),
            MESSAGE.boc().hex(),
            "0" * 64,
            "-",
            "-",
            "0",
        ]
        (self.output / "x-roots.tsv").write_text("#pq-tx-roots-v1\n" + "\t".join(row) + "\n")
        expected = [
            "case",
            "accepted",
            transaction_hash,
            self.effect["account_hash"],
            self.effect["shard_account_hash"],
        ]
        (self.output / "x-root-expected.tsv").write_text("\t".join(expected).lower() + "\n")
        (self.output / "x-config.boc").write_bytes(Cell().uint(0, 256).ref(CONFIG).boc())
        return artifacts.main([str(self.dir / "work"), str(self.output)])

    def test_matching_record_passes_and_names_the_fixture(self) -> None:
        self.assertEqual(self.roots(self.effect["transaction_hash"]), 0)
        note = convert.read_jsonl(self.dir / "work" / "create.jsonl")[0]["note"]
        self.assertTrue(note.startswith("x-roots.tsv:1:case"), note)

    def test_red_control_wrong_record_hash_fails(self) -> None:
        self.assertEqual(self.roots("2" * 64), 1)

    def test_red_control_record_without_a_context_fails(self) -> None:
        self.assertEqual(self.roots(self.effect["transaction_hash"], now=1), 1)


CONFIG_DICT = CONFIG


class RtosTests(unittest.TestCase):
    def row(self, special: str = "0", wc: str = "0") -> list[str]:
        account = Cell().uint(1, 1).uint(5, 8)
        wrapper = Cell().uint(0x55, 256).ref(CONFIG_DICT)
        return [
            "case",
            "200",
            "2000000001",
            wrapper.boc().hex(),
            account.boc().hex(),
            MESSAGE.boc().hex(),
            "-",
            special,
            wc,
            "11" * 32,
        ]

    def test_input_row_becomes_a_context(self) -> None:
        ctx, reason = rtos.context(self.row())
        self.assertIsNone(reason)
        assert ctx is not None
        self.assertEqual((ctx["now"], ctx["lt"], ctx["rand_seed"]), (200, 2_000_000_001, "0" * 64))
        shard = convert.from_boc(base64.b64decode(ctx["shard_account"]))
        self.assertEqual(shard.bits, "0" * 320)
        config = convert.from_boc(base64.b64decode(ctx["config"]))
        self.assertEqual(config.hash, CONFIG_DICT.hash)
        self.assertEqual(ctx["_version"], 16)

    def test_tick_rows_follow_the_filler_rule(self) -> None:
        self.assertEqual(rtos.tick_kind("context-v10-tock-balance0", "name"), "tock")
        self.assertIsNone(rtos.tick_kind("tick-and-tock", "name"))
        self.assertEqual(rtos.tick_kind("tick-address-v16-tock-x", "tick-address-prefix"), "tock")
        self.assertIsNone(rtos.tick_kind("matrix-v16-tick", "tick-address-prefix"))

    def test_error_rows_mean_not_accepted(self) -> None:
        self.assertEqual(rtos.expected(["ERROR", "ERROR"]), {"outcome": "rejected"})

    def test_special_basechain_account_is_not_expressible(self) -> None:
        ctx, reason = rtos.context(self.row(special="1", wc="0"))
        self.assertIsNone(ctx)
        self.assertIsNotNone(reason)


if __name__ == "__main__":
    unittest.main()
