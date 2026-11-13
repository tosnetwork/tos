#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Tests of the VM family converters (migrate/vmfam.py, migrate/vmfam_rtos.py).

Each comparison is shown to fail on a controlled defect; each conversion rule is pinned on a
small input whose context is written out here.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

MIGRATE = Path(__file__).resolve().parent.parent / "migrate"
sys.path.insert(0, str(MIGRATE))

import vmfam  # noqa: E402  # pyright: ignore[reportMissingImports]
import vmfam_rtos  # noqa: E402  # pyright: ignore[reportMissingImports]

HASH = "A" * 64
CELL_HEX = "b5ee9c72010101010002000000"  # an empty cell


def effects(gas: int = 30, exit_code: int = 0, stack: list[str] | None = None) -> dict[str, Any]:
    return {
        "exit_code": exit_code,
        "gas_used": gas,
        "steps": 3,
        "committed": exit_code == 0,
        "c4_hash": HASH if exit_code == 0 else None,
        "c5_hash": HASH if exit_code == 0 else None,
        "stack": ["-1"] if stack is None else stack,
    }


def fixture(fixture_id: str, eff: dict[str, Any]) -> dict[str, Any]:
    return {"metadata": {"fixture_id": fixture_id}, "effects": eff}


def quiet_compare(name: str, fixtures: list[dict[str, Any]], rows: dict[str, list[str]]) -> int:
    with redirect_stdout(io.StringIO()):
        return vmfam.compare(vmfam.FAMILIES[name], fixtures, rows)


class CompareTests(unittest.TestCase):
    def test_equal_rows_pass(self) -> None:
        rows = {"a": ["0", "30", "3", "1", HASH, HASH, "-1"]}
        self.assertEqual(quiet_compare("vm-prefix", [fixture("a", effects())], rows), 0)

    def test_changed_gas_is_a_difference(self) -> None:
        rows = {"a": ["0", "31", "3", "1", HASH, HASH, "-1"]}
        self.assertEqual(quiet_compare("vm-prefix", [fixture("a", effects())], rows), 1)

    def test_changed_stack_is_a_difference(self) -> None:
        rows = {"a": ["0", "30", "3", "1", HASH, HASH, "0"]}
        self.assertEqual(quiet_compare("vm-prefix", [fixture("a", effects())], rows), 1)

    def test_fixture_without_a_driver_row_fails(self) -> None:
        self.assertEqual(quiet_compare("vm-prefix", [fixture("a", effects())], {}), 1)

    def test_suite_value_is_the_single_result(self) -> None:
        rows = {"a": ["0", "30", "-1", "3"], "b": ["9", "30", "99", "3"]}
        fixtures = [fixture("a", effects()), fixture("b", effects(exit_code=9, stack=["0"]))]
        self.assertEqual(quiet_compare("pq-suite-parity", fixtures, rows), 0)
        rows["a"][2] = "0"
        self.assertEqual(quiet_compare("pq-suite-parity", fixtures, rows), 1)

    def test_two_results_never_equal_a_driver_value(self) -> None:
        rows = {"a": ["0", "30", "-1", "3"]}
        fixtures = [fixture("a", effects(stack=["-1", "-1"]))]
        self.assertEqual(quiet_compare("pq-suite-parity", fixtures, rows), 1)


class TosConversionTests(unittest.TestCase):
    def test_endstate_row_pushes_lower_values_then_the_top(self) -> None:
        row = ["x", "16", "500", "V", "int:5", "int:1", "skip", "skip", "int:2", CELL_HEX]
        ctx = vmfam.endstate_context(row)
        self.assertEqual([i["value"] for i in ctx["stack"]], ["1", "2", "5"])
        self.assertEqual(ctx["gas"], {"limit": 500, "max": 500})
        self.assertNotIn("c7", ctx)

    def test_pq_rows_repeat_operands_and_skip_ignored_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "s.tsv"
            rows = [
                ["a", "16", "1000", "0", "2", "V", "int", "skip", CELL_HEX, "skip"],
                ["b", "16", "1000", "1", "1", "V", "int", "skip", "skip", "skip"],
                ["c", "16", "1000", "0", "1", "V", "int", "skip", "skip", "skip", CELL_HEX],
            ]
            path.write_text("".join("\t".join(r) + "\n" for r in rows))
            vmfam.SKIPPED.clear()
            entries = vmfam.pq_entries(path, 0xF93100, 12)
        self.assertEqual([e["fixture_id"] for e in entries], ["a", "c"])
        self.assertEqual([s.fixture_id for s in vmfam.SKIPPED], ["b"])
        self.assertEqual([i["type"] for i in entries[0]["context"]["stack"]], ["int", "cell"] * 2)
        # A compiled program is entered with 0 on top.
        self.assertEqual(entries[1]["context"]["stack"][-1], {"type": "int", "value": "0"})
        # Two opcodes with DROP between: 24 + 8 + 24 bits.
        self.assertEqual(entries[0]["context"]["code"], vmfam.code_of(0xF93100, 2))
        self.assertNotIn("chksig_always_succeed", entries[0]["context"])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "s.tsv"
            path.write_text("".join("\t".join(r) + "\n" for r in rows))
            ignored = vmfam.pq_entries(path, 0xF93100, 12, ignored=True)
        self.assertEqual([e["fixture_id"] for e in ignored], ["b"])
        self.assertIs(ignored[0]["context"]["chksig_always_succeed"], True)


class RtosConversionTests(unittest.TestCase):
    ROW: dict[str, Any] = {
        "prices": CELL_HEX,
        "limits": CELL_HEX,
        "address": CELL_HEX,
        "context": "normal",
    }

    def c7_info(self, context: str) -> list[dict[str, Any]]:
        c7 = vmfam_rtos.sendmsg_c7(dict(self.ROW, context=context))
        return c7["items"][0]["items"]

    def test_sendmsg_c7_shape(self) -> None:
        info = self.c7_info("normal")
        self.assertEqual(len(info), 18)
        self.assertEqual(len(info[14]["items"]), 7)
        self.assertEqual(info[8]["type"], "slice")

    def test_sendmsg_short_limits_drop_the_last_entry(self) -> None:
        self.assertEqual(len(self.c7_info("limits-short")[14]["items"]), 6)

    def test_integer_outside_257_bits_is_not_convertible(self) -> None:
        with self.assertRaises(vmfam_rtos.NotConvertible):
            self.c7_info("balance-wide")
        self.assertEqual(self.c7_info("balance-max")[7]["items"][0]["value"], str((1 << 256) - 1))

    def test_unknown_context_is_refused(self) -> None:
        with self.assertRaises(SystemExit):
            self.c7_info("unheard-of")

    def test_short_code_pads_and_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "s.tsv"
            path.write_text("# header\nx\t16\t100\t3\t9\t7180\t0\t0\t0\n")
            result = vmfam_rtos.short_code(path, vmfam_rtos.Builder(None))
            stack = result.entries[0]["context"]["stack"]
            self.assertEqual([i["value"] for i in stack], ["1", "2", "3"])
            path.write_text("x\t16\t100\t0\t9\t7181\t0\t0\t0\n")
            with self.assertRaises(SystemExit):
                vmfam_rtos.short_code(path, vmfam_rtos.Builder(None))

    def test_pq_cases_with_ignore_are_not_converted(self) -> None:
        data = {
            "cells": [CELL_HEX],
            "cases": [
                {
                    "name": n,
                    "version": 16,
                    "gas": 100,
                    "ignore": ignore,
                    "repeats": 1,
                    "operands": [0, "skip"],
                    "program": 0,
                    "expected": [],
                }
                for n, ignore in (("kept", False), ("ignored", True))
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "d.json"
            path.write_text(json.dumps(data))

            class FakeBuilder(vmfam_rtos.Builder):
                def run(self) -> None:
                    self.results = [CELL_HEX for _ in self.requests]

            result = vmfam_rtos.pq_family("pq-mldsa44")(path, FakeBuilder(None))
            ignored = vmfam_rtos.pq_family("pq-mldsa44", ignored=True)(path, FakeBuilder(None))
        self.assertEqual([e["fixture_id"] for e in result.entries], ["kept"])
        self.assertEqual(result.skipped[0][0], "ignored")
        self.assertEqual(result.entries[0]["context"]["gas"]["max"], vmfam_rtos.TEST_GAS_MAX)
        self.assertNotIn("chksig_always_succeed", result.entries[0]["context"])
        self.assertEqual([e["fixture_id"] for e in ignored.entries], ["ignored"])
        self.assertIs(ignored.entries[0]["context"]["chksig_always_succeed"], True)

    def test_library_limit_names_become_fixture_ids(self) -> None:
        self.assertEqual(vmfam_rtos.limit_id("single-v9-limitSome(2)"), "single-v9-limitSome-2")
        self.assertEqual(vmfam_rtos.limit_id("single-v9-limitNone"), "single-v9-limitNone")


if __name__ == "__main__":
    unittest.main()
