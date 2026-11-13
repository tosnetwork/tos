#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Tests of the get_method harness validator and authored assertions on its frozen families."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parent))

import conformance as c  # noqa: E402
import fixture_types as t  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "test" / "conformance" / "vectors" / "get_method" / "fixtures"
C7_SHAPE = ROOT / "test" / "validator" / "data" / "getter-c7-shape.tsv"
HASH = "A" * 64
BOC = "te6ccgEBAQEAAwAAAXA="
SEED = "0" * 64

# Row counts of the Rust node's frozen getter families; every row is migrated.
RUST_FAMILY_ROWS = {
    "rust-get-context": 748,
    "rust-get-history-context": 1314,
    "rust-get-method-id-context": 80,
}


def context(**changes: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "mc_state": BOC,
        "mc_block": {"seqno": 1, "root_hash": HASH, "file_hash": HASH},
        "account": BOC,
        "now": 200,
        "lt": 2000000000,
        "rand_seed": SEED,
        "method_id": "12345",
        "stack": [{"type": "int", "value": "7"}],
        "gas_limit": 300000,
    }
    base.update(changes)
    return base


def family_path(family: str) -> Path | None:
    """In the tree, or in the external vectors checkout named by CONFORMANCE_VECTORS_DIR."""
    candidates = [FIXTURES / f"{family}.jsonl"]
    external = os.environ.get("CONFORMANCE_VECTORS_DIR")
    if external:
        candidates.append(Path(external) / "get_method" / "fixtures" / f"{family}.jsonl")
    return next((p for p in candidates if p.exists()), None)


def fixtures(family: str) -> dict[str, dict[str, Any]]:
    path = family_path(family)
    if path is None:
        raise unittest.SkipTest(
            f"{family}: in the external vectors repository; set CONFORMANCE_VECTORS_DIR"
        )
    loaded = c.load_family(path)
    return {
        cast(str, f["metadata"]["fixture_id"]): cast(dict[str, Any], f["effects"])
        for f in loaded.fixtures
    }


class ValidatorTests(unittest.TestCase):
    def test_context_shapes(self) -> None:
        c.validate_context("get_method", context())
        c.validate_context("get_method", context(method_id="-9223372036854775808"))
        for bad in (
            context(method_id="9223372036854775808"),
            context(method_id="012"),
            context(method_id=12345),
            context(lt=2**63),
            context(now=2**32),
            context(rand_seed="A" * 64),
            context(mc_block={"seqno": 1, "root_hash": HASH}),
            context(stack=[{"type": "cont"}]),
            {k: v for k, v in context().items() if k != "gas_limit"},
        ):
            with self.subTest(context=bad), self.assertRaises(t.FixtureError):
                c.validate_context("get_method", bad)

    def test_effect_shapes(self) -> None:
        executed = {
            "outcome": "executed",
            "exit_code": 0,
            "gas_used": 10,
            "stack": ["1"],
            "missing_library": None,
        }
        c.validate_effects("get_method", executed)
        c.validate_effects("get_method", {**executed, "missing_library": HASH})
        c.validate_effects("get_method", {"outcome": "no_state"})
        c.validate_effects("get_method", {"outcome": "context_unavailable"})
        for bad in (
            {**executed, "missing_library": "abc"},
            {k: v for k, v in executed.items() if k != "missing_library"},
            {"outcome": "no_state", "exit_code": 0},
            {"outcome": "error"},
        ):
            with self.subTest(effects=bad), self.assertRaises(t.FixtureError):
                c.validate_effects("get_method", bad)


class FrozenFamilyTests(unittest.TestCase):
    """Assertions checked against the C++ fill; a failure is a finding, not a fixture to edit."""

    def test_c7_shape_rows(self) -> None:
        effects = fixtures("c7-shape")
        rows = [
            line.split("\t")
            for line in C7_SHAPE.read_text().splitlines()
            if line and not line.startswith("#")
        ]
        self.assertTrue(rows)
        for version, length, slot in rows:
            with self.subTest(version=version):
                self.assertEqual(effects[f"c7-shape-v{version}-length"]["stack"], ["12345", length])
                probe = effects[f"c7-shape-v{version}-slot18"]
                if slot == "absent":
                    # INDEXVAR past the end of the tuple is a range check error.
                    self.assertEqual(probe["exit_code"], 5)
                else:
                    self.assertEqual(slot, "null")
                    self.assertEqual((probe["exit_code"], probe["stack"]), (0, ["12345", "-1"]))

    def test_rust_families_are_complete(self) -> None:
        for family, rows in RUST_FAMILY_ROWS.items():
            with self.subTest(family=family):
                self.assertEqual(len(fixtures(family)), rows)

    def test_method_id_reaches_the_code(self) -> None:
        # The echo probe leaves the pushed method id; the dispatch probe compares it with its own.
        for fixture_id, effects in fixtures("rust-get-method-id-context").items():
            with self.subTest(fixture=fixture_id):
                self.assertEqual(effects["outcome"], "executed")
                self.assertEqual(effects["exit_code"], 0)
                if fixture_id.endswith("-dispatch"):
                    self.assertEqual(effects["stack"], ["111"])
                else:
                    self.assertEqual(len(effects["stack"]), 1)

    def test_system_contract_getters_succeed(self) -> None:
        elector = 0
        for fixture_id, effects in fixtures("rel02-getters").items():
            address, method = fixture_id.split(":")[1], fixture_id.split(":")[3]
            if address.startswith("3333") or (
                address.startswith("5555") and method not in ("seqno", "get_public_key")
            ):
                elector += address.startswith("3333")
                with self.subTest(fixture=fixture_id):
                    self.assertEqual((effects["outcome"], effects["exit_code"]), ("executed", 0))
        self.assertGreater(elector, 0)


if __name__ == "__main__":
    unittest.main()
