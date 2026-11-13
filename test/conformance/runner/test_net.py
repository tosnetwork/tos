#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Tests of the net harness validator, its refusal-class table and its frozen families. Each check is
shown to fail on a controlled defect."""

from __future__ import annotations

import importlib
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "migrate"))

import conformance as c  # noqa: E402
import fixture_types as t  # noqa: E402
from harnesses import net as h  # noqa: E402

# The generator lives beside the runner, not in it.
nc: Any = importlib.import_module("net_contexts")

ROOT = HERE.parent
VECTORS = ROOT / "vectors" / "net"
ID = "ab" * 32


def walk_strings(value: object) -> list[str]:
    if isinstance(value, dict):
        return [s for item in cast(dict[str, Any], value).values() for s in walk_strings(item)]
    if isinstance(value, list):
        return [s for item in cast(list[Any], value) for s in walk_strings(item)]
    return [value] if isinstance(value, str) else []


class ValidatorTests(unittest.TestCase):
    def test_minimal_contexts_of_each_op(self) -> None:
        c.validate_context("net", {"op": "public_key", "public_key": "00"})
        c.validate_context("net", {"op": "adnl_id", "id": ID})
        c.validate_context("net", {"op": "adnl_id", "text": "X"})
        c.validate_context(
            "net",
            {
                "op": "adnl_channel",
                "local_channel_key": ID,
                "peer_channel_key": ID,
                "local_id": ID,
                "peer_id": ID,
                "datagram": "",
            },
        )
        c.validate_context(
            "net",
            {"op": "overlay_member_certificate", "certificate": "00", "node": ID, "now": -1},
        )
        c.validate_context(
            "net",
            {"op": "rldp2_budget", "data_size": "0", "symbol_size": "1", "symbols_count": "2"},
        )
        c.validate_context("net", {"op": "rldp2_receive", "packets": []})

    def test_bad_contexts(self) -> None:
        good = {"op": "verify", "public_key": "00", "message": "", "signature": ""}
        for bad in (
            {**good, "op": "unknown"},
            {**good, "public_key": "0"},
            {**good, "public_key": "AB"},
            {**good, "extra": 1},
            {"op": "verify", "public_key": "00", "message": ""},
            {"op": "adnl_id"},
            {"op": "adnl_id", "id": ID, "text": "X"},
            {"op": "adnl_id", "id": ID.upper()},
            {"op": "overlay_member_certificate", "certificate": "00", "node": "00", "now": 0},
            {"op": "rldp2_budget", "data_size": 0, "symbol_size": "1", "symbols_count": "2"},
            {
                "op": "rldp2_budget",
                "data_size": str(1 << 64),
                "symbol_size": "1",
                "symbols_count": "2",
            },
            {
                "op": "fec_encode",
                "algorithm": "lt",
                "data": "00",
                "symbol_size": 1,
                "symbol_ids": [],
            },
            {
                "op": "fec_encode",
                "algorithm": "raptorq",
                "data": "00",
                "symbol_size": 1,
                "symbol_ids": [1 << 24],
            },
            {"op": "preauth_source", "address": {"ip": "192.0.2.1", "port": 0}},
        ):
            with self.subTest(context=bad), self.assertRaises(t.FixtureError):
                c.validate_context("net", bad)

    def test_effect_shapes(self) -> None:
        c.validate_effects("net", {"outcome": "verified"})
        c.validate_effects("net", {"outcome": "refused", "reason": "unclassified"})
        c.validate_effects(
            "net",
            {"outcome": "gate", "results": ["admitted", "rate_limited"], "sources": 1, "held": 0},
        )
        for bad in (
            {"outcome": "refused", "reason": "some new class"},
            {"outcome": "refused"},
            {"outcome": "verified", "extra": 1},
            {"outcome": "gate", "results": ["accepted"], "sources": 1, "held": 0},
            {"outcome": "signature", "signature": "XY"},
            {"outcome": "secret", "secret": "00"},
        ):
            with self.subTest(effects=bad), self.assertRaises(t.FixtureError):
                c.validate_effects("net", bad)


class ReasonTableTests(unittest.TestCase):
    """The validator, the schema and the C++ classification table name the same classes."""

    def test_schema_enum(self) -> None:
        schema = json.loads((ROOT / "schema" / "harness" / "net-v1.schema.json").read_text())
        self.assertEqual(set(schema["$defs"]["reason"]["enum"]), set(h.REASONS))

    def test_cpp_table(self) -> None:
        source = (ROOT / "ref" / "harness-net.cpp").read_text()
        table = source[source.index("constexpr ReasonRule kReasonRules[] = {") :]
        table = table[: table.index("};")]
        classes = set(re.findall(r'\{"(?:[^"\\]|\\.)+", "([a-z0-9_]+)"\}', table))
        self.assertEqual(classes | {"unclassified"}, set(h.REASONS))

    def test_schema_ops(self) -> None:
        schema = json.loads((ROOT / "schema" / "harness" / "net-v1.schema.json").read_text())
        ops = set(schema["$defs"]["context"]["properties"]["op"]["enum"])
        self.assertEqual(ops, set(h.OP_REQUIRED))
        source = (ROOT / "ref" / "harness-net.cpp").read_text()
        table = source[source.index("constexpr OpEntry kOps[] = {") :]
        table = table[: table.index("};")]
        self.assertEqual(set(re.findall(r'\{"([a-z0-9_]+)", op_', table)), set(h.OP_REQUIRED))


def families() -> dict[str, c.FamilyFile]:
    return {p.stem: c.load_family(p) for p in sorted((VECTORS / "fixtures").glob("*.jsonl"))}


class FamilyTests(unittest.TestCase):
    """The frozen families: every class reached, nothing unclassified, sources as declared."""

    def test_families_are_the_generator_families(self) -> None:
        self.assertEqual(set(families()), set(nc.FAMILY_SOURCES))
        for name, fam in families().items():
            for fixture in fam.fixtures:
                self.assertEqual(fixture["metadata"]["source"], nc.FAMILY_SOURCES[name])

    def test_every_refusal_class_is_reached(self) -> None:
        reached: set[str] = set()
        for fam in families().values():
            for fixture in fam.fixtures:
                reached |= {s for s in walk_strings(fixture["effects"]) if s in h.REASONS}
        self.assertEqual(set(h.REASONS) - reached, {"unclassified"})

    def test_every_op_is_exercised(self) -> None:
        ops = {f["context"]["op"] for fam in families().values() for f in fam.fixtures}
        self.assertEqual(ops, set(h.OP_REQUIRED))


class CrossCheckControlTests(unittest.TestCase):
    """net_contexts.py check passes on the frozen families and fails on each controlled defect."""

    # Placeholder; setUp assigns it before a test runs.
    copy: Path = Path()

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.copy = Path(tmp.name) / "net"
        _ = shutil.copytree(VECTORS, self.copy)

    def edit(self, family: str, fixture_id: str, change: Any) -> None:
        path = self.copy / "fixtures" / f"{family}.jsonl"
        records = [json.loads(line) for line in path.read_text().splitlines()]
        for record in records:
            if record["metadata"]["fixture_id"] == fixture_id:
                change(record)
                break
        else:
            self.fail(f"{family}/{fixture_id} not found")
        path.write_text(
            "".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in records)
        )

    def test_frozen_families_pass(self) -> None:
        self.assertEqual(nc.command_check(VECTORS), [])

    def test_wrong_known_answer_fails(self) -> None:
        def change(record: dict[str, Any]) -> None:
            record["effects"]["signature"] = "00" + record["effects"]["signature"][2:]

        self.edit("ed25519-rfc8032", "000/sign", change)
        self.assertTrue(nc.command_check(self.copy))

    def test_channel_ends_disagreeing_fails(self) -> None:
        def change(record: dict[str, Any]) -> None:
            record["effects"]["in_id"] = "00" * 32

        self.edit("adnl-channel", "alice-ids", change)
        self.assertTrue(nc.command_check(self.copy))

    def test_rldp2_framing_difference_fails(self) -> None:
        def change(record: dict[str, Any]) -> None:
            record["effects"]["packets"][0]["sha256"] = "00" * 32

        self.edit("rldp2", "send/768", change)
        self.assertTrue(nc.command_check(self.copy))

    def test_decoded_data_difference_fails(self) -> None:
        def change(record: dict[str, Any]) -> None:
            record["effects"]["data_sha256"] = "00" * 32

        self.edit("fec-raptorq", "decode/s768-n769-source", change)
        self.assertTrue(nc.command_check(self.copy))

    def test_broadcast_delivery_difference_fails(self) -> None:
        def change(record: dict[str, Any]) -> None:
            record["effects"]["delivered"] = record["effects"]["delivered"][:1]

        self.edit("overlay-broadcast", "twostep/fec-6", change)
        self.assertTrue(nc.command_check(self.copy))

    def test_broadcast_replay_difference_fails(self) -> None:
        def change(record: dict[str, Any]) -> None:
            emitted = record["effects"]["emitted"][0]
            emitted["canonical"] = emitted["canonical"][:-2] + "ff"

        self.edit("overlay-broadcast", "simple/hello", change)
        self.assertTrue(nc.command_check(self.copy))


if __name__ == "__main__":
    unittest.main()
