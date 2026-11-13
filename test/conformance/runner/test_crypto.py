#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Tests of the crypto harness validator, its schema and its cross-check scripts. Each check is
shown to fail on a controlled defect."""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

RUNNER = Path(__file__).resolve().parent
CONFORMANCE = RUNNER.parent
SOURCE = CONFORMANCE.parent.parent
sys.path.insert(0, str(RUNNER))

import conformance as c  # noqa: E402
from harnesses import crypto as h  # noqa: E402


def load_script(name: str) -> Any:
    """A migrate/ script as a module; they are programs, not part of the runner's import path."""
    spec = importlib.util.spec_from_file_location(name, CONFORMANCE / "migrate" / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ImportError(name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


crypto_authored = load_script("crypto_authored")
crypto_generators = load_script("crypto_generators")

FIXTURES = CONFORMANCE / "vectors" / "crypto" / "fixtures"
SCHEMA = CONFORMANCE / "schema" / "harness" / "crypto-v1.schema.json"
KEY = "AAEC"


def mldsa(**inputs: Any) -> dict[str, Any]:
    base = {"message": "", "context": "", "signature": KEY, "public_key": KEY}
    return {"scheme": "mldsa44", "operation": "verify", "inputs": {**base, **inputs}}


class ContextTests(unittest.TestCase):
    def ok(self, context: dict[str, Any]) -> None:
        c.validate_context("crypto", context)

    def bad(self, context: dict[str, Any]) -> None:
        with self.assertRaises(c.FixtureError):
            c.validate_context("crypto", context)

    def test_operation_must_be_known(self) -> None:
        self.ok(mldsa())
        self.bad({**mldsa(), "operation": "sign"})
        self.bad({**mldsa(), "scheme": "rsa"})

    def test_inputs_must_match_the_operation(self) -> None:
        context = mldsa()
        del context["inputs"]["context"]
        self.bad(context)
        self.bad(mldsa(extra=KEY))

    def test_bytes_are_base64_or_a_blob(self) -> None:
        self.ok(mldsa(signature={"blob": "0" * 64}))
        self.bad(mldsa(signature="not base64!"))
        self.bad(mldsa(signature="AAE"))
        self.bad(mldsa(signature={"blob": "X"}))

    def test_edits_name_a_byte_input(self) -> None:
        self.ok(
            {**mldsa(), "edits": [{"input": "signature", "op": "xor", "offset": 3, "value": 1}]}
        )
        self.bad({**mldsa(), "edits": [{"input": "nonce", "op": "fill", "value": 0}]})
        self.bad(
            {**mldsa(), "edits": [{"input": "signature", "op": "xor", "offset": 3, "value": 0}]}
        )
        self.bad(
            {
                **mldsa(),
                "edits": [{"input": "signature", "op": "resize", "length": 1 << 17, "value": 0}],
            }
        )
        self.bad({**mldsa(), "edits": []})
        surface = {"scheme": "mldsa44", "operation": "verify_consensus"}
        inputs = {"surface": "simplex", "message": "", "signature": KEY, "public_key": KEY}
        self.bad(
            {**surface, "inputs": inputs, "edits": [{"input": "surface", "op": "fill", "value": 0}]}
        )

    def test_integers_and_identifiers(self) -> None:
        threshold = {"scheme": "quorum", "operation": "threshold"}
        self.ok({**threshold, "inputs": {"total_weight": "18446744073709551615"}})
        self.bad({**threshold, "inputs": {"total_weight": "18446744073709551616"}})
        self.bad({**threshold, "inputs": {"total_weight": "01"}})
        self.bad({**threshold, "inputs": {"total_weight": 5}})
        config = {"scheme": "validator_session", "operation": "config_hash"}
        inputs = {
            "global_id": -239,
            "validator_options_hash": "ab" * 32,
            "simplex_config_cell_hash": "cd" * 32,
        }
        self.ok({**config, "inputs": inputs})
        self.bad({**config, "inputs": {**inputs, "validator_options_hash": "AB" * 32}})
        self.bad({**config, "inputs": {**inputs, "global_id": 1 << 31}})

    def test_validator_set_is_a_set_or_wrapped_descriptors(self) -> None:
        unpack = {"scheme": "validator_set", "operation": "unpack"}
        header = {"utime_since": 1, "utime_until": 2, "total": 1, "main": 1, "total_weight": "5"}
        self.ok({**unpack, "inputs": {"set": KEY}})
        self.ok({**unpack, "inputs": {"descriptors": [KEY], **header}})
        self.bad({**unpack, "inputs": {"set": KEY, "descriptors": [KEY], **header}})
        self.bad({**unpack, "inputs": {"descriptors": [KEY], "total": 1}})
        self.bad({**unpack, "inputs": {}})


class EffectTests(unittest.TestCase):
    def test_shapes(self) -> None:
        for effects in (
            {"outcome": "verdict", "verdict": "malformed_input"},
            {"outcome": "bytes", "output": "00ff"},
            {"outcome": "integer", "value": "7"},
            {"outcome": "boolean", "value": False},
            {"outcome": "record", "fields": {"session_id": "ab"}},
            {"outcome": "rejected", "reason": "candidate_tl"},
        ):
            c.validate_effects("crypto", effects)
        for effects in (
            {"outcome": "verdict", "verdict": "maybe"},
            {"outcome": "bytes", "output": "0F"},
            {"outcome": "integer", "value": 7},
            {"outcome": "boolean", "value": "false"},
            {"outcome": "record", "fields": {"slot": 1}},
            {"outcome": "record", "fields": {}},
            {"outcome": "rejected", "reason": "Too much data"},
            {"outcome": "verdict", "verdict": "valid", "detail": "x"},
        ):
            with self.subTest(effects=effects), self.assertRaises(c.FixtureError):
                c.validate_effects("crypto", effects)


class SchemaTests(unittest.TestCase):
    """The per-operation input table of the validator and of the schema must agree."""

    def disagreements(self) -> list[str]:
        operations = cast(dict[str, Any], json.loads(SCHEMA.read_text())["$defs"]["operations"])
        out: list[str] = []
        if set(operations) != set(h.OPERATIONS):
            out.append(f"operations: {sorted(set(operations) ^ set(h.OPERATIONS))}")
        for name, node in operations.items():
            if name not in h.OPERATIONS:
                continue
            required, allowed = h.input_keys(name)
            props = cast(dict[str, Any], node["properties"])
            if set(cast(list[str], node.get("required", []))) != required or set(props) != allowed:
                out.append(f"{name}: keys")
                continue
            for key, prop in props.items():
                kind = h.kind_of(name, key)
                if isinstance(kind, tuple):
                    if kind[0] == "int":
                        same = (prop.get("minimum"), prop.get("maximum")) == (kind[1], kind[2])
                    else:
                        same = prop.get("enum") == list(kind[1:])
                else:
                    same = prop.get("$ref") == f"#/$defs/{kind}"
                if not same:
                    out.append(f"{name}.{key}")
        return out

    def test_operations_agree(self) -> None:
        self.assertEqual(self.disagreements(), [])

    def test_patterns_agree(self) -> None:
        defs = cast(dict[str, Any], json.loads(SCHEMA.read_text())["$defs"])
        self.assertEqual(defs["bytes"]["oneOf"][0]["pattern"], h.B64_RE.pattern)
        self.assertEqual(defs["hex32"]["pattern"], h.HEX32_RE.pattern)
        self.assertEqual(defs["u64"]["pattern"], h.U64_RE.pattern)
        self.assertEqual(defs["decimal"]["pattern"], h.DECIMAL_RE.pattern)

    def test_schema_drift_is_caught(self) -> None:
        saved = h.OPERATIONS["sha256/digest"]
        try:
            h.OPERATIONS["sha256/digest"] = {"data": "bytes", "salt?": "bytes"}
            self.assertEqual(self.disagreements(), ["sha256/digest: keys"])
            h.OPERATIONS["sha256/digest"] = {"data": "hex32"}
            self.assertEqual(self.disagreements(), ["sha256/digest.data"])
        finally:
            h.OPERATIONS["sha256/digest"] = saved


class CrossCheckTests(unittest.TestCase):
    """The migration cross-checks pass on the frozen fixtures and fail on a tampered copy."""

    def run_quietly(self, fn: Any, *args: Any) -> int:
        with contextlib.redirect_stdout(io.StringIO()):
            return cast(int, fn(*args))

    def tampered(self, family: str, mutate: Any) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        copy = Path(tmp.name) / "fixtures"
        shutil.copytree(FIXTURES, copy)
        path = copy / f"{family}.jsonl"
        records = c.read_jsonl(path)
        mutate(records[0]["effects"])
        c.write_jsonl(path, records)
        return copy

    def generators(self, vectors: Path) -> int:
        args = argparse.Namespace(
            source_dir=SOURCE, vectors=vectors, **dict.fromkeys(crypto_generators.GENERATORS)
        )
        return self.run_quietly(crypto_generators.check, args)

    def test_generator_families_match_their_frozen_files(self) -> None:
        self.assertEqual(self.generators(FIXTURES), 0)

    def test_generator_cross_check_sees_a_changed_effect(self) -> None:
        def flip(effects: dict[str, Any]) -> None:
            effects["output"] = "00" + effects["output"][2:]

        self.assertEqual(self.generators(self.tampered("authorisation-preimage", flip)), 1)

    def test_generator_cross_check_sees_a_changed_reason(self) -> None:
        def reason(effects: dict[str, Any]) -> None:
            if effects["outcome"] == "record":
                effects["fields"]["slot"] = "0"
            else:
                effects["reason"] = "signer_count"

        self.assertEqual(self.generators(self.tampered("pq-block-signatures", reason)), 1)

    def test_authored_expectations_hold(self) -> None:
        self.assertEqual(self.run_quietly(crypto_authored.check, SOURCE, FIXTURES), 0)

    def test_authored_check_sees_a_changed_verdict(self) -> None:
        def flip(effects: dict[str, Any]) -> None:
            effects["verdict"] = "invalid" if effects["verdict"] == "valid" else "valid"

        copy = self.tampered("wycheproof-ed25519", flip)
        self.assertEqual(self.run_quietly(crypto_authored.check, SOURCE, copy), 1)

    def test_every_family_validates(self) -> None:
        self.assertGreater(c.command_validate([FIXTURES]), 9000)


if __name__ == "__main__":
    unittest.main()
