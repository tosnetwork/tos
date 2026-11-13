#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Tests of the consensus harness validator, its fixture cross-checks and the network scenario
comparison. Each check is shown to fail on a controlled defect."""

from __future__ import annotations

import copy
import importlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "migrate"))
sys.path.insert(0, str(HERE.parent / "scenarios"))

import conformance as c  # noqa: E402

# The generator and the scenario runner live beside the runner, not in it.
cc: Any = importlib.import_module("consensus_contexts")
rs: Any = importlib.import_module("run_scenarios")

VECTORS = HERE.parent / "vectors" / "consensus"
HASH = "A" * 64
BLOCK = {
    "workchain": -1,
    "shard": "8000000000000000",
    "seqno": 5,
    "root_hash": HASH,
    "file_hash": HASH,
}


def reference_cli() -> Path | None:
    configured = os.environ.get("CONFORMANCE_REFERENCE")
    candidates = [Path(configured)] if configured else []
    candidates.append(HERE.parents[2] / "build" / "test" / "conformance" / "conformance-ref-cli")
    return next((p for p in candidates if p.is_file()), None)


class ValidatorTests(unittest.TestCase):
    def test_minimal_contexts_of_each_op(self) -> None:
        c.validate_context("consensus", {"op": "quorum", "total_weight": "4", "signed_weight": "3"})
        c.validate_context("consensus", {"op": "weight_total", "weights": []})
        c.validate_context("consensus", {"op": "protocol_version", "protocol_version": 2})
        c.validate_context("consensus", {"op": "decode_proof", "block_proof": "te6c"})
        c.validate_context(
            "consensus",
            {
                "op": "vote",
                "session_id": HASH,
                "slot": 1,
                "candidate": "00",
                "final": True,
                "block": BLOCK,
            },
        )

    def test_op_selects_its_keys(self) -> None:
        for bad in (
            {"op": "quorum", "total_weight": "4"},
            {"op": "quorum", "total_weight": "4", "signed_weight": "3", "slot": 1},
            {"op": "unknown"},
            {"total_weight": "4", "signed_weight": "3"},
        ):
            with self.subTest(context=bad), self.assertRaises(c.FixtureError):
                c.validate_context("consensus", bad)

    def test_weights_are_canonical_u64_decimals(self) -> None:
        for weight in ("01", "-1", "18446744073709551616", "1.0", 1):
            with self.subTest(weight=weight), self.assertRaises(c.FixtureError):
                c.validate_context(
                    "consensus", {"op": "quorum", "total_weight": weight, "signed_weight": "0"}
                )
        c.validate_context(
            "consensus",
            {"op": "quorum", "total_weight": "18446744073709551615", "signed_weight": "0"},
        )

    def test_finality_needs_exactly_one_signature_source(self) -> None:
        base: dict[str, Any] = {
            "op": "finality",
            "validators": [],
            "catchain_seqno": 0,
            "block": BLOCK,
            "expected_session_id": HASH,
            "role": "final",
        }
        sig_set = {
            "catchain_seqno": 0,
            "validator_set_hash": 0,
            "session_id": HASH,
            "slot": 0,
            "candidate": "00",
            "signatures": [],
        }
        c.validate_context("consensus", {**base, "signature_set": sig_set})
        c.validate_context("consensus", {**base, "block_proof": "te6c"})
        for bad in (
            base,
            {**base, "signature_set": sig_set, "block_proof": "te6c"},
            {**base, "block_proof": "te6c", "claimed_weight": "1"},
        ):
            with self.subTest(keys=sorted(bad)), self.assertRaises(c.FixtureError):
                c.validate_context("consensus", bad)

    def test_effects_by_outcome(self) -> None:
        c.validate_effects("consensus", {"outcome": "refused", "reason": "duplicate_signer"})
        c.validate_effects(
            "consensus", {"outcome": "quorum", "threshold": "3", "has_quorum": False}
        )
        for bad in (
            {"outcome": "refused", "reason": "Duplicate signer"},
            {"outcome": "refused", "reason": "x", "detail": "text"},
            {"outcome": "quorum", "threshold": 3, "has_quorum": False},
            {
                "outcome": "vote",
                "candidate_hash": HASH,
                "data_to_sign": "00",
                "signature_check": "ok",
            },
        ):
            with self.subTest(effects=bad), self.assertRaises(c.FixtureError):
                c.validate_effects("consensus", bad)


class CrossCheckTests(unittest.TestCase):
    """The frozen families agree with each other; a tampered copy is reported."""

    copy: Path = Path()

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.copy = Path(tmp.name) / "consensus"
        shutil.copytree(VECTORS, self.copy)

    def family(self, name: str) -> tuple[Path, list[dict[str, Any]]]:
        path = self.copy / "fixtures" / f"{name}.jsonl"
        return path, c.read_jsonl(path)

    def test_frozen_families_agree(self) -> None:
        self.assertEqual(cc.command_check(self.copy), [])

    def test_changed_session_effect_breaks_its_expectation(self) -> None:
        path, records = self.family("session-real")
        real = next(r for r in records if r["metadata"]["fixture_id"].startswith("real/"))
        real["effects"]["session_id"] = "B" * 64
        c.write_jsonl(path, records)
        problems = cc.command_check(self.copy)
        self.assertTrue(any("session_id" in p for p in problems), problems)

    def test_disagreeing_session_derivations_are_reported(self) -> None:
        path, records = self.family("key-block-context-real")
        records[0]["effects"]["validator_path_session_id"] = "C" * 64
        c.write_jsonl(path, records)
        problems = cc.command_check(self.copy)
        self.assertTrue(any("derivations differ" in p for p in problems), problems)

    def test_changed_refusal_class_breaks_its_expectation(self) -> None:
        path, records = self.family("finality-authored")
        refused = next(r for r in records if r["effects"]["outcome"] == "refused")
        refused["effects"]["reason"] = "unclassified"
        c.write_jsonl(path, records)
        self.assertNotEqual(cc.command_check(self.copy), [])

    def test_tampered_fixture_fails_against_the_reference(self) -> None:
        reference = reference_cli()
        if reference is None:
            self.skipTest("conformance-ref-cli not built; conformance-vectors covers this in ctest")
        path, records = self.family("quorum-authored")
        mutated = copy.deepcopy(records)
        mutated[0]["effects"]["has_quorum"] = not mutated[0]["effects"]["has_quorum"]
        c.write_jsonl(path, mutated)
        others = [p for p in (self.copy / "fixtures").glob("*.jsonl") if p != path]
        for other in others:
            other.unlink()
        for blobs in (self.copy / "fixtures").glob("*.blobs.json"):
            blobs.unlink()
        tally = c.command_run(str(reference), [self.copy])
        self.assertEqual((tally.mismatched, tally.equal), (1, len(records) - 1))
        c.write_jsonl(path, records)
        self.assertTrue(c.command_run(str(reference), [self.copy]).ok())


def observation(name: str, state: str = "D" * 64, signers: int = 3) -> Any:
    obs = rs.NodeObservation(name, "cpp:test")
    for seqno in (1, 2):
        obs.blocks[seqno] = (f"{seqno:064X}", HASH)
        obs.proof_blocks[seqno] = obs.blocks[seqno]
        obs.states[seqno] = state
        obs.certificates[seqno] = rs.Certificate(
            HASH, seqno, "00", 0, [f"V{i}" for i in range(signers)], []
        )
    return obs


WEIGHTS = {f"V{i}": 17 for i in range(4)}
THRESHOLD = (2 * 68 + 2) // 3


class ScenarioComparisonTests(unittest.TestCase):
    def check(self, observations: list[Any], expected: Any = None):
        return rs.compare(observations, [1, 2], WEIGHTS, THRESHOLD, expected or rs.Expected())

    def test_agreeing_nodes_pass(self) -> None:
        self.assertEqual(self.check([observation("a"), observation("b")]), [])

    def test_different_state_root_fails(self) -> None:
        failures = self.check([observation("a"), observation("b", state="E" * 64)])
        self.assertTrue(any("state root" in f for f in failures), failures)

    def test_different_block_id_fails(self) -> None:
        b = observation("b")
        b.blocks[2] = ("F" * 64, HASH)
        failures = self.check([observation("a"), b])
        self.assertTrue(any("block id" in f for f in failures), failures)

    def test_wrong_expected_root_fails(self) -> None:
        pinned = rs.Expected(states={1: "0" * 64})
        failures = self.check([observation("a"), observation("b")], pinned)
        self.assertEqual(len([f for f in failures if "expected" in f]), 2, failures)

    def test_certificate_below_threshold_fails(self) -> None:
        failures = self.check([observation("a", signers=2)])
        self.assertTrue(any("below" in f for f in failures), failures)

    def test_invalid_or_missing_certificate_fails(self) -> None:
        bad = observation("a")
        bad.certificates[1].invalid_signers.append("V0")
        del bad.certificates[2]
        failures = self.check([bad])
        self.assertTrue(any("invalid signatures" in f for f in failures), failures)
        self.assertTrue(any("no finality certificate" in f for f in failures), failures)

    def test_missing_observation_fails(self) -> None:
        b = observation("b")
        del b.states[1]
        self.assertNotEqual(self.check([observation("a"), b]), [])
        self.assertEqual(
            rs.compare([], [1], WEIGHTS, THRESHOLD, rs.Expected()), ["no node was observed"]
        )

    def test_node_specs(self) -> None:
        exe = Path(sys.executable)
        self.assertEqual(len(rs.parse_node_specs([f"cpp:{exe}"], 4)), 4)
        mixed = rs.parse_node_specs([f"cpp:{exe}", f"adapter:{exe}"], 2)
        self.assertEqual([m.kind for m in mixed], ["cpp", "adapter"])
        for bad in ([f"rust:{exe}"], ["cpp:/nonexistent/engine"], [f"cpp:{exe}"] * 3):
            with self.subTest(spec=bad), self.assertRaises(rs.ScenarioError):
                rs.parse_node_specs(bad, 4)

    def test_runner_reports_a_failed_assertion(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        reference = root / "build" / "test" / "conformance" / "conformance-ref-cli"
        reference.parent.mkdir(parents=True)
        reference.write_text("")

        async def fake(name: str, settings: Any) -> dict[str, Any]:
            obs = [observation("a"), observation("b")]
            failures = rs.compare(obs, [1, 2], WEIGHTS, THRESHOLD, settings.expected)
            return {"scenario": name, "failures": failures}

        argv = [
            "--build-dir",
            str(root / "build"),
            "--source-dir",
            str(root),
            "--work-dir",
            str(root / "work"),
            "--node",
            f"cpp:{sys.executable}",
            "--scenario",
            "bootstrap",
            "--allow-rotational",
        ]
        self.assertEqual(rs.main(argv, runner=fake), 0)
        self.assertEqual(rs.main([*argv, "--expect-state", f"1={'0' * 64}"], runner=fake), 1)
        reports = cast(
            list[dict[str, Any]], json.loads((root / "work" / "run-2" / "report.json").read_text())
        )
        self.assertTrue(reports[0]["failures"])


if __name__ == "__main__":
    unittest.main()
