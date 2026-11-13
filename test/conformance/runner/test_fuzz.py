#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Tests of the fuzz tools (fuzz_process.py, fuzz_boc.py, minimize.py, debug_mismatch.py) against fake
targets. Each check is shown to fail on a controlled defect. The C++ driver and the real reference are
checked by the conformance-fuzz-* ctests (parts/fuzz.cmake)."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
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
import debug_mismatch as dbg  # noqa: E402
import fuzz_boc as boc  # noqa: E402
import fuzz_process as fp  # noqa: E402
import minimize as mz  # noqa: E402

VECTORS = Path(__file__).resolve().parent.parent / "vectors"
Json = dict[str, Any]

# A generator with the --emit interface: case i is a vm context whose code is one byte, i % 256.
FAKE_GENERATOR = r"""
import base64, json, sys
args = sys.argv[1:]
def arg(name, default):
    return int(args[args.index(name) + 1]) if name in args else default
cases, start, seed = arg("--cases", 1), arg("--start", 0), arg("--seed", 1)
for i in range(start, start + cases):
    byte = (i * 7 + seed) % 256
    boc = bytes.fromhex("b5ee9c72010101010003000002") + bytes([byte])
    ctx = {"code": base64.b64encode(boc).decode(), "global_version": 16,
           "gas": {"limit": 1000, "max": 1000}, "stack": []}
    print(json.dumps({"index": i, "lineage": "grammar" if i % 2 else "seedfam", "context": ctx}))
"""

# A target with the line protocol. FAKE_FUZZ_MODE: exact; mutate (gas + 1 when the code byte is a multiple
# of 5); refuse-some (refuses multiples of 3); trace-diverge (answers trace requests, the trace differing
# at event 3); trace-perturb (the trace request changes the effects); no-trace (refuses trace requests).
FAKE_TARGET = r"""
import base64, json, os, sys
mode = os.environ.get("FAKE_FUZZ_MODE", "exact")
if sys.argv[1] == "--info":
    print(json.dumps({"reference_commit": "0" * 40, "dirty": False, "harnesses": ["vm"]}))
    sys.exit(0)
out = []
for line in sys.stdin.read().splitlines():
    ctx = json.loads(line)
    raw = base64.b64decode(ctx["code"])
    byte = raw[-1]
    effects = {"exit_code": 0, "gas_used": 18 + byte, "steps": 1, "committed": True,
               "c4_hash": None, "c5_hash": None, "stack": [str(len(ctx["stack"]))]}
    if mode == "mutate" and byte % 5 == 0:
        effects["gas_used"] += 1
    if mode == "refuse-some" and byte % 3 == 0:
        effects = {"harness_error": "refused for the test"}
    if ctx.get("trace"):
        if mode in ("exact", "mutate", "refuse-some", "no-trace"):
            effects = {"harness_error": "trace requires a build with TOS_VM_STEP_TRACE"}
        else:
            events = [{"kind": "step", "step": n, "gas": 10 * n} for n in range(6)]
            if os.environ.get("FAKE_FUZZ_SIDE") == "target":
                events[3]["gas"] += 1
            effects["trace"] = {"events": events, "truncated": False}
            if mode == "trace-perturb":
                effects["steps"] += 1
    out.append(json.dumps(effects))
print("\n".join(out))
"""


def script(directory: Path, name: str, body: str, env: dict[str, str] | None = None) -> str:
    """An executable; with env, a wrapper that sets those variables first."""
    path = directory / name
    prefix = "".join(f"os.environ[{k!r}] = {v!r}\n" for k, v in (env or {}).items())
    path.write_text(f"#!{sys.executable}\nimport os\n{prefix}{body}")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


def quiet_main(fn: Any, argv: list[str]) -> int:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return cast(int, fn(argv))


class Fixture(unittest.TestCase):
    dir: Path = Path()
    generator: str = ""
    exact: str = ""
    mutant: str = ""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.generator = script(self.dir, "fake-generator", FAKE_GENERATOR)
        self.exact = script(self.dir, "fake-exact", FAKE_TARGET, {"FAKE_FUZZ_MODE": "exact"})
        self.mutant = script(self.dir, "fake-mutant", FAKE_TARGET, {"FAKE_FUZZ_MODE": "mutate"})

    def run_campaign(self, target: str, *extra: str, cases: int = 200) -> int:
        argv = ["run", "--generator", self.generator, "--harness", "vm", "--reference", self.exact]
        argv += ["--target", target, "--cases", str(cases), "--batch", "64", *extra]
        return quiet_main(fp.main, argv)


class ProcessDriverTests(Fixture):
    def test_target_equal_to_the_reference_passes(self) -> None:
        self.assertEqual(self.run_campaign(self.exact), 0)

    def test_mutant_fails_and_its_mismatches_are_written(self) -> None:
        out = self.dir / "out"
        self.assertEqual(self.run_campaign(self.mutant, "--out", str(out)), 1)
        files = sorted(out.rglob("*.json"))
        self.assertTrue(files)
        for path in files:
            document = json.loads(path.read_text())
            self.assertEqual(document["format"], "fuzz-mismatch-v1")
            expected = hashlib.sha256(fp.canonical(document["context"]).encode()).hexdigest()
            self.assertEqual(path.name, f"{expected}.json")
            self.assertEqual(path.parent.name, document["lineage"])
            self.assertEqual(path.parent.parent.name, "fuzz-mismatches")
            self.assertEqual(path.parent.parent.parent.parent.name, "vm")
            self.assertEqual(
                document["effects"]["target"]["gas_used"],
                document["effects"]["reference"]["gas_used"] + 1,
            )

    def test_expect_mismatch_inverts_the_verdict(self) -> None:
        self.assertEqual(self.run_campaign(self.mutant, "--expect-mismatch"), 0)
        # Control: the same flag on an agreeing target fails, so a self-check cannot pass vacuously.
        self.assertEqual(self.run_campaign(self.exact, "--expect-mismatch"), 1)

    def test_one_sided_refusal_is_a_mismatch(self) -> None:
        refusing = script(self.dir, "fake-refuse", FAKE_TARGET, {"FAKE_FUZZ_MODE": "refuse-some"})
        self.assertEqual(self.run_campaign(refusing), 1)
        self.assertEqual(fp.agree({"harness_error": "a"}, {"harness_error": "b"}), "both-refused")
        self.assertEqual(fp.agree({"harness_error": "a"}, {"exit_code": 0}), "mismatch")

    def test_batches_do_not_change_the_cases(self) -> None:
        one = fp.emit(self.generator, "vm", [], 5, 0, 10)
        two = fp.emit(self.generator, "vm", [], 5, 0, 4) + fp.emit(
            self.generator, "vm", [], 5, 4, 6
        )
        self.assertEqual(one, two)

    def test_same_mismatches_as(self) -> None:
        first, second = self.dir / "first", self.dir / "second"
        self.assertEqual(self.run_campaign(self.mutant, "--out", str(first)), 1)
        self.assertEqual(
            self.run_campaign(
                self.mutant,
                "--out",
                str(second),
                "--expect-mismatch",
                "--same-mismatches-as",
                str(first),
            ),
            0,
        )
        # Controls: a missing file and a changed effect are both reported.
        victim = sorted(first.rglob("*.json"))[0]
        saved = victim.read_text()
        victim.unlink()
        self.assertTrue(any("only in" in p for p in fp.same_mismatches(second, first)))
        document = json.loads(saved)
        document["effects"]["target"]["gas_used"] += 5
        victim.write_text(json.dumps(document))
        self.assertTrue(any("effects differs" in p for p in fp.same_mismatches(second, first)))
        # An empty pair of trees is not agreement either.
        empty_a, empty_b = self.dir / "a", self.dir / "b"
        empty_a.mkdir()
        empty_b.mkdir()
        self.assertTrue(fp.same_mismatches(empty_a, empty_b))


def bits_of(value: int, n: int) -> list[int]:
    return [(value >> (n - 1 - i)) & 1 for i in range(n)]


def internal_message(
    body: list[int], body_refs: tuple[boc.Cell, ...] = (), init: bool = False
) -> boc.Cell:
    address = bits_of(0b100, 3) + bits_of(0, 8) + [1] * 256  # addr_std, no anycast, workchain 0
    bits = [0, 1, 1, 0] + address + address
    bits += bits_of(1, 4) + bits_of(100, 8) + [0]  # value: 100 and no extra currencies
    bits += bits_of(0, 4) + bits_of(0, 4) + bits_of(7, 64) + bits_of(9, 32)
    refs: list[boc.Cell] = []
    if init:
        bits += [1, 1]  # init present, in a reference
        refs.append(boc.Cell.make([1, 0, 1]))
    else:
        bits += [0]
    if len(bits) + 1 + len(body) <= boc.MAX_BITS:
        return boc.Cell.make([*bits, 0, *body], [*refs, *body_refs])
    return boc.Cell.make([*bits, 1], [*refs, boc.Cell.make(body, body_refs)])


class BocTests(unittest.TestCase):
    def fixture_bocs(self) -> list[str]:
        family = c.load_family(VECTORS / "vm" / "fixtures" / "vm-endstate.jsonl")
        found: list[str] = []
        for context in family.contexts():
            found.append(context["code"])
            if "data" in context:
                found.append(context["data"])
        return found

    def test_fixture_bocs_round_trip(self) -> None:
        bocs = self.fixture_bocs()
        self.assertGreater(len(bocs), 100)
        for text in bocs:
            cell = boc.from_b64(text)
            self.assertEqual(boc.from_b64(boc.to_b64(cell)), cell)
            if not cell.refs:  # one cell: the C++ serializer's bytes exactly
                self.assertEqual(boc.to_b64(cell), text)

    def test_index_and_checksum(self) -> None:
        cell = boc.Cell.make([1, 0, 1], [boc.Cell.make([1] * 9), boc.Cell.make([])])
        raw = boc.serialize(cell, with_index=True, with_crc=True)
        self.assertEqual(boc.deserialize(raw), cell)
        corrupted = bytearray(raw)
        corrupted[-5] ^= 1
        with self.assertRaises(boc.BocError):
            boc.deserialize(bytes(corrupted))

    def test_completion_tag(self) -> None:
        for n in (0, 1, 7, 8, 9, 1023):
            cell = boc.Cell.make([1] * n)
            self.assertEqual(len(boc.from_b64(boc.to_b64(cell)).bits), n)
        with self.assertRaises(boc.BocError):
            boc.Cell.make([0] * 1024)

    def test_message_body_is_located_and_replaced(self) -> None:
        body = bits_of(0xDEADBEEF, 32)
        for init in (False, True):
            message = internal_message(body, init=init)
            layout = boc.message_layout(message)
            self.assertEqual(layout.has_init, init)
            self.assertEqual(boc.message_body(message, layout).bits, tuple(body))
            emptied = boc.with_body(message, layout, boc.Cell.make([]))
            relaid = boc.message_layout(emptied)
            self.assertEqual(boc.message_body(emptied, relaid).bits, ())
            dropped = boc.with_body(message, layout, boc.Cell.make(body), keep_init=False)
            self.assertFalse(boc.message_layout(dropped).has_init)
        # Control: an outbound message header is not an inbound message.
        with self.assertRaises(boc.BocError):
            boc.message_layout(boc.Cell.make([1, 1] + [0] * 20))

    def test_body_in_a_reference(self) -> None:
        message = internal_message([1] * 600)
        layout = boc.message_layout(message)
        self.assertFalse(layout.body_inline)
        self.assertEqual(len(boc.message_body(message, layout).bits), 600)


def vm_context(code: boc.Cell, stack: list[Json]) -> Json:
    return {
        "code": boc.to_b64(code),
        "global_version": 16,
        "gas": {"limit": 1000, "max": 5000, "credit": 10},
        "stack": stack,
        "c7": {
            "type": "tuple",
            "items": [{"type": "tuple", "items": [{"type": "int", "value": "1"}]}],
        },
        "flags": 1,
    }


def has_seven(ctx: Json) -> bool:
    return any(item == {"type": "int", "value": "7"} for item in ctx["stack"])


def has_marker_byte(ctx: Json) -> bool:
    code = boc.from_b64(ctx["code"])

    def walk(cell: boc.Cell) -> bool:
        data = "".join(map(str, cell.bits))
        return "10100000" in data or any(walk(ref) for ref in cell.refs)

    return walk(code)


class MinimizeTests(unittest.TestCase):
    def code(self) -> boc.Cell:
        leaf = boc.Cell.make(bits_of(0xA0, 8) + bits_of(0x30, 8))
        return boc.Cell.make(
            bits_of(0x7120, 16) + bits_of(0x5859, 16), [boc.Cell.make([1] * 40), leaf]
        )

    def test_vm_context_shrinks_to_what_the_mismatch_needs(self) -> None:
        stack = [{"type": "null"}, {"type": "int", "value": "7"}, {"type": "int", "value": "123"}]
        ctx = vm_context(self.code(), stack)

        def runner(contexts: Any) -> list[bool]:
            return [has_seven(x) and has_marker_byte(x) for x in contexts]

        result, rounds = mz.minimize("vm", ctx, runner, 200)
        self.assertGreater(rounds, 0)
        self.assertEqual(result["stack"], [{"type": "int", "value": "7"}])
        self.assertNotIn("c7", result)
        self.assertNotIn("flags", result)
        self.assertEqual(result["gas"], {"limit": 0, "max": 0})
        code = boc.from_b64(result["code"])
        self.assertTrue(has_marker_byte(result))
        self.assertLess(code.tree_size(), self.code().tree_size())
        c.validate_context("vm", result)

    def test_a_kept_field_is_kept(self) -> None:
        # Control: when the mismatch needs c7, the minimizer must not drop it.
        ctx = vm_context(self.code(), [{"type": "int", "value": "7"}])
        result, _ = mz.minimize("vm", ctx, lambda xs: ["c7" in x for x in xs], 200)
        self.assertIn("c7", result)

    def test_agreeing_input_is_refused(self) -> None:
        ctx = vm_context(self.code(), [])
        with self.assertRaises(c.FixtureError):
            mz.minimize("vm", ctx, lambda xs: [False for _ in xs], 10)

    def test_txn_body_and_optional_fields(self) -> None:
        message = internal_message(bits_of(0x12345678, 32) + [1] * 64, init=True)
        ctx: Json = {
            "config": base64.b64encode(boc.serialize(boc.Cell.make([1]))).decode(),
            "shard_account": base64.b64encode(boc.serialize(boc.Cell.make([0]))).decode(),
            "now": 1,
            "lt": 1,
            "rand_seed": "0" * 64,
            "message": boc.to_b64(message),
            "libraries": base64.b64encode(boc.serialize(boc.Cell.make([]))).decode(),
        }

        def needs_op(contexts: Any) -> list[bool]:
            out: list[bool] = []
            for x in contexts:
                msg = boc.from_b64(x["message"])
                body = boc.message_body(msg, boc.message_layout(msg))
                out.append(body.bits[:8] == tuple(bits_of(0x12, 8)))
            return out

        result, _ = mz.minimize("txn", ctx, needs_op, 200)
        self.assertNotIn("libraries", result)
        msg = boc.from_b64(result["message"])
        layout = boc.message_layout(msg)
        self.assertFalse(layout.has_init)
        self.assertEqual(boc.message_body(msg, layout).bits, tuple(bits_of(0x12, 8)))

    def test_command_line_on_fake_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            exact = script(directory, "exact", FAKE_TARGET, {"FAKE_FUZZ_MODE": "exact"})
            mutant = script(directory, "mutant", FAKE_TARGET, {"FAKE_FUZZ_MODE": "mutate"})
            source = directory / "ctx.json"
            code = boc.Cell.make(bits_of(0x7700, 16) + bits_of(0x0A, 8))  # last byte 10: mutated
            source.write_text(json.dumps(vm_context(code, [{"type": "null"}])))
            out = directory / "min.json"
            argv = ["--reference", exact, "--target", mutant, "--harness", "vm", "--out", str(out)]
            self.assertEqual(quiet_main(mz.main, [*argv, str(source)]), 0)
            result = json.loads(out.read_text())
            self.assertEqual(result["stack"], [])
            # Control: two equal targets have nothing to minimize.
            argv[3] = exact
            self.assertEqual(quiet_main(mz.main, [*argv, str(source)]), 2)


class DebugMismatchTests(unittest.TestCase):
    def targets(self, directory: Path, mode: str) -> tuple[str, str]:
        reference = script(directory, f"ref-{mode}", FAKE_TARGET, {"FAKE_FUZZ_MODE": mode})
        target = script(
            directory,
            f"target-{mode}",
            FAKE_TARGET,
            {"FAKE_FUZZ_MODE": mode, "FAKE_FUZZ_SIDE": "target"},
        )
        return reference, target

    def mismatch_file(self, directory: Path) -> Path:
        code = boc.Cell.make(bits_of(0x0A, 8))
        context: Json = {
            "code": boc.to_b64(code),
            "global_version": 16,
            "gas": {"limit": 9, "max": 9},
            "stack": [],
        }
        path = directory / "vm" / "inputs" / "fuzz-mismatches" / "grammar" / "x.json"
        path.parent.mkdir(parents=True)
        document = {
            "format": "fuzz-mismatch-v1",
            "harness": "vm",
            "context": context,
            "effects": {},
        }
        path.write_text(json.dumps(document))
        return path

    def test_first_diverging_step_is_found(self) -> None:
        reference = {"trace": {"events": [{"g": 1}, {"g": 2}, {"g": 3}]}}
        self.assertEqual(
            dbg.trace_report(reference, {"trace": {"events": [{"g": 1}, {"g": 9}]}})[1], 1
        )
        self.assertEqual(
            dbg.trace_report(reference, {"trace": {"events": [{"g": 1}, {"g": 2}]}})[1], 2
        )
        # Control: identical traces have no divergence.
        self.assertIsNone(dbg.trace_report(reference, reference)[1])

    def test_expect_trace_on(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            path = self.mismatch_file(directory)
            reference, target = self.targets(directory, "trace-diverge")
            argv = ["--reference", reference, "--target", target, "--expect-trace", "on"]
            self.assertEqual(quiet_main(dbg.main, [*argv, "--first-of", str(directory)]), 0)
            # Control: a trace request that changes the effects fails the check.
            reference, target = self.targets(directory, "trace-perturb")
            argv = ["--reference", reference, "--target", target, "--expect-trace", "on"]
            self.assertEqual(quiet_main(dbg.main, [*argv, str(path)]), 1)
            # Control: a build without the hook cannot pass the "on" check.
            reference, target = self.targets(directory, "no-trace")
            argv = ["--reference", reference, "--target", target, "--expect-trace", "on"]
            self.assertEqual(quiet_main(dbg.main, [*argv, str(path)]), 1)

    def test_expect_trace_off(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            path = self.mismatch_file(directory)
            reference, target = self.targets(directory, "no-trace")
            argv = ["--reference", reference, "--target", target, "--expect-trace", "off"]
            self.assertEqual(quiet_main(dbg.main, [*argv, str(path)]), 0)
            # Control: a build that answers trace requests fails the "off" check.
            reference, target = self.targets(directory, "trace-diverge")
            argv = ["--reference", reference, "--target", target, "--expect-trace", "off"]
            self.assertEqual(quiet_main(dbg.main, [*argv, str(path)]), 1)

    def test_fixture_lookup(self) -> None:
        harness, context, recorded = dbg.load_fixture("vm/vm-endstate/end-normal", VECTORS)
        self.assertEqual(harness, "vm")
        self.assertIn("code", context)
        self.assertIsNotNone(recorded)
        with self.assertRaises(c.FixtureError):
            dbg.load_fixture("vm/vm-endstate/no-such-fixture", VECTORS)

    def test_field_diff_lists_stack_items(self) -> None:
        lines = dbg.field_diff(
            {"stack": ["1", "2"], "gas_used": 3}, {"stack": ["1", "5"], "gas_used": 3}
        )
        self.assertEqual(lines[0], "stack: 2 items vs 2 items")
        self.assertIn("[1] reference", lines[1])


class LayoutTests(unittest.TestCase):
    def test_mismatch_directories_hold_no_fixture_files(self) -> None:
        # The runner discovers *.jsonl under vectors/; the mismatch tree must never hold one.
        for directory in VECTORS.glob("*/inputs/fuzz-mismatches"):
            self.assertFalse(list(directory.rglob("*.jsonl")), directory)
        self.assertTrue((VECTORS / "vm" / "inputs" / "fuzz-mismatches" / "README.md").exists())


if __name__ == "__main__":
    os.environ.setdefault("PYTHONHASHSEED", "0")
    unittest.main()
