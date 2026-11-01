#!/usr/bin/env python3
"""Harness controls only: these tests are not a real-testnet capacity result."""

import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "replica_capacity", Path(__file__).with_name("wallet-index-replica-capacity.py")
)
CAPACITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAPACITY)


def block(seqno, root="a", file="b"):
    return f"(-1,8000000000000000,{seqno}):{root * 64}:{file * 64}"


def ready(**changes):
    body = dict(
        masterchain_seqno=42, source_seqno=42, caught_up=True, settled=True, verification="full"
    )
    body.update(changes)
    return body


class CapacityHarnessTests(unittest.TestCase):
    def test_requires_full_and_settled_at_exact_frozen_tip(self):
        self.assertTrue(CAPACITY.check_sample({}, 200, ready(), 42))
        self.assertFalse(CAPACITY.check_sample({}, 503, ready(verification="partial"), 42))
        self.assertFalse(CAPACITY.check_sample({}, 200, ready(settled=False), 42))
        with self.assertRaisesRegex(RuntimeError, "without Full"):
            CAPACITY.check_sample({}, 200, ready(verification="partial"), 42)
        with self.assertRaisesRegex(RuntimeError, "source tip differs"):
            CAPACITY.check_sample({}, 503, ready(source_seqno=43), 42)

    def test_cursor_must_not_reset_or_regress(self):
        for cursor in (None, 0, 40):
            with self.subTest(cursor=cursor), self.assertRaisesRegex(RuntimeError, "regressed"):
                CAPACITY.check_sample(
                    ready(masterchain_seqno=41), 503, ready(masterchain_seqno=cursor), 42
                )

    def test_canonical_digest_binds_full_target_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "dump"
            log.write_text(
                f"checkpoint={block(1)} {block(42).upper()}\nsha256={'c' * 64}\n"
                "head=42\nwindow_base=20\nanchor_verified=no\n"
            )
            self.assertEqual(CAPACITY.canonical_summary(log, block(42))["sha256"], "c" * 64)
            with self.assertRaisesRegex(RuntimeError, "different target"):
                CAPACITY.canonical_summary(log, block(42, root="d"))
            log.write_text(f"checkpoint={block(1)} {block(42)}\n")
            with self.assertRaisesRegex(RuntimeError, "integrity digest"):
                CAPACITY.canonical_summary(log, block(42))

    def test_missing_preparation_never_passes_time_target(self):
        self.assertEqual(CAPACITY.time_assessment(1, None, 7200)["status"], "unavailable")
        self.assertEqual(CAPACITY.time_assessment(1800, 5400, 7200)["status"], "pass")
        self.assertEqual(CAPACITY.time_assessment(1801, 5400, 7200)["status"], "fail")

    def test_nonfinite_time_and_resource_limits_are_refused(self):
        for value in ("nan", "inf", "-inf", "-1"):
            with self.subTest(value=value), self.assertRaises(CAPACITY.argparse.ArgumentTypeError):
                CAPACITY.nonnegative_float(value)
        self.assertEqual(CAPACITY.nonnegative_float("0"), 0)
        with self.assertRaises(CAPACITY.argparse.ArgumentTypeError):
            CAPACITY.positive_float("0")

    def test_sampled_disk_walk_tolerates_compaction_removal(self):
        with mock.patch.object(CAPACITY.os, "walk", return_value=[("/sample", [], ["gone"])]):
            with mock.patch.object(Path, "lstat", side_effect=FileNotFoundError):
                self.assertEqual(CAPACITY.sampled_disk_bytes(Path("/sample")), 0)

    def test_growth_uses_real_header_times_and_rejects_wrong_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "headers.json"
            rows = [
                dict(block_id=block(10), gen_utime=100),
                dict(block_id=block(20), gen_utime=105),
            ]
            path.write_text(json.dumps(rows))
            measured = CAPACITY.historical_growth(path, 42)
            self.assertEqual(measured["mc_blocks_per_second"], 2)
            path.write_text(json.dumps(rows[::-1]))
            with self.assertRaisesRegex(ValueError, "not monotonic"):
                CAPACITY.historical_growth(path, 42)
        self.assertEqual(CAPACITY.historical_growth(None, 42)["status"], "unavailable")

    def test_wait4_captures_peak_even_for_short_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = CAPACITY.run_stage(
                [sys.executable, "-c", "memory = bytearray(8 * 1024 * 1024)"],
                root,
                "child",
                10,
                root / "absent",
            )
            self.assertEqual(result["exit_code"], 0)
            self.assertGreaterEqual(result["peak_rss_kib"], 8192)
            self.assertFalse(result["reached"])

    def test_child_failure_is_not_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(RuntimeError, "did not complete"):
                CAPACITY.run_stage(
                    [sys.executable, "-c", "raise SystemExit(7)"],
                    root,
                    "child",
                    10,
                    root / "absent",
                )
            self.assertEqual(json.loads((root / "child.json").read_text())["exit_code"], 7)

    def test_reference_cannot_be_the_output_under_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            for name in ("state", "celldb", "archive"):
                (source / name).mkdir(parents=True)
            output = root / "output"
            result = subprocess.run(
                [
                    sys.executable,
                    SPEC.origin,
                    "--mode",
                    "path-a",
                    "--dataset-kind",
                    "fixture-smoke",
                    "--build",
                    str(root / "unused-build"),
                    "--source-db",
                    str(source),
                    "--source-commit",
                    "a" * 40,
                    "--target-block-id",
                    block(42),
                    "--root",
                    str(output),
                    "--reference-index",
                    str(output / "data/index"),
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("reference index and new output must not overlap", result.stderr)
            self.assertFalse(output.exists())

    def test_observer_failure_terminates_child_and_keeps_receipt(self):
        def reject(_elapsed):
            raise RuntimeError("bad readiness")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(RuntimeError, "bad readiness"):
                CAPACITY.run_stage(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    root,
                    "child",
                    10,
                    root / "absent",
                    reject,
                )
            self.assertLess(json.loads((root / "child.json").read_text())["exit_code"], 0)

    def test_cli_sigterm_stops_native_child_and_records_interruption(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            for name in ("state", "celldb", "archive"):
                (source / name).mkdir(parents=True)
            build = root / "build/services"
            build.mkdir(parents=True)
            output = root / "output"
            child_pid = output / "child.pid"
            # An explicit test double checks subprocess cleanup, not capacity.
            program = (
                f"#!{sys.executable}\nimport os,time\nfrom pathlib import Path\n"
                f"Path({str(child_pid)!r}).write_text(str(os.getpid()))\ntime.sleep(60)\n"
            )
            for name in ("tos-wallet-index", "tos-wallet-index-snapshot", "tos-wallet-index-dump"):
                path = build / name
                path.write_text(program)
                path.chmod(0o700)
            snapshot = root / "snapshot"
            snapshot.write_bytes(b"TEST-ONLY")
            command = [
                sys.executable,
                SPEC.origin,
                "--mode",
                "path-b",
                "--dataset-kind",
                "fixture-smoke",
                "--build",
                str(root / "build"),
                "--source-db",
                str(source),
                "--source-commit",
                "a" * 40,
                "--snapshot",
                str(snapshot),
                "--target-block-id",
                block(42),
                "--root",
                str(output),
            ]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 10
                while (
                    not child_pid.exists()
                    and process.poll() is None
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.05)
                self.assertTrue(child_pid.exists(), "native test child was not launched")
                pid = int(child_pid.read_text())
                os.kill(pid, 0)
                process.terminate()
                process.communicate(timeout=10)
                with self.assertRaises(
                    ProcessLookupError, msg="native child survived parent SIGTERM"
                ):
                    os.kill(pid, 0)
                self.assertTrue(
                    (output / "receipt.json").is_file(), "interruption did not persist a receipt"
                )
                receipt = json.loads((output / "receipt.json").read_text())
                self.assertEqual(receipt["result"], "failed")
                self.assertIn("InterruptedError", receipt["error"])
                self.assertTrue(receipt["source_metadata_unchanged"])
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=10)
                if child_pid.exists():
                    try:
                        os.killpg(int(child_pid.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass


if __name__ == "__main__":
    unittest.main()
