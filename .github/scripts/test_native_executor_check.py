"""Prove diagnostic reporting cannot hide a failed or missing native test."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

import native_executor_check as check


class NativeExecutorCheckTests(unittest.TestCase):
    def test_original_native_commands_are_retained(self):
        self.assertEqual(
            check.PHASES,
            (
                (
                    "build",
                    ["cmake", "--build", "build", "--target", "test-fift", "test-cells", "-j2"],
                ),
                ("test-fift", ["./build/test-fift"]),
                ("test-cells", ["./build/test-cells"]),
            ),
        )

    def test_success_runs_every_phase(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            phases = [(name, [sys.executable, "-c", "print('ok')"]) for name in ("a", "b")]
            status, messages = check.run_phases(phases, directory)
            self.assertEqual(status, 0)
            self.assertTrue(messages[0].startswith("PASS"))
            receipts = json.loads((directory / "receipts.json").read_text())
            self.assertEqual([row["phase"] for row in receipts], ["a", "b"])

    def test_failure_stays_red_and_stops_later_phases(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            phases = [
                ("fail", [sys.executable, "-c", "print('assert: sentinel'); raise SystemExit(7)"]),
                ("not-reached", [sys.executable, "-c", "raise SystemExit(0)"]),
            ]
            status, messages = check.run_phases(phases, directory)
            self.assertEqual(status, 7)
            self.assertIn("assert: sentinel", messages)
            self.assertFalse((directory / "not-reached.tail.txt").exists())

    def test_missing_program_is_not_success(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            status, messages = check.run_phases(
                [("missing", [str(directory / "missing")])], directory
            )
            self.assertEqual(status, 127)
            self.assertIn("exit 127", messages[0])

    def test_diagnostics_and_retained_tail_are_bounded(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            command = [sys.executable, "-c", "print('x' * 200000); raise SystemExit(2)"]
            status, messages = check.run_phases([("large", command)], directory)
            self.assertEqual(status, 2)
            self.assertLessEqual((directory / "large.tail.txt").stat().st_size, check.TAIL_BYTES)
            self.assertLessEqual(len(messages), 7)
            self.assertTrue(all(len(message) <= 350 for message in messages))


if __name__ == "__main__":
    unittest.main()
