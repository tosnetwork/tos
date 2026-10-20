"""Controls for strict output comparison; no generated positive chain fixtures."""

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

spec = importlib.util.spec_from_file_location("rel02", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ComparisonControls(unittest.TestCase):
    def test_names_the_first_changed_consensus_field(self):
        expected = [{"gas_used": "4057", "result_hash": "abc"}]
        with self.assertRaisesRegex(ValueError, r"\$\[0\].gas_used"):
            runner.check_records(expected, [{"gas_used": "4058", "result_hash": "abc"}], "control")

    def test_missing_records_refuse(self):
        with self.assertRaisesRegex(ValueError, "length"):
            runner.check_records([{"kind": "block"}], [], "control")

    def test_missing_field_refuses(self):
        with self.assertRaisesRegex(ValueError, "result_hash"):
            runner.check_records([{"result_hash": "abc"}], [{}], "control")

    def test_changed_prefix_is_reported_before_a_missing_tail(self):
        with self.assertRaisesRegex(ValueError, r"\$\[0\].gas_used"):
            runner.check_records(
                [{"gas_used": "1"}, {"gas_used": "2"}], [{"gas_used": "9"}], "control"
            )

    def test_nonzero_native_exit_cannot_report_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(
                executable=Path("/unused"),
                timeout=1,
                output=Path(directory) / "out.jsonl",
                metrics=None,
            )
            with mock.patch.object(
                runner.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "")
            ):
                with self.assertRaisesRegex(ValueError, "native replay exited 1"):
                    runner.run(args, {"blocks": [], "supplements": [], "expected": []}, {})

    def test_does_not_equate_boolean_and_number(self):
        self.assertIsNotNone(runner.difference({"aborted": False}, {"aborted": 0}))


if __name__ == "__main__":
    unittest.main()
