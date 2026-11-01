"""The process fixture must never certify a missing native-chain acceptance."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run_delivery_fixture as runner


class DeliveryRunnerTests(unittest.TestCase):
    def test_native_requirement_refuses_before_running_fixture_or_writing_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "native.json"
            with (
                patch.object(
                    runner.unittest,
                    "TextTestRunner",
                    side_effect=AssertionError("fixture execution is forbidden at this boundary"),
                ) as execute,
                contextlib.redirect_stderr(io.StringIO()) as diagnostic,
            ):
                result = runner.main(["--require-native", "--out", str(output)])
            self.assertEqual(result, 2)
            self.assertIn("BR1_NATIVE_ACCEPTANCE_UNAVAILABLE:", diagnostic.getvalue())
            self.assertFalse(output.exists())
            execute.assert_not_called()

    def test_missing_or_extra_scenario_cannot_be_reported_as_complete(self):
        for names in (
            set(runner.SCENARIOS) - {min(runner.SCENARIOS)},
            set(runner.SCENARIOS) | {"test_unregistered_case"},
        ):
            with self.subTest(names=names), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "fixture.json"
                with (
                    patch.object(
                        runner.unittest.defaultTestLoader, "getTestCaseNames", return_value=names
                    ),
                    patch.object(
                        runner.unittest,
                        "TextTestRunner",
                        side_effect=AssertionError(
                            "fixture execution is forbidden at this boundary"
                        ),
                    ) as execute,
                    contextlib.redirect_stderr(io.StringIO()) as diagnostic,
                ):
                    result = runner.main(["--out", str(output)])
                self.assertEqual(result, 1)
                self.assertIn("BR1_FIXTURE_INVENTORY_MISMATCH", diagnostic.getvalue())
                self.assertFalse(output.exists())
                execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
