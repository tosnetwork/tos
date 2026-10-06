"""Receipt and evidence-preservation controls for transaction timing."""

import tempfile
import unittest
from pathlib import Path

import benchmark_transactions as bench


class BenchmarkControls(unittest.TestCase):
    def test_changed_rejection_is_not_a_timing_sample(self):
        result = {"success": False, "vm_exit_code": 2007}
        bench.check_receipt("invalid", result, "invalid\t2007\t0\t-\t-")
        with self.assertRaisesRegex(ValueError, "replay differs"):
            bench.check_receipt("invalid", result, "invalid\t0\t0\t-\t-")

    def test_existing_evidence_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            receipt = output / "measurements.json"
            receipt.write_text("retained")
            with self.assertRaises(FileExistsError):
                bench.run(output / "missing", output, 1, 1)
            self.assertEqual(receipt.read_text(), "retained")

    def test_receipt_guard_deletion_is_detected(self):
        source = Path(bench.__file__).read_text()
        guard = "if actual != expected:"
        self.assertEqual(source.count(guard), 1)
        namespace = {"__name__": "benchmark_mutant"}
        exec(compile(source.replace(guard, "if False:"), bench.__file__, "exec"), namespace)
        # The same changed result is wrongly admitted when the guard is deleted.
        namespace["check_receipt"](
            "invalid", {"success": False, "vm_exit_code": 2007}, "invalid\t0\t0\t-\t-"
        )


if __name__ == "__main__":
    unittest.main()
