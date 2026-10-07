"""Receipt and evidence-preservation controls for transaction timing."""

import tempfile
import unittest
from pathlib import Path

import benchmark_transactions as bench
from cells import make_dict
from default_credit_timing import default_configuration
from fee_tx_parity import Cell, credit, read_dict


class BenchmarkControls(unittest.TestCase):
    def test_default_credit_changes_only_credit(self):
        for prefix in ("", format(0xD1, "08b") + format(123, "0128b")):
            prices = Cell(bits=prefix).uint(0xDE, 8)
            for value in (400, 1000000, 1000000, 20000, 77, 88, 99):
                prices.uint(value, 64)
            root = (
                Cell()
                .uint(42, 256)
                .ref(make_dict({21: Cell().ref(prices), 8: Cell().ref(Cell().uint(17, 32))}, 32))
            )
            changed = default_configuration(root)
            self.assertEqual(changed.bits, root.bits)
            self.assertEqual(credit(changed.refs[0]), 10000)
            before, after = read_dict(root.refs[0], 32), read_dict(changed.refs[0], 32)
            self.assertEqual(before[8].hash, after[8].hash)
            offset = len(prefix) + 8 + 3 * 64
            actual = after[21].refs[0].bits
            self.assertEqual(actual[:offset], prices.bits[:offset])
            self.assertEqual(actual[offset + 64 :], prices.bits[offset + 64 :])

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
