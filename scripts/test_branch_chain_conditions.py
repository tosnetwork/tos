"""The archive exception must not permit runtime gates to become conditional."""

import importlib.util
import unittest
from pathlib import Path


class BranchConditionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).with_name("check-branch-chain-python-ci.py")
        spec = importlib.util.spec_from_file_location("branch_guard", path)
        cls.guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.guard)
        cls.workflow = (path.parents[1] / ".github/workflows/branch-chain-python.yml").read_text()

    def test_always_archive_is_accepted(self):
        self.guard.validate_unconditional_steps(self.workflow)

    def test_archive_exception_cannot_skip_runtime_or_run_other_code(self):
        mutants = [
            self.workflow.replace("        if: always()", "        if: false"),
            self.workflow.replace(
                "      - name: Run the complete Python suite",
                "      - name: Run the complete Python suite\n        if: false",
            ),
            self.workflow.replace(
                "      - name: Run the complete Python suite",
                "      - name: Run the complete Python suite\n        if: always()",
            ),
            self.workflow.replace(
                "  python-and-pq-chain:", "  python-and-pq-chain:\n    if: false"
            ),
            self.workflow.replace(
                "uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
                "run: echo archive",
            ),
        ]
        for index, workflow in enumerate(mutants):
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                self.guard.validate_unconditional_steps(workflow)


if __name__ == "__main__":
    unittest.main()
