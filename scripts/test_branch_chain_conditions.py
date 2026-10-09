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

    def test_triggers_are_every_pull_request_and_pushes_to_main(self):
        self.guard.validate_triggers(self.workflow)

    def test_trigger_changes_are_refused(self):
        triggers = self.guard.TRIGGERS
        mutants = {
            "push to every branch": "on:\n  push:\n  pull_request:\n  workflow_dispatch:\n",
            "push to another branch": "on:\n  push:\n    branches: [main, 'feat/**']\n"
            "  pull_request:\n  workflow_dispatch:\n",
            "push with branches-ignore": "on:\n  push:\n    branches-ignore: [wip]\n"
            "  pull_request:\n  workflow_dispatch:\n",
            "no push": "on:\n  pull_request:\n  workflow_dispatch:\n",
            "pull requests into main only": "on:\n  push:\n    branches: [main]\n"
            "  pull_request:\n    branches: [main]\n  workflow_dispatch:\n",
            "pull request path filter": "on:\n  push:\n    branches: [main]\n"
            "  pull_request:\n    paths: ['test/**']\n  workflow_dispatch:\n",
            "no pull request": "on:\n  push:\n    branches: [main]\n  workflow_dispatch:\n",
            "no dispatch": "on:\n  push:\n    branches: [main]\n  pull_request:\n",
        }
        self.assertIn(triggers, self.workflow)
        for name, replacement in mutants.items():
            with self.subTest(name), self.assertRaises(RuntimeError):
                self.guard.validate_triggers(self.workflow.replace(triggers, replacement, 1))


if __name__ == "__main__":
    unittest.main()
