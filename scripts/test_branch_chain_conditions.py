"""The archive exception must not permit runtime gates to become conditional."""

import importlib.util
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


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

    def test_each_archive_exception_is_narrow(self):
        for name in (
            "Retain Quantum candidate configuration and boot evidence",
            "Retain public explorer RPC response receipts",
        ):
            archive = re.search(
                rf"(?ms)^      - name: {re.escape(name)}\n.*?(?=^      - |\Z)",
                self.workflow,
            )
            self.assertIsNotNone(archive)
            original = archive.group(0)
            mutants = {
                "wrong action pin": original.replace(
                    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
                    "actions/upload-artifact@main",
                ),
                "skip condition": original.replace("if: always()", "if: false"),
                "runtime command": original.replace(
                    "        if: always()", "        if: always()\n        run: echo bypass"
                ),
                "unknown archive": original.replace(name, "Another evidence archive"),
            }
            for mutation, replacement in mutants.items():
                with self.subTest(archive=name, mutation=mutation), self.assertRaises(RuntimeError):
                    self.guard.validate_unconditional_steps(
                        self.workflow.replace(original, replacement, 1)
                    )

    def test_failure_log_exceptions_cannot_run_tests_or_skip_the_upload(self):
        mutants = [
            self.workflow.replace("if: failure()", "if: false"),
            self.workflow.replace("python3 scripts/collect-disposable-node-logs.py", "echo skip"),
            self.workflow.replace("path: build/disposable-node-logs/", "path: build/"),
            self.workflow.replace("Retain disposable node failure logs", "Unknown failure upload"),
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


class NodeFailureLogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).with_name("collect-disposable-node-logs.py")
        spec = importlib.util.spec_from_file_location("node_failure_logs", path)
        cls.collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.collector)

    def test_real_node_log_locations_survive_without_private_files(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            networks = [
                "build/quantum-payment-ci/network",
                "build/quantum-candidate-ci/network",
                "build/explorer-rpc-candidate-v16/attempt-1/network",
                "build/explorer-rpc-ordinary-v16/attempt-2/network",
                "test/integration/.network",
                "test/integration/.pq-unsafe-rotation-ci/nonzero",
                "test/integration/.pq-consensus-key-rotation-ci/rotation",
            ]
            for network in networks:
                node = root / network / "node1"
                for name in (
                    "log",
                    "stderr.log",
                    "logs/node.log",
                    "celldb/LOG",
                    "keyring/key.log",
                    "config.json",
                ):
                    path = node / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"own validator output")
                external = Path(outside) / "secret"
                external.write_bytes(b"private")
                (node / "escape.log").symlink_to(external)
            self.collector.collect(root)
            output = root / "build/disposable-node-logs"
            for network in networks:
                for name in ("log", "stderr.log", "logs/node.log", "celldb/LOG"):
                    retained = output / network / "node1" / name
                    self.assertTrue(retained.is_file(), f"missing validator log: {network}/{name}")
                    self.assertEqual(retained.read_bytes(), b"own validator output")
            self.assertFalse(list(output.rglob("key.log")))
            self.assertFalse(list(output.rglob("config.json")))
            self.assertFalse(list(output.rglob("escape.log")))

    def test_log_tails_have_per_file_total_and_count_bounds(self):
        for max_files, expected_files, expected_bytes in [(2, 2, 8), (64, 3, 10)]:
            with self.subTest(max_files=max_files), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                node = root / "build/quantum-payment-ci/network/node1"
                node.mkdir(parents=True)
                for index in range(10):
                    (node / f"{index}.log").write_bytes(b"01234567")
                with patch.multiple(
                    self.collector, FILE_BYTES=4, TOTAL_BYTES=10, MAX_FILES=max_files
                ):
                    self.collector.collect(root)
                logs = sorted((root / "build/disposable-node-logs").rglob("*.log"))
                self.assertEqual(len(logs), expected_files)
                self.assertEqual(sum(path.stat().st_size for path in logs), expected_bytes)
                self.assertEqual(logs[0].read_bytes(), b"4567")


if __name__ == "__main__":
    unittest.main()
