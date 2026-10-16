"""Negative controls for split-suite coverage and receipt validation."""

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "rescue_ci_guard", Path(__file__).with_name("check-rescue-context-ci.py")
)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class RescueCiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = guard.WORKFLOW.read_text()
        cls.contract = json.loads(guard.CONTRACT.read_text())
        cls.source_guard = (guard.ROOT / ".github/workflows/source-guards.yml").read_text()

    def check(self, text=None, contract=None, source_guard=None):
        return guard.validate(
            text if text is not None else self.workflow,
            contract if contract is not None else self.contract,
            source_guard if source_guard is not None else self.source_guard,
        )

    def test_all_original_steps_and_architectures_remain(self):
        coverage = self.check()
        self.assertEqual(len(coverage), 9)
        self.assertEqual(len(self.contract["steps"]), 52)
        for row in self.contract["steps"]:
            expected = {guard.RUNNERS[0]} if row["x86_only"] else set(guard.RUNNERS)
            self.assertEqual(
                {runner for (_, runner), names in coverage.items() if row["name"] in names},
                expected,
            )

    def test_each_original_step_cannot_disappear_change_or_be_skipped(self):
        for row in self.contract["steps"]:
            name = row["name"]
            block = next(
                b
                for b in guard.blocks(self.workflow.split("\n  parity:\n")[0])
                if b.startswith("      - name: " + name + "\n")
            )
            mutants = [
                ("", "missing serial step"),
                (
                    block.replace("        run:", "        run: exit 0 #", 1),
                    "serial commands changed",
                ),
                (
                    block.replace("        run:", "        if: false\n        run:", 1),
                    "unexpected condition or metadata",
                ),
            ]
            for mutation, reason in mutants:
                with (
                    self.subTest(name=name, mutation=mutation[:80]),
                    self.assertRaisesRegex(ValueError, reason),
                ):
                    self.check(self.workflow.replace(block, mutation, 1))

    def test_prerequisites_cannot_be_removed_from_other_suites(self):
        contract = copy.deepcopy(self.contract)
        row = next(
            r for r in contract["steps"] if r["name"] == "Generated admission configuration loading"
        )
        old = guard.condition(row)
        row["suites"] = ["release-wallet"]
        text = self.workflow.replace(old, guard.condition(row), 1)
        with self.assertRaisesRegex(ValueError, "missing prerequisite"):
            self.check(text, contract)

    def test_matrix_and_gate_cannot_hide_failures(self):
        mutants = {
            "arm omitted": self.workflow.replace(
                "runner: [ubuntu-24.04, ubuntu-24.04-arm]", "runner: [ubuntu-24.04]", 1
            ),
            "fail fast": self.workflow.replace("fail-fast: false", "fail-fast: true", 1),
            "ignored errors": self.workflow.replace(
                "  suites:\n", "  suites:\n    continue-on-error: true\n", 1
            ),
            "job skipped": self.workflow.replace("  suites:\n", "  suites:\n    if: false\n", 1),
            "success on failure": self.workflow.replace(
                'run: test "$SUITES_RESULT" = success', "run: true"
            ),
            "gate skipped": self.workflow.replace("    if: always()\n", "    if: success()\n"),
            "no receipts": self.workflow.replace("--verify-receipts receipts", "--help"),
            "mutable fixture download": self.workflow.replace(
                "    steps:\n", "    steps:\n      - uses: actions/download-artifact@unsafe\n", 1
            ),
            "tree published": self.workflow.replace(
                "            !artifacts/context/**/PUBLIC-TEST-ONLY-tree\n", ""
            ),
            "restoration omitted": self.workflow.replace(
                "        run: git diff --exit-code\n", "        run: true\n"
            ),
            "receipt optional": self.workflow.replace(
                "if-no-files-found: error", "if-no-files-found: warn", 1
            ),
            "source gate omitted": self.source_guard.replace(
                "python3 scripts/check-rescue-context-ci.py", "true"
            ),
        }
        for name, mutant in mutants.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                if name == "source gate omitted":
                    self.check(source_guard=mutant)
                else:
                    self.check(mutant)

    def test_receipts_require_every_suite_same_source_run_and_checks(self):
        coverage = self.check()
        original = []
        for (suite, runner), names in sorted(coverage.items()):
            original.append(
                {
                    "source": "a" * 40,
                    "run_id": "123",
                    "run_attempt": "1",
                    "suite": suite,
                    "runner": runner,
                    "checks": names,
                    "contract_sha256": guard.digest(guard.CONTRACT.read_text()),
                }
            )

        def verify(rows, attempt="1"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for i, row in enumerate(rows):
                    p = root / str(i) / "suite-success.json"
                    p.parent.mkdir()
                    p.write_text(json.dumps(row))
                guard.verify_receipts(root, "a" * 40, "123", attempt, coverage)

        verify(original)
        retried = copy.deepcopy(original)
        retried[0]["run_attempt"] = "2"
        # Previously successful jobs do not need to rerun or re-upload.
        verify(retried, "2")
        verify(original + [retried[0]], "2")
        with self.assertRaisesRegex(ValueError, "future attempt"):
            verify(retried)
        for name in [
            "missing",
            "duplicate",
            "source",
            "run_id",
            "run_attempt",
            "checks",
            "contract_sha256",
        ]:
            rows = copy.deepcopy(original)
            if name == "missing":
                rows.pop()
            elif name == "duplicate":
                rows.append(rows[0])
            else:
                rows[0][name] = [] if name == "checks" else "wrong"
            with self.subTest(name=name), self.assertRaises(ValueError):
                verify(rows)


if __name__ == "__main__":
    unittest.main()
