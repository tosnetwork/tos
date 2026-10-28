"""Negative controls for split-suite coverage and receipt validation."""

import copy
import importlib.util
import json
import os
import subprocess
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
        self.assertEqual(len(coverage), 19)
        self.assertEqual(len(self.contract["steps"]), 52)
        for row in guard.expanded_steps(self.contract):
            expected = {guard.RUNNERS[0]} if row["x86_only"] else set(guard.RUNNERS)
            self.assertEqual(
                {runner for (_, runner), names in coverage.items() if row["name"] in names},
                expected,
            )

    def test_event_specific_scheduling_and_receipt_cli(self):
        coverage = self.check()
        for event, count in [("pull_request", 19), ("workflow_dispatch", 19)]:
            scheduled = guard.coverage_for_event(coverage, event)
            self.assertEqual(len(scheduled), count)
            self.assertEqual({r for _, r in scheduled}, set(guard.RUNNERS))
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                env = dict(
                    os.environ,
                    GITHUB_EVENT_NAME=event,
                    GITHUB_RUN_ID="123",
                    GITHUB_RUN_ATTEMPT="1",
                    SOURCE_SHA=subprocess.check_output(
                        ["git", "rev-parse", "HEAD"], cwd=guard.ROOT, text=True
                    ).strip(),
                )
                for suite, runner in sorted(scheduled):
                    subprocess.run(
                        [
                            "python3",
                            str(guard.ROOT / "scripts/check-rescue-context-ci.py"),
                            "--write-receipt",
                            str(root / suite / runner / "suite-success.json"),
                            "--suite",
                            suite,
                            "--runner",
                            runner,
                        ],
                        env=env,
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                verify = [
                    "python3",
                    str(guard.ROOT / "scripts/check-rescue-context-ci.py"),
                    "--verify-receipts",
                    str(root),
                ]
                subprocess.run(verify, env=env, check=True, capture_output=True, text=True)
                missing = next(root.rglob("suite-success.json"))
                receipt = json.loads(missing.read_text())
                receipt["event"] = (
                    "pull_request" if event == "workflow_dispatch" else "workflow_dispatch"
                )
                missing.write_text(json.dumps(receipt))
                failed = subprocess.run(verify, env=env, capture_output=True, text=True)
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn("another workflow event", failed.stderr)
                missing.unlink()
                failed = subprocess.run(verify, env=env, capture_output=True, text=True)
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn("missing success receipts", failed.stderr)
                receipt["event"] = event
                missing.write_text(json.dumps(receipt))
                # Both events must reject complete x86 coverage with no ARM receipts.
                for path in root.rglob("suite-success.json"):
                    if json.loads(path.read_text())["runner"] == guard.RUNNERS[1]:
                        path.unlink()
                failed = subprocess.run(verify, env=env, capture_output=True, text=True)
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn("missing success receipts", failed.stderr)
                self.assertIn(guard.RUNNERS[1], failed.stderr)
        with self.assertRaisesRegex(ValueError, "unsupported workflow event"):
            guard.coverage_for_event(coverage, "push")

    def test_each_original_step_cannot_disappear_change_or_be_skipped(self):
        for row in guard.expanded_steps(self.contract):
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
                    "serial commands changed|split commands do not reconstruct original|split body must be a literal script",
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

    def test_split_commands_cannot_change_even_with_updated_part_hash(self):
        contract = copy.deepcopy(self.contract)
        original = next(row for row in contract["steps"] if "parts" in row)
        part = original["parts"][0]
        block = next(
            b
            for b in guard.blocks(self.workflow.split("\n  parity:\n")[0])
            if b.startswith("      - name: " + part["name"] + "\n")
        )
        changed = block.replace("          cargo test", "          true # cargo test", 1)
        part["run_sha256"] = guard.digest(changed[changed.index("        run:") :].rstrip() + "\n")
        with self.assertRaisesRegex(ValueError, "split commands do not reconstruct original"):
            self.check(self.workflow.replace(block, changed, 1), contract)
        contract = copy.deepcopy(self.contract)
        original = next(row for row in contract["steps"] if "parts" in row)
        original["parts"].reverse()
        with self.assertRaisesRegex(ValueError, "split commands do not reconstruct original"):
            self.check(contract=contract)

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

    def test_each_consumer_keeps_its_local_prerequisites(self):
        for consumer in guard.expanded_steps(self.contract):
            for suite in consumer["suites"]:
                for name in consumer["requires"]:
                    contract = copy.deepcopy(self.contract)
                    prerequisite = next(
                        row for row in guard.expanded_steps(contract) if row["name"] == name
                    )
                    old = guard.condition(prerequisite)
                    prerequisite["suites"].remove(suite)
                    block = next(
                        b
                        for b in guard.blocks(self.workflow.split("\n  parity:\n")[0])
                        if b.startswith("      - name: " + name + "\n")
                    )
                    mutant = self.workflow.replace(
                        block, block.replace(old, guard.condition(prerequisite), 1), 1
                    )
                    with self.subTest(consumer=consumer["name"], suite=suite, missing=name):
                        with self.assertRaisesRegex(
                            ValueError, "missing prerequisite|architecture lost"
                        ):
                            self.check(mutant, contract)

    def test_matrix_and_gate_cannot_hide_failures(self):
        mutants = {
            "manual trigger removed": self.workflow.replace("  workflow_dispatch:\n", "", 1),
            "ARM made manual-only": self.workflow.replace(
                guard.RUNNER_MATRIX,
                "runner: ${{ fromJSON(github.event_name == 'workflow_dispatch' && '[\"ubuntu-24.04\",\"ubuntu-24.04-arm\"]' || '[\"ubuntu-24.04\"]') }}",
                1,
            ),
            "gate schedule differs": self.workflow.replace(
                guard.RUNNER_MATRIX, "runner: [ubuntu-24.04]"
            ),
            "arm omitted": self.workflow.replace(guard.RUNNER_MATRIX, "runner: [ubuntu-24.04]", 1),
            "fee CLI missing in new suites": self.workflow.replace(
                'contains(fromJSON(\'["fee-lifecycle","fee-successor","fee-promotion"]\'), matrix.suite)',
                "matrix.suite == 'fee-lifecycle'",
                1,
            ),
            "parallel bottleneck": self.workflow.replace("max-parallel: 20", "max-parallel: 4", 1),
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
                    "event": "workflow_dispatch",
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
                guard.verify_receipts(root, "a" * 40, "123", attempt, coverage, "workflow_dispatch")

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
            "event",
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

    def test_generated_root_obligations_cannot_be_removed_or_narrowed(self):
        mutations = [
            (
                "          python test/executor-parity/test_wallet_module_inputs.py",
                "          true",
            ),
            (
                "--mode candidate --output artifacts/module-root-controls.json",
                "--mode diagnostic --output artifacts/module-root-controls.json",
            ),
            (
                "--mode diagnostic --output artifacts/module-root-controls.json",
                "--mode candidate --output artifacts/module-root-controls.json",
            ),
            (
                "--module-candidate artifacts/context/quantum-release-primary",
                "--module-candidate artifacts/context/quantum-module",
            ),
            (
                "--module-diagnostic artifacts/context/quantum-module",
                "--module-diagnostic artifacts/context/quantum-release-primary",
            ),
            (
                "--module-repeat-candidate artifacts/module-repeat-candidate",
                "--module-repeat-candidate artifacts/context/quantum-release-primary",
            ),
            (
                "--module-controls artifacts/module-root-controls.json",
                "--module-controls artifacts/generated-root-controls.json",
            ),
            ("test/executor-parity/**", "test/unrelated/**"),
            ("test/falcon-auth/linked_roots.py", "test/unrelated/helper.py"),
            ("test/rel02/**", "test/unrelated/replay/**"),
            ("  actions: read\n", ""),
            (
                "--release artifacts/context/quantum-release-transactions --post artifacts/context/quantum-post-accept --emulator",
                "--release wrong --post artifacts/context/quantum-post-accept --emulator",
            ),
            (
                "          python test/executor-parity/test_generated_bundle.py",
                "          python test/executor-parity/removed_bundle.py",
            ),
            (
                "          python test/executor-parity/generated_bundle.py --bundle",
                "          python test/executor-parity/removed_bundle.py --bundle",
            ),
            (
                "          name: rescue-roots-${{ matrix.runner }}-attempt-${{ github.run_attempt }}",
                "          name: rescue-roots-fixed",
            ),
            ("          path: artifacts/generated-roots", "          path: artifacts/context"),
            ("run: python test/executor-parity/generated_bundle.py --check-download", "run: true"),
            ("          pattern: rescue-roots-*", "          pattern: other-roots-*"),
            (
                "run: python test/executor-parity/generated_bundle.py --compare roots --receipts receipts",
                "run: true",
            ),
        ]
        for old, new in mutations:
            with self.subTest(old=old):
                self.assertIn(old, self.workflow)
                with self.assertRaises(ValueError):
                    self.check(self.workflow.replace(old, new))
        for name in (
            "Verify generated transaction root controls and bundle",
            "Retain generated transaction roots",
        ):
            old = (
                "      - name: "
                + name
                + "\n        if: contains(fromJSON('[\"release-wallet\"]'), matrix.suite)\n"
            )
            new = old.rstrip() + " && matrix.runner == 'ubuntu-24.04'\n"
            with self.subTest(step=name), self.assertRaises(ValueError):
                self.assertIn(old, self.workflow)
                self.check(self.workflow.replace(old, new))
        before, parity = self.workflow.split("\n  parity:\n", 1)
        parity = parity.replace(
            "ref: ${{ github.event.pull_request.head.sha || github.sha }}", "ref: main"
        )
        with self.assertRaises(ValueError):
            self.check(before + "\n  parity:\n" + parity)


if __name__ == "__main__":
    unittest.main()
