#!/usr/bin/env python3
"""Each workflow-policy rule turns red when the tree breaks it, and the tree passes."""

from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SPEC = importlib.util.spec_from_file_location(
    "check_workflow_policy", HERE / "check-workflow-policy.py"
)
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


class PolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        shutil.copytree(ROOT / ".github" / "workflows", self.root / ".github" / "workflows")
        (self.root / "scripts").mkdir()
        for name in ("platform-matrix.json", "release-artifacts.json"):
            shutil.copy(HERE / name, self.root / "scripts" / name)

    def tearDown(self) -> None:
        self.dir.cleanup()

    def mutate(self, name: str, before: str, after: str) -> None:
        path = self.root / ".github" / "workflows" / name
        text = path.read_text()
        self.assertEqual(text.count(before), 1, f"{name}: {before!r}")
        path.write_text(text.replace(before, after))

    def violations(self, rule: str, name: str) -> list[str]:
        return [p for p in policy.check(self.root) if p.startswith(f"{rule} {name}")]

    def assert_red(self, rule: str, name: str) -> None:
        self.assertTrue(self.violations(rule, name), f"{rule} did not fire for {name}")

    def test_the_tree_passes(self) -> None:
        self.assertEqual(policy.check(ROOT), [])
        self.assertEqual(policy.check(self.root), [])

    def test_r1_missing_timeout(self) -> None:
        self.mutate("connect-trust.yml", "    timeout-minutes: 30\n", "")
        self.assert_red("R1", "connect-trust.yml")

    def test_r1_exempts_reusable_workflow_calls(self) -> None:
        self.assertFalse(self.violations("R1", "platform-matrix.yml"))

    def test_r2_missing_permissions(self) -> None:
        self.mutate("connect-trust.yml", "permissions:\n  contents: read\n", "")
        self.assert_red("R2", "connect-trust.yml")

    def test_r3_missing_concurrency(self) -> None:
        self.mutate(
            "connect-trust.yml",
            "concurrency:\n  group: connect-trust-${{ github.event.pull_request.number || github.ref }}\n"
            "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n",
            "",
        )
        self.assert_red("R3", "connect-trust.yml")

    def test_r3_callable_grouping_on_the_caller_name(self) -> None:
        self.mutate(
            "build-tos-wasm-emscripten.yml", "  group: wasm-", "  group: ${{ github.workflow }}-"
        )
        self.assert_red("R3", "build-tos-wasm-emscripten.yml")

    def test_r3_release_that_cancels(self) -> None:
        self.mutate(
            "create-release.yml", "  cancel-in-progress: false\n", "  cancel-in-progress: true\n"
        )
        self.assert_red("R3", "create-release.yml")

    def test_r4_moving_runner_label(self) -> None:
        self.mutate("connect-trust.yml", "runs-on: ubuntu-24.04", "runs-on: ubuntu-latest")
        self.assert_red("R4", "connect-trust.yml")

    def test_r5_dead_branch(self) -> None:
        self.mutate(
            "source-hygiene.yml",
            "branches: [main, 'feature/**']",
            "branches: [testnet, main, 'feature/**']",
        )
        self.assert_red("R5", "source-hygiene.yml")

    def test_r6_member_without_a_job(self) -> None:
        self.mutate(
            "platform-matrix.yml",
            "  wasm:\n    needs: changes\n    if: needs.changes.outputs.relevant == 'true'\n"
            "    uses: ./.github/workflows/build-tos-wasm-emscripten.yml\n",
            "",
        )
        self.assert_red("R6", "platform-matrix.yml")

    def test_r6_nightly_member_under_the_platform_condition(self) -> None:
        self.mutate(
            "platform-matrix.yml",
            "  cppcheck:\n    needs: changes\n    if: needs.changes.outputs.relevant == 'true' && "
            "(github.event_name == 'schedule' || github.event_name == 'workflow_dispatch')\n",
            "  cppcheck:\n    needs: changes\n    if: needs.changes.outputs.relevant == 'true'\n",
        )
        self.assert_red("R6", "platform-matrix.yml")

    def test_r6_unknown_job(self) -> None:
        self.mutate(
            "platform-matrix.yml",
            "  platform-gate:\n",
            "  extra:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: true\n\n"
            "  platform-gate:\n",
        )
        self.assert_red("R6", "platform-matrix.yml")

    def test_r6_gate_missing_a_member(self) -> None:
        self.mutate("platform-matrix.yml", "      - cppcheck\n", "")
        self.assert_red("R6", "platform-matrix.yml")

    def test_r6_gate_not_always(self) -> None:
        self.mutate("platform-matrix.yml", "    if: always()\n", "")
        self.assert_red("R6", "platform-matrix.yml")

    def test_r6_uncached_build_without_its_input(self) -> None:
        self.mutate("platform-matrix.yml", "    with:\n      no_ccache: true\n", "")
        self.assert_red("R6", "platform-matrix.yml")

    def test_r6_report_outside_the_schedule(self) -> None:
        self.mutate(
            "platform-nightly.yml",
            "    if: always() && github.event_name == 'schedule'\n",
            "    if: always()\n",
        )
        self.assert_red("R6", "platform-nightly.yml")

    def test_r6_report_with_a_wider_grant(self) -> None:
        self.mutate(
            "platform-nightly.yml",
            "      issues: write\n",
            "      issues: write\n      contents: write\n",
        )
        self.assert_red("R6", "platform-nightly.yml")

    def test_r6_nightly_on_pull_requests(self) -> None:
        self.mutate(
            "platform-nightly.yml",
            "  workflow_dispatch:\n",
            "  workflow_dispatch:\n  pull_request:\n",
        )
        self.assert_red("R6", "platform-nightly.yml")

    def test_r6_matrix_not_callable(self) -> None:
        self.mutate("platform-matrix.yml", "  workflow_call:\n", "")
        self.assert_red("R6", "platform-matrix.yml")

    def test_r6_member_without_workflow_call(self) -> None:
        self.mutate("build-tos-wasm-emscripten.yml", "  workflow_call:\n", "")
        self.assert_red("R6", "build-tos-wasm-emscripten.yml")

    def test_r7_branchless_pull_request_on_an_inherited_workflow(self) -> None:
        self.mutate("build-tos-macos-15-arm64-shared.yml", "on:\n", "on:\n  pull_request:\n")
        self.assert_red("R7", "build-tos-macos-15-arm64-shared.yml")

    def test_r7_push_that_lost_its_tags(self) -> None:
        self.mutate("tos-x86-64-windows.yml", "  push:\n    tags: ['v*']\n", "  push:\n")
        self.assert_red("R7", "tos-x86-64-windows.yml")

    def test_r8_release_build_without_its_tag(self) -> None:
        self.mutate("build-tos-linux-x86-64-appimage.yml", "  push:\n    tags: ['v*']\n", "")
        self.assert_red("R8", "build-tos-linux-x86-64-appimage.yml")

    def test_r9_member_using_a_secret(self) -> None:
        self.mutate(
            "build-tos-wasm-emscripten.yml",
            "  workflow_call:\n",
            "  workflow_call:\nenv:\n  LEAK: ${{ secrets.DEPLOY_KEY }}\n",
        )
        self.assert_red("R9", "build-tos-wasm-emscripten.yml")

    def test_r9_matrix_passing_secrets(self) -> None:
        self.mutate(
            "platform-matrix.yml",
            "    uses: ./.github/workflows/build-tos-wasm-emscripten.yml\n",
            "    uses: ./.github/workflows/build-tos-wasm-emscripten.yml\n    secrets: inherit\n",
        )
        self.assert_red("R9", "platform-matrix.yml")


if __name__ == "__main__":
    unittest.main()
