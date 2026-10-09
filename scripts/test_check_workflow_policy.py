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
        shutil.copy(ROOT / "README.md", self.root / "README.md")

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

    def test_r6_platform_removed_from_manifest_and_matrix_together(self) -> None:
        manifest = self.root / "scripts" / "platform-matrix.json"
        text = manifest.read_text()
        line = '    "wasm": {"workflow": "build-tos-wasm-emscripten.yml", "tier": "platform"},\n'
        self.assertEqual(text.count(line), 1)
        manifest.write_text(text.replace(line, ""))
        self.mutate(
            "platform-matrix.yml",
            "  wasm:\n    needs: changes\n    if: needs.changes.outputs.relevant == 'true'\n"
            "    uses: ./.github/workflows/build-tos-wasm-emscripten.yml\n",
            "",
        )
        self.mutate("platform-matrix.yml", "      - wasm\n", "")
        self.assert_red("R6", "build-tos-wasm-emscripten.yml")

    def test_yaml_extension_is_checked(self) -> None:
        (self.root / ".github" / "workflows" / "extra.yaml").write_text(
            "name: extra\non:\n  push:\n    branches: [main]\npermissions:\n  contents: read\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n"
        )
        for rule in ("R1", "R3", "R4"):
            self.assert_red(rule, "extra.yaml")

    def badge(self, url: str) -> None:
        readme = self.root / "README.md"
        readme.write_text(readme.read_text() + f"\n[![x]({url})](x)\n")

    def test_r10_badge_on_a_matrix_callee(self) -> None:
        # Called workflows' runs belong to the caller; their own badge never updates on main.
        self.badge(
            "https://github.com/tosnetwork/tos/actions/workflows/"
            "build-tos-macos-15-arm64-shared.yml/badge.svg?branch=main"
        )
        self.assert_red("R10", "build-tos-macos-15-arm64-shared.yml")

    def test_r10_badge_on_a_missing_workflow(self) -> None:
        self.badge("https://github.com/tosnetwork/tos/actions/workflows/gone.yml/badge.svg")
        self.assert_red("R10", "gone.yml")

    def test_r10_schedule_badge_on_a_workflow_without_a_schedule(self) -> None:
        self.badge(
            "https://github.com/tosnetwork/tos/actions/workflows/"
            "platform-matrix.yml/badge.svg?event=schedule"
        )
        self.assert_red("R10", "platform-matrix.yml")

    def test_r10_the_readme_badges_hold(self) -> None:
        self.assertFalse([p for p in policy.check(ROOT) if p.startswith("R10")])
        self.assertTrue(policy.BADGE.findall((ROOT / "README.md").read_text()))

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

    SOURCE_GUARDS_PUSH = "  push:\n    branches: [main]\n  pull_request:\n"

    def test_r11_unfiltered_push_beside_pull_requests(self) -> None:
        self.mutate("source-guards.yml", self.SOURCE_GUARDS_PUSH, "  push:\n  pull_request:\n")
        self.assert_red("R11", "source-guards.yml")

    def test_r11_push_to_another_branch(self) -> None:
        self.mutate(
            "source-guards.yml",
            self.SOURCE_GUARDS_PUSH,
            "  push:\n    branches: [main, 'feat/**']\n  pull_request:\n",
        )
        self.assert_red("R11", "source-guards.yml")

    def test_r11_branches_ignore_admits_unlisted_branches(self) -> None:
        self.mutate(
            "source-guards.yml",
            self.SOURCE_GUARDS_PUSH,
            "  push:\n    branches-ignore: [wip]\n  pull_request:\n",
        )
        self.assert_red("R11", "source-guards.yml")

    def test_r11_negation_and_pattern_are_refused(self) -> None:
        for branches in ("['!main']", "['ma*']", "['**']"):
            with self.subTest(branches):
                self.tearDown()
                self.setUp()
                self.mutate(
                    "source-guards.yml",
                    self.SOURCE_GUARDS_PUSH,
                    f"  push:\n    branches: {branches}\n  pull_request:\n",
                )
                self.assert_red("R11", "source-guards.yml")

    def test_r11_path_filter_alone_is_unfiltered(self) -> None:
        self.mutate(
            "source-guards.yml",
            self.SOURCE_GUARDS_PUSH,
            "  push:\n    paths: ['scripts/**']\n  pull_request:\n",
        )
        self.assert_red("R11", "source-guards.yml")

    def test_r11_tag_only_push_is_accepted(self) -> None:
        self.mutate(
            "source-guards.yml",
            self.SOURCE_GUARDS_PUSH,
            "  push:\n    tags: ['v*']\n  pull_request:\n",
        )
        self.assertFalse(self.violations("R11", "source-guards.yml"))

    def test_r11_the_integration_branch_exception(self) -> None:
        self.assertIn("node-health-monitor", policy.INTEGRATION_BRANCHES)
        self.assertFalse(self.violations("R11", "node-health-monitor.yml"))
        self.mutate(
            "node-health-monitor.yml",
            "    branches: [node-health-monitor]\n",
            "    branches: [node-health-monitor-2]\n",
        )
        self.assert_red("R11", "node-health-monitor.yml")

    def test_r11_push_without_pull_requests_is_out_of_scope(self) -> None:
        self.mutate("source-guards.yml", self.SOURCE_GUARDS_PUSH, "  push:\n")
        self.assertFalse(self.violations("R11", "source-guards.yml"))

    ROUTED = "network-safety-asan.yml"
    TRUSTED_ACTOR = (
        " &&\n       contains(fromJSON(vars.CI_TRUSTED_LOGINS), github.triggering_actor))))"
    )

    def routed_jobs(self) -> dict[str, list[str]]:
        found: dict[str, list[str]] = {}
        for path in sorted((self.root / ".github" / "workflows").glob("*.yml")):
            doc = policy.yaml.safe_load(path.read_text()) or {}
            for job_id, job in (doc.get("jobs") or {}).items():
                labels = job.get("runs-on")
                if isinstance(labels, str) and " ".join(labels.split()) == policy.ROUTED_RUNS_ON:
                    found.setdefault(path.name, []).append(job_id)
        return found

    def test_r12_the_routing_expression_matches_the_routed_jobs(self) -> None:
        # Without this, a constant that matched no job would leave every R12
        # rule below with nothing to check.
        self.assertEqual(
            self.routed_jobs(),
            {
                "branch-chain-python.yml": ["python-and-pq-chain"],
                "build-tos-linux-x86-64-werror.yml": ["strict-build"],
                "jsonrpc-asan.yml": ["unit", "corpus"],
                "network-safety-asan.yml": ["network-safety"],
            },
        )

    def test_r12_literal_self_hosted_label(self) -> None:
        self.mutate(
            "connect-trust.yml", "runs-on: ubuntu-24.04\n", "runs-on: [self-hosted, linux]\n"
        )
        self.assert_red("R12", "connect-trust.yml")

    def test_r12_routing_without_the_trusted_actor(self) -> None:
        self.mutate(self.ROUTED, self.TRUSTED_ACTOR, ")))")
        self.assert_red("R12", self.ROUTED)

    def test_r12_routing_a_fork_or_target_event(self) -> None:
        for before, after in (
            (
                "       github.event.pull_request.head.repo.full_name == github.repository &&\n",
                "",
            ),
            (
                "(github.event_name == 'pull_request' &&",
                "(github.event_name == 'pull_request_target' &&",
            ),
            ("github.ref == 'refs/heads/main'", "startsWith(github.ref, 'refs/heads/')"),
        ):
            with self.subTest(before=before):
                self.tearDown()
                self.setUp()
                self.mutate(self.ROUTED, before, after)
                self.assert_red("R12", self.ROUTED)

    def test_r12_routing_whitespace_is_not_significant(self) -> None:
        self.mutate(self.ROUTED, self.TRUSTED_ACTOR, self.TRUSTED_ACTOR.replace("\n       ", " "))
        self.assertEqual(self.violations("R12", self.ROUTED), [])

    def test_r12_write_permission(self) -> None:
        self.mutate(
            self.ROUTED, "permissions:\n  contents: read\n", "permissions:\n  contents: write\n"
        )
        self.assert_red("R12", self.ROUTED)

    def test_r12_default_permissions(self) -> None:
        self.mutate(self.ROUTED, "permissions:\n  contents: read\n", "")
        self.assert_red("R12", self.ROUTED)

    def test_r12_write_all_permission(self) -> None:
        self.mutate(self.ROUTED, "permissions:\n  contents: read\n", "permissions: write-all\n")
        self.assert_red("R12", self.ROUTED)

    def test_r12_job_write_permission(self) -> None:
        self.mutate(
            self.ROUTED,
            "    timeout-minutes: 100\n",
            "    timeout-minutes: 100\n    permissions:\n      pull-requests: write\n",
        )
        self.assert_red("R12", self.ROUTED)

    def test_r12_secret(self) -> None:
        self.mutate(
            self.ROUTED,
            "    timeout-minutes: 100\n",
            "    timeout-minutes: 100\n    env:\n      KEY: ${{ secrets.DEPLOY_KEY }}\n",
        )
        self.assert_red("R12", self.ROUTED)

    def test_r12_indexed_secret(self) -> None:
        self.mutate(
            self.ROUTED,
            "    timeout-minutes: 100\n",
            "    timeout-minutes: 100\n    env:\n      KEY: ${{ secrets['DEPLOY_KEY'] }}\n",
        )
        self.assert_red("R12", self.ROUTED)

    def test_r12_whole_secrets_context(self) -> None:
        for env in (
            "ALL: ${{ toJSON(secrets) }}",
            "ALL: '${{ toJSON(secrets) }}'",
            "ALL: ${{ join(secrets, ',') }}",
            "ALL: ${{ toJSON(SECRETS) }}",
            "KEY: ${{ Secrets.DEPLOY_KEY }}",
        ):
            with self.subTest(env=env):
                self.tearDown()
                self.setUp()
                self.mutate(
                    self.ROUTED,
                    "    timeout-minutes: 100\n",
                    f"    timeout-minutes: 100\n    env:\n      {env}\n",
                )
                self.assert_red("R12", self.ROUTED)

    def test_r12_secrets_behind_braces_in_a_literal(self) -> None:
        # A }} inside a string literal does not end the expression.
        for env in (
            "KEY: ${{ format('}}{0}', secrets.DEPLOY_KEY) }}",
            "KEY: \"${{ format('}}{0}', secrets.DEPLOY_KEY) }}\"",
            "KEY: '${{ format(''}}{0}'', secrets.DEPLOY_KEY) }}'",
            "KEY: ${{ format('it''s }}', secrets.DEPLOY_KEY) }}",
            "KEY: ${{ toJSON(secrets)",
        ):
            with self.subTest(env=env):
                self.tearDown()
                self.setUp()
                self.mutate(
                    self.ROUTED,
                    "    timeout-minutes: 100\n",
                    f"    timeout-minutes: 100\n    env:\n      {env}\n",
                )
                self.assert_red("R12", self.ROUTED)

    def test_r12_secrets_inside_a_literal_is_text(self) -> None:
        for env in (
            "NAME: ${{ 'secrets-vault' }}",
            "NAME: '${{ ''secrets'' }}'",
            "NAME: ${{ format('{0} secrets', 'it''s') }}",
        ):
            with self.subTest(env=env):
                self.tearDown()
                self.setUp()
                self.mutate(
                    self.ROUTED,
                    "    timeout-minutes: 100\n",
                    f"    timeout-minutes: 100\n    env:\n      {env}\n",
                )
                self.assertEqual(self.violations("R12", self.ROUTED), [])

    def test_r12_secrets_in_a_bare_condition(self) -> None:
        self.mutate(
            self.ROUTED,
            "    timeout-minutes: 100\n",
            "    timeout-minutes: 100\n    if: toJSON(secrets) != '{}'\n",
        )
        self.assert_red("R12", self.ROUTED)

    def test_r12_secrets_passed_to_a_called_workflow(self) -> None:
        self.mutate(
            self.ROUTED,
            "\njobs:\n",
            "\njobs:\n  call:\n    uses: ./.github/workflows/jsonrpc-asan.yml\n"
            "    secrets: inherit\n",
        )
        self.assert_red("R12", self.ROUTED)

    def test_r12_the_token_and_a_crate_name_are_not_secret_access(self) -> None:
        # The tree's routed workflows log in with secrets.GITHUB_TOKEN and test
        # the secrets-vault crate; neither reads another secret.
        text = (self.root / ".github" / "workflows" / "branch-chain-python.yml").read_text()
        self.assertIn("${{ secrets.GITHUB_TOKEN }}", text)
        self.assertIn("-p secrets-vault", text)
        self.assertEqual(self.violations("R12", "branch-chain-python.yml"), [])

    def test_r12_schedule(self) -> None:
        schedule = "  schedule:\n    - cron: '37 3 * * 0'\n"
        for after in (
            "",
            schedule + "    - cron: '37 3 * * 3'\n",
            "  schedule:\n    - cron: '37 3 * * *'\n",
            "  schedule:\n    - cron: '37 3 * * 1-5'\n",
            "  schedule:\n    - cron: '*/5 * * * *'\n",
        ):
            with self.subTest(after=after):
                self.tearDown()
                self.setUp()
                self.mutate(self.ROUTED, schedule, after)
                self.assert_red("R12", self.ROUTED)

    def test_r12_timeout_beyond_the_host_cap(self) -> None:
        limit = policy.HOST_JOB_CAP_MINUTES - policy.HOST_SETUP_MARGIN_MINUTES
        self.mutate(self.ROUTED, "    timeout-minutes: 100\n", f"    timeout-minutes: {limit}\n")
        self.assertEqual(self.violations("R12", self.ROUTED), [])
        self.mutate(
            self.ROUTED, f"    timeout-minutes: {limit}\n", f"    timeout-minutes: {limit + 1}\n"
        )
        self.assert_red("R12", self.ROUTED)

    def test_r12_timeout_from_an_expression(self) -> None:
        self.mutate(self.ROUTED, "    timeout-minutes: 100\n", "    timeout-minutes: ${{ 100 }}\n")
        self.assert_red("R12", self.ROUTED)


if __name__ == "__main__":
    unittest.main()
