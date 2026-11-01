"""The archive exception must not permit runtime gates to become conditional."""

import ast
import importlib.util
import os
import re
import subprocess
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

    def test_checkout_trust_is_immediate_scoped_and_fail_closed(self):
        self.guard.validate_checkout_trust(self.workflow)
        step = re.search(
            r"(?ms)^      - name: Trust the checkout for container steps\n.*?(?=^      - |\Z)",
            self.workflow,
        ).group(0)
        mutants = {
            "omitted": self.workflow.replace(step, "", 1),
            "too late": self.workflow.replace(step, "", 1) + step,
        }
        for before, after in (
            ('safe.directory "$GITHUB_WORKSPACE"', "safe.directory '*'"),
            ('safe.directory "$GITHUB_WORKSPACE"', 'safe.directory "$GITHUB_WORKSPACE/*"'),
            ("git config --global", 'HOME="$RUNNER_TEMP" git config --global'),
            ("git config --global", "git config --system"),
            ('"$GITHUB_WORKSPACE"', '"$GITHUB_WORKSPACE" || true'),
            ("git rev-parse HEAD", "# git rev-parse HEAD"),
            ("set -euo pipefail", "set +e"),
        ):
            mutants[after] = self.workflow.replace(step, step.replace(before, after), 1)
        for name, workflow in mutants.items():
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "checkout trust"):
                self.guard.validate_checkout_trust(workflow)

    def test_checkout_temporary_home_does_not_trust_later_container_steps(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout_home, runtime_home = root / "checkout-home", root / "runtime-home"
            checkout_home.mkdir()
            runtime_home.mkdir()
            workspace, unrelated = root / "workspace checkout", root / "unrelated"
            runtime_env = {
                key: value for key, value in os.environ.items() if not key.startswith("GIT_")
            }
            runtime_env.update(
                HOME=str(runtime_home),
                XDG_CONFIG_HOME=str(root / "xdg"),
                GIT_CONFIG_NOSYSTEM="1",
                GITHUB_WORKSPACE=str(workspace),
                LC_ALL="C",
            )

            def git(*args, env=runtime_env):
                return subprocess.run(
                    ["git", *map(str, args)],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

            for repo in (workspace, unrelated):
                git("init", "--quiet", repo).check_returncode()
                git(
                    "-C",
                    repo,
                    "-c",
                    "user.name=CI regression",
                    "-c",
                    "user.email=ci-regression@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    f"core.hooksPath={os.devnull}",
                    "commit",
                    "--quiet",
                    "--allow-empty",
                    "-m",
                    repo.name,
                ).check_returncode()
            expected_head = git("-C", workspace, "rev-parse", "HEAD")
            expected_head.check_returncode()
            runtime_env["GIT_TEST_ASSUME_DIFFERENT_OWNER"] = "1"
            checkout_env = dict(runtime_env, HOME=str(checkout_home))
            git(
                "config", "--global", "--add", "safe.directory", workspace, env=checkout_env
            ).check_returncode()
            during_checkout = git("-C", workspace, "rev-parse", "HEAD", env=checkout_env)
            during_checkout.check_returncode()
            self.assertEqual(during_checkout.stdout, expected_head.stdout)
            checkout_config = (checkout_home / ".gitconfig").read_bytes()

            before = git("-C", workspace, "rev-parse", "HEAD")
            self.assertEqual(before.returncode, 128)
            self.assertIn("detected dubious ownership", before.stderr)
            self.assertFalse((runtime_home / ".gitconfig").exists())
            step = re.search(
                r"(?ms)^      - name: Trust the checkout for container steps\n"
                r".*?^        run: \|\n(?P<commands>(?:          [^\n]*\n)+)",
                self.workflow,
            )
            self.assertIsNotNone(step, "container checkout trust step is absent")
            script = "\n".join(line[10:] for line in step.group("commands").splitlines())
            bootstrap = subprocess.run(
                ["bash", "--noprofile", "--norc", "-c", script],
                cwd=workspace,
                env=runtime_env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(bootstrap.returncode, 0, bootstrap.stderr)
            self.assertEqual(bootstrap.stdout, expected_head.stdout)
            later_step = git("-C", workspace, "rev-parse", "HEAD")
            later_step.check_returncode()
            self.assertEqual(later_step.stdout, expected_head.stdout)
            outside = git("-C", unrelated, "rev-parse", "HEAD")
            self.assertEqual(outside.returncode, 128)
            self.assertIn("detected dubious ownership", outside.stderr)
            trusted = git("config", "--global", "--get-all", "safe.directory")
            trusted.check_returncode()
            self.assertEqual(trusted.stdout.splitlines(), [str(workspace)])
            self.assertEqual((checkout_home / ".gitconfig").read_bytes(), checkout_config)

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
            "Retain public self-pay proofs",
            "Retain native init-block publisher evidence",
            "Retain native wallet-index verification evidence",
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

    def test_init_block_lifecycle_cannot_be_omitted_or_commented_out(self):
        self.guard.validate_init_block_lifecycle(self.workflow)
        for marker in (
            "uv run python test/integration/node_sync_init_block.py",
            "grep -Fx 'NATIVE_SERIALIZER_NONLOCAL_REFUSAL_OK'",
            "grep -Fx 'NATIVE_INIT_BLOCK_JOIN_OK'",
            "export NODE_SYNC_NATIVE_INIT_ROOT=",
            "grep -Fx 'PRODUCTION_INIT_BLOCK_PUBLISH_BOOTSTRAP_OK'",
            "python3 scripts/check-init-block-pre-anchor-control.py",
            "grep -Fx 'INIT_BLOCK_PRE_ANCHOR_CONTROL_OK'",
        ):
            lines = [line for line in self.workflow.splitlines() if marker in line]
            self.assertEqual(len(lines), 1)
            for replacement in ("", "          # " + lines[0].lstrip()):
                with self.subTest(marker=marker, replacement=replacement):
                    with self.assertRaisesRegex(RuntimeError, "init-block lifecycle command"):
                        self.guard.validate_init_block_lifecycle(
                            self.workflow.replace(lines[0], replacement, 1)
                        )

    def test_node_store_proof_cannot_be_omitted(self):
        self.guard.validate_node_store_proof(self.workflow)
        controls = (
            "export NODE_STORE_NATIVE_DIR=",
            "export NODE_STORE_FIXTURE=",
            "cargo test --manifest-path tosctl/src/Cargo.toml --locked -p node-store",
            "grep -F 'test result: ok. 1 passed; 0 failed; 0 ignored'",
            "cargo build --manifest-path tosctl/src/Cargo.toml --locked -p node-store",
            "cargo test --manifest-path tosctl/src/Cargo.toml --locked -p node-data-sync --features native --lib service::tests::refuse_writers_checks_child_descriptor_access_modes",
            "grep -Fx 'CHILD_DESCRIPTOR_WRITER_CONTROL_OK' build/node-sync-writer-control.log",
            "cargo test --manifest-path tosctl/src/Cargo.toml --locked -p commands --features node-data-sync-native --lib commands::nodectl::node_cmd::status_tests::standalone_status_keeps_rpc_only_contract_without_control_or_references",
            "grep -F 'test result: ok. 1 passed; 0 failed; 0 ignored' build/node-status-compatibility.log",
            "run: uv run python test/integration/node_store_native_reopen.py",
        )
        for command in controls:
            with self.subTest(command=command), self.assertRaises(RuntimeError):
                self.guard.validate_node_store_proof(self.workflow.replace(command, "REMOVED"))

    def test_writer_inspection_capability_must_belong_to_the_native_container(self):
        self.guard.validate_node_store_proof(self.workflow)
        options = next(
            line for line in self.workflow.splitlines() if line.startswith("      options:")
        )
        without = self.workflow.replace(" --cap-add SYS_PTRACE", "", 1)
        mutants = {
            "missing capability": without,
            "dropped capability": self.workflow.replace(
                "--cap-add SYS_PTRACE", "--cap-drop SYS_PTRACE", 1
            ),
            "capability overridden": self.workflow.replace(options, options + " --cap-drop ALL", 1),
            "comment only": without.replace(
                options.replace(" --cap-add SYS_PTRACE", ""),
                options.replace(" --cap-add SYS_PTRACE", "") + " # --cap-add SYS_PTRACE",
                1,
            ),
            "commented options": self.workflow.replace(options, "      # " + options.lstrip(), 1),
            "missing options": self.workflow.replace(options + "\n", "", 1),
            "other job": without.replace(
                "  rust-workspace-tests-compile:\n",
                "  rust-workspace-tests-compile:\n    container:\n" + options + "\n",
                1,
            ),
            "step text only": without.replace(
                "    steps:\n", "    steps:\n      - run: echo --cap-add SYS_PTRACE\n", 1
            ),
        }
        for name, workflow in mutants.items():
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(RuntimeError, "container must grant SYS_PTRACE"),
            ):
                self.guard.validate_node_store_proof(workflow)

    def test_wallet_index_native_acceptance_cannot_be_omitted_or_narrowed(self):
        self.guard.validate_wallet_index_acceptance(self.workflow)
        for marker in (
            "python3 scripts/test-wallet-index-review-controls.py",
            "grep -Fx 'WALLET_INDEX_REVIEW_CONTROLS_OK'",
            "uv run python test/integration/wallet_index_verify_native.py",
            "grep -Fx 'NATIVE_WALLET_INDEX_VERIFY_OK'",
        ):
            lines = [line for line in self.workflow.splitlines() if marker in line]
            self.assertEqual(len(lines), 1)
            for replacement in ("", "          # " + lines[0].lstrip()):
                with (
                    self.subTest(marker=marker, replacement=replacement),
                    self.assertRaises(RuntimeError),
                ):
                    self.guard.validate_wallet_index_acceptance(
                        self.workflow.replace(lines[0], replacement, 1)
                    )
        command = next(
            line
            for line in self.workflow.splitlines()
            if "uv run python test/integration/wallet_index_verify_native.py" in line
        )
        for replacement in (
            command.replace(" | tee", " --scenarios | tee"),
            command.replace(" | tee", " --scenarios reference path-b | tee"),
            command.replace(
                '"$(git rev-parse HEAD)"', '"${{ github.event.pull_request.head.sha }}"'
            ),
        ):
            with self.subTest(replacement=replacement), self.assertRaises(RuntimeError):
                self.guard.validate_wallet_index_acceptance(
                    self.workflow.replace(command, replacement, 1)
                )

    def test_wallet_index_acceptance_requires_pipeline_failures_and_bounded_receipts(self):
        for before, after in (
            ("set -euo pipefail", "set -eu"),
            ("shell: bash", "shell: sh"),
            (
                "build/node-sync-init-block/wallet-index-fixtures.json",
                "build/node-sync-init-block/network/",
            ),
            ("build/node-sync-init-block/wallet-traffic/*.boc", "build/node-sync-init-block/**"),
            (
                "build/wallet-index-verify-native/*/receipt.json",
                "build/wallet-index-verify-native/**",
            ),
            ("build/wallet-index-review-controls/*.log", "build/wallet-index-review-controls/"),
            ("retention-days: 14", "retention-days: 1"),
        ):
            with self.subTest(before=before), self.assertRaises(RuntimeError):
                self.guard.validate_wallet_index_acceptance(self.workflow.replace(before, after))

    def test_wallet_index_fixture_cannot_be_omitted_from_the_shared_image(self):
        with self.assertRaisesRegex(RuntimeError, "init-block lifecycle command"):
            self.guard.validate_init_block_lifecycle(
                self.workflow.replace(" --wallet-index-fixtures", "")
            )

    def test_wallet_index_default_must_include_each_required_scenario(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / "test/integration/wallet_index_verify_native.py").read_text()
        self.guard.validate_wallet_index_scenarios(source)
        for name in self.guard.WALLET_INDEX_SCENARIOS:

            class RemoveScenario(ast.NodeTransformer):
                def visit_Constant(self, node):
                    if node.value == name:
                        return ast.copy_location(ast.Constant(value="removed-scenario"), node)
                    return node

            changed = ast.unparse(RemoveScenario().visit(ast.parse(source)))
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "scenarios differ"):
                self.guard.validate_wallet_index_scenarios(changed)
        for default in ("[]", "['reference']"):
            with (
                self.subTest(default=default),
                self.assertRaisesRegex(RuntimeError, "entire scenario registry"),
            ):
                self.guard.validate_wallet_index_scenarios(
                    source.replace("default=list(SCENARIOS)", f"default={default}")
                )
        with self.assertRaisesRegex(RuntimeError, "include every red control"):
            self.guard.validate_wallet_index_scenarios(
                source.replace(
                    "**{control.name: scenario_red(control) for control in RED_CONTROLS},", ""
                )
            )

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


class StorageModeBoundaryTests(unittest.TestCase):
    def test_each_lifecycle_boundary_keeps_its_expected_mode(self):
        import shutil

        checkout = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location(
            "mode_guard", checkout / "scripts/check-branch-chain-python-ci.py"
        )
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            relative = Path("tosctl/src/node-control/node-data-sync/src")
            (root / relative).mkdir(parents=True)
            for name in ("operations.rs", "service.rs", "cas.rs", "references.rs", "lib.rs"):
                shutil.copy2(checkout / relative / name, root / relative / name)
            for relative_file in (
                ".github/workflows/branch-chain-python.yml",
                "tosctl/src/node-control/node-data-sync/Cargo.toml",
                "tosctl/src/node-control/node-data-sync/build.rs",
            ):
                destination = root / relative_file
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(checkout / relative_file, destination)
            guard.validate_node_data_sync_modes(root)
            path = root / relative / "operations.rs"
            original = path.read_text()
            # Mutate every individual binding, not a single catch-all call.
            expressions = (
                "service.permanent_cells()?",
                "service.require_mode(permanent)?;",
                "service.require_mode(permanent).context(",
                ".start_in_mode(frozen, permanent)",
                "request.context.service().permanent_cells()?",
                "require_unexchanged_target(request, None)?;",
                "require_unexchanged_target(request, Some(signed.manifest.permanent_cells))?;",
                "require_unexchanged_target(&request, Some(signed.manifest.permanent_cells))",
                "service.require_restore_target(expected)?;",
                "service.require_selected_mode(expected)?;",
                "check_installed()?;",
                "context.service().require_restore_target(Some(signed.manifest.permanent_cells))",
                "context.service().start_restore(frozen, signed.manifest.permanent_cells)?;",
            )
            controls = 0
            for expression in expressions:
                for occurrence in range(original.count(expression)):
                    with self.subTest(expression=expression, occurrence=occurrence):
                        pieces = original.split(expression)
                        mutated = (
                            expression.join(pieces[: occurrence + 1])
                            + "REMOVED_BINDING"
                            + expression.join(pieces[occurrence + 1 :])
                        )
                        path.write_text(mutated)
                        with self.assertRaises(RuntimeError):
                            guard.validate_node_data_sync_modes(root)
                        controls += 1
            path.write_text(
                original.replace(
                    "prepare_stop(request, &signed, &operation, &operation_id)?;",
                    "REMOVED_DESCRIPTOR",
                    1,
                )
            )
            with self.assertRaises(RuntimeError):
                guard.validate_node_data_sync_modes(root)
            path.write_text(
                original.replace(
                    "    let stop = if crate::safe_io::absent(",
                    '    let _ = operation.path.join("FORWARD_ONLY");\n'
                    "    let stop = if crate::safe_io::absent(",
                    1,
                )
            )
            with self.assertRaisesRegex(RuntimeError, "standalone FORWARD_ONLY file"):
                guard.validate_node_data_sync_modes(root)
            path.write_text(original)
            guard.validate_node_data_sync_modes(root)
            cargo = root / "tosctl/src/node-control/node-data-sync/Cargo.toml"
            pristine = cargo.read_text()
            cargo.write_text(
                pristine.replace("default = []", 'default = ["native-lifecycle-tests"]')
            )
            with self.assertRaisesRegex(RuntimeError, "must not be default"):
                guard.validate_node_data_sync_modes(root)
            cargo.write_text(pristine)
            build = root / "tosctl/src/node-control/node-data-sync/build.rs"
            pristine = build.read_text()
            build.write_text(pristine.replace('== Ok("release")', '== Ok("never")'))
            with self.assertRaisesRegex(RuntimeError, "release profile must reject"):
                guard.validate_node_data_sync_modes(root)
            build.write_text(pristine)
            guard.validate_node_data_sync_modes(root)
            self.assertGreaterEqual(controls, 12)


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
                "build/node-sync-init-block/network",
                "build/node-sync-init-block/nonlocal-1",
                "build/node-sync-init-block/nonlocal-2",
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
