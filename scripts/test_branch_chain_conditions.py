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
            "Retain public self-pay proofs",
            "Retain native init-block publisher evidence",
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
            "cargo test --manifest-path tosctl/src/Cargo.toml --locked -p commands --features node-data-sync-native --lib commands::nodectl::node_cmd::status_tests::standalone_status_keeps_rpc_only_contract_without_control_or_references",
            "grep -F 'test result: ok. 1 passed; 0 failed; 0 ignored' build/node-status-compatibility.log",
            "run: uv run python test/integration/node_store_native_reopen.py",
        )
        for command in controls:
            with self.subTest(command=command), self.assertRaises(RuntimeError):
                self.guard.validate_node_store_proof(self.workflow.replace(command, "REMOVED"))

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
