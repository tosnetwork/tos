"""Exercise drift detection with real, disposable Git repositories."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("ci_workflow_inventory.py")
SPEC = importlib.util.spec_from_file_location("ci_workflow_inventory", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


class InventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.git("init", "-q")
        self.git("config", "user.email", "ci-fixture@example.invalid")
        self.git("config", "user.name", "CI fixture")
        self.workflows = self.repo / ".github" / "workflows"
        self.workflows.mkdir(parents=True)
        (self.workflows / "base.yml").write_text("name: fixture\non: push\njobs: {}\n")
        self.base = self.commit()

    def git(self, *args: str) -> str:
        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        return subprocess.run(
            ["git", "-C", str(self.repo), *args],
            capture_output=True,
            text=True,
            check=True,
            env=env,
        ).stdout.strip()

    def commit(self) -> str:
        self.git("add", ".github")
        self.git("commit", "-qm", "Fixture")
        return self.git("rev-parse", "HEAD")

    def report(self, candidate: str | None = None) -> dict:
        base = inventory.snapshot(self.repo, self.base)
        head = inventory.snapshot(self.repo, candidate or self.base)
        return {
            "format": inventory.FORMAT,
            "base": base,
            "candidate": head,
            "changes": inventory.changes(base, head),
        }

    def cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(MODULE_PATH), "--repo", str(self.repo), *args],
            text=True,
            capture_output=True,
            check=False,
        )

    def expected_file(self) -> Path:
        path = self.repo / "expected.json"
        path.write_text(json.dumps(self.report()))
        return path

    def test_real_tree_object_identity(self) -> None:
        report = self.report()
        inventory.validate_report(report)
        value = report["base"]
        self.assertEqual(inventory.tree_oid(value["entries"], 40), value["tree"])
        self.assertEqual(value["workflow_count"], 1)

    def test_add_remove_modify(self) -> None:
        (self.workflows / "second.yaml").write_text("name: second\n")
        second = self.commit()
        (self.workflows / "base.yml").unlink()
        (self.workflows / "second.yaml").write_text("name: changed\n")
        (self.workflows / "third.yml").write_text("name: third\n")
        last = self.commit()
        result = inventory.changes(
            inventory.snapshot(self.repo, second), inventory.snapshot(self.repo, last)
        )
        self.assertEqual(
            result, {"added": ["third.yml"], "removed": ["base.yml"], "modified": ["second.yaml"]}
        )

    def test_mode_only_change_is_not_hidden(self) -> None:
        self.git("update-index", "--chmod=+x", ".github/workflows/base.yml")
        self.git("commit", "-qm", "Executable fixture")
        self.assertEqual(self.report("HEAD")["changes"]["modified"], ["base.yml"])

    def test_nested_entries_use_tree_sort_order(self) -> None:
        (self.workflows / "a").mkdir()
        (self.workflows / "a" / "nested.yml").write_text("name: nested\n")
        (self.workflows / "a.txt").write_text("not a workflow\n")
        value = inventory.snapshot(self.repo, self.commit())
        self.assertEqual(value["workflow_count"], 1)
        self.assertEqual(inventory.tree_oid(value["entries"], 40), value["tree"])

    def test_tabs_and_unicode_are_not_split_as_records(self) -> None:
        (self.workflows / "name\t日本.yaml").write_text("name: fixture\n")
        value = inventory.snapshot(self.repo, self.commit())
        self.assertEqual(value["workflow_count"], 2)
        self.assertIn("name\t日本.yaml", value["entries"])

    def test_missing_ref_fails(self) -> None:
        with self.assertRaises(inventory.InventoryError):
            inventory.snapshot(self.repo, "nonexistent-ref")

    def test_option_shaped_ref_fails(self) -> None:
        with self.assertRaises(inventory.InventoryError):
            inventory.snapshot(self.repo, "--all")

    def test_missing_workflow_directory_fails(self) -> None:
        (self.workflows / "base.yml").unlink()
        head = self.commit()
        with self.assertRaises(inventory.InventoryError):
            inventory.snapshot(self.repo, head)

    def test_no_workflow_files_is_not_success(self) -> None:
        (self.workflows / "base.yml").rename(self.workflows / "README.md")
        with self.assertRaisesRegex(inventory.InventoryError, "No workflow files"):
            inventory.snapshot(self.repo, self.commit())

    def test_workflow_symlink_refused(self) -> None:
        (self.workflows / "link.yml").symlink_to("base.yml")
        with self.assertRaisesRegex(inventory.InventoryError, "ordinary file"):
            inventory.snapshot(self.repo, self.commit())

    def test_promisor_repo_refused(self) -> None:
        self.git("config", "remote.origin.promisor", "true")
        with self.assertRaisesRegex(inventory.InventoryError, "non-promisor"):
            inventory.snapshot(self.repo, self.base)

    def test_replacement_commit_cannot_change_snapshot(self) -> None:
        expected = inventory.snapshot(self.repo, self.base)
        (self.workflows / "base.yml").write_text("name: replacement\n")
        other = self.commit()
        self.git("replace", self.base, other)
        self.assertEqual(inventory.snapshot(self.repo, self.base), expected)

    def test_candidate_yaml_is_not_executed(self) -> None:
        marker = self.repo / "SHOULD-NOT-EXIST"
        (self.workflows / "base.yml").write_text(f"run: touch {marker}\n")
        inventory.snapshot(self.repo, self.commit())
        self.assertFalse(marker.exists())

    def test_dirty_files_are_not_mislabeled_committed(self) -> None:
        expected = inventory.snapshot(self.repo, self.base)
        (self.workflows / "base.yml").write_text("uncommitted\n")
        self.assertEqual(inventory.snapshot(self.repo, self.base), expected)

    def test_cli_identical_baseline_passes(self) -> None:
        result = self.cli(
            "--base", self.base, "--candidate", self.base, "--expect", str(self.expected_file())
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cli_workflow_drift_fails(self) -> None:
        expected = self.expected_file()
        (self.workflows / "base.yml").write_text("name: changed\n")
        candidate = self.commit()
        result = self.cli("--base", self.base, "--candidate", candidate, "--expect", str(expected))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Inventory drift", result.stderr)

    def test_cli_source_only_movement_fails(self) -> None:
        expected = self.expected_file()
        (self.repo / "source.txt").write_text("new source\n")
        self.git("add", "source.txt")
        self.git("commit", "-qm", "Source fixture")
        result = self.cli("--base", self.base, "--candidate", "HEAD", "--expect", str(expected))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["changes"]["modified"], [])

    def test_cli_missing_ref_returns_input_error(self) -> None:
        result = self.cli("--base", self.base, "--candidate", "missing")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")

    def test_metadata_verification_never_claims_ci_pass(self) -> None:
        result = self.cli("--verify-baseline", str(self.expected_file()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(json.loads(result.stdout)["ci_result"])

    def test_metadata_mode_refuses_conflicting_arguments(self) -> None:
        result = self.cli("--verify-baseline", str(self.expected_file()), "--base", self.base)
        self.assertEqual(result.returncode, 2)

    def test_duplicate_json_key_refused(self) -> None:
        path = self.repo / "bad.json"
        path.write_text('{"format": "one", "format": "two"}')
        with self.assertRaisesRegex(inventory.InventoryError, "Duplicate"):
            inventory.read_report(path)

    def test_tampered_tree_refused(self) -> None:
        report = self.report()
        report["candidate"]["entries"]["base.yml"][1] = "0" * 40
        report["changes"] = inventory.changes(report["base"], report["candidate"])
        with self.assertRaisesRegex(inventory.InventoryError, "identity"):
            inventory.validate_report(report)

    def test_tampered_count_refused(self) -> None:
        report = self.report()
        report["candidate"]["workflow_count"] = 0
        with self.assertRaisesRegex(inventory.InventoryError, "count"):
            inventory.validate_report(report)

    def test_tampered_changes_refused(self) -> None:
        report = self.report()
        report["changes"]["added"] = ["invented.yml"]
        with self.assertRaisesRegex(inventory.InventoryError, "Change list"):
            inventory.validate_report(report)

    def test_unknown_fields_refused(self) -> None:
        report = copy.deepcopy(self.report())
        report["ci_pass"] = True
        with self.assertRaises(inventory.InventoryError):
            inventory.validate_report(report)

    def test_recorded_metadata_has_exact_tree_identities(self) -> None:
        baseline = Path(__file__).parent.parent / "doc" / "ci-local-first-baseline.json"
        value = inventory.read_report(baseline)
        self.assertEqual(value["base"]["workflow_count"], 50)
        self.assertEqual(value["candidate"]["workflow_count"], 54)
        self.assertEqual(len(value["changes"]["added"]), 4)
        self.assertEqual(len(value["changes"]["modified"]), 4)


if __name__ == "__main__":
    unittest.main()
