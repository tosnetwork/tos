"""Cache maintenance must not touch main, open PRs, branches or artifacts."""

import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "pr_caches", Path(__file__).with_name("clean-closed-pr-caches.py")
)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class FakeApi:
    def __init__(self):
        self.rows = [
            {"id": i, "ref": ref, "size_in_bytes": 100}
            for i, ref in enumerate(
                [
                    "refs/heads/main",
                    "refs/heads/feature",
                    "refs/pull/1/merge",
                    "refs/pull/2/merge",
                    "refs/pull/2/head",
                    "refs/tags/release",
                    "refs/pull/2/merge/extra",
                ],
                1,
            )
        ]
        self.deleted = []
        self.states = {1: "open", 2: "closed"}
        self.reopen = False
        self.pr_reads = {}

    def request(self, path, method="GET"):
        if method == "DELETE":
            self.deleted.append(path)
            return None
        if path.startswith("actions/caches?"):
            return {"actions_caches": self.rows}
        number = int(path.split("/")[-1])
        self.pr_reads[number] = self.pr_reads.get(number, 0) + 1
        return {
            "state": "open" if self.reopen and self.pr_reads[number] > 1 else self.states[number]
        }


class CacheCleanupTests(unittest.TestCase):
    def test_default_is_dry_run_and_only_closed_pr_refs_qualify(self):
        api = FakeApi()
        self.assertEqual([row[0] for row in mod.candidates(api)], [4, 5])
        result = mod.cleanup(api)
        self.assertEqual(result["eligible_in_batch"], 2)
        self.assertEqual(result["deleted"], 0)
        self.assertFalse(api.deleted)

    def test_apply_uses_only_confirmed_ids_and_is_bounded(self):
        api = FakeApi()
        result = mod.cleanup(api, apply=True, limit=1)
        self.assertEqual(result["deleted"], 1)
        self.assertEqual(api.deleted, ["actions/caches/4"])

    def test_reopened_pr_is_preserved(self):
        api = FakeApi()
        api.reopen = True
        self.assertEqual(mod.cleanup(api, apply=True)["deleted"], 0)
        self.assertFalse(api.deleted)

    def test_unknown_state_or_inventory_error_never_deletes(self):
        api = FakeApi()
        api.states[2] = "unknown"
        self.assertEqual(mod.cleanup(api, apply=True)["deleted"], 0)
        self.assertFalse(api.deleted)
        api = FakeApi()
        del api.states[2]
        with self.assertRaises(KeyError):
            mod.cleanup(api, apply=True)
        self.assertFalse(api.deleted)

    def test_maintenance_workflow_never_runs_pr_code_with_write_permission(self):
        path = Path(__file__).resolve().parents[1] / ".github/workflows/cache-maintenance.yml"
        text = path.read_text()
        self.assertNotRegex(text, r"(?m)^  pull_request(?:_target)?:")
        self.assertIn(
            "if: github.ref == format('refs/heads/{0}', github.event.repository.default_branch)",
            text,
        )
        self.assertIn("ref: ${{ github.event.repository.default_branch }}", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("default: false", text)


if __name__ == "__main__":
    unittest.main()
