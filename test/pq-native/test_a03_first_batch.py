import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("first_batch", ROOT / "scripts/a03_first_batch.py")
first_batch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(first_batch)
MEMO = Path(os.environ.get("A03_MEMO_REPO", "/datax/memo-pg-e16-current-20260925"))
# Last tree whose first batch still indexed X01 as an open offline candidate.
STALE_X01_COMMIT = "a1d3ea8a1574345a4412672bfd43fecde64418df"


class FirstBatchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot_bytes = (ROOT / "doc/pq-native/a03-task-snapshot.json").read_bytes()
        cls.snapshot = json.loads(cls.snapshot_bytes)
        cls.original = json.loads((ROOT / "doc/pq-native/a03-first-batch.json").read_bytes())

    def check(self, batch):
        return first_batch.validate(batch, self.snapshot, self.snapshot_bytes, ROOT, MEMO)

    def test_real_original_first_batch_is_integrity_green_only(self):
        self.assertEqual([], self.check(self.original))
        self.assertFalse(any(row["accepted"] for row in self.original["entries"].values()))
        self.assertTrue(all(row["gaps"] for row in self.original["entries"].values()))

    def test_signed_e16_cannot_be_silently_accepted(self):
        batch = copy.deepcopy(self.original)
        batch["entries"]["E16"]["accepted"] = True
        self.assertIn("E16: status/acceptance differs from frozen task table", self.check(batch))

    def test_exact_e16_console_bytes_required(self):
        batch = copy.deepcopy(self.original)
        batch["entries"]["E16"]["raw"][0]["sha256"] = "0" * 64
        self.assertIn("E16:raw:0: missing or SHA mismatch", self.check(batch))
        self.assertIn("E16: natural command exit not in original console", self.check(batch))

    def test_e16_ci_success_cannot_be_relabelled_failure(self):
        batch = copy.deepcopy(self.original)
        for item in batch["entries"]["E16"]["ci"]:
            if item["name"] == "Branch PQ chain and Python tests":
                item["conclusion"] = "failure"
                break
        self.assertTrue(any("run identity/outcome mismatch" in e for e in self.check(batch)))

    def test_f01_no_exact_ci_query_cannot_be_replaced(self):
        batch = copy.deepcopy(self.original)
        batch["entries"]["F01"]["ci_query"]["sha256"] = "0" * 64
        self.assertIn("F01:ci-query: missing or SHA mismatch", self.check(batch))

    def stale(self, path):
        return json.loads(subprocess.check_output(["git", "show", f"{STALE_X01_COMMIT}:{path}"], cwd=ROOT))

    def test_stale_offline_x01_entry_red_against_signed_row(self):
        batch = copy.deepcopy(self.original)
        batch["entries"]["X01"] = self.stale("doc/pq-native/a03-first-batch.json")["entries"]["X01"]
        errors = self.check(batch)
        self.assertIn("X01: status/acceptance differs from frozen task table", errors)
        self.assertIn("X01: signed row must index its signed real-chain run", errors)
        self.assertIn("X01: exact binary snapshots missing", errors)
        self.assertIn("X01: 3 fixed CI dispositions required", errors)

    def test_stale_snapshot_rows_red_even_with_current_table_sha(self):
        snapshot = self.stale("doc/pq-native/a03-task-snapshot.json")
        snapshot["memo_commit"] = self.snapshot["memo_commit"]
        snapshot["task_table_sha256"] = self.snapshot["task_table_sha256"]
        payload = json.dumps(snapshot, ensure_ascii=False).encode()
        batch = copy.deepcopy(self.original)
        batch["snapshot_sha256"] = hashlib.sha256(payload).hexdigest()
        errors = first_batch.validate(batch, snapshot, payload, ROOT, MEMO)
        self.assertEqual(["X01: snapshot status ▶ differs from task table ✅",
                          "Z01: snapshot owner PQ differs from task table PQ + PG + Mac",
                          "Z01: snapshot status □ differs from task table ▶"],
                         [e for e in errors if e.startswith(("snapshot", "X01: snapshot", "Z01: snapshot"))])

    def test_open_row_cannot_be_promoted_by_signed_evidence(self):
        snapshot = copy.deepcopy(self.snapshot)
        next(t for t in snapshot["tasks"] if t["id"] == "X01")["status"] = "▶"
        payload = json.dumps(snapshot, ensure_ascii=False).encode()
        batch = copy.deepcopy(self.original)
        batch["snapshot_sha256"] = hashlib.sha256(payload).hexdigest()
        batch["entries"]["X01"]["task_status"] = "▶"
        errors = first_batch.validate(batch, snapshot, payload, ROOT, MEMO)
        self.assertIn("X01: snapshot status ▶ differs from task table ✅", errors)
        self.assertIn("X01: open unit cannot be promoted", errors)

    def test_x01_console_sha_and_natural_exit_required(self):
        batch = copy.deepcopy(self.original)
        batch["entries"]["X01"]["raw"][0]["sha256"] = "0" * 64
        errors = self.check(batch)
        self.assertIn("X01:raw:0: missing or SHA mismatch", errors)
        self.assertIn("X01: natural command exit not in original console", errors)
        batch = copy.deepcopy(self.original)
        batch["entries"]["X01"]["command"]["exit_raw_marker"] = 'COMMAND_EXIT_CODE="1"'
        self.assertIn("X01: natural command exit not in original console", self.check(batch))

    def test_reported_exit_must_equal_unique_terminal_console_marker(self):
        batch = copy.deepcopy(self.original)
        batch["entries"]["X01"]["command"]["reported_exit"] = 1
        self.assertIn("X01: natural command exit not in original console", self.check(batch))
        self.assertEqual(0, first_batch.console_exit_code(b'Script done on 2026-09-25 19:03:50+00:00 [COMMAND_EXIT_CODE="0"]\n'))
        self.assertIsNone(first_batch.console_exit_code(b'Script done on now [COMMAND_EXIT_CODE="0"]\nScript done on later [COMMAND_EXIT_CODE="1"]\n'))
        self.assertIsNone(first_batch.console_exit_code(b'log mentions COMMAND_EXIT_CODE="0"\n'))

    def test_x01_independent_review_required(self):
        batch = copy.deepcopy(self.original)
        del batch["entries"]["X01"]["review"]
        self.assertIn("X01: fixed independent review missing", self.check(batch))
        batch = copy.deepcopy(self.original)
        batch["entries"]["X01"]["review"]["memo_commit"] = STALE_X01_COMMIT
        self.assertIn("X01:review: fixed Git blob missing or SHA mismatch", self.check(batch))

    def test_x01_reported_argv_must_be_in_fixed_review(self):
        batch = copy.deepcopy(self.original)
        batch["entries"]["X01"]["command"]["reported_argv_text"] += " --skip-fault-window"
        self.assertIn("X01: reported argv absent from fixed independent review", self.check(batch))
        batch = copy.deepcopy(self.original)
        del batch["entries"]["X01"]["command"]["argv_gap"]
        self.assertIn("X01: documented command and exact reported exit missing", self.check(batch))

    def test_x01_binary_snapshot_bytes_required(self):
        batch = copy.deepcopy(self.original)
        batch["entries"]["X01"]["binaries"][0]["sha256"] = "0" * 64
        self.assertIn("X01:binary:0: missing or SHA mismatch", self.check(batch))
        batch["entries"]["X01"]["binaries"] = []
        self.assertIn("X01: exact binary snapshots missing", self.check(batch))

    def test_ci_on_other_source_needs_verified_docs_only_descendant(self):
        batch = copy.deepcopy(self.original)
        del batch["entries"]["X01"]["ci"][0]["source_equivalence"]
        self.assertIn("X01:ci:0: run identity/outcome mismatch", self.check(batch))
        # A descendant that changes code outside doc/ is not the same source.
        with tempfile.TemporaryDirectory() as temp:
            batch = copy.deepcopy(self.original)
            item = batch["entries"]["X01"]["ci"][0]
            run = json.loads(Path(item["raw"]["path"]).read_bytes())
            run["headSha"] = item["head_sha"] = STALE_X01_COMMIT
            path = Path(temp) / "run.json"
            path.write_bytes(json.dumps(run).encode())
            item["raw"] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            self.assertIn("X01:ci:0: run identity/outcome mismatch", self.check(batch))

    def test_f01_exact_source_ci_contradicts_retained_empty_query(self):
        batch = copy.deepcopy(self.original)
        batch["entries"]["F01"]["ci"][0]["head_sha"] = batch["entries"]["F01"]["source_blobs"][0]["commit"]
        self.assertIn("F01: exact-source no-CI query missing or contradicted", self.check(batch))

    def test_each_id_requires_scope_and_invalidation_conditions(self):
        batch = copy.deepcopy(self.original)
        batch["entries"]["E16"]["invalidating_changes"] = []
        batch["entries"]["F01"]["scope"] = ""
        errors = self.check(batch)
        self.assertIn("E16: invalidating changes missing", errors)
        self.assertIn("F01: applicability scope missing", errors)


if __name__ == "__main__":
    unittest.main()
