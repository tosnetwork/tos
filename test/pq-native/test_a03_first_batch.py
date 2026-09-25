import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("first_batch", ROOT / "scripts/a03_first_batch.py")
first_batch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(first_batch)
MEMO = Path("/datax/memo-pg-e16-current-20260925")


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

    def test_x01_offline_candidate_cannot_claim_live_route(self):
        batch = copy.deepcopy(self.original)
        batch["entries"]["X01"]["command"]["kind"] = "real_chain"
        self.assertIn("X01: offline candidate misclassified", self.check(batch))

    def test_each_id_requires_scope_and_invalidation_conditions(self):
        batch = copy.deepcopy(self.original)
        batch["entries"]["E16"]["invalidating_changes"] = []
        batch["entries"]["F01"]["scope"] = ""
        errors = self.check(batch)
        self.assertIn("E16: invalidating changes missing", errors)
        self.assertIn("F01: applicability scope missing", errors)


if __name__ == "__main__":
    unittest.main()
