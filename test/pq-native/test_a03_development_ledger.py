import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("ledger", ROOT / "scripts/a03_development_ledger.py")
ledger_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ledger_module)
COMMIT = "84a30e4268f94e894497e402d97058cadcbb876d"


class LedgerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.evidence_root = Path(self.temp.name)
        self.snapshot = json.loads((ROOT / "doc/pq-native/a03-task-snapshot.json").read_text())
        self.snapshot["tasks"] = [dict(t, status="✅") for t in self.snapshot["tasks"]]
        self.table_bytes = b"synthetic table with 72 signed rows"
        self.snapshot["task_table_sha256"] = hashlib.sha256(self.table_bytes).hexdigest()
        self.snapshot_bytes = json.dumps(self.snapshot, ensure_ascii=False).encode()
        source = subprocess.check_output(["git", "show", f"{COMMIT}:AGENTS.md"], cwd=ROOT)
        source_sha = hashlib.sha256(source).hexdigest()

        def file(name, payload):
            path = self.evidence_root / name
            path.write_bytes(payload)
            return {"path": name, "sha256": hashlib.sha256(payload).hexdigest()}

        units = {}
        for task in self.snapshot["tasks"]:
            tid = task["id"]
            ev = {
                "unit_id": tid,
                "source_commit": COMMIT,
                "source_files": [{"path": "AGENTS.md", "sha256": source_sha}],
                "command": {"argv": ["python3", "unit.py", tid], "exit": 0},
                "raw": file(f"{tid}-raw", f"{tid} raw".encode()),
                "controls": {
                    "old_red": {"argv": ["python3", "old.py", tid], "exit": 1, "raw": file(f"{tid}-old", f"{tid} old red".encode())},
                    "new_green": {"argv": ["python3", "new.py", tid], "exit": 0, "raw": file(f"{tid}-green", f"{tid} new green".encode())},
                    "mutant_red": {"argv": ["python3", "mutant.py", tid], "exit": 1, "raw": file(f"{tid}-mutant", f"{tid} mutant red".encode())},
                },
                "binary": {"gap": "No binary for this synthetic Python fixture."},
                "independent_review": file(f"{tid}-review", f"{tid} independent review".encode()),
                "applicability": f"Synthetic {tid} only",
                "invalidating_changes": ["source file changes"],
                "ci": {"state": "pending", "reason": "Local independent review suffices until CI completes."},
            }
            for role, run in [("main", ev["command"])] + list(ev["controls"].items()):
                raw = ev["raw"] if role == "main" else run["raw"]
                receipt = {
                    "schema": 1, "unit_id": tid, "role": role, "source_commit": COMMIT,
                    "argv": run["argv"], "exit": run["exit"], "raw_sha256": raw["sha256"],
                }
                item = file(f"{tid}-{role}-receipt", json.dumps(receipt, sort_keys=True).encode())
                run["receipt"] = item
            ev["receipt"] = ev["command"].pop("receipt")
            units[tid] = {"status": "✅", "scope": task["lane"], "accepted": True, "evidence": ev}
        self.ledger = {"schema": 1, "snapshot_sha256": hashlib.sha256(self.snapshot_bytes).hexdigest(), "source_commit": COMMIT, "units": units}

    def check(self):
        return ledger_module.validate(self.snapshot, self.ledger, self.snapshot_bytes, ROOT, self.evidence_root, self.table_bytes, ROOT)

    def test_complete_individual_evidence_green(self):
        self.assertEqual([], self.check())

    def test_open_task_cannot_borrow_other_green(self):
        self.snapshot["tasks"][0]["status"] = "□"
        tid = self.snapshot["tasks"][0]["id"]
        self.ledger["units"][tid]["status"] = "□"
        self.snapshot_bytes = json.dumps(self.snapshot, ensure_ascii=False).encode()
        self.ledger["snapshot_sha256"] = hashlib.sha256(self.snapshot_bytes).hexdigest()
        self.assertIn(f"{tid}: open item marked accepted", self.check())

    def test_duplicate_raw_across_units_red(self):
        first, second = list(self.ledger["units"])[:2]
        self.ledger["units"][second]["evidence"]["raw"] = copy.deepcopy(self.ledger["units"][first]["evidence"]["raw"])
        self.assertIn(f"{second}: raw reused from {first}:raw", self.check())

    def test_same_unit_raw_and_controls_cannot_share_bytes(self):
        tid = next(iter(self.ledger["units"]))
        ev = self.ledger["units"][tid]["evidence"]
        for name in ("old_red", "new_green", "mutant_red"):
            ev["controls"][name]["raw"] = copy.deepcopy(ev["raw"])
        errors = self.check()
        self.assertIn(f"{tid}: raw reused from {tid}:raw", errors)
        self.assertIn(f"{tid}: raw content reused from {tid}:raw", errors)

    def test_same_content_under_different_paths_red(self):
        tid = next(iter(self.ledger["units"]))
        ev = self.ledger["units"][tid]["evidence"]
        original = self.evidence_root / ev["raw"]["path"]
        duplicate = self.evidence_root / f"{tid}-copied-old"
        duplicate.write_bytes(original.read_bytes())
        ev["controls"]["old_red"]["raw"] = {"path": duplicate.name, "sha256": ev["raw"]["sha256"]}
        self.assertIn(f"{tid}: raw content reused from {tid}:raw", self.check())

    def test_changed_current_memo_table_red(self):
        self.table_bytes = b"changed task table"
        self.assertIn("snapshot: current memo task table differs", self.check())

    def test_partial_evidence_row_tamper_red(self):
        tid = next(iter(self.ledger["units"]))
        row = f"| {tid} | synthetic | runner | ✅ | evidence |\n".encode()
        self.table_bytes = row
        self.snapshot["task_table_sha256"] = hashlib.sha256(row).hexdigest()
        self.snapshot_bytes = json.dumps(self.snapshot, ensure_ascii=False).encode()
        self.ledger["snapshot_sha256"] = hashlib.sha256(self.snapshot_bytes).hexdigest()
        unit = self.ledger["units"][tid]
        unit["evidence"] = None
        unit["partial_evidence"] = {"task_table_row_sha256": "0" * 64, "review_reports": [], "memo_raw_artifacts": [], "local_raw_artifacts": []}
        errors = self.check()
        self.assertIn(f"{tid}: task-table row SHA mismatch", errors)
        self.assertIn(f"{tid}: signed row lacks machine evidence", errors)

    def test_partial_local_raw_hash_tamper_red(self):
        tid = next(iter(self.ledger["units"]))
        row = f"| {tid} | synthetic | runner | ✅ | evidence |\n".encode()
        self.table_bytes = row
        self.snapshot["task_table_sha256"] = hashlib.sha256(row).hexdigest()
        self.snapshot_bytes = json.dumps(self.snapshot, ensure_ascii=False).encode()
        self.ledger["snapshot_sha256"] = hashlib.sha256(self.snapshot_bytes).hexdigest()
        unit = self.ledger["units"][tid]
        unit["evidence"] = None
        raw = self.evidence_root / "partial-raw"
        raw.write_text("bytes that were reviewed")
        unit["partial_evidence"] = {
            "task_table_row_sha256": hashlib.sha256(row).hexdigest(),
            "review_reports": [], "memo_raw_artifacts": [],
            "local_raw_artifacts": [{"path": str(raw), "sha256": "0" * 64}],
            "source_references": [], "missing_required_fields": ["controls not mapped"],
        }
        self.assertIn(f"{tid}: local raw:0 SHA mismatch or missing", self.check())

    def test_missing_or_wrong_raw_hash_red(self):
        tid = next(iter(self.ledger["units"]))
        self.ledger["units"][tid]["evidence"]["raw"]["sha256"] = "0" * 64
        self.assertIn(f"{tid}:raw: raw SHA mismatch", self.check())

    def test_command_and_control_metadata_must_match_raw_receipts(self):
        tid = next(iter(self.ledger["units"]))
        ev = self.ledger["units"][tid]["evidence"]
        ev["command"]["argv"] = ["python3", "different.py", tid]
        ev["command"]["exit"] = 1
        ev["controls"]["new_green"]["argv"] = ["python3", "different-green.py", tid]
        errors = self.check()
        self.assertIn(f"{tid}:main: run receipt does not bind unit/role/source/argv/exit/raw", errors)
        self.assertIn(f"{tid}:new_green: run receipt does not bind unit/role/source/argv/exit/raw", errors)

    def test_receipt_cannot_be_borrowed_from_another_role_or_unit(self):
        first, second = list(self.ledger["units"])[:2]
        ev = self.ledger["units"][second]["evidence"]
        ev["receipt"] = copy.deepcopy(self.ledger["units"][first]["evidence"]["receipt"])
        ev["controls"]["old_red"]["receipt"] = copy.deepcopy(ev["controls"]["mutant_red"]["receipt"])
        errors = self.check()
        self.assertIn(f"{second}:main: run receipt does not bind unit/role/source/argv/exit/raw", errors)
        self.assertIn(f"{second}:old_red: run receipt does not bind unit/role/source/argv/exit/raw", errors)

    def test_valid_new_raw_with_stale_receipt_red(self):
        tid = next(iter(self.ledger["units"]))
        ev = self.ledger["units"][tid]["evidence"]
        fresh = self.evidence_root / f"{tid}-replacement-raw"
        fresh.write_bytes(b"different but valid original raw bytes")
        ev["raw"] = {"path": fresh.name, "sha256": hashlib.sha256(fresh.read_bytes()).hexdigest()}
        self.assertIn(f"{tid}:main: run receipt does not bind unit/role/source/argv/exit/raw", self.check())

    def test_boolean_receipt_exit_is_not_numeric_exit(self):
        tid = next(iter(self.ledger["units"]))
        ev = self.ledger["units"][tid]["evidence"]
        receipt_item = ev["receipt"]
        receipt_path = self.evidence_root / receipt_item["path"]
        receipt = json.loads(receipt_path.read_text())
        receipt["exit"] = False
        payload = json.dumps(receipt, sort_keys=True).encode()
        receipt_path.write_bytes(payload)
        receipt_item["sha256"] = hashlib.sha256(payload).hexdigest()
        self.assertIn(f"{tid}:main: run receipt does not bind unit/role/source/argv/exit/raw", self.check())

    def test_binary_review_ci_and_invalidation_are_per_unit(self):
        tid = next(iter(self.ledger["units"]))
        ev = self.ledger["units"][tid]["evidence"]
        binary = self.evidence_root / f"{tid}-binary"
        binary.write_bytes(b"fixed synthetic binary")
        ev["binary"] = {"path": binary.name, "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
        self.assertEqual([], self.check())
        binary.write_bytes(b"mutated synthetic binary")
        ev["independent_review"]["sha256"] = "0" * 64
        ev["ci"] = {"state": "failed", "reason": "reopened by relevant CI"}
        ev["invalidating_changes"] = []
        errors = self.check()
        self.assertIn(f"{tid}:binary: raw SHA mismatch", errors)
        self.assertIn(f"{tid}:review: raw SHA mismatch", errors)
        self.assertIn(f"{tid}: CI status/reason missing or failed", errors)
        self.assertIn(f"{tid}: invalidating changes missing", errors)

    def test_missing_mutant_and_wrong_source_red(self):
        tid = next(iter(self.ledger["units"]))
        ev = self.ledger["units"][tid]["evidence"]
        ev["controls"]["mutant_red"]["exit"] = 0
        ev["source_files"][0]["sha256"] = "0" * 64
        errors = self.check()
        self.assertIn(f"{tid}:mutant_red: wrong or missing exit", errors)
        self.assertIn(f"{tid}:source:0: fixed-commit source SHA mismatch", errors)

    def test_git_tree_listing_is_not_source_file(self):
        tid = next(iter(self.ledger["units"]))
        listing = subprocess.check_output(["git", "show", f"{COMMIT}:doc/pq-native/"], cwd=ROOT)
        self.ledger["units"][tid]["evidence"]["source_files"] = [{"path": "doc/pq-native/", "sha256": hashlib.sha256(listing).hexdigest()}]
        self.assertIn(f"{tid}:source:0: fixed source is not a blob", self.check())

    def test_failed_ci_or_unreviewed_signed_row_red(self):
        tid = next(iter(self.ledger["units"]))
        ev = self.ledger["units"][tid]["evidence"]
        ev["ci"] = {"state": "failed", "reason": "CI reopened this unit"}
        self.ledger["units"][tid]["accepted"] = False
        errors = self.check()
        self.assertIn(f"{tid}: CI status/reason missing or failed", errors)
        self.assertIn(f"{tid}: evidence not reconciled/accepted", errors)

    def test_task_status_drift_red(self):
        tid = self.snapshot["tasks"][0]["id"]
        self.ledger["units"][tid]["status"] = "□"
        self.assertIn(f"{tid}: task-table status/scope mismatch", self.check())

    def test_missing_id_and_testnet_acceptance_red(self):
        tid = next(iter(self.ledger["units"]))
        self.ledger["units"].pop(tid)
        self.assertIn("ledger: missing or extra task IDs", self.check())
        self.ledger["units"][tid] = {"status": "◇", "scope": self.snapshot["tasks"][0]["lane"], "accepted": True}
        self.snapshot["tasks"][0]["status"] = "◇"
        self.snapshot_bytes = json.dumps(self.snapshot, ensure_ascii=False).encode()
        self.ledger["snapshot_sha256"] = hashlib.sha256(self.snapshot_bytes).hexdigest()
        self.assertIn(f"{tid}: testnet item cannot close development gate", self.check())


if __name__ == "__main__":
    unittest.main()
