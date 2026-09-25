"""No-network controls for X02's exact-rule orchestration and cleanup."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("x02_directed_run",
                                              REPO / "scripts/x02_directed_run.py")
import sys
sys.path.insert(0, str(REPO / "scripts"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def policy():
    edges = [("three_of_four", f"r{i}") for i in range(1, 7)]
    edges += [("two_of_four", f"r{i}") for i in range(7, 11)]
    return {"source_commit": "a" * 40, "clsact": {
        "interface": "lo", "cleanup_argv": ["tc", "qdisc", "del", "dev", "lo", "clsact"]},
        "rules": [{"id": name, "phase": phase,
                   "remove_argv": ["tc", "filter", "del", name]}
                  for phase, name in edges]}


class DirectedRunTests(unittest.TestCase):
    def exercise(self, fail_at=None, verifier_passed=True):
        current = [0.0]
        heights = [100, 100, 102, 102, 102, 102, 102, 102, 104]
        index = [0]

        def sample(_policy, _sha, phase, _anchor, _previous):
            index[0] += 1
            if phase == fail_at:
                raise RuntimeError("injected sample failure")
            return {"phase": phase, "common_seqno": heights[index[0] - 1]}

        def event(_policy, _sha, rule_id, action):
            if (rule_id, action) == fail_at:
                raise RuntimeError("injected post-command receipt failure")
            return {"rule_id": rule_id, "action": action, "command": {"exit": 0}}

        def tc(_policy):
            return {"lo": {"filters": {}, "qdiscs": {}}}

        def sleep(seconds):
            current[0] += seconds

        with tempfile.TemporaryDirectory(prefix="x02-directed-") as directory:
            root = Path(directory) / "run"
            with (patch.object(runner.x02, "require_source_commit"),
                  patch.object(runner.os, "geteuid", return_value=0),
                  patch.object(runner.x02, "capture_tc", side_effect=tc),
                  patch.object(runner.x02, "command_json", return_value=[]),
                  patch.object(runner.x02, "has_clsact", return_value=False),
                  patch.object(runner.x02, "fault_event", side_effect=event),
                  patch.object(runner.x02, "capture", side_effect=sample),
                  patch.object(runner.x02, "verify",
                               return_value={"passed": verifier_passed}),
                  patch.object(runner.x02, "run_raw", return_value={"exit": 0}),
                  patch.object(runner.time, "sleep", side_effect=sleep),
                  patch.object(runner.time, "monotonic", side_effect=lambda: current[0])):
                result = runner.collect(policy(), "b" * 64, root)
            self.assertTrue((root / "result.json").exists())
            return result, root.joinpath("cleanup.json").read_text(), sorted(root.iterdir())

    def test_complete_ten_rule_run_retains_all_events_and_samples(self):
        result, cleanup, paths = self.exercise()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["events"], 22)
        self.assertEqual(result["snapshots"], 9)
        self.assertIn('"fallback_commands": []', cleanup)
        self.assertEqual(len([path for path in paths if path.name.startswith("event-")]), 22)

    def test_failure_removes_only_installed_rules_and_clsact(self):
        result, cleanup, _paths = self.exercise(fail_at="three_of_four")
        self.assertEqual(result["status"], "failed")
        self.assertIn("injected sample failure", result["error"])
        self.assertIn('"rule_id": "r6"', cleanup)
        self.assertIn('"rule_id": "clsact"', cleanup)
        self.assertNotIn('"rule_id": "r7"', cleanup)

    def test_missing_install_receipt_still_removes_attempted_rule(self):
        result, cleanup, _paths = self.exercise(fail_at=("r2", "install"))
        self.assertEqual(result["status"], "failed")
        self.assertIn('"rule_id": "r2"', cleanup)
        self.assertNotIn('"rule_id": "r3"', cleanup)

    def test_missing_clsact_receipt_still_attempts_cleanup(self):
        result, cleanup, _paths = self.exercise(fail_at=("clsact", "setup"))
        self.assertEqual(result["status"], "failed")
        self.assertIn('"rule_id": "clsact"', cleanup)

    def test_verifier_must_explicitly_pass(self):
        result, _cleanup, _paths = self.exercise(verifier_passed=False)
        self.assertEqual(result["status"], "failed")


if __name__ == "__main__":
    unittest.main()
