"""Bound the F01-only wider Stage-A window and every PQ positive order."""

import runpy
from pathlib import Path
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[2] / "scripts/validator-election-stage-a.py"
stage = runpy.run_path(str(SOURCE))


class F01StakeWindowTests(unittest.IsolatedAsyncioTestCase):
    def test_source_guard_rejects_disabled_presend_and_inbound_checks(self):
        source = SOURCE.read_text()
        guard = SOURCE.parent / "check-pq-election-fixture-source.py"
        mutations = (
            ("elect_at != election_id or elect_close - chain_time <= 30",
             "False and (elect_at != election_id or elect_close - chain_time <= 30)"),
            ("if elector_input.utime >= elect_close:",
             "if False and elector_input.utime >= elect_close:"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            for dependency in ("crypto", "test", "toslib", "tosctl"):
                (root / dependency).symlink_to(SOURCE.parents[1] / dependency,
                                               target_is_directory=True)
            for before, after in mutations:
                self.assertEqual(source.count(before), 1)
                (root / "scripts/validator-election-stage-a.py").write_text(
                    source.replace(before, after))
                result = subprocess.run(
                    ["python3", str(guard), str(root)],
                    capture_output=True, text=True, check=False,
                )
                self.assertNotEqual(result.returncode, 0, before)
                self.assertIn("PQ_ELECTION_FIXTURE_SOURCE_FAILURE", result.stderr)

    def test_extended_profile_is_opt_in_and_stage_a_only(self):
        default = stage["PROFILES"]["a"]
        self.assertIs(stage["f01_profile"](default, False), default)
        wide = stage["f01_profile"](default, True)
        self.assertEqual((wide.elected_for, wide.elect_start_before,
                          wide.elect_end_before, wide.initial_set_valid),
                         (300, 240, 60, 600))
        self.assertEqual(default.elect_start_before, 180)
        with self.assertRaisesRegex(ValueError, "requires Stage A"):
            stage["f01_profile"](stage["PROFILES"]["b"], True)
        fixture = stage["ValidatorElectionRehearsal"].__new__(
            stage["ValidatorElectionRehearsal"])
        fixture.profile = wide
        fixture.fixture_only = False
        fixture.pq_election = False
        fixture.pq_full = False
        fixture.experiment = None
        config = stage["NetworkConfig"]()
        fixture.configure_network_profile(config)
        self.assertEqual(config.validator_election_stage_a_start_before, 240)

    async def test_presend_requires_matching_open_window_and_margin(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = stage["ValidatorElectionRehearsal"].__new__(
                stage["ValidatorElectionRehearsal"])
            fixture.artifacts_dir = Path(directory)
            events = []
            fixture.event = lambda name, **fields: events.append((name, fields))
            fixture.file_provenance = lambda path: {"path": str(path)}

            async def getter(_method):
                return "result: [ 900 850 0 0 () ]"

            fixture.runmethod = getter

            async def chain_time():
                return 810

            fixture.chain_time = chain_time
            self.assertEqual(await fixture.require_open_pq_election(900, "validator-4"), 850)
            self.assertTrue((Path(directory) / "pq-validator-4-presend-window.txt").exists())
            self.assertEqual(events[-1][1]["chain_time"], 810)
            with self.assertRaisesRegex(RuntimeError, "target=901"):
                await fixture.require_open_pq_election(901, "wrong-id")

            async def too_late():
                return 821

            fixture.chain_time = too_late
            with self.assertRaisesRegex(RuntimeError, "lacks an open"):
                await fixture.require_open_pq_election(900, "late")


if __name__ == "__main__":
    unittest.main()
