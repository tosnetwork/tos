"""Checks that local facts cannot become a whole-validator healthy verdict."""

import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest


ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location(
    "local_validator_health", ROOT / "scripts" / "sample-local-validator-health.py"
)
sampler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sampler)


def sample():
    return {
        "pid": 42, "native_epoch": "e" * 32, "native_generation": 2,
        "native_hash": "a" * 64, "native_complete": False,
        "native_missing": ["local_duties"], "ready": True,
        "sync_lag_seconds": 0, "block_seqno": 101, "block_utime": 1,
        "actions": {name: {"requested": 10, "committed": 10, "failed": 0, "pending": 0}
                    for name in ("proposal", "notarize_vote", "finalize_vote", "skip_vote")},
        "pq_sign_failed": 0,
    }


class LocalValidatorHealthTest(unittest.TestCase):
    def test_unverified_core_cannot_turn_into_healthy(self):
        old = sample()
        new = sample()
        old["native_generation"] = 1
        old["block_seqno"] = 100
        for action in old["actions"].values():
            action["requested"] = action["committed"] = 9
        self.assertEqual(sampler.evaluate(new, old, 60_000),
                         ("unknown", ["unverified_validator_dimensions"]))
        facts = sampler.facts(new, old)
        self.assertEqual(facts["block_delta"], 1)
        self.assertEqual(facts["storage_ack_delta"], 4)

    def test_real_negative_signals_are_not_unknown_or_healthy(self):
        old = sample()
        new = sample()
        old["native_generation"] = 1
        old["block_seqno"] = 100
        new["ready"] = False
        self.assertEqual(sampler.evaluate(new, old, 60_000)[0], "degraded")
        new["ready"] = True
        new["actions"]["notarize_vote"]["failed"] = 1
        self.assertEqual(sampler.evaluate(new, old, 60_000),
                         ("degraded", ["local_action_failure"]))
        new["actions"]["notarize_vote"]["failed"] = 0
        new["pq_sign_failed"] = 1
        self.assertEqual(sampler.evaluate(new, old, 60_000),
                         ("degraded", ["pq_sign_failure"]))

    def test_epoch_change_and_counter_reset_do_not_fake_progress(self):
        old = sample()
        new = sample()
        old["native_generation"] = 1
        old["block_seqno"] = 100
        new["native_epoch"] = "f" * 32
        self.assertEqual(sampler.evaluate(new, old, 60_000)[0], "unknown")
        new["native_epoch"] = old["native_epoch"]
        new["actions"]["proposal"]["requested"] = 9
        self.assertEqual(sampler.evaluate(new, old, 60_000),
                         ("unknown", ["action_counter_reset"]))

    def test_private_state_refuses_world_readable_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.json"
            sampler.write_private(path, {"schema_version": 1})
            self.assertEqual(sampler.read_private(path), {"schema_version": 1})
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "state_permissions"):
                sampler.read_private(path)


if __name__ == "__main__":
    unittest.main()
