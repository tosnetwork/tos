"""Checks that local facts cannot become a whole-validator healthy verdict."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location(
    "local_validator_health", ROOT / "scripts" / "sample-local-validator-health.py"
)
sampler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sampler)


def sample():
    return {
        "pid": 42,
        "native_epoch": "e" * 32,
        "native_generation": 2,
        "native_hash": "a" * 64,
        "native_complete": False,
        "native_missing": ["local_duties"],
        "ready": True,
        "sync_lag_seconds": 0,
        "block_seqno": 101,
        "block_utime": 1,
        "actions": {
            name: {"requested": 10, "committed": 10, "failed": 0, "pending": 0}
            for name in ("proposal", "notarize_vote", "finalize_vote", "skip_vote")
        },
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
        self.assertEqual(
            sampler.evaluate(new, old, 60_000), ("unknown", ["unverified_validator_dimensions"])
        )
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
        self.assertEqual(sampler.evaluate(new, old, 60_000), ("degraded", ["local_action_failure"]))
        new["actions"]["notarize_vote"]["failed"] = 0
        new["pq_sign_failed"] = 1
        self.assertEqual(sampler.evaluate(new, old, 60_000), ("degraded", ["pq_sign_failure"]))

    def test_stale_block_time_reaches_stall_decision(self):
        now = 1_000_000
        sampler.check_readiness_clock({"node_time": now, "last_block_utime": now - 120}, now)
        old = sample()
        new = sample()
        old["native_generation"] = 1
        self.assertEqual(
            sampler.evaluate(new, old, 60_000), ("degraded", ["chain_not_progressing"])
        )
        with self.assertRaisesRegex(ValueError, "readiness_clock"):
            sampler.check_readiness_clock({"node_time": now, "last_block_utime": now + 31}, now)
        with self.assertRaisesRegex(ValueError, "readiness_clock"):
            sampler.check_readiness_clock({"node_time": now - 31, "last_block_utime": now}, now)

    def test_missing_native_source_stays_unknown(self):
        manifest = {"network_id": "a" * 64, "nodes": {node: {} for node in sampler.NODES}}

        def fetch(node, _manifest, _validator):
            if node == "validator1":
                raise ValueError("native_unavailable")
            return sample()

        result = sampler.run(manifest, {}, {}, fetch=fetch)
        self.assertNotIn("validator1", result["samples"])
        self.assertEqual(
            result["verdicts"]["validator1"],
            {"status": "unknown", "reasons": ["native_unavailable"], "facts": {}},
        )
        self.assertEqual(result["whole_validator_health"], "unknown")

    def test_v3_chain_observation_is_identified_and_aged(self):
        from native_chain_anchor import chain_anchor

        network = "a" * 64
        block = {
            "file_hash": "b" * 64,
            "kind": "block",
            "network_id": network,
            "point": "applied",
            "root_hash": "c" * 64,
            "scope_id": "masterchain",
            "seqno": 15,
            "shard": "9223372036854775808",
            "workchain": -1,
        }
        chain = {
            "applied": block,
            "served": None,
            "observed_unix_seconds": "1000",
            "applied_advanced_unix_seconds": "0",
        }
        self.assertEqual(
            chain_anchor(chain, network, "1970-01-01T00:16:40Z", 1001), (chain, "observed")
        )
        self.assertEqual(
            chain_anchor(chain, network, "1970-01-01T00:17:11Z", 1031), (None, "stale")
        )
        current = sample()
        current.update(
            native_version="native-core-v3", chain_anchor=chain, chain_anchor_status="observed"
        )
        self.assertEqual(sampler.facts(current, None)["chain_anchor"], chain)
        self.assertEqual(sampler.evaluate(current, None, None)[0], "unknown")
        bad = json.loads(json.dumps(chain))
        bad["applied"]["network_id"] = "d" * 64
        with self.assertRaisesRegex(ValueError, "chain_block_identity"):
            chain_anchor(bad, network, "1970-01-01T00:16:40Z", 1001)
        bad["applied"]["network_id"] = network
        bad["applied"]["root_hash"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "chain_block_identity"):
            chain_anchor(bad, network, "1970-01-01T00:16:40Z", 1001)
        bad = json.loads(json.dumps(chain))
        bad["applied_advanced_unix_seconds"] = "1001"
        with self.assertRaisesRegex(ValueError, "chain_clock"):
            chain_anchor(bad, network, "1970-01-01T00:16:40Z", 1001)

        served = {**block, "point": "served", "seqno": 14}
        full = {**chain, "served": served}
        manifest = {"network_id": network, "nodes": {node: {} for node in sampler.NODES}}

        def fetch(_node, _manifest, _validator):
            current = sample()
            current.update(
                native_version="native-core-v3", chain_anchor=full, chain_anchor_status="observed"
            )
            return current

        result = sampler.run(manifest, {}, {}, fetch=fetch)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "v3.json"
            sampler.write_private(path, result)
            self.assertLessEqual(path.stat().st_size, sampler.MAX_STATE)
        self.assertTrue(all("chain_anchor" not in item for item in result["samples"].values()))

    def test_epoch_change_and_counter_reset_do_not_fake_progress(self):
        old = sample()
        new = sample()
        old["native_generation"] = 1
        old["block_seqno"] = 100
        new["native_epoch"] = "f" * 32
        self.assertEqual(sampler.evaluate(new, old, 60_000)[0], "unknown")
        new["native_epoch"] = old["native_epoch"]
        new["actions"]["proposal"]["requested"] = 9
        self.assertEqual(sampler.evaluate(new, old, 60_000), ("unknown", ["action_counter_reset"]))

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
