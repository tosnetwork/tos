"""Run with the tostester Python environment from the repository root."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "test/tostester/src"))

from pytosiq_core import Cell
from pytosiq_core.tlb.block import ShardStateUnsplit
from tostester.install import Install
from tostester.key import Key
from tostester.zerostate import NetworkConfig, create_zerostate


class CounterGenesis(unittest.TestCase):
    def test_checkpoint_profile_admission_precedes_generation(self):
        invalid = [NetworkConfig(counter_checkpoint_genesis_time=1788656400),
                   NetworkConfig(counter_workchain=True, validator_economics_profile=True,
                                 counter_checkpoint_genesis_time=1788656400)]
        invalid += [NetworkConfig(counter_workchain=True, global_id=-23903, global_version=15,
                                  counter_checkpoint_genesis_time=value)
                    for value in (True, 0, -1, 1.5, "1788656400", (1 << 32) - 3 * (1 << 17))]
        for config in invalid:
            with self.subTest(config=config), patch("tostester.zerostate.run_fift") as run:
                with self.assertRaisesRegex(ValueError, "Counter checkpoint genesis"):
                    create_zerostate(Install(REPO / "build", REPO), REPO / "build", config, [])
                run.assert_not_called()

    def test_checkpoint_genesis_timestamp_and_committee_lifetime(self):
        # A key block at current_time must cross the unchanged native bucket.
        current_time = 1788656400
        genesis_time = current_time // (1 << 17) * (1 << 17) - 1
        config = NetworkConfig(counter_workchain=True, global_id=-23903, global_version=15,
                               counter_checkpoint_genesis_time=genesis_time)
        with tempfile.TemporaryDirectory(prefix="counter-checkpoint-genesis-", dir=REPO / "build") as directory:
            with patch.dict(os.environ, {"SOURCE_DATE_EPOCH": str(current_time)}):
                state = create_zerostate(Install(REPO / "build", REPO), Path(directory), config, [Key()])
                self.assertEqual(os.environ["SOURCE_DATE_EPOCH"], str(current_time))
            parsed = [ShardStateUnsplit.deserialize(Cell.one_from_boc(shard.file.read_bytes()).begin_parse())
                      for shard in (state.masterchain, state.shardchain, *state.extra_shards)]
            self.assertEqual([shard.gen_utime for shard in parsed], [genesis_time] * 3)
            self.assertNotEqual(parsed[0].gen_utime // (1 << 17), current_time // (1 << 17))
            committee = parsed[0].custom.config.config[34]
            self.assertEqual(committee.load_uint(8), 0x12)
            self.assertEqual(committee.load_uint(32), genesis_time)
            valid_until = committee.load_uint(32)
            self.assertEqual(valid_until, genesis_time + 3 * (1 << 17))
            self.assertGreater(valid_until, current_time + (1 << 17))

    def test_payload_requires_counter_profile_before_generation(self):
        with patch("tostester.zerostate.run_fift") as run:
            with self.assertRaisesRegex(ValueError, "payload requires"):
                create_zerostate(Install(REPO / "build", REPO), REPO / "build",
                                 NetworkConfig(counter_payload=True), [])
            run.assert_not_called()

    def test_requires_isolated_activated_unsplit_profile(self):
        for changes in ({"global_id": 3}, {"global_version": 14}, {"split": 1}, {"monitor_min_split": 1}):
            config = NetworkConfig(counter_workchain=True, global_id=-23903, global_version=15)
            for name, value in changes.items():
                setattr(config, name, value)
            with self.subTest(changes=changes), patch(
                "tostester.zerostate.run_fift", side_effect=AssertionError("generator invoked before admission")
            ) as run:
                with self.assertRaisesRegex(ValueError, "Counter network requires"):
                    create_zerostate(Install(REPO / "build", REPO), REPO / "build", config, [])
                run.assert_not_called()

    def test_real_genesis_contains_counter_only_when_enabled(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory(prefix="counter-genesis-", dir=REPO / "build") as directory:
                config = NetworkConfig(counter_workchain=enabled, global_id=-23903, global_version=15)
                with patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "1788656400"}):
                    state = create_zerostate(Install(REPO / "build", REPO), Path(directory), config, [Key()])
                parsed = ShardStateUnsplit.deserialize(Cell.one_from_boc(state.masterchain.file.read_bytes()).begin_parse())
                self.assertEqual(parsed.gen_utime, 1788656400)
                params = parsed.custom.config.config
                committee = params[34]
                self.assertEqual(committee.load_uint(8), 0x12)
                self.assertEqual(committee.load_uint(32), 1788656400)
                self.assertEqual(committee.load_uint(32), 1788656400 + 3600)
                workchains = params[12].load_dict(32)
                self.assertEqual(set(workchains), {0, 2} if enabled else {0})
                version = params[8]
                self.assertEqual(version.load_uint(8), 0xc4)
                self.assertEqual(version.load_uint(32), 15)
                self.assertEqual(bool(version.load_uint(64) & 1024), enabled)
                self.assertEqual(len(state.extra_shards), int(enabled))
                self.assertEqual(84 in params, enabled)
                if enabled:
                    extra = state.extra_shards[0]
                    descriptor = workchains[2]
                    self.assertEqual(descriptor.load_uint(8), 0xa7)
                    descriptor.load_uint(32)  # enabled_since
                    self.assertEqual(descriptor.load_uint(24), 0)  # split depths
                    self.assertEqual(descriptor.load_uint(16), 0xe000)
                    self.assertEqual(descriptor.load_bytes(32), extra.root_hash)
                    self.assertEqual(descriptor.load_bytes(32), extra.file_hash)
                    self.assertEqual(descriptor.load_uint(32), 0)  # version
                    self.assertEqual(descriptor.load_uint(4), 1)  # basic format
                    self.assertEqual(descriptor.load_int(32), 0x434e5431)
                    root = Cell.one_from_boc(extra.file.read_bytes())
                    self.assertEqual(root.hash, extra.root_hash)
                    shard = ShardStateUnsplit.deserialize(root.begin_parse())
                    self.assertEqual(shard.global_id, -23903)
                    self.assertEqual(shard.shard_id.workchain_id, 2)


if __name__ == "__main__":
    unittest.main()
