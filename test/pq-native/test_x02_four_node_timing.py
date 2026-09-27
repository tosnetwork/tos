#!/usr/bin/env python3
"""Constructed chain timing controls, not live RPC/native/socket evidence."""

import unittest
from pathlib import Path

from x02_four_node import (
    ChainCapture,
    config34_pairs,
    declared_node_mapping,
    distinct_db_inodes,
    fresh_observer_epoch,
    recovery_target_met,
)
from x02_partial_sequence import candidate_policy

THRESHOLDS = candidate_policy("0" * 40)["chain_thresholds"]
PROGRESS = THRESHOLDS["progress_min_delta"]
RECOVERY = THRESHOLDS["recovery_min_delta"]


class FourNodeTimingControls(unittest.TestCase):
    def setUp(self):
        self.chain = ChainCapture.__new__(ChainCapture)
        self.chain.nodes = [{"name": f"node{i}"} for i in range(1, 5)]
        self.chain.native = {
            node["name"]: {11: ("a", "b", 101, "cursor11"), 12: ("c", "d", 102, "cursor12")}
            for node in self.chain.nodes
        }
        self.anchor = {"full_id": (-1, "8000000000000000", 10, "r10", "f10")}
        self.current = {"full_id": (-1, "8000000000000000", 12, "c", "d"), "completed_ns": 150}

    def test_two_consecutive_ids_after_install(self):
        self.assertTrue(self.chain.progress_after(self.anchor, self.current, 100, PROGRESS))

    def test_one_preinstall_native_id_cannot_count(self):
        self.chain.native["node4"][11] = ("a", "b", 99, "cursor11")
        self.assertFalse(self.chain.progress_after(self.anchor, self.current, 100, PROGRESS))

    def test_just_one_new_height_cannot_count(self):
        anchor = {"full_id": (-1, "8000000000000000", 11, "a", "b")}
        self.assertFalse(self.chain.progress_after(anchor, self.current, 100, PROGRESS))

    def test_first_recovery_sample_already_at_fixed_target(self):
        self.assertTrue(recovery_target_met(self.anchor, self.current, 200, RECOVERY))

    def test_no_moving_or_late_recovery_target(self):
        self.assertFalse(recovery_target_met(self.anchor, self.current, 149, RECOVERY))
        just_one = dict(self.current, full_id=(-1, "8000000000000000", 11, "a", "b"))
        self.assertFalse(recovery_target_met(self.anchor, just_one, 200, RECOVERY))

    def test_a_larger_delta_needs_that_many_post_install_ids(self):
        current = dict(self.current, full_id=(-1, "8000000000000000", 13, "e", "f"))
        for node in self.chain.nodes:
            self.chain.native[node["name"]][13] = ("e", "f", 103, "cursor13")
        self.assertTrue(self.chain.progress_after(self.anchor, current, 100, 3))
        self.chain.native["node2"][11] = ("a", "b", 99, "cursor11")
        self.assertFalse(self.chain.progress_after(self.anchor, current, 100, 3))
        self.assertTrue(self.chain.progress_after(self.anchor, current, 100, 2))
        self.assertFalse(recovery_target_met(self.anchor, self.current, 200, 3))
        with self.assertRaisesRegex(ValueError, "progress delta is not a positive integer"):
            self.chain.progress_after(self.anchor, current, 100, 0)

    def test_coordinator_windows_come_from_the_frozen_policy(self):
        source = (Path(__file__).resolve().parents[2] / "scripts/x02_four_node.py").read_text()
        self.assertIn("binding.get('partial_engine') == 'nft-ordinal-v1'", source)
        self.assertIn("numgen inc mod 4 == 0", source)
        self.assertIn("seen == dropped + passed", source)
        self.assertIn("recovery_target_met(anchor, current, recovery_deadline, 2)", source)

    def test_fresh_postdrain_idle_epoch(self):
        self.assertTrue(
            fresh_observer_epoch(
                {
                    "requested_epoch": 1,
                    "completed_epoch": 1,
                    "requested_ns": 200,
                    "last_packet_ns": 210,
                    "idle_started_ns": 220,
                    "idle_completed_ns": 240,
                },
                1,
            )
        )

    def test_sticky_prior_timeout_cannot_count(self):
        self.assertFalse(
            fresh_observer_epoch(
                {
                    "requested_epoch": 1,
                    "completed_epoch": 1,
                    "requested_ns": 200,
                    "last_packet_ns": 0,
                    "idle_started_ns": 100,
                    "idle_completed_ns": 240,
                },
                1,
            )
        )

    def test_packet_after_idle_or_wrong_epoch_cannot_count(self):
        state = {
            "requested_epoch": 1,
            "completed_epoch": 1,
            "requested_ns": 200,
            "last_packet_ns": 250,
            "idle_started_ns": 220,
            "idle_completed_ns": 240,
        }
        self.assertFalse(fresh_observer_epoch(state, 1))
        self.assertFalse(fresh_observer_epoch(dict(state, last_packet_ns=0), 2))

    def test_four_db_paths_require_four_distinct_real_inodes(self):
        nodes = [
            {"data_dir": f"/owned/node{i}", "db_dev": 2049, "db_ino": 100 + i} for i in range(4)
        ]
        self.assertTrue(distinct_db_inodes(nodes))
        alias = [dict(node) for node in nodes]
        alias[3]["db_ino"] = alias[0]["db_ino"]
        self.assertFalse(distinct_db_inodes(alias))
        alias[3]["db_ino"] = 0
        self.assertFalse(distinct_db_inodes(alias))
        alias[3]["db_ino"] = True
        self.assertFalse(distinct_db_inodes(alias))

    def test_declared_public_row_swap_rejects_before_fault(self):
        keys = ("controller_id_hex", "consensus_key_id_hex", "adnl_id_hex")
        rows = [
            dict(validator_index=i, node_name=f"node-{i}", **{key: f"{i:064x}" for key in keys})
            for i in range(1, 5)
        ]
        nodes = [
            dict(
                name=f"node{i}",
                validator_index=i,
                controller_id=f"{i:064x}",
                consensus_key_id=f"{i:064x}",
                adnl_id=f"{i:064x}",
            )
            for i in range(1, 5)
        ]
        self.assertEqual(declared_node_mapping(nodes, {"validators": rows}), rows)
        swapped = [dict(row) for row in rows]
        swapped[0]["controller_id_hex"], swapped[1]["controller_id_hex"] = (
            swapped[1]["controller_id_hex"],
            swapped[0]["controller_id_hex"],
        )
        with self.assertRaisesRegex(ValueError, "declared controller/key/ADNL row differs"):
            declared_node_mapping(nodes, {"validators": swapped})

    def test_raw_config34_pairs_bind_controller_and_adnl(self):
        controller, key, adnl = "a" * 64, "c" * 64, "b" * 64
        raw = (
            f"validator_pq validator_id:x{controller} algorithm_id:1 "
            f"key_id:x{key} weight:1 adnl_addr:x{adnl}"
        )
        self.assertEqual(config34_pairs(raw), [(controller, key, adnl)])
        with self.assertRaisesRegex(ValueError, "key/ADNL text record malformed"):
            config34_pairs(raw.replace(key, "not-a-pq-key"))
        with self.assertRaisesRegex(ValueError, "Config34 PQ identities alias"):
            config34_pairs(raw + " " + raw)

    @staticmethod
    def record(controller, key, adnl):
        return (
            f"validator_pq validator_id:x{controller} algorithm_id:1 "
            f"key_id:x{key} weight:1 adnl_addr:x{adnl}"
        )

    def test_raw_config34_rejects_a_key_shared_by_two_controllers(self):
        raw = (
            self.record("a" * 64, "c" * 64, "b" * 64)
            + " "
            + self.record("d" * 64, "c" * 64, "e" * 64)
        )
        with self.assertRaisesRegex(ValueError, "Config34 PQ identities alias"):
            config34_pairs(raw)

    def test_raw_config34_record_needs_exactly_one_key_and_one_adnl(self):
        good = self.record("a" * 64, "c" * 64, "b" * 64)
        for raw in (
            good.replace(" weight:1", f" key_id:x{'f' * 64} weight:1"),
            good.replace(f" adnl_addr:x{'b' * 64}", ""),
            good.replace("key_id:x", "pub_key_id:x"),
        ):
            with (
                self.subTest(raw=raw[:60]),
                self.assertRaisesRegex(ValueError, "key/ADNL text record malformed"),
            ):
                config34_pairs(raw)

    def test_raw_config34_swapped_keys_do_not_match_frozen_rows(self):
        first, second = ("a" * 64, "c" * 64, "b" * 64), ("d" * 64, "f" * 64, "e" * 64)
        expected = {controller: (key, adnl) for controller, key, adnl in (first, second)}
        swapped = (
            self.record(first[0], second[1], first[2])
            + " "
            + self.record(second[0], first[1], second[2])
        )
        mapping = {controller: (key, adnl) for controller, key, adnl in config34_pairs(swapped)}
        self.assertEqual(set(mapping), set(expected))
        self.assertNotEqual(mapping, expected)


if __name__ == "__main__":
    unittest.main()
