#!/usr/bin/env python3
"""Constructed chain timing controls, not live RPC/native/socket evidence."""
import unittest

from x02_four_node import ChainCapture, recovery_target_met, fresh_observer_epoch


class FourNodeTimingControls(unittest.TestCase):
    def setUp(self):
        self.chain = ChainCapture.__new__(ChainCapture)
        self.chain.nodes = [{'name': f'node{i}'} for i in range(1, 5)]
        self.chain.native = {node['name']: {11: ('a', 'b', 101, 'cursor11'),
                                          12: ('c', 'd', 102, 'cursor12')}
                             for node in self.chain.nodes}
        self.anchor = {'full_id': (-1, '8000000000000000', 10, 'r10', 'f10')}
        self.current = {'full_id': (-1, '8000000000000000', 12, 'c', 'd'),
                        'completed_ns': 150}

    def test_two_consecutive_ids_after_install(self):
        self.assertTrue(self.chain.progress_after(self.anchor, self.current, 100))

    def test_one_preinstall_native_id_cannot_count(self):
        self.chain.native['node4'][11] = ('a', 'b', 99, 'cursor11')
        self.assertFalse(self.chain.progress_after(self.anchor, self.current, 100))

    def test_just_one_new_height_cannot_count(self):
        anchor = {'full_id': (-1, '8000000000000000', 11, 'a', 'b')}
        self.assertFalse(self.chain.progress_after(anchor, self.current, 100))

    def test_first_recovery_sample_already_at_fixed_target(self):
        self.assertTrue(recovery_target_met(self.anchor, self.current, 200))

    def test_no_moving_or_late_recovery_target(self):
        self.assertFalse(recovery_target_met(self.anchor, self.current, 149))
        just_one = dict(self.current, full_id=(-1, '8000000000000000', 11, 'a', 'b'))
        self.assertFalse(recovery_target_met(self.anchor, just_one, 200))

    def test_fresh_postdrain_idle_epoch(self):
        self.assertTrue(fresh_observer_epoch({'requested_epoch': 1, 'completed_epoch': 1,
            'requested_ns': 200, 'last_packet_ns': 210, 'idle_started_ns': 220,
            'idle_completed_ns': 240}, 1))

    def test_sticky_prior_timeout_cannot_count(self):
        self.assertFalse(fresh_observer_epoch({'requested_epoch': 1, 'completed_epoch': 1,
            'requested_ns': 200, 'last_packet_ns': 0, 'idle_started_ns': 100,
            'idle_completed_ns': 240}, 1))

    def test_packet_after_idle_or_wrong_epoch_cannot_count(self):
        state = {'requested_epoch': 1, 'completed_epoch': 1, 'requested_ns': 200,
                 'last_packet_ns': 250, 'idle_started_ns': 220, 'idle_completed_ns': 240}
        self.assertFalse(fresh_observer_epoch(state, 1))
        self.assertFalse(fresh_observer_epoch(dict(state, last_packet_ns=0), 2))


if __name__ == '__main__':
    unittest.main()
