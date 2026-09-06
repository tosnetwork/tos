"""Validator-weight fixture encoding checks; not consensus acceptance."""
from pathlib import Path
import sys
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "test/tostester/src"))
from pytosiq_core import Builder, HashMap
from pytosiq_core.tlb.config import ValidatorSet
from tostester.counter_committee import rewrite_committee


def fixture(weight=4):
    entries = {i: (Builder().store_uint(0x73, 8).store_uint(0x8e81278a, 32)
                   .store_bytes(bytes([i + 1]) * 32).store_uint(1, 64)
                   .store_bytes(bytes([i + 5]) * 32).end_cell()) for i in range(4)}
    return (Builder().store_uint(0x12, 8).store_uint(100, 32).store_uint(1000, 32)
            .store_uint(4, 16).store_uint(4, 16).store_uint(weight, 64)
            .store_dict(HashMap(16, map_=entries).serialize()).end_cell())


class CounterCommittee(unittest.TestCase):
    def test_reweight_preserves_members_and_lifetime(self):
        original = fixture()
        changed = rewrite_committee(original)
        self.assertNotEqual(changed.hash, original.hash)
        parsed = ValidatorSet.deserialize(changed.begin_parse())
        self.assertEqual((parsed.utime_since, parsed.utime_until, parsed.total, parsed.main), (100, 1000, 4, 4))
        self.assertEqual(parsed.total_weight, 5)
        self.assertEqual([parsed.list[i].weight for i in range(4)], [2, 1, 1, 1])
        for i, entry in parsed.list.items():
            self.assertEqual(entry.public_key.pubkey, bytes([i + 1]) * 32)
            self.assertEqual(entry.adnl_addr, bytes([i + 5]) * 32)

    def test_inconsistent_total_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "total weight mismatch"):
            rewrite_committee(fixture(5))

    def test_replacement_preserves_weights_and_other_members(self):
        key, adnl = bytes([9]) * 32, bytes([10]) * 32
        changed = rewrite_committee(fixture(), (bytes([1]) * 32, key, adnl))
        parsed = ValidatorSet.deserialize(changed.begin_parse())
        self.assertEqual(parsed.total_weight, 4)
        self.assertEqual([entry.weight for entry in parsed.list.values()], [1, 1, 1, 1])
        self.assertEqual(parsed.list[0].public_key.pubkey, key)
        self.assertEqual(parsed.list[0].adnl_addr, adnl)
        for i in range(1, 4):
            self.assertEqual(parsed.list[i].public_key.pubkey, bytes([i + 1]) * 32)
            self.assertEqual(parsed.list[i].adnl_addr, bytes([i + 5]) * 32)

    def test_replacement_must_introduce_a_new_member(self):
        for old, new in ((1, 2), (9, 10)):
            with self.subTest(old=old, new=new), self.assertRaisesRegex(ValueError, "remove one member"):
                rewrite_committee(fixture(), (bytes([old]) * 32, bytes([new]) * 32, bytes(32)))

    def test_total_overflow_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "total weight overflow"):
            rewrite_committee(fixture((1 << 64) - 1))


if __name__ == "__main__":
    unittest.main()
