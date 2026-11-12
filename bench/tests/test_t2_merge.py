"""The basechain merge wait of the remote T2 run: LayoutWatch and wait_merged against a fake RPC."""

import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "bench"), str(ROOT / "test/tostester/src")]

from shard import t2collect  # noqa: E402
from shard.rpc import RpcError  # noqa: E402


class FakeRpc:
    """Answers getMasterchainInfo / getShards from a list of shard counts, one per reading."""

    def __init__(self, counts):
        self.counts = list(counts)
        self.seqno = 100
        self.current = None

    async def call(self, method, params=None):
        if method == "getMasterchainInfo":
            self.current = self.counts.pop(0) if len(self.counts) > 1 else self.counts[0]
            self.seqno += 1
            if self.current is None:
                raise RpcError("getMasterchainInfo", 500, "unavailable")
            return {"last": {"seqno": self.seqno}}
        if method == "getShards":
            assert params == {"seqno": self.seqno}
            return {"shards": [{"workchain": 0}] * self.current + [{"workchain": -1}]}
        raise AssertionError(method)


async def no_sleep(_):
    return None


def run(coro):
    with patch.object(t2collect.asyncio, "sleep", no_sleep):
        return asyncio.run(coro)


class WaitMergedTest(unittest.TestCase):
    def test_one_shard_after_a_split_is_a_merge(self):
        merged = run(t2collect.wait_merged(FakeRpc([2, 4, 2, 1]), 5.0))
        self.assertIsNotNone(merged)
        self.assertEqual(merged["peak_shards_seen"], 4)
        self.assertEqual(merged["mc_seqno"], 104)

    def test_a_basechain_that_never_split_is_not_a_merge(self):
        self.assertIsNone(run(t2collect.wait_merged(FakeRpc([1]), 0.05)))

    def test_a_split_seen_earlier_counts(self):
        merged = run(t2collect.wait_merged(FakeRpc([1]), 5.0, split_seen=True))
        self.assertIsNotNone(merged)

    def test_still_split_at_the_timeout_is_not_a_merge(self):
        self.assertIsNone(run(t2collect.wait_merged(FakeRpc([2]), 0.05)))

    def test_an_unreadable_layout_is_skipped(self):
        merged = run(t2collect.wait_merged(FakeRpc([2, None, 1]), 5.0))
        self.assertIsNotNone(merged)


class LayoutWatchTest(unittest.TestCase):
    def test_records_each_layout_change_once(self):
        async def go():
            watch = t2collect.LayoutWatch(FakeRpc([1, 1, 2, 2, 4, 2, 1]), poll=0.001)
            task = asyncio.create_task(watch.run())
            await asyncio.sleep(0.05)
            watch.stop()
            await task
            return watch

        watch = asyncio.run(go())
        self.assertEqual([r["shards"] for r in watch.rows], [1, 2, 4, 2, 1])
        self.assertEqual(watch.peak, 4)


if __name__ == "__main__":
    unittest.main()
