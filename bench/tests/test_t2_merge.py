"""The basechain merge wait of the remote T2 run: LayoutWatch and wait_merged against a fake RPC."""

import asyncio
import sys
import unittest
from pathlib import Path
from typing import cast
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "bench"), str(ROOT / "test/tostester/src")]

from shard import t2collect  # noqa: E402
from shard.rpc import PacedRpc, RpcError  # noqa: E402


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
            count = self.current
            assert count is not None
            return {"shards": [{"workchain": 0}] * count + [{"workchain": -1}]}
        raise AssertionError(method)


def paced(fake) -> PacedRpc:
    """The fakes answer the two calls the merge wait makes; type them as the RPC."""
    return cast(PacedRpc, fake)


async def no_sleep(_):
    return None


def run(coro):
    with patch.object(t2collect.asyncio, "sleep", no_sleep):
        return asyncio.run(coro)


class WaitMergedTest(unittest.TestCase):
    def test_one_shard_after_a_split_is_a_merge(self):
        merged = run(t2collect.wait_merged(paced(FakeRpc([2, 4, 2, 1])), 5.0))
        assert merged is not None
        self.assertEqual(merged["peak_shards_seen"], 4)
        self.assertEqual(merged["mc_seqno"], 104)

    def test_a_basechain_that_never_split_is_not_a_merge(self):
        self.assertIsNone(run(t2collect.wait_merged(paced(FakeRpc([1])), 0.05)))

    def test_a_split_seen_earlier_counts(self):
        merged = run(t2collect.wait_merged(paced(FakeRpc([1])), 5.0, split_seen=True))
        self.assertIsNotNone(merged)

    def test_still_split_at_the_timeout_is_not_a_merge(self):
        self.assertIsNone(run(t2collect.wait_merged(paced(FakeRpc([2])), 0.05)))

    def test_an_unreadable_layout_is_skipped(self):
        merged = run(t2collect.wait_merged(paced(FakeRpc([2, None, 1])), 5.0))
        self.assertIsNotNone(merged)


class SlowRpc(FakeRpc):
    """Answers only after a real delay, longer than the allowance under test."""

    def __init__(self, counts, delay):
        super().__init__(counts)
        self.delay = delay

    async def call(self, method, params=None):
        await asyncio.sleep(self.delay)
        return await super().call(method, params)


class LateReadingTest(unittest.TestCase):
    def test_a_reading_that_ends_after_the_allowance_is_not_a_merge(self):
        # Real sleeps: the RPC takes 60 ms, the allowance is 10 ms.
        merged = asyncio.run(
            t2collect.wait_merged(paced(SlowRpc([1], 0.03)), 0.01, split_seen=True)
        )
        self.assertIsNone(merged)

    def test_a_zero_allowance_reads_nothing(self):
        rpc = FakeRpc([1])
        self.assertIsNone(asyncio.run(t2collect.wait_merged(paced(rpc), 0.0, split_seen=True)))
        self.assertIsNone(rpc.current)


class MergeWaitArgumentTest(unittest.TestCase):
    BASE = [
        "--remote",
        "--rpc",
        "http://127.0.0.1:1/jsonRPC",
        "--out",
        "/nonexistent/x",
        "--key-file",
        "/nonexistent/k",
        "--signer",
        "/nonexistent/s",
        "--auth-tag",
        "00" * 32,
        "--accounts",
        "2",
        "--chains",
        "1",
        "--forks",
        "0",
        "--hops",
        "1",
        "--account-funding",
        "0.01",
        "--load-funding",
        "0.01",
        "--max-cost",
        "1",
        "--max-messages",
        "10",
    ]

    def test_non_finite_or_negative_merge_waits_are_refused(self):
        from shard import remote

        for value in ("nan", "inf", "-1"):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                remote.parse_args(self.BASE + ["--merge-wait", value])

    def test_a_finite_merge_wait_is_accepted(self):
        from shard import remote

        self.assertEqual(remote.parse_args(self.BASE + ["--merge-wait", "900"]).merge_wait, 900.0)


class LayoutWatchTest(unittest.TestCase):
    def test_records_each_layout_change_once(self):
        async def go():
            watch = t2collect.LayoutWatch(paced(FakeRpc([1, 1, 2, 2, 4, 2, 1])), poll=0.001)
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
