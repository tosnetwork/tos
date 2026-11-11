"""Block scanner coverage when a liteserver advertises blocks before it can serve them."""

import asyncio
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import create_autospec, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "bench"), str(ROOT / "test/tostester/src")]

from pqbench import chain  # noqa: E402
from tosapi import toslib_api  # noqa: E402
from toslib.toslibjson import ToslibError  # noqa: E402

ACCOUNT = bytes(range(32))
NOT_FOUND = (
    "LITE_SERVER_NOTREADY: cannot find block (0,8000000000000000) seqno=12: ltdb: block not found"
)
# These two diagnostic heights are masterchain heights, independent of shard seqno 12.
LAG = NOT_FOUND + " (possibly out of sync: shard_client_seqno=200 ls_seqno=201)"


def rpc_error(message):
    return ToslibError(toslib_api.Error(code=500, message=message))


class ScanNode:
    """Advertises shard blocks 11 through 13. Individual block reads are scriptable."""

    def __init__(self, before_read):
        self.before_read = before_read
        self.calls = []
        self.completed_at = {}
        self.advertised_head = 13
        self.head_reads = []
        client = create_autospec(chain.PacedClient, instance=True)
        client.call.side_effect = self.call
        self.scanner = chain.Scanner(client, {ACCOUNT: "wallet"})
        self.scanner.last_seqno = 10
        self.scanner.track.add(ACCOUNT)

    async def call(self, method, *args, cost=1):
        if method == "get_masterchain_info":
            return SimpleNamespace(last=SimpleNamespace(seqno=201))
        if method == "get_shards":
            self.head_reads.append(self.advertised_head)
            head = SimpleNamespace(
                workchain=0, shard=chain.BASECHAIN_SHARD, seqno=self.advertised_head
            )
            return SimpleNamespace(shards=[head])
        seqno = args[2] if method == "lookup_block" else args[0].seqno
        self.calls.append((method, seqno))
        await self.before_read(method, seqno)
        if method == "lookup_block":
            return SimpleNamespace(seqno=seqno)
        if method == "get_block_header":
            return SimpleNamespace(gen_utime=1000 + seqno)
        if method == "get_block_transactions":
            self.completed_at[seqno] = time.time()
            if seqno == 13:
                self.scanner.stop()
            return [SimpleNamespace(account=ACCOUNT)]
        raise AssertionError(method)


class ScannerTests(unittest.IsolatedAsyncioTestCase):
    async def test_retry_at_each_block_read_resumes_in_order_without_double_counting(self):
        for failing in ("lookup_block", "get_block_header", "get_block_transactions"):
            with self.subTest(failing=failing):
                attempts = 0
                first_retry_wait = []

                async def read(method, seqno):
                    nonlocal attempts
                    if (method, seqno) == (failing, 12):
                        attempts += 1
                        if attempts == 1:
                            asyncio.get_running_loop().call_soon(
                                lambda: first_retry_wait.append(time.time())
                            )
                        if attempts <= 2:
                            raise rpc_error(LAG)

                node = ScanNode(read)
                scanner = node.scanner
                await asyncio.wait_for(scanner.run(poll=0.001), timeout=3)
                self.assertIsNone(scanner.lag)
                self.assertEqual(scanner.last_seqno, 13)
                self.assertEqual(attempts, 3)
                self.assertEqual([row.seqno for row in scanner.rows], [11, 12, 13])
                for row in scanner.rows:
                    self.assertEqual((row.total, row.by_class), (1, {"wallet": 1}))
                    self.assertGreaterEqual(row.observed, node.completed_at[row.seqno])
                before, recovered, after = scanner.rows
                self.assertIsNone(before.lag_started_at)
                self.assertIsNone(after.lag_started_at)
                assert recovered.lag_started_at is not None
                self.assertGreaterEqual(recovered.lag_started_at, before.observed)
                self.assertLessEqual(recovered.lag_started_at, first_retry_wait[0])
                self.assertEqual(
                    scanner.first_seen[ACCOUNT], [row.observed for row in scanner.rows]
                )

    async def test_persistent_lag_preserves_contiguous_prefix_with_or_without_stop(self):
        for stop_during_lag in (False, True):
            with self.subTest(stop_during_lag=stop_during_lag):

                async def read(method, seqno):
                    if (method, seqno) == ("lookup_block", 12):
                        if stop_during_lag:
                            node.advertised_head = 15
                            node.scanner.stop()
                        raise rpc_error(LAG)

                node = ScanNode(read)
                scanner = node.scanner
                await asyncio.wait_for(scanner.run(poll=0.001, lag_timeout=0.05), timeout=1)
                self.assertEqual([row.seqno for row in scanner.rows], [11])
                self.assertEqual(scanner.first_seen[ACCOUNT], [scanner.rows[0].observed])
                self.assertEqual(scanner.last_seqno, 11)
                self.assertFalse(any(seqno == 13 for _, seqno in node.calls))
                assert scanner.lag is not None
                self.assertEqual(scanner.lag["first_missing_seqno"], 12)
                self.assertEqual(scanner.lag["last_scanned_seqno"], 11)
                self.assertEqual(
                    scanner.lag["advertised_head_seqno"], 15 if stop_during_lag else 13
                )
                self.assertEqual(scanner.lag["timeout_s"], 0.05)
                self.assertEqual(scanner.lag["error"], LAG)

    async def test_lag_deadline_bounds_an_unresponsive_retry(self):
        attempts = 0

        async def read(method, seqno):
            nonlocal attempts
            if (method, seqno) == ("lookup_block", 12):
                attempts += 1
                if attempts == 1:
                    raise rpc_error(LAG)
                await asyncio.Event().wait()

        scanner = ScanNode(read).scanner
        await asyncio.wait_for(scanner.run(poll=0.001, lag_timeout=0.5), timeout=2)
        self.assertEqual(attempts, 2)
        assert scanner.lag is not None
        self.assertEqual(scanner.lag["first_missing_seqno"], 12)
        self.assertEqual(scanner.last_seqno, 11)

    async def test_healthy_reads_do_not_consume_a_lag_budget(self):
        async def read(method, seqno):
            if (method, seqno) == ("lookup_block", 12):
                await asyncio.sleep(0.02)

        scanner = ScanNode(read).scanner
        await asyncio.wait_for(scanner.run(poll=0.001, lag_timeout=0.001), timeout=1)
        self.assertEqual(scanner.last_seqno, 13)
        self.assertIsNone(scanner.lag)

    async def test_new_lag_after_stop_shares_the_original_grace_period(self):
        async def read(method, seqno):
            if method != "lookup_block" or node.calls.count((method, seqno)) != 1:
                return
            if seqno == 11:
                node.scanner.stop()
                raise rpc_error(LAG.replace("seqno=12:", "seqno=11:"))
            if seqno == 12:
                # A healthy first read may take time. By the time this node signals lag
                # again, the stage has already waited out its original grace period.
                await asyncio.sleep(0.15)
                raise rpc_error(LAG)

        node = ScanNode(read)
        await asyncio.wait_for(node.scanner.run(poll=0.001, lag_timeout=0.1), timeout=2)
        self.assertEqual([row.seqno for row in node.scanner.rows], [11])
        self.assertEqual(node.calls.count(("lookup_block", 12)), 1)
        assert node.scanner.lag is not None
        self.assertEqual(node.scanner.lag["first_missing_seqno"], 12)

    async def test_stop_after_lag_scans_to_one_fresh_fixed_head(self):
        async def read(method, seqno):
            if method == "lookup_block" and seqno == 12 and node.calls.count((method, seqno)) == 1:
                node.scanner.stop()
                # While the original batch is outstanding, the node learns two more blocks.
                node.advertised_head = 15
                raise rpc_error(LAG)
            if method == "lookup_block" and seqno == 13:
                # The stop snapshot must already be fixed when the original batch finishes.
                node.advertised_head = 16

        node = ScanNode(read)
        await asyncio.wait_for(node.scanner.run(poll=0.001, lag_timeout=0.1), timeout=1)
        self.assertEqual(node.head_reads, [13, 15])
        self.assertEqual([row.seqno for row in node.scanner.rows], [11, 12, 13, 14, 15])
        self.assertEqual(node.scanner.last_seqno, 15)
        self.assertIsNone(node.scanner.lag)

    async def test_unrelated_errors_propagate_on_the_first_attempt(self):
        for error in (
            rpc_error(NOT_FOUND),  # Missing historical block without a shard lag indication.
            rpc_error("LITE_SERVER_NOTREADY: external message source rate limit exceeded"),
            rpc_error(LAG.replace("LITE_SERVER_NOTREADY", "LITE_SERVER_UNKNOWN")),
            RuntimeError(LAG),
            TimeoutError("unrelated transport timeout"),
        ):
            with self.subTest(error=error):

                async def read(method, seqno):
                    if (method, seqno) == ("lookup_block", 12):
                        raise error

                node = ScanNode(read)
                with self.assertRaises(type(error)) as raised:
                    await asyncio.wait_for(node.scanner.run(poll=0.001), timeout=1)
                self.assertIs(raised.exception, error)
                self.assertEqual(node.calls.count(("lookup_block", 12)), 1)

    async def test_final_head_rpc_error_survives_concurrent_block_timeout(self):
        async def read(method, seqno):
            node.scanner.stop()
            raise rpc_error(LAG)

        node = ScanNode(read)
        error = rpc_error("LITE_SERVER_UNKNOWN: cannot read masterchain info")
        with patch.object(
            node.scanner, "_shard_head", side_effect=[SimpleNamespace(seqno=13), error]
        ):
            with self.assertRaises(ToslibError) as raised:
                await asyncio.wait_for(node.scanner.run(poll=0.001, lag_timeout=0.05), timeout=1)
        self.assertIs(raised.exception, error)


if __name__ == "__main__":
    unittest.main()
