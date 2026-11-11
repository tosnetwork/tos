"""A stage with an incomplete block scan still reconciles deliveries and saves its results."""

import asyncio
import csv
import itertools
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "bench"), str(ROOT / "test/tostester/src")]

import run_local_bench as bench  # noqa: E402
from pqbench import chain  # noqa: E402
from pytosiq_core import Address  # noqa: E402
from tosapi import toslib_api  # noqa: E402
from toslib.toslibjson import ToslibError  # noqa: E402


class ShortDeadlineScanner(chain.Scanner):
    async def run(self, poll=0.001, lag_timeout=0.01):
        await super().run(poll=poll, lag_timeout=lag_timeout)


def shard_heads(start, head):
    def reply(seqno):
        shard = SimpleNamespace(workchain=0, shard=chain.BASECHAIN_SHARD, seqno=seqno)
        return SimpleNamespace(shards=[shard])

    return itertools.chain([reply(start)], itertools.repeat(reply(head)))


class ScannerStageTests(unittest.IsolatedAsyncioTestCase):
    async def test_saves_partial_scan_reconciles_and_runs_next_stage(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        args = SimpleNamespace(
            out=Path(tmp.name),
            build=ROOT,
            seed="test",
            sinks=1,
            duration=1,
            warmup=0,
            drain=0.03,
            transfer_value=0.001,
            max_senders=1,
            thermal_log=None,
        )
        transport = AsyncMock()
        transport.get_masterchain_info.return_value = SimpleNamespace(last=object())
        transport.get_shards.side_effect = shard_heads(100, 103)
        wallet = Address((0, b"w" * 32))
        transport.get_block_header.return_value = SimpleNamespace(gen_utime=int(time.time()))
        transport.get_block_transactions.return_value = [SimpleNamespace(account=wallet.hash_part)]
        error = (
            "LITE_SERVER_NOTREADY: cannot find block (0,8000000000000000) seqno=102: "
            "ltdb: block not found (possibly out of sync: shard_client_seqno=87 ls_seqno=88)"
        )

        reconciled = asyncio.Event()

        async def lookup(workchain, shard, seqno):
            self.assertEqual((workchain, shard), (0, chain.BASECHAIN_SHARD))
            if seqno == 102:
                # The observer cannot finish its scan before the end balance
                # is read. Waiting for it before reconciling would deadlock.
                await reconciled.wait()
                raise ToslibError(toslib_api.Error(code=500, message=error))
            return seqno

        transport.lookup_block.side_effect = lookup
        scan = chain.PacedClient(transport, "scan", qps=1_000_000)
        preparer = Mock(spec=bench.preparation.WalletPreparer)
        preparer.presign = AsyncMock(side_effect=[[b"x"] * 4, [b"x"] * 3])
        run = bench.Bench(
            args, Mock(spec=bench.Network), None, chain.ClientPool([scan]), scan, preparer
        )
        run.configs = ["validator"]
        run.load_addresses = [wallet]
        run.classes[wallet.hash_part] = bench.LOAD_CLASS
        sink = run.sinks[0].hash_part
        transfer = bench.nano(args.transfer_value)
        balances = iter((0, 2, 2, 5))

        async def read_balances(pool, addresses):
            delivered = next(balances)
            if delivered == 2:
                reconciled.set()
            return {sink: delivered * transfer}

        def send(root, build, configs, bocs, rate, senders, pace, startup):
            now = time.time()
            return now, [chain.SendRecord(i, now, now, True, None) for i in range(len(bocs))]

        with (
            patch.object(chain, "Scanner", ShortDeadlineScanner),
            patch.object(run, "_now", new=AsyncMock(return_value=int(time.time()))),
            patch.object(
                run,
                "counters",
                new=AsyncMock(side_effect=[{wallet.hash_part: n} for n in (0, 3, 3, 6)]),
            ),
            patch.object(chain, "read_balances", read_balances),
            patch.object(chain, "gas_sample", new=AsyncMock(return_value={})),
            patch.object(bench.sender, "distributed_send", send),
            patch.object(bench, "package_temperatures", return_value=None),
        ):
            first = await asyncio.wait_for(run.stage(4), timeout=5)
            transport.get_shards.side_effect = shard_heads(103, 104)
            second = await run.stage(3)

        lag = first["scanner_lag"]
        self.assertEqual(lag["first_missing_seqno"], 102)
        self.assertEqual(lag["last_scanned_seqno"], 101)
        self.assertEqual(lag["advertised_head_seqno"], 103)
        self.assertEqual(lag["error"], error)
        self.assertEqual(lag["timeout_s"], 0.01)
        self.assertIsNone(first["saturated"])
        self.assertEqual(first["messages_sent"], 4)
        self.assertEqual(first["requests_accepted"], 3)
        self.assertEqual(first["transfers_executed"], 2)
        self.assertEqual(first["requests_accepted_but_not_delivered"], 1)
        self.assertEqual(first["sink_value_gained_nanotos"], 2 * transfer)
        self.assertIsNone(second["scanner_lag"])
        self.assertEqual(second["transfers_executed"], 3)
        for rate, result, seqno in [(4, first, 101), (3, second, 104)]:
            stage_dir = args.out / f"stage-quantum-{rate}"
            self.assertEqual(json.loads((stage_dir / "result.json").read_text()), result)
            with (stage_dir / "blocks.csv").open(newline="") as csv_file:
                rows = list(csv.DictReader(csv_file))
            self.assertEqual([int(row["seqno"]) for row in rows], [seqno])
            with (stage_dir / "timeline.csv").open(newline="") as csv_file:
                timeline = list(csv.DictReader(csv_file))
            self.assertEqual(sum(int(row["messages_sent"]) for row in timeline), rate)


if __name__ == "__main__":
    unittest.main()
