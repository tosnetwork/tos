"""Stage preparation ordering, responsiveness and child lifetimes. Optionally use --signer PATH."""

import argparse
import asyncio
import multiprocessing
import os
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "bench"), str(ROOT / "test/tostester/src")]
from pqbench import preparation, signer  # noqa: E402
from pqbench.workload import QSP_PRIMARY_CONTEXT, sinks  # noqa: E402
from pytosiq_core import Cell  # noqa: E402

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--signer", type=Path)
ARGS, REST = parser.parse_known_args()


def wait_on_cpu_worker(_work, marker):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    marker.write_text(str(os.getpid()))
    time.sleep(12)


class PreparationTests(unittest.IsolatedAsyncioTestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.helper = Path(self.tmp.name) / "signer"
        self.marker = Path(self.tmp.name) / "active"
        self.config = preparation.WalletConfig(Cell.empty(), 1, b"a" * 32, b"s" * 32, 3)

    def executable(self, script: str):
        self.helper.write_text(f"#!{sys.executable}\n" + script)
        self.helper.chmod(0o700)
        return signer.BatchSigner(self.helper, 1)

    def working_signer(self):
        return (
            signer.BatchSigner(ARGS.signer, 2)
            if ARGS.signer
            else self.executable(
                "import hashlib, sys\n"
                "size = 1312 if sys.argv[1] == 'public' else 2420\n"
                "for row in sys.stdin.buffer: print(hashlib.shake_256(row).hexdigest(size))\n"
            )
        )

    async def test_presigned_messages_match_in_send_order(self):
        tool = self.working_signer()
        work = preparation.WalletWork(tool, self.config)
        wallets = work.derive("load", range(2))
        dest = sinks(self.config.sink_count, self.config.seed)
        start = {w.address.hash_part: 5 + i * 7 for i, w in enumerate(wallets)}
        expected = []
        for k in range(7):
            w = wallets[k % len(wallets)]
            req = w.request(
                start[w.address.hash_part] + k // len(wallets),
                [w.transfer(dest[k % len(dest)], 11)],
                165000,
            )
            [sig] = tool.sign([(w.pq_seed, req.hash)], QSP_PRIMARY_CONTEXT)
            expected.append(w.external(req, sig).serialize().to_boc())
        async with preparation.wallet_preparer(tool, self.config) as worker:
            result = []
            for first in range(0, 7, 3):
                result.extend(
                    await worker.run(
                        preparation.WalletWork.transfers,
                        first,
                        min(7, first + 3),
                        2,
                        start,
                        11,
                        165000,
                    )
                )
        self.assertEqual(result, expected)

    async def test_two_deployers_keep_their_own_wallets_and_nonces(self):
        tool = self.working_signer()
        work = preparation.WalletWork(tool, self.config)
        reference = work.derive("load", range(4))
        async with preparation.wallet_preparer(tool, self.config) as worker:
            addresses = await worker.run(preparation.WalletWork.addresses, range(4))
            self.assertEqual(addresses, [w.address for w in reference])
            deployers = await worker.run(preparation.WalletWork.derive, "deployer", range(2))

            async def share(i, deployer):
                await worker.run(
                    preparation.WalletWork.start_deployment_chunk, deployer.wallet_id, [i, i + 2]
                )
                for seq in range(2):
                    # Force a single action per transaction, keeping the other wallet for later.
                    boc, more = await worker.run(
                        preparation.WalletWork.deployment, deployer, seq + 10, 7, 15000, 1
                    )
                    self.assertEqual(more, seq == 0)
                    w = reference[i + seq * 2]
                    req = deployer.request(
                        seq + 10, [w.deployment_message(deployer.address, 7)], 15000
                    )
                    [sig] = tool.sign([(deployer.pq_seed, req.hash)], QSP_PRIMARY_CONTEXT)
                    self.assertEqual(boc, deployer.external(req, sig).serialize().to_boc())

            await asyncio.gather(*(share(i, d) for i, d in enumerate(deployers)))

    async def prepare_addresses(self, tool):
        async with preparation.wallet_preparer(tool, self.config) as worker:
            return await worker.run(preparation.WalletWork.addresses, range(2))

    def waiting_signer(self):
        return self.executable(
            "import os, signal, time\n"
            "from pathlib import Path\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            f"Path({str(self.marker)!r}).write_text(str(os.getpid()))\n"
            "time.sleep(12)\n"
        )

    def assert_reaped(self, pid: int):
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        self.assertFalse(
            [p for p in multiprocessing.active_children() if p.name == "bench-preparation"]
        )

    async def test_observer_runs_while_signing_and_cancel_reaps_both_children(self):
        task = asyncio.create_task(self.prepare_addresses(self.waiting_signer()))
        try:
            async with asyncio.timeout(5):
                while not self.marker.exists():
                    await asyncio.sleep(0.01)
            pid = int(self.marker.read_text())
            (worker,) = [
                p for p in multiprocessing.active_children() if p.name == "bench-preparation"
            ]
            assert worker.pid is not None
            self.assertEqual(os.getpgid(pid), os.getpgrp())
            self.assertEqual(os.getpgid(worker.pid), os.getpgrp())
            self.assertFalse(task.done())
        finally:
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 5)
        self.assert_reaped(pid)

    async def test_computation_timeout_reaps_worker(self):
        with patch.object(preparation, "BATCH_TIMEOUT", 1):
            with self.assertRaises(TimeoutError):
                async with preparation.wallet_preparer(
                    self.working_signer(), self.config
                ) as worker:
                    await worker.run(wait_on_cpu_worker, self.marker)
        self.assert_reaped(int(self.marker.read_text()))

    async def test_signer_timeout_reaps_both_children(self):
        with patch.object(signer, "BATCH_TIMEOUT", 1):
            with self.assertRaises(TimeoutError):
                await self.prepare_addresses(self.waiting_signer())
        self.assert_reaped(int(self.marker.read_text()))


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0], *REST])
