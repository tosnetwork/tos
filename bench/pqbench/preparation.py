"""CPU preparation for the local bench. The asyncio parent owns every native signer."""

import asyncio
import multiprocessing
from contextlib import asynccontextmanager
from dataclasses import dataclass
from itertools import batched
from multiprocessing.connection import Connection

from pytosiq_core import Cell

from .signer import BATCH_TIMEOUT, BatchSigner, SignerProtocol
from .workload import MAX_ACTIONS, QSP_PRIMARY_CONTEXT, QuantumWallet, quantum_seed, sinks


@dataclass(frozen=True)
class WalletConfig:
    code: Cell
    net_id: int
    auth_tag: bytes
    seed: bytes
    sink_count: int


class _WorkerSigner(SignerProtocol):
    def __init__(self, channel: Connection):
        self.channel = channel

    def _run(self, args: list[str], lines: list[str], size: int) -> list[bytes]:
        self.channel.send(("signer", args, ("\n".join(lines) + "\n").encode()))
        return self._decode(self.channel.recv().decode(), len(lines), size)


class WalletWork:
    """Runs only in the computation process, except in wire-compatibility tests."""

    def __init__(self, signer: SignerProtocol, config: WalletConfig):
        self.signer = signer
        self.config = config
        self.destinations = sinks(config.sink_count, config.seed)
        self.deploy_queues: dict[int, list[QuantumWallet]] = {}
        self.transfer_wallets: dict[int, tuple[QuantumWallet, int]] = {}

    def derive(self, tag, indices):
        c = self.config
        seeds = [quantum_seed(c.seed, tag, i) for i in indices]
        keys = self.signer.public_keys(seeds)
        return [
            QuantumWallet.derive(c.code, c.net_id, c.auth_tag, c.seed, tag, i, key, seed)
            for i, key, seed in zip(indices, keys, seeds, strict=True)
        ]

    def addresses(self, indices):
        return [w.address for w in self.derive("load", indices)]

    def start_deployment_chunk(self, wallet_id, indices):
        # One partially consumed chunk per deployer. Release it as soon as its last
        # transaction is built. The next chunk arrives only after chain confirmation.
        self.deploy_queues[wallet_id] = self.derive("load", indices)

    def deployment(self, deployer, nonce, funding, deadline, budget):
        queue = self.deploy_queues[deployer.wallet_id]
        take = min(MAX_ACTIONS, len(queue))
        while True:
            actions = [w.deployment_message(deployer.address, funding) for w in queue[:take]]
            request = deployer.request(nonce, actions, deadline)
            size = len(deployer.external(request, bytes(2420)).serialize().to_boc())
            if size <= budget or take == 1:
                break
            take = max(1, take * budget // size - 1)
        [signature] = self.signer.sign([(deployer.pq_seed, request.hash)], QSP_PRIMARY_CONTEXT)
        boc = deployer.external(request, signature).serialize().to_boc()
        del queue[:take]
        if not queue:
            del self.deploy_queues[deployer.wallet_id]
        return boc, bool(queue)

    def start_transfer_chunk(self, indices, start):
        if self.transfer_wallets:
            raise RuntimeError("previous transfer wallet chunk is incomplete")
        for i, wallet in zip(indices, self.derive("load", indices), strict=True):
            self.transfer_wallets[i] = (wallet, start[wallet.address.hash_part])

    def transfers(self, positions, wallet_count, count, transfer, deadline):
        jobs = []
        for k in positions:
            i = k % wallet_count
            wallet, nonce = self.transfer_wallets[i]
            request = wallet.request(
                nonce + k // wallet_count,
                [wallet.transfer(self.destinations[k % len(self.destinations)], transfer)],
                deadline,
            )
            jobs.append((wallet, request))
            if k + wallet_count >= count:
                del self.transfer_wallets[i]
        signatures = self.signer.sign([(w.pq_seed, r.hash) for w, r in jobs], QSP_PRIMARY_CONTEXT)
        return [
            w.external(r, sig).serialize().to_boc()
            for (w, r), sig in zip(jobs, signatures, strict=True)
        ]


def transfer_plan(wallet_count: int, count: int, batch_size: int):
    """Derive each used wallet once and sign its scheduled transfers in bounded batches."""
    used = min(wallet_count, count)
    for first in range(0, used, batch_size):
        wallets = range(first, min(used, first + batch_size))
        positions = (k for i in wallets for k in range(i, count, wallet_count))
        yield wallets, batched(positions, batch_size)


def _worker(channel: Connection, config: WalletConfig):
    with channel:
        work = WalletWork(_WorkerSigner(channel), config)
        while (job := channel.recv()) is not None:
            method, args = job
            try:
                channel.send(("result", method(work, *args)))
            except Exception as exc:
                channel.send(("error", f"{type(exc).__name__}: {exc}"))
                return


class WalletPreparer:
    def __init__(self, signer: BatchSigner, channel):
        self.signer = signer
        self.channel = channel
        self.lock = asyncio.Lock()
        self.broken = False

    async def presign(self, addresses, start, count, transfer, deadline, batch_size) -> list[bytes]:
        wallet_count = len(addresses)
        bocs = [b""] * count
        for wallets, batches in transfer_plan(wallet_count, count, batch_size):
            nonces = {addresses[i].hash_part: start[addresses[i].hash_part] for i in wallets}
            await self.run(WalletWork.start_transfer_chunk, wallets, nonces)
            for positions in batches:
                signed = await self.run(
                    WalletWork.transfers, positions, wallet_count, count, transfer, deadline
                )
                for k, boc in zip(positions, signed, strict=True):
                    bocs[k] = boc
        return bocs

    async def run(self, method, *args):
        # A single in-flight request also caps total native parallelism at --signer-threads
        # when all deployers are ready to prepare transactions simultaneously.
        async with self.lock:
            if self.broken:
                raise RuntimeError("wallet preparation interrupted")
            self.broken = True
            await asyncio.wait_for(
                asyncio.to_thread(self.channel.send, (method, args)), BATCH_TIMEOUT
            )
            while True:
                event, *data = await asyncio.wait_for(
                    asyncio.to_thread(self.channel.recv), BATCH_TIMEOUT
                )
                if event == "result":
                    self.broken = False
                    return data[0]
                if event == "error":
                    raise RuntimeError("wallet preparation failed: " + data[0])
                if event != "signer":
                    raise RuntimeError(f"unknown wallet preparation event {event!r}")
                output = await self.signer.run_batch(*data)
                await asyncio.wait_for(asyncio.to_thread(self.channel.send, output), BATCH_TIMEOUT)


@asynccontextmanager
async def wallet_preparer(signer: BatchSigner, config: WalletConfig):
    ctx = multiprocessing.get_context("spawn")
    channel, peer = ctx.Pipe()
    worker = ctx.Process(target=_worker, args=(peer, config), name="bench-preparation")
    try:
        worker.start()
    finally:
        peer.close()
        if worker.pid is None:
            channel.close()
    try:
        preparer = WalletPreparer(signer, channel)
        yield preparer
        if not preparer.broken:
            await asyncio.wait_for(asyncio.to_thread(channel.send, None), BATCH_TIMEOUT)
            await asyncio.to_thread(worker.join, 5)
            if worker.exitcode != 0:
                raise RuntimeError(f"wallet preparation worker exit status: {worker.exitcode}")
    finally:
        # This child only computes. The parent owns and reaps the native signer.
        # Both stay in the benchmark's original thermal-guard process group.
        try:
            if worker.is_alive():
                worker.terminate()
                try:
                    await asyncio.to_thread(worker.join, 1)
                finally:
                    if worker.is_alive():
                        worker.kill()
                        await asyncio.to_thread(worker.join, 5)
            if worker.is_alive():
                raise RuntimeError("wallet preparation worker failed to exit")
            worker.close()
        finally:
            channel.close()
