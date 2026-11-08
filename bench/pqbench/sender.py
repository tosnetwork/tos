"""Sender worker processes: many liteserver client identities without one process's thread cap.

A toslib client runs its own threads and a process can host at most 256, so a
bench that needs hundreds of client identities (each admitted 30 externals per
10 s by a node) spreads them over worker processes. Each worker opens its
connections, sends its pre-serialized messages at their absolute scheduled
times, never retries a send, and returns one record per message.
"""

import asyncio
import multiprocessing
import sys
import time
from pathlib import Path

PER_WORKER_CONNECTIONS = 100


class _Config:
    """The liteserver config as the JSON toslib consumes (the TL object does not pickle)."""

    def __init__(self, text: str):
        self._text = text

    def to_json(self) -> str:
        return self._text


def _worker(args) -> list[tuple[int, float, float, bool, str | None]]:
    root, build, configs, connections, rate, items = args
    sys.path[:0] = [str(Path(root) / "bench"), str(Path(root) / "test/tostester/src")]
    return asyncio.run(_run(Path(build), configs, connections, rate, items))


async def _run(build: Path, configs: list[str], connections: int, rate: float, items):
    from pqbench.chain import PacedClient
    from toslib import ToslibClient
    from toslib.toslib_cdll import ToslibCDLL

    library = ToslibCDLL(build / "toslib/libtoslibjson.so")
    library.client_set_verbosity_level(1)
    clients = []
    try:
        for k in range(connections):
            c = ToslibClient(_Config(configs[k % len(configs)]), library)
            await c.init()
            clients.append(PacedClient(c, f"send{k}", qps=rate, inflight=4))
        out = []
        rr = 0

        async def one(index, scheduled, boc, client):
            sent = time.time()
            try:
                await client.call("raw_send_message", boc)
                out.append((index, scheduled, sent, True, None))
            except Exception as error:  # admission refusals are results, not crashes
                out.append((index, scheduled, sent, False, str(error)[:200]))

        tasks = []
        for index, scheduled, boc in items:
            delay = scheduled - time.time()
            if delay > 0:
                await asyncio.sleep(delay)
            tasks.append(asyncio.create_task(one(index, scheduled, boc, clients[rr % len(clients)])))
            rr += 1
        await asyncio.gather(*tasks)
        return out
    finally:
        for c in clients:
            await c.client.aclose()


def distributed_send(root: Path, build: Path, configs: list[str], bocs: list[bytes], rate: float,
                     senders: int, per_connection_rate: float, start_delay: float):
    """Send bocs at `rate` over `senders` identities in worker processes.

    Returns the schedule start (after workers have had `start_delay` seconds to
    connect) and the SendRecords in message order.
    """
    from pqbench.chain import SendRecord

    if rate <= 0 or senders < 1:
        raise ValueError("positive rate and at least one sender required")
    if rate > senders * per_connection_rate * 1.0001:
        raise ValueError(f"offered {rate:g}/s exceeds {senders} senders x {per_connection_rate:g}/s")
    workers = max(1, -(-senders // PER_WORKER_CONNECTIONS))
    start = time.time() + start_delay
    shares: list[list] = [[] for _ in range(workers)]
    for i, boc in enumerate(bocs):
        shares[i % workers].append((i, start + i / rate, boc))
    counts = [senders // workers + (1 if w < senders % workers else 0) for w in range(workers)]
    jobs = [(str(root), str(build), configs, counts[w], per_connection_rate, shares[w]) for w in range(workers)]
    with multiprocessing.get_context("spawn").Pool(workers) as pool:
        results = pool.map(_worker, jobs)
    records = [SendRecord(*row) for rows in results for row in rows]
    records.sort(key=lambda r: r.index)
    if len(records) != len(bocs):
        raise RuntimeError("a sender worker lost records")
    return start, records
