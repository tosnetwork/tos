"""Live-chain helpers: rate-paced sending, block scanning and account reads.

The scanner walks every basechain block between consecutive masterchain blocks,
so per-block transaction counts are exact rather than sampled. Counting by
account class keeps the numbers interpretable: a transaction on a module is
one on-chain ML-DSA-44 verification, one on a load wallet is one executed
transfer, and one on a relayer is one relay batch.
"""

import asyncio
import base64
import time
from dataclasses import dataclass, field

from pytosiq_core import Address, Cell, MessageAny
from tosapi import toslib_api

from contract import WalletV5State
from toslib import ToslibClient

BASECHAIN_SHARD = -(2**63)
# Each liteserver connection admits 64 queries per second with 32 in flight;
# stay under both so the bench measures the chain, not its own refusals.
CONNECTION_QPS = 48
CONNECTION_INFLIGHT = 24
READ_ATTEMPTS = 8
TRANSIENT_READ_ERRORS = ("admission limit exceeded", "NETWORKCancelled", "LITE_SERVER_NETWORK", "timeout")


class PacedClient:
    """A toslib client that never exceeds one liteserver connection's admission budget."""

    def __init__(self, client: ToslibClient, name: str, qps: float = CONNECTION_QPS,
                 inflight: int = CONNECTION_INFLIGHT):
        self.client, self.name, self.qps = client, name, qps
        self._gate = asyncio.Semaphore(inflight)
        self._next = 0.0
        self._lock = asyncio.Lock()
        self.retries = 0

    async def _slot(self, cost: int) -> None:
        async with self._lock:
            now = time.monotonic()
            start = max(now, self._next)
            self._next = start + cost / self.qps
        if start > now:
            await asyncio.sleep(start - now)

    async def call(self, method: str, *args, cost: int = 1):
        """Reads retry admission refusals with backoff; a send is attempted once and its outcome kept."""
        attempts = 1 if method == "raw_send_message" else READ_ATTEMPTS
        for attempt in range(attempts):
            await self._slot(cost)
            try:
                async with self._gate:
                    return await getattr(self.client, method)(*args)
            except Exception as error:
                if attempt + 1 == attempts or not any(m in str(error) for m in TRANSIENT_READ_ERRORS):
                    raise
                self.retries += 1
                await asyncio.sleep(min(5.0, 0.2 * 2**attempt))
        raise AssertionError("unreachable")


class ClientPool:
    """Round-robin over paced connections spread across every validator's liteserver."""

    def __init__(self, clients: list[PacedClient]):
        if not clients:
            raise ValueError("a client pool needs at least one connection")
        self.clients = clients
        self._i = 0

    def pick(self) -> PacedClient:
        client = self.clients[self._i % len(self.clients)]
        self._i += 1
        return client

    async def call(self, method: str, *args, cost: int = 1):
        return await self.pick().call(method, *args, cost=cost)

    @property
    def qps(self) -> float:
        return sum(c.qps for c in self.clients)


def account_key(raw: bytes | str) -> bytes:
    """A shortTxId account field as the 32-byte address hash."""
    data = base64.b64decode(raw) if isinstance(raw, str) else raw
    if len(data) != 32:
        raise ValueError("unexpected account id length in block transaction list")
    return data


@dataclass
class BlockRow:
    seqno: int
    gen_utime: int
    observed: float
    total: int
    by_class: dict[str, int]


@dataclass
class Scanner:
    client: PacedClient
    classes: dict[bytes, str]
    rows: list[BlockRow] = field(default_factory=list)
    last_seqno: int | None = None
    first_seen: dict[bytes, list[float]] = field(default_factory=dict)
    track: set[bytes] = field(default_factory=set)
    _stop: asyncio.Event = field(default_factory=asyncio.Event)

    async def _shard_head(self) -> toslib_api.Tos_blockIdExt:
        info = await self.client.call("get_masterchain_info")
        shards = await self.client.call("get_shards", info.last)
        heads = [s for s in shards.shards if s.workchain == 0]
        if len(heads) != 1 or heads[0].shard != BASECHAIN_SHARD:
            raise RuntimeError("the bench expects one unsplit basechain shard")
        return heads[0]

    async def _scan_block(self, seqno: int, observed: float) -> None:
        block = await self.client.call("lookup_block", 0, BASECHAIN_SHARD, seqno, cost=3)
        header = await self.client.call("get_block_header", block)
        txs = await self.client.call("get_block_transactions", block, cost=2)
        by_class: dict[str, int] = {}
        for tx in txs:
            key = account_key(tx.account)
            name = self.classes.get(key, "other")
            by_class[name] = by_class.get(name, 0) + 1
            if key in self.track:
                self.first_seen.setdefault(key, []).append(observed)
        self.rows.append(BlockRow(seqno, int(header.gen_utime), observed, len(txs), by_class))

    async def start_position(self) -> None:
        self.last_seqno = (await self._shard_head()).seqno

    async def run(self, poll: float = 0.2) -> None:
        if self.last_seqno is None:
            await self.start_position()
        while not self._stop.is_set():
            head = await self._shard_head()
            observed = time.time()
            assert self.last_seqno is not None
            for seqno in range(self.last_seqno + 1, head.seqno + 1):
                await self._scan_block(seqno, observed)
            self.last_seqno = max(self.last_seqno, head.seqno)
            try:
                await asyncio.wait_for(self._stop.wait(), poll)
            except TimeoutError:
                pass

    def stop(self) -> None:
        self._stop.set()


@dataclass
class SendRecord:
    index: int
    scheduled: float
    sent: float
    ok: bool
    error: str | None


async def paced_send(
    pool: ClientPool,
    messages: list[MessageAny],
    rate: float,
    concurrency: int = 256,
) -> list[SendRecord]:
    """Send pre-serialized messages at a fixed offered rate; never block the schedule on answers."""
    if rate <= 0:
        raise ValueError("rate must be positive")
    if not messages:
        return []
    if rate > pool.qps:
        raise ValueError(f"offered {rate:g} messages/s exceeds the pool's {pool.qps:g} queries/s")
    bocs = [m.serialize().to_boc() for m in messages]
    gate = asyncio.Semaphore(concurrency)
    records: list[SendRecord | None] = [None] * len(bocs)
    start = time.time() + 0.5

    async def one(i: int, boc: bytes, scheduled: float) -> None:
        async with gate:
            sent = time.time()
            try:
                await pool.call("raw_send_message", boc)
                records[i] = SendRecord(i, scheduled, sent, True, None)
            except Exception as error:  # admission refusals are results, not crashes
                records[i] = SendRecord(i, scheduled, sent, False, str(error)[:200])

    tasks = []
    for i, boc in enumerate(bocs):
        scheduled = start + i / rate
        delay = scheduled - time.time()
        if delay > 0:
            await asyncio.sleep(delay)
        tasks.append(asyncio.create_task(one(i, boc, scheduled)))
    await asyncio.gather(*tasks)
    return [r for r in records if r is not None]


async def read_wallet_states(
    pool: ClientPool, addresses: list[Address]
) -> dict[bytes, WalletV5State | None]:
    out: dict[bytes, WalletV5State | None] = {}

    async def one(address: Address) -> None:
        state = await pool.call("raw_get_account_state", address)
        data = state.data
        out[address.hash_part] = WalletV5State.parse(Cell.one_from_boc(data)) if data else None

    await asyncio.gather(*(one(a) for a in addresses))
    return out


async def account_active(pool: ClientPool, addresses: list[Address]) -> dict[bytes, bool]:
    out: dict[bytes, bool] = {}

    async def one(address: Address) -> None:
        out[address.hash_part] = bool((await pool.call("raw_get_account_state", address)).code)

    await asyncio.gather(*(one(a) for a in addresses))
    return out


async def config_snapshot(pool: ClientPool, params=(20, 21, 22, 23, 24, 25)) -> dict[str, dict]:
    """The live gas price, block limit and forwarding parameters every stage ran under."""
    out = {}
    for p in params:
        cell = await pool.call("get_config_param", p)
        out[str(p)] = {"hash": cell.hash.hex(), "boc": cell.to_boc().hex()}
    return out


async def gas_sample(pool: ClientPool, accounts: dict[str, list[Address]], per_class: int = 8) -> dict:
    """Measured compute gas and total fees of recent ordinary transactions, per account class."""
    from pytosiq_core import Transaction

    report = {}
    for name, addresses in accounts.items():
        gas, fees, aborted = [], [], 0
        for address in addresses[:per_class]:
            state = await pool.call("raw_get_account_state", address)
            last = state.last_transaction_id
            if last is None or not int(last.lt):
                continue
            txs = await pool.call("raw_get_transactions", address, last)
            for tx in txs.transactions[:4]:
                parsed = Transaction.deserialize(Cell.one_from_boc(tx.data).begin_parse())
                phase = getattr(parsed.description, "compute_ph", None)
                used = getattr(phase, "gas_used", None)
                if used is None:
                    continue
                gas.append(int(used))
                fees.append(int(tx.fee))
                aborted += int(bool(getattr(parsed.description, "aborted", False)))
        if gas:
            gas.sort()
            report[name] = {
                "transactions": len(gas),
                "gas_min": gas[0],
                "gas_median": gas[len(gas) // 2],
                "gas_max": gas[-1],
                "fee_median_nanotos": sorted(fees)[len(fees) // 2],
                "aborted": aborted,
            }
    return report
