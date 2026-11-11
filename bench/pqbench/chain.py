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
from pathlib import Path
from typing import Any, Literal

from contract import WalletV5State
from pytosiq_core import Address, Cell, MessageAny
from tosapi import toslib_api

from toslib import ToslibClient, ToslibError

BASECHAIN_SHARD = -(2**63)
SHARD_CLIENT_STATE_CAPABILITY = 8
# Each liteserver connection admits 64 queries per second with 32 in flight;
# stay under both so the bench measures the chain, not its own refusals.
CONNECTION_QPS = 48
CONNECTION_INFLIGHT = 24
# The pool has no per-source admission limit; the connection's own query budget
# (CONNECTION_QPS) is the bound. Stay well under it so sends never queue there.
SOURCE_SEND_RATE = 10.0
# A liteserver admits 64 connections per source IP (ExtServerConnectionLimits);
# leave room for each node's read, deployment and scanner connections.
SENDERS_PER_NODE = 56
READ_ATTEMPTS = 8
TRANSIENT_READ_ERRORS = (
    "admission limit exceeded",
    "NETWORKCancelled",
    "LITE_SERVER_NETWORK",
    "timeout",
)


class PacedClient:
    """A toslib client that never exceeds one liteserver connection's admission budget."""

    def __init__(
        self,
        client: ToslibClient,
        name: str,
        qps: float = CONNECTION_QPS,
        inflight: int = CONNECTION_INFLIGHT,
    ):
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
                if attempt + 1 == attempts or not any(
                    m in str(error) for m in TRANSIENT_READ_ERRORS
                ):
                    raise
                self.retries += 1
                await asyncio.sleep(min(5.0, 0.2 * 2**attempt))
        raise AssertionError("unreachable")


class ClientPool:
    """Round-robin over paced connections spread across every validator's liteserver.

    Reads use ``clients``; external messages go only through ``senders``, each
    paced under the per-identity external admission rate.
    """

    def __init__(self, clients: list[PacedClient], senders: list[PacedClient] | None = None):
        if not clients:
            raise ValueError("a client pool needs at least one connection")
        self.clients = clients
        self.senders = senders or []
        self._i = 0
        self._s = 0

    def pick_sender(self) -> PacedClient:
        if not self.senders:
            return self.pick()
        sender = self.senders[self._s % len(self.senders)]
        self._s += 1
        return sender

    @property
    def send_rate(self) -> float:
        return sum(s.qps for s in self.senders) if self.senders else self.qps

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
    block: object = None  # the block id, kept so a stage can measure sampled blocks
    lag_started_at: float | None = None


@dataclass
class Scanner:
    client: PacedClient
    classes: dict[bytes, str]
    rows: list[BlockRow] = field(default_factory=list)
    last_seqno: int | None = None
    first_seen: dict[bytes, list[float]] = field(default_factory=dict)
    track: set[bytes] = field(default_factory=set)
    lag: dict[str, int | float | str | None] | None = None
    _stop: asyncio.Event = field(default_factory=asyncio.Event)
    _stopped_at: float | None = None
    head_source: Literal["shard_client", "advertised"] | None = field(default=None, init=False)

    async def _shard_head(self) -> toslib_api.Tos_blockIdExt:
        # Mode 0 also advertises capabilities. Older nodes keep their default
        # head and bounded block-read retries. On supporting nodes, use the
        # shard client's applied head for every scan boundary on this connection.
        mode = 1 if self.head_source == "shard_client" else 0
        info = await self.client.call("get_masterchain_info_ext", mode)
        if mode == 0 and info.capabilities & SHARD_CLIENT_STATE_CAPABILITY:
            mode = 1
            info = await self.client.call("get_masterchain_info_ext", mode)
        if info.mode != mode:
            raise RuntimeError(f"liteserver returned head mode {info.mode}, requested {mode}")
        self.head_source = "shard_client" if mode == 1 else "advertised"
        shards = await self.client.call("get_shards", info.last)
        heads = [s for s in shards.shards if s.workchain == 0]
        if len(heads) != 1 or heads[0].shard != BASECHAIN_SHARD:
            raise RuntimeError("the bench expects one unsplit basechain shard")
        return heads[0]

    async def _scan_block(self, seqno: int, lag_started_at: float | None) -> None:
        block = await self.client.call("lookup_block", 0, BASECHAIN_SHARD, seqno, cost=3)
        header = await self.client.call("get_block_header", block)
        txs = await self.client.call("get_block_transactions", block, cost=2)
        observed = time.time()
        by_class: dict[str, int] = {}
        for tx in txs:
            key = account_key(tx.account)
            name = self.classes.get(key, "other")
            by_class[name] = by_class.get(name, 0) + 1
            if key in self.track:
                self.first_seen.setdefault(key, []).append(observed)
        self.rows.append(
            BlockRow(
                seqno, int(header.gen_utime), observed, len(txs), by_class, block, lag_started_at
            )
        )

    async def start_position(self) -> None:
        self.last_seqno = (await self._shard_head()).seqno

    async def _scan_with_retry(
        self, seqno: int, head: int, poll: float, lag_timeout: float
    ) -> bool:
        # Healthy paginated reads have their own transport timeouts. Start this
        # deadline only when the node identifies a gap in its applied shard.
        deadline = asyncio.timeout(None)
        last_error = ""
        lag_started_at = None
        try:
            async with deadline:
                while True:
                    try:
                        await self._scan_block(seqno, lag_started_at)
                        return True
                    except ToslibError as error:
                        message = str(error)
                        if not (
                            message.startswith("LITE_SERVER_NOTREADY:")
                            and "(possibly out of sync: shard_client_seqno=" in message
                        ):
                            raise
                        last_error = message
                    if deadline.when() is None:
                        lag_started_at = time.time()
                        now = asyncio.get_running_loop().time()
                        start = self._stopped_at if self._stopped_at is not None else now
                        deadline.reschedule(start + lag_timeout)
                    await asyncio.sleep(poll)
        except TimeoutError:
            if not deadline.expired():
                raise
        self.lag = {
            "last_scanned_seqno": self.last_seqno,
            "first_missing_seqno": seqno,
            "advertised_head_seqno": head,
            "timeout_s": lag_timeout,
            "error": last_error,
        }
        return False

    async def _head_at_stop(self) -> toslib_api.Tos_blockIdExt:
        await self._stop.wait()
        return await self._shard_head()

    async def run(self, poll: float = 0.2, lag_timeout: float = 30.0) -> None:
        if self.last_seqno is None:
            await self.start_position()
        # Snapshot the advertised head when the stage ends, even if the scan
        # connection is waiting for an older block. Never chase later heads.
        final_head = asyncio.create_task(self._head_at_stop())
        try:
            while True:
                stopping = self._stop.is_set()
                head = await final_head if stopping else await self._shard_head()
                assert self.last_seqno is not None
                for seqno in range(self.last_seqno + 1, head.seqno + 1):
                    if not await self._scan_with_retry(seqno, head.seqno, poll, lag_timeout):
                        if final_head.done():
                            # Keep a newer cutoff already returned by the node, or
                            # propagate its RPC error even if the block also timed out.
                            assert self.lag is not None
                            self.lag["advertised_head_seqno"] = max(
                                head.seqno, final_head.result().seqno
                            )
                        return
                    self.last_seqno = seqno
                if stopping:
                    return
                try:
                    await asyncio.wait_for(self._stop.wait(), poll)
                except TimeoutError:
                    pass
        finally:
            final_head.cancel()
            await asyncio.gather(final_head, return_exceptions=True)

    def stop(self) -> None:
        if not self._stop.is_set():
            # All remaining blocks of the advertised batch share one grace
            # period for lag after the stage ends.
            self._stopped_at = asyncio.get_running_loop().time()
            self._stop.set()


@dataclass
class SendRecord:
    index: int
    scheduled: float
    sent: float
    ok: bool
    error: str | None
    connection: str = ""


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
    if rate > pool.send_rate * 1.0001:
        raise ValueError(f"offered {rate:g} messages/s exceeds the senders' {pool.send_rate:g}/s")
    bocs = [m.serialize().to_boc() for m in messages]
    gate = asyncio.Semaphore(concurrency)
    records: list[SendRecord | None] = [None] * len(bocs)
    start = time.time() + 0.5

    async def one(i: int, boc: bytes, scheduled: float) -> None:
        async with gate:
            sent = time.time()
            try:
                await pool.pick_sender().call("raw_send_message", boc)
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


async def read_balances(pool: ClientPool, addresses: list[Address]) -> dict[bytes, int]:
    """Current balances in nanotos; an account that does not exist yet reads as 0."""
    out: dict[bytes, int] = {}

    async def one(address: Address) -> None:
        out[address.hash_part] = int((await pool.call("raw_get_account_state", address)).balance)

    await asyncio.gather(*(one(a) for a in addresses))
    return out


async def account_active(pool: ClientPool, addresses: list[Address]) -> dict[bytes, bool]:
    out: dict[bytes, bool] = {}

    async def one(address: Address) -> None:
        out[address.hash_part] = bool((await pool.call("raw_get_account_state", address)).code)

    await asyncio.gather(*(one(a) for a in addresses))
    return out


async def config_snapshot(
    pool: ClientPool, params=(20, 21, 22, 23, 24, 25)
) -> dict[str, dict[str, str]]:
    """The live gas price, block limit and forwarding parameters every stage ran under."""
    out = {}
    for p in params:
        cell = await pool.call("get_config_param", p)
        out[str(p)] = {"hash": cell.hash.hex(), "boc": cell.to_boc().hex()}
    return out


async def gas_sample(
    pool: ClientPool, accounts: dict[str, list[Address]], per_class: int = 8
) -> dict[str, dict[str, int]]:
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


async def action_report(
    pool: ClientPool, address: Address, limit: int = 16
) -> list[dict[str, int | bool]]:
    """Action-phase outcome of an account's recent transactions (why an action was skipped)."""
    from pytosiq_core import Transaction

    state = await pool.call("raw_get_account_state", address)
    last = state.last_transaction_id
    if last is None or not int(last.lt):
        return []
    rows = []
    txs = await pool.call("raw_get_transactions", address, last)
    for tx in txs.transactions[:limit]:
        parsed = Transaction.deserialize(Cell.one_from_boc(tx.data).begin_parse())
        action = getattr(parsed.description, "action", None)
        if action is None:
            continue
        rows.append(
            {
                "lt": int(tx.transaction_id.lt),
                "success": bool(action.success),
                "result_code": int(action.result_code),
                "no_funds": bool(action.no_funds),
                "tot_actions": int(action.tot_actions),
                "skipped_actions": int(action.skipped_actions),
                "msgs_created": int(action.msgs_created),
                "total_fwd_fees": int(action.total_fwd_fees or 0),
                "balance_after": int(state.balance),
            }
        )
    return rows


async def read_data(pool: ClientPool, addresses: list[Address]) -> dict[bytes, Cell | None]:
    out: dict[bytes, Cell | None] = {}

    async def one(address: Address) -> None:
        data = (await pool.call("raw_get_account_state", address)).data
        out[address.hash_part] = Cell.one_from_boc(data) if data else None

    await asyncio.gather(*(one(a) for a in addresses))
    return out


def collation_stats(network_dir: Path, lo: float, hi: float) -> dict[str, Any]:
    """Basechain collation records the validators wrote in [lo, hi] (their session-logs files).

    Each record is the collator's own account of one collated block: its serialized size,
    the size estimate the byte limits apply to, gas, lt delta, collation CPU time and, when
    a soft limit stopped it, which one. Records are per collation attempt and per node.
    """
    import json
    import statistics

    rows = []
    for path in sorted(network_dir.glob("node*/session-logs")):
        with path.open(errors="replace") as f:
            for line in f:
                if '"validatorStats.collatedBlock"' not in line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if d["block_id"]["workchain"] != 0 or not lo <= float(d["collated_at"]) <= hi:
                    continue
                limits = d["block_limits"]
                reason = next(
                    (
                        part.split(": ", 1)[1]
                        for part in limits.get("limits_log", "").split("\n")
                        if part.startswith("INBOUND_EXT_MESSAGES: ")
                    ),
                    "",
                )
                rows.append(
                    {
                        "transactions": int(d.get("block_stats", {}).get("transactions", 0)),
                        "bytes": int(d["bytes"]),
                        "estimated_bytes": int(limits["bytes"]),
                        "gas": int(limits["gas"]),
                        "lt_delta": int(limits["lt_delta"]),
                        "collated_data_bytes": int(d["collated_data_bytes"]),
                        "cpu_seconds": float(d["cpu_work_time"]),
                        "stop": reason.split(" ")[0] + " " + reason.split(" ")[1]
                        if reason.startswith("block_full")
                        else reason,
                    }
                )
    if not rows:
        return {"collations": 0}

    def summary(key: str) -> dict[str, float]:
        values = sorted(r[key] for r in rows)
        return {"median": statistics.median(values), "max": values[-1]}

    stops: dict[str, int] = {}
    for r in rows:
        stops[r["stop"] or "none (queue drained)"] = (
            stops.get(r["stop"] or "none (queue drained)", 0) + 1
        )
    full = [r for r in rows if r["stop"].startswith("block_full")]
    out: dict[str, Any] = {
        "collations": len(rows),
        "external_stop_reasons": stops,
        **{
            key: summary(key)
            for key in (
                "transactions",
                "bytes",
                "estimated_bytes",
                "gas",
                "lt_delta",
                "cpu_seconds",
            )
        },
    }
    if full:
        out["full_blocks"] = {
            "count": len(full),
            "transactions_median": statistics.median(r["transactions"] for r in full),
            "bytes_median": statistics.median(r["bytes"] for r in full),
            "estimated_bytes_median": statistics.median(r["estimated_bytes"] for r in full),
            "gas_median": statistics.median(r["gas"] for r in full),
            "cpu_seconds_median": statistics.median(r["cpu_seconds"] for r in full),
        }
    return out


def basechain_soft_limits(chain_config: dict[str, dict[str, str]]) -> tuple[int, int, int]:
    """(bytes, gas, lt delta) soft limits of the basechain from a ConfigParam 23 snapshot."""
    s = Cell.one_from_boc(bytes.fromhex(chain_config["23"]["boc"])).begin_parse()
    s.skip_bits(8)  # block_limits tag

    def tiers():
        s.skip_bits(8)
        return s.load_uint(32), s.load_uint(32), s.load_uint(32)

    byte_tiers, gas_tiers, lt_tiers = tiers(), tiers(), tiers()
    return byte_tiers[1], gas_tiers[1], lt_tiers[1]


async def chain_now(pool: ClientPool, attempts: int = 20, pause: float = 0.25) -> int:
    """The latest masterchain block's time, read from one liteserver.

    Both reads go to the same connection: another node may not have applied the
    block yet and would answer LITE_SERVER_NOTREADY. A NOTREADY from that one
    node, which can lag under load, is retried; any other error is raised.
    """
    client = pool.pick()
    for attempt in range(attempts):
        try:
            info = await client.call("get_masterchain_info")
            return int((await client.call("get_block_header", info.last)).gen_utime)
        except Exception as error:
            if "LITE_SERVER_NOTREADY" not in str(error) or attempt + 1 == attempts:
                raise
            await asyncio.sleep(pause)
    raise AssertionError("unreachable")
