"""T4 transfer ramp against existing JSON-RPC endpoints.

Every read and send goes through ``shard.rpc.PacedRpc`` inside
``--rpc-share`` of each node's per-source budget; nothing on this path opens a
liteserver connection or boots a node. A run:

1. checks the plan and computes its bound: transfers, externals, and the
   load-wallet funding the run may take out of the bench wallet. It prints
   the bound and refuses to go on when the funding alone exceeds
   ``--max-cost`` or the transfers ``--max-transfers``. Nothing is read or
   sent before;
2. derives ``--wallets`` self-pay Quantum load wallets from the bench key
   (each has its own ML-DSA-44 seed, derived from the bench seed and never
   written anywhere, and the bench key's RESCUE key), reads every one of
   them and the gas, forwarding and storage prices of the live
   configuration (ConfigParams 21, 25 and 18), and derives the fee bound of
   the whole planned ramp with ``shard.remote``'s fee model: every funding
   external of the bench wallet and its storage, every transfer external of
   every step and repeat (each with its exact action count and message
   sizes), every return sweep, the computation on everything the load
   wallets receive, and their storage. Every request's deadline is capped at
   the horizon that storage bound covers. It refuses when the funding plus
   the bench wallet's fee bound exceeds ``--max-cost``, or the load wallets'
   fee bound exceeds their funding. Nothing is written or sent before this
   step either;
3. deploys or tops up the load wallets from the bench wallet in
   multi-action externals, and checks each one's real fee against its bound;
4. runs the steps: from ``--start-rate`` transfers/s, multiplied by
   ``--factor`` per step, ``--step-seconds`` each. Every external carries up to
   ``--batch`` transfers, one send action each (mode 3: pay fees separately,
   ignore errors), from one load wallet to other load wallets. A follower
   walks every masterchain block and the shard blocks it commits and binds
   each transfer in the ledger (``t4.ledger``). Each step drains, waits for
   finality, and applies the pass rule over its window after
   ``--warmup``. A step spanning a layout change does not count and is
   repeated up to ``--layout-repeats`` times; the ramp ends at the first
   counted failing step. Every executed transfer external's reported fee is
   checked against its bound, and one over it stops the ramp;
5. writes the ledger (one line per external, every action's outcome) and the
   results, then returns what is left in the load wallets to ``--return-to``
   (default: the bench wallet).

A load wallet carries one external at a time. An ambiguous submission is
never resent: its wallet is held until the request's deadline has passed on
chain, and then the wallet's nonce is read again before it sends new
transfers.

Exit statuses (``exit_status``): 0 when the ramp ran as specified (every
step passed, or it ended at the first counted failing step), 1 when the
ledger saw an anomaly or a duplicate, 3 when it was refused before anything
was sent, 4 when it stopped after sending without an answer.

Run: ``bench/run_t4_ramp.py --help``.
"""

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import math
import os
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

from contract.pq_auth import transfer_message
from pqbench.workload import (
    PUBLIC_KEY_BYTES,
    QSP_PRIMARY_CONTEXT,
    SIGNATURE_BYTES,
    QuantumWallet,
    primary_nonce,
)
from pytosiq_core import Address, Cell, MessageAny
from shard import hopbench, remote, t2collect
from shard.remote import BenchWallet, Remote, Secret, raw
from shard.rpc import PacedRpc, RateLimited, RpcError
from shard.t2check import McRecord

from t4.ledger import NO_WALLET, External, Ledger, StepRule, step_layout, step_metrics

NANO = remote.NANO
REFUSED = remote.REFUSED
# The node refuses externals above 64 KiB; keep the local bench's headroom.
EXT_MESSAGE_BUDGET = 60_000
# The wallet's error code for a request whose nonce is not the current one.
BAD_NONCE = 1804
SEND_MODE = 3  # pay fees separately, ignore errors: a failing action is skipped
SWEEP_MODE = 130  # carry the whole remaining balance, ignore errors
LOAD_TAG = b"tos-t4-load-wallet"
# Chain seconds past a request's deadline after which no block can still execute it.
DEADLINE_GRACE = 30.0
STALL_SECONDS = 120.0
MAX_WALLETS = 65_536
log = logging.getLogger("t4-ramp")


# ─── the plan and its bound ──────────────────────────────────────────


@dataclass(frozen=True)
class Plan:
    wallets: int
    batch: int
    start_rate: float
    factor: float
    steps: int
    step_seconds: int
    warmup: int
    repeats: int
    transfer_value: int  # nanotos; action i of an external carries this plus i
    wallet_funding: int  # nanotos each load wallet is funded or topped up to
    deploy_batch: int  # deployment actions per bench-wallet external

    def rates(self) -> list[float]:
        return [self.start_rate * self.factor**k for k in range(self.steps)]


def _int_in(name: str, value: object, lo: int, hi: int) -> int:
    if type(value) is not int or not lo <= value <= hi:
        raise ValueError(f"{name} must be an integer in [{lo}, {hi}]")
    return value


def validate_plan(plan: Plan) -> Plan:
    """Refuse any plan the bound, the wallet or the ledger does not support."""
    _int_in("wallets", plan.wallets, 2, MAX_WALLETS)
    _int_in("batch", plan.batch, 1, 255)
    _int_in("steps", plan.steps, 1, 32)
    _int_in("step seconds", plan.step_seconds, 1, 86_400)
    _int_in("warmup", plan.warmup, 0, plan.step_seconds - 1)
    _int_in("layout repeats", plan.repeats, 0, 8)
    _int_in("deploy batch", plan.deploy_batch, 1, 255)
    for name in ("start_rate", "factor"):
        value = getattr(plan, name)
        if not isinstance(value, float | int) or not math.isfinite(value):
            raise ValueError(f"{name} must be a finite number")
    if not 0 < plan.start_rate <= 1_000_000:
        raise ValueError("the start rate must be in (0, 1000000] transfers/s")
    if not 1 <= plan.factor <= 16:
        raise ValueError("the step factor must be in [1, 16]")
    if max(plan.rates()) > 1_000_000:
        raise ValueError("the last step's rate exceeds 1000000 transfers/s")
    for name in ("transfer_value", "wallet_funding"):
        _int_in(name, getattr(plan, name), 1, (1 << 120) - 1)
    return plan


def transfers_in(rate: float, seconds: int) -> int:
    return max(1, math.ceil(rate * seconds - 1e-9))


def externals_for(transfers: int, batch: int) -> int:
    return -(-transfers // batch)


def planned_sizes(plan: Plan) -> dict[int, int]:
    """How many load externals of each action count the whole ramp may send.

    Every step runs up to ``1 + repeats`` times; a step of ``total`` transfers
    sends ``total // batch`` full externals and one with the rest, exactly as
    ``Ramp.step`` cuts them.
    """
    validate_plan(plan)
    runs = 1 + plan.repeats
    sizes: Counter[int] = Counter()
    for rate in plan.rates():
        full, rest = divmod(transfers_in(rate, plan.step_seconds), plan.batch)
        sizes[plan.batch] += runs * full
        if rest:
            sizes[rest] += runs
    return {k: n for k, n in sorted(sizes.items()) if n}


@dataclass(frozen=True)
class Bound:
    transfers: int
    load_externals: int
    sweep_externals: int
    deploy_externals: int
    funding: int
    bench_fees: int
    load_fees: int
    cost: int
    fee_spend: int
    recoverable_floor: int

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = asdict(self)
        out["cost_tos"] = self.cost / NANO
        out["load_fees_tos"] = self.load_fees / NANO
        out["fee_spend_tos"] = self.fee_spend / NANO
        out["recoverable_floor_tos"] = self.recoverable_floor / NANO
        return out


def work_bound(plan: Plan, fees: "RampFees | None" = None) -> Bound:
    """An upper bound on the run's transfers and externals, and on its cost to the bench wallet.

    Every step may run ``1 + repeats`` times. The bench wallet sends at most
    one funding action per load wallet, ``deploy_batch`` per external, so the
    most it can lose is that funding plus its own fees (``fees.bench_total``).
    The load wallets pay every fee of theirs out of that funding:
    ``fees.load_total`` bounds them over the whole planned ramp (every
    transfer external of every step and repeat, every sweep, the computation
    on everything they receive and their storage), and ``refusal`` requires
    it to fit inside the funding, so adding it to the cost would count the
    same nanotos twice. ``fee_spend`` is the most the run can burn in fees
    when the sweep returns the rest. Before the configuration is read the
    bound is taken with no fees, which already refuses a run whose funding
    alone exceeds ``--max-cost``.
    """
    sizes = planned_sizes(plan)
    transfers = sum(size * n for size, n in sizes.items())
    load_externals = sum(sizes.values())
    deploy = (
        len(fees.funding) if fees is not None else externals_for(plan.wallets, plan.deploy_batch)
    )
    funding = plan.wallets * plan.wallet_funding
    bench_fees = fees.bench_total if fees is not None else 0
    load_fees = fees.load_total if fees is not None else 0
    return Bound(
        transfers,
        load_externals,
        plan.wallets,
        deploy,
        funding,
        bench_fees,
        load_fees,
        funding + bench_fees,
        bench_fees + load_fees,
        max(0, funding - load_fees),
    )


def refusal(bound: Bound, max_cost: int, max_transfers: int) -> str | None:
    """Why the bound is over a limit, or None when it is inside every one."""
    _int_in("max cost", max_cost, 1, 1 << 120)
    _int_in("max transfers", max_transfers, 1, 1 << 40)
    reasons = []
    if bound.cost > max_cost:
        reasons.append(f"cost bound {bound.cost} nanotos exceeds --max-cost {max_cost}")
    if bound.transfers > max_transfers:
        reasons.append(f"transfer bound {bound.transfers} exceeds --max-transfers {max_transfers}")
    if bound.load_fees > bound.funding:
        reasons.append(
            f"load fee bound {bound.load_fees} nanotos exceeds the load wallets' funding"
            f" {bound.funding}"
        )
    return "; ".join(reasons) or None


# ─── wallets, keys and signing ───────────────────────────────────────


def load_seed(bench_seed: Secret, index: int) -> Secret:
    """A load wallet's ML-DSA-44 seed; it exists only in memory and on the signer's stdin."""
    _int_in("load wallet index", index, 0, MAX_WALLETS - 1)
    return Secret(
        hashlib.sha256(LOAD_TAG + bench_seed.reveal() + index.to_bytes(4, "big")).digest()
    )


def run_signer(
    executable: Path, args: list[str], lines: list[str], size: int, threads: int
) -> list[bytes]:
    """One bench signer call over stdin; errors carry only the exit status, never the input."""
    if not lines:
        return []
    result = subprocess.run(
        [str(executable), *args, "--threads", str(threads)],
        input="\n".join(lines) + "\n",
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"bench signer failed with exit status {result.returncode}")
    out: list[bytes] = []
    for line in result.stdout.splitlines():
        try:
            out.append(bytes.fromhex(line))
        except ValueError:
            raise RuntimeError("bench signer returned a malformed answer") from None
    if len(out) != len(lines) or any(len(x) != size for x in out):
        raise RuntimeError("bench signer returned a short or malformed batch")
    return out


class Signs(Protocol):
    def sign(self, jobs: list[tuple[Secret, bytes]]) -> list[bytes]: ...


class BatchSigner:
    def __init__(self, executable: Path, threads: int):
        if not executable.is_file():
            raise FileNotFoundError(f"bench signer not found: {executable}")
        _int_in("signer threads", threads, 1, 256)
        self.executable, self.threads = executable.resolve(), threads

    def public_keys(self, seeds: list[Secret]) -> list[bytes]:
        lines = [s.reveal().hex() for s in seeds]
        return run_signer(self.executable, ["public"], lines, PUBLIC_KEY_BYTES, self.threads)

    def sign(self, jobs: list[tuple[Secret, bytes]]) -> list[bytes]:
        lines = [f"{s.reveal().hex()} {m.hex()}" for s, m in jobs]
        return run_signer(
            self.executable,
            ["sign", QSP_PRIMARY_CONTEXT.hex()],
            lines,
            SIGNATURE_BYTES,
            self.threads,
        )


def load_wallet(
    code: Cell, global_id: int, auth: bytes, index: int, public_key: bytes, rescue: bytes
) -> QuantumWallet:
    return QuantumWallet.derive(
        code, global_id, auth, bytes(32), "t4-load", index, public_key, b"", rescue=rescue
    )


@dataclass(eq=False)
class LoadWallet:
    index: int
    wallet: QuantumWallet
    seed: Secret
    nonce: int = 0
    seqno: int = 0
    busy: External | None = None
    resync: bool = False
    resyncing: bool = False

    @property
    def address(self) -> str:
        return raw(self.wallet.address)

    @property
    def free(self) -> bool:
        return self.busy is None and not self.resync and not self.resyncing


def destinations(sender: int, seqno: int, size: int, batch: int, wallets: int) -> list[int]:
    """Peer indices for one external: every other wallet in turn, never the sender."""
    if wallets < 2:
        raise ValueError("transfers need at least two load wallets")
    return [(sender + 1 + (seqno * batch + i) % (wallets - 1)) % wallets for i in range(size)]


def transfer_actions(
    sender: Address, destinations: list[Address], values: list[int]
) -> list[MessageAny]:
    """The send actions of one transfer external; the sender and the fee bound build them alike."""
    return [transfer_message(sender, d, v) for d, v in zip(destinations, values, strict=True)]


def unsigned_external(
    wallet: QuantumWallet, actions: list[MessageAny], mode: int = SEND_MODE
) -> MessageAny:
    """A load wallet's external as it will be sent, with a placeholder of the signature's size.

    Nonce and deadline are fixed-width fields, so their values do not change the size.
    """
    return wallet.external(wallet.request(0, actions, 1, mode=mode), bytes(SIGNATURE_BYTES))


def external_size(wallet: QuantumWallet, actions: list[MessageAny], mode: int = SEND_MODE) -> int:
    return len(unsigned_external(wallet, actions, mode).serialize().to_boc())


def size_plan(code: Cell, batch: int, value: int, funding: int) -> tuple[int, int, int]:
    """(transfer external bytes at ``batch``, deployment actions that fit one external, its bytes).

    Every wallet of a run has the same shape, so a placeholder key sizes them all.
    """
    dummy = [
        load_wallet(code, 0, bytes(32), i, bytes([i % 251]) * PUBLIC_KEY_BYTES, bytes(32))
        for i in range(256)
    ]
    sender = dummy[0]
    transfers = [
        transfer_message(sender.address, dummy[1 + i % 255].address, value + i)
        for i in range(batch)
    ]
    transfer_bytes = external_size(sender, transfers)
    take, deploy_bytes = 255, 0
    while take >= 1:
        actions = [w.deployment_message(sender.address, funding) for w in dummy[1 : take + 1]]
        deploy_bytes = external_size(sender, actions)
        if deploy_bytes <= EXT_MESSAGE_BUDGET:
            break
        take = max(0, min(take - 1, take * EXT_MESSAGE_BUDGET // deploy_bytes - 1))
    return transfer_bytes, take, deploy_bytes


# ─── the fee bound from the live configuration ───────────────────────
#
# Every term comes from shard.remote's fee model (ConfigParams 21, 25 and 18
# priced as crypto/block/transaction.cpp does); nothing here restates it.
# The bench wallet and every load wallet are self-pay Quantum wallets on the
# basechain (QuantumWallet.address is always workchain 0), so ConfigParams 21
# and 25 price all of them; ``derive_fees`` refuses any other workchain.


@dataclass(frozen=True)
class RampFees:
    """The fee bound of the whole planned ramp, every term derived before anything is sent."""

    horizon: int
    funding: list[remote.ExternalFee]  # the bench wallet's funding externals, in send order
    bench_storage: remote.StorageFee
    transfers: dict[int, remote.ExternalFee]  # one load external, by its action count
    transfer_counts: dict[int, int]  # load externals of each action count the plan may send
    sweep: remote.ExternalFee  # one load wallet's return sweep
    receipts: int  # load wallets' computation on the funding they receive
    recipients: int  # load wallets' computation on every planned transfer they receive
    load_storage: list[remote.StorageFee]  # one per load wallet, in index order

    @property
    def bench_total(self) -> int:
        return sum(x.total for x in self.funding) + self.bench_storage.fee

    @property
    def transfer_total(self) -> int:
        return sum(self.transfers[k].total * n for k, n in self.transfer_counts.items())

    @property
    def load_total(self) -> int:
        storage = sum(x.fee for x in self.load_storage)
        sweeps = len(self.load_storage) * self.sweep.total
        return self.transfer_total + sweeps + self.receipts + self.recipients + storage

    def as_dict(self) -> dict[str, Any]:
        storage = [x.fee for x in self.load_storage]
        return {
            "horizon": self.horizon,
            "bench": {
                "funding_externals": [asdict(x) for x in self.funding],
                "storage": asdict(self.bench_storage),
                "total": self.bench_total,
            },
            "load": {
                "transfer_externals": {
                    str(k): {
                        "count": self.transfer_counts[k],
                        **asdict(self.transfers[k]),
                    }
                    for k in sorted(self.transfer_counts)
                },
                "transfer_total": self.transfer_total,
                "sweep": asdict(self.sweep),
                "sweeps": len(self.load_storage),
                "receipts": self.receipts,
                "recipients": self.recipients,
                "storage_per_wallet_max": max(storage, default=0),
                "storage_total": sum(storage),
                "total": self.load_total,
            },
        }


# Chain seconds past the fee horizon a transfer sent before it may still be
# delivered in; the load wallets' storage bound runs this much further.
DELIVERY_SLACK = 3600


def fee_horizon(now: int, plan: Plan, a: argparse.Namespace, funding_externals: int) -> int:
    """The latest chain time any request of the run may execute at.

    The funding externals each wait at most ``--deploy-wait``, as does the
    activation check; every step attempt runs ``--step-seconds``, drains and
    reaches the head within ``--drain`` each and waits ``--finality-wait``;
    the end waits for the last deadline and finality, then sweeps. Every
    request is signed to expire by this horizon, so the storage bound up to
    it holds even if chain time runs ahead of these waits.
    """
    funding = (funding_externals + 1) * a.deploy_wait
    attempt = plan.step_seconds + 2 * a.drain + a.finality_wait
    ramp = (1 + plan.repeats) * plan.steps * attempt
    tail = a.drain + 2 * a.lifetime + a.deadline_grace + a.finality_wait
    horizon = now + 2 * remote.REQUEST_LIFETIME + math.ceil(funding + ramp + tail)
    if not now < horizon < (1 << 32):
        raise ValueError(f"the fee horizon {horizon} does not fit a request deadline")
    return horizon


def transfer_bounds(
    config: remote.FeeConfig, wallets: list[QuantumWallet], plan: Plan
) -> dict[int, remote.ExternalFee]:
    """The fee bound of one load external of every action count the plan uses.

    The external is built as ``Ramp.issue`` builds it: wallet 0 sending
    ``transfer_value + i`` to its peers in turn. Addresses, nonce and
    deadline are fixed-width, so every wallet's external of that count has
    the same size, and so the same bound.
    """
    out: dict[int, remote.ExternalFee] = {}
    sender = wallets[0]
    for size in planned_sizes(plan):
        peers = destinations(0, 0, size, plan.batch, len(wallets))
        values = [plan.transfer_value + i for i in range(size)]
        actions = transfer_actions(sender.address, [wallets[p].address for p in peers], values)
        out[size] = remote.external_fee_bound(
            config, f"transfer x{size}", unsigned_external(sender, actions), actions
        )
    return out


def derive_fees(
    config: remote.FeeConfig,
    plan: Plan,
    horizon: int,
    now: int,
    bench: BenchWallet,
    bench_deployed: bool,
    bench_stat: tuple[int, int, int, int],
    funding_actions: list[MessageAny],
    funding_amounts: list[int],
    wallets: list[QuantumWallet],
    wallet_stats: list[tuple[int, int, int, int] | None],
    sweep_target: Address,
) -> RampFees:
    """The whole ramp's fee bound from the configuration and what the survey read."""
    if config.workchain != 0:
        raise ValueError("the ramp's wallets run on the basechain")
    for what, address in [("bench wallet", bench.address)] + [
        (f"load wallet {i}", w.address) for i, w in enumerate(wallets)
    ]:
        if address.wc != config.workchain:
            raise ValueError(f"the {what} is on workchain {address.wc}, not the basechain")
    if len(wallet_stats) != len(wallets) or len(funding_amounts) != len(funding_actions):
        raise ValueError("the survey does not match the load wallets")
    funding = [
        remote.external_fee_bound(
            config,
            f"funding {k}",
            bench.unsigned_external(
                funding_actions[i : i + plan.deploy_batch], k == 0 and not bench_deployed
            ),
            funding_actions[i : i + plan.deploy_batch],
        )
        for k, i in enumerate(range(0, len(funding_actions), plan.deploy_batch))
    ]
    bench_storage = remote.account_storage(
        config, bench.wallet.state_init.serialize(), bench_stat, now, horizon
    )
    counts = planned_sizes(plan)
    transfers = transfer_bounds(config, wallets, plan)
    sweep_actions = [transfer_message(wallets[0].address, sweep_target, 0)]
    sweep = remote.external_fee_bound(
        config, "sweep", unsigned_external(wallets[0], sweep_actions, SWEEP_MODE), sweep_actions
    )
    gas = config.gas
    receipts = sum(gas.internal_fee(x) for x in funding_amounts)
    recipients = sum(
        n * sum(gas.internal_fee(plan.transfer_value + i) for i in range(size))
        for size, n in counts.items()
    )
    until = horizon + DELIVERY_SLACK
    load_storage = [
        remote.account_storage(config, w.state_init.serialize(), s, now, until)
        for w, s in zip(wallets, wallet_stats, strict=True)
    ]
    return RampFees(
        horizon,
        funding,
        bench_storage,
        transfers,
        counts,
        sweep,
        receipts,
        recipients,
        load_storage,
    )


# ─── send outcomes ───────────────────────────────────────────────────


def classify_send_error(error: RpcError) -> tuple[bool, str]:
    """(definitely refused, reason) for an error answer to sendBoc.

    Only answers that say the node did not take the message are refusals: an
    invalid request, or the node's external check rejecting it. Anything
    else could have reached the network and is ambiguous.
    """
    detail = error.error if isinstance(error.error, dict) else {}
    code = detail.get("code")
    message = str(detail.get("message", ""))[:300]
    if code == -32602:
        return True, f"invalid request: {message}"
    if "cannot apply external message" in message:
        if f"exitcode={BAD_NONCE}," in message:
            return True, "seqno conflict: the wallet's nonce moved"
        return True, f"external rejected: {message}"
    return False, f"unclassified error: HTTP {error.status}, code {code}: {message}"


# ─── the follower ────────────────────────────────────────────────────


class Follower:
    """Walks every masterchain block and the shard blocks it commits, feeding the ledger."""

    def __init__(
        self,
        rpc: PacedRpc,
        ledger: Ledger,
        on_included: Callable[[External], None],
        first: McRecord,
        poll: float,
        per_round: int = 16,
    ):
        self.rpc, self.ledger, self.on_included = rpc, ledger, on_included
        self.mcs: list[McRecord] = [first]
        self.poll, self.per_round = poll, per_round
        self.last_advance = time.monotonic()
        self.errors = 0
        self.incomplete_blocks: list[list[int]] = []
        self.closed = False

    @property
    def last(self) -> McRecord:
        return self.mcs[-1]

    @property
    def chain_now(self) -> int:
        return self.last.gen_utime

    async def round(self) -> int:
        info = await self.rpc.call("getMasterchainInfo")
        head = t2collect.parse_block_id(info.get("last")).seqno
        if head <= self.last.seqno:
            return 0
        hi = min(head, self.last.seqno + self.per_round)
        fresh = await t2collect.read_masterchain(self.rpc, self.last.seqno + 1, hi)
        for cur in fresh:
            blocks = await t2collect.walk_blocks(self.rpc, [self.last, cur], max_blocks=4096)
            # Load wallets are basechain accounts, so masterchain transactions are not read.
            txs = await t2collect.read_all_transactions(self.rpc, [b.ref for b in blocks.values()])
            for key, block in txs.items():
                if not block.complete:
                    self.incomplete_blocks.append(list(key))
            included = self.ledger.observe(
                (tx, cur.seqno, cur.gen_utime) for block in txs.values() for tx in block.txs
            )
            for ext in included:
                self.on_included(ext)
            self.mcs.append(cur)
            self.last_advance = time.monotonic()
        return len(fresh)

    async def run(self) -> None:
        while not self.closed:
            try:
                if await self.round():
                    continue
            except Exception as error:  # a failed read is retried; the stall check stops a run
                self.errors += 1
                log.warning("follower read failed: %s", type(error).__name__)
            await asyncio.sleep(max(self.poll, 0.02))

    async def reach(self, seqno: int, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while self.last.seqno < seqno and time.monotonic() < deadline:
            await asyncio.sleep(self.poll or 0.05)
        return self.last.seqno >= seqno


# ─── the run ─────────────────────────────────────────────────────────


@dataclass
class Endpoint:
    url: str
    rpc: PacedRpc  # retries the rate gate; for reads
    send: PacedRpc  # one attempt; shares the read client's budget


@dataclass
class Ramp:
    a: argparse.Namespace
    plan: Plan
    rule: StepRule
    endpoints: list[Endpoint]
    signer: Signs
    wallets: list[LoadWallet]
    ledger: Ledger
    horizon: int  # no request may expire after this chain time (``fee_horizon``)
    fee_bounds: dict[int, int]  # one load external's fee bound by action count, storage aside
    storage_bounds: list[int]  # each load wallet's storage bound over the whole run
    follower: Follower | None = None
    stop_reason: str | None = None
    fee_overruns: list[dict[str, Any]] = field(default_factory=list)
    fees_unreported: int = 0
    tasks: set[asyncio.Task[None]] = field(default_factory=set)
    steps_done: list[dict[str, Any]] = field(default_factory=list)
    stated_rate: float | None = None
    _cursor: int = 0
    _send_cursor: int = 0

    @property
    def reader(self) -> PacedRpc:
        return self.endpoints[0].rpc

    def chain_now(self) -> int:
        assert self.follower is not None
        return self.follower.chain_now

    # ── wallet state ──

    def included(self, ext: External) -> None:
        if ext.wallet == NO_WALLET:
            return
        w = self.wallets[ext.wallet]
        w.nonce = max(w.nonce, ext.nonce + 1)
        if w.busy is ext:
            w.busy = None
        self.check_fee(ext)

    def check_fee(self, ext: External) -> None:
        """Stop the ramp when an executed external cost more than its derived bound.

        The node reports total_fees, which holds the import, storage and gas
        fees and the share of every forwarding fee collected in this block;
        it never exceeds what the wallet paid, so a total_fees over the
        bound plus all the storage the wallet may owe proves the fee model
        wrong, and with it the cost bound.
        """
        if ext.tx_fee is None or ext.fee_bound is None:
            self.fees_unreported += 1
            return
        limit = ext.fee_bound + self.storage_bounds[ext.wallet]
        if ext.tx_fee <= limit:
            return
        self.fee_overruns.append({"external": ext.msg_hash, "fee": ext.tx_fee, "bound": limit})
        if self.stop_reason is None:
            self.stop_reason = (
                f"load external {ext.msg_hash} cost {ext.tx_fee} nanotos in fees, over its"
                f" derived bound {limit}"
            )
            log.error("stopping new submissions: %s", self.stop_reason)

    def release(self, ext: External, resync: bool) -> None:
        w = self.wallets[ext.wallet]
        if w.busy is ext:
            w.busy = None
        w.resync = w.resync or resync

    def housekeeping(self) -> None:
        now = self.chain_now()
        for w in self.wallets:
            ext = w.busy
            if (
                ext is not None
                and ext.tx_hash is None
                and now > ext.deadline + self.a.deadline_grace
            ):
                # Past its deadline nothing can execute it any more; learn the nonce again.
                w.busy, w.resync = None, True
            if w.resync and not w.resyncing and w.busy is None:
                w.resyncing = True
                self._spawn(self.resync(w))

    async def resync(self, w: LoadWallet) -> None:
        try:
            answer = await self.reader.call("getAddressInformation", {"address": w.address})
            data = answer.get("data") if isinstance(answer, dict) else None
            if not isinstance(data, str) or not data:
                raise ValueError("a load wallet has no data")
            w.nonce = primary_nonce(Cell.one_from_boc(base64.b64decode(data)))
            w.resync = False
        except Exception as error:  # the wallet stays out of use until a read succeeds
            log.warning("resync of load wallet %d failed: %s", w.index, type(error).__name__)
        finally:
            w.resyncing = False

    def next_free(self) -> LoadWallet | None:
        n = len(self.wallets)
        for k in range(n):
            w = self.wallets[(self._cursor + k) % n]
            if w.free:
                self._cursor = (w.index + 1) % n
                return w
        return None

    def _spawn(self, coro: Any) -> None:
        task = asyncio.ensure_future(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    # ── stop conditions ──

    def check_stop(self) -> None:
        if self.stop_reason is not None:
            return
        if self.a.stop_file is not None and self.a.stop_file.exists():
            self.stop_reason = f"stop file {self.a.stop_file} present"
        elif self.ledger.duplicates:
            self.stop_reason = "the ledger saw a duplicate"
        elif (
            self.follower is not None
            and time.monotonic() - self.follower.last_advance > STALL_SECONDS
        ):
            self.stop_reason = f"masterchain head did not advance for {STALL_SECONDS:g} s"
        if self.stop_reason is not None:
            log.error("stopping new submissions: %s", self.stop_reason)

    # ── sending ──

    def send_room(self) -> list[int]:
        return [max(0, e.send.budget.room()) for e in self.endpoints]

    def pick_endpoint(self, room: list[int]) -> Endpoint | None:
        n = len(self.endpoints)
        for k in range(n):
            i = (self._send_cursor + k) % n
            if room[i] > 0:
                room[i] -= 1
                self._send_cursor = (i + 1) % n
                return self.endpoints[i]
        return None

    def build(self, step: int, intended: float, size: int, w: LoadWallet | None) -> External:
        n, batch = len(self.wallets), self.plan.batch
        sender = w.index if w is not None else 0
        seqno = w.seqno if w is not None else len(self.ledger.externals)
        peers = destinations(sender, seqno, size, batch, n)
        values = tuple(self.plan.transfer_value + i for i in range(size))
        ext = External(
            wallet=w.index if w is not None else NO_WALLET,
            seqno=seqno,
            nonce=w.nonce if w is not None else 0,
            step=step,
            intended=intended,
            sender=w.address if w is not None else "",
            destinations=tuple(self.wallets[p].address for p in peers),
            values=values,
        )
        if w is not None:
            w.seqno += 1
        return self.ledger.add(ext)

    async def issue(self, step: int, due: list[tuple[float, int]]) -> None:
        """Build, sign and submit the externals that are due now."""
        room = self.send_room()
        ready: list[tuple[External, LoadWallet, Endpoint, Cell]] = []
        for intended, size in due:
            w = self.next_free()
            if w is None:
                self.ledger.refuse(self.build(step, intended, size, None), "local: no free wallet")
                continue
            ext = self.build(step, intended, size, w)
            endpoint = self.pick_endpoint(room)
            if endpoint is None:
                self.ledger.refuse(ext, "local: no send budget")
                continue
            now = self.chain_now()
            # Capped at the fee horizon, so the storage bound covers every execution.
            ext.deadline = min(now + self.a.lifetime, self.horizon)
            if ext.deadline <= now:
                self.ledger.refuse(ext, "local: past the fee horizon")
                if self.stop_reason is None:
                    self.stop_reason = f"chain time {now} reached the fee horizon {self.horizon}"
                    log.error("stopping new submissions: %s", self.stop_reason)
                continue
            ext.fee_bound = self.fee_bounds.get(size)
            if ext.fee_bound is None:
                self.ledger.refuse(ext, f"local: no fee bound for {size} actions")
                continue
            actions = transfer_actions(
                w.wallet.address, [Address(d) for d in ext.destinations], list(ext.values)
            )
            request = w.wallet.request(ext.nonce, actions, ext.deadline, mode=SEND_MODE)
            w.busy = ext
            ready.append((ext, w, endpoint, request))
        if not ready:
            return
        try:
            signatures = await asyncio.to_thread(
                self.signer.sign, [(w.seed, request.hash) for _, w, _, request in ready]
            )
        except Exception as error:
            for ext, *_ in ready:
                self.ledger.refuse(ext, f"local: signing failed ({type(error).__name__})")
                self.release(ext, False)
            return
        for (ext, w, endpoint, request), signature in zip(ready, signatures):
            message = w.wallet.external(request, signature)
            cell = message.serialize()
            boc = base64.b64encode(cell.to_boc()).decode()
            self.ledger.submitted(ext, cell.hash.hex(), endpoint.url, time.time())
            self._spawn(self.submit(ext, endpoint, boc))

    async def submit(self, ext: External, endpoint: Endpoint, boc: str) -> None:
        try:
            await endpoint.send.call("sendBoc", {"boc": boc})
        except RateLimited as error:
            self.ledger.refuse(ext, f"rate gate: {error.reason}")
            self.release(ext, False)
        except RpcError as error:
            definite, reason = classify_send_error(error)
            if definite:
                self.ledger.refuse(ext, reason)
                self.release(ext, reason.startswith("seqno conflict"))
            else:
                # Held until its deadline passes: it may still execute, and is never resent.
                self.ledger.ambiguous(ext, reason)
        except Exception as error:  # no answer: the message may have reached the network
            self.ledger.ambiguous(ext, f"no answer: {type(error).__name__}")
        else:
            self.ledger.accept(ext)
        if ext.submission == "refused" and ext.tx_hash is not None:
            self.ledger.anomalies.append(
                {"reason": "a refused external executed", "msg": ext.msg_hash}
            )

    # ── steps ──

    async def config(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for param in (12, 22, 23):
            try:
                out[str(param)] = await self.reader.call("getConfigParam", {"param": param})
            except Exception as error:
                out[str(param)] = {"error": type(error).__name__}
        return out

    async def head(self) -> int:
        info = await self.reader.call("getMasterchainInfo")
        return t2collect.parse_block_id(info.get("last")).seqno

    async def step(self, index: int, attempt: int, rate: float) -> dict[str, Any]:
        assert self.follower is not None
        plan = self.plan
        config = await self.config()
        mc_from = await self.head()
        step_id = len(self.steps_done)
        total = transfers_in(rate, plan.step_seconds)
        count = externals_for(total, plan.batch)
        start = time.time()
        end = start + plan.step_seconds
        j = 0
        log.info(
            "step %d (attempt %d): %g transfers/s for %d s", index, attempt, rate, plan.step_seconds
        )
        while j < count and self.stop_reason is None:
            now = time.time()
            due: list[tuple[float, int]] = []
            while j < count and start + j * plan.batch / rate <= now:
                due.append((start + j * plan.batch / rate, min(plan.batch, total - j * plan.batch)))
                j += 1
            if due:
                await self.issue(step_id, due)
            self.housekeeping()
            self.check_stop()
            await asyncio.sleep(self.a.tick)
        while time.time() < end and self.stop_reason is None:
            self.housekeeping()
            self.check_stop()
            await asyncio.sleep(self.a.tick)
        mc_to = await self.head()
        mine = [e for e in self.ledger.externals if e.step == step_id]
        drain_until = time.monotonic() + self.a.drain
        while time.monotonic() < drain_until and not all(e.settled() for e in mine):
            self.housekeeping()
            await asyncio.sleep(self.a.tick)
        await self.follower.reach(mc_to, self.a.drain)
        needed = max([mc_to, *(m for e in mine for m in e.recipient_mc if m is not None)])
        finalized = await t2collect.wait_finalized(
            [e.rpc for e in self.endpoints], needed, self.a.finality_wait, self.a.poll
        )
        lo, hi = math.ceil(start + plan.warmup), math.floor(end)
        metrics = step_metrics(mine, lo, max(hi, lo + 1), finalized, self.rule)
        layout = step_layout(self.follower.mcs, mc_from, mc_to)
        record = {
            "step": step_id,
            "rate_index": index,
            "attempt": attempt,
            "rate": rate,
            "window": [start, end],
            "externals_planned": count,
            "externals_built": len(mine),
            "finalized_mc": finalized,
            "config": config,
            "layout": layout,
            "counts": layout["stable"],
            "outcomes": self.ledger.counts(finalized, step_id),
            "metrics": metrics,
            "passed": metrics["passed"] and layout["stable"],
            "stopped": self.stop_reason,
        }
        self.steps_done.append(record)
        log.info(
            "step %d: offered %.1f/s completed %.1f/s backlog %d->%d p95 %s layout %s: %s",
            step_id,
            metrics["offered_per_s"],
            metrics["completed_per_s"],
            metrics["backlog_at_start"],
            metrics["backlog_at_end"],
            metrics["p95_s"],
            "stable" if layout["stable"] else "CHANGED",
            "PASS" if record["passed"] else "FAIL",
        )
        return record

    async def ramp(self) -> str | None:
        """Run the steps; the stated rate is the last counted passing step's."""
        stated: float | None = None
        for index, rate in enumerate(self.plan.rates()):
            record: dict[str, Any] | None = None
            for attempt in range(1 + self.plan.repeats):
                record = await self.step(index, attempt, rate)
                if self.stop_reason is not None or record["counts"]:
                    break
                log.warning("step %d spanned a layout change; repeating at %g/s", index, rate)
            assert record is not None
            if self.stop_reason is not None:
                break
            if not record["counts"]:
                self.stop_reason = "no stable layout within the layout repeats"
                break
            if not record["passed"]:
                break
            stated = rate
        self.stated_rate = stated
        return self.stop_reason


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="run_t4_ramp.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--rpc", action="append", required=True, help="JSON-RPC URL (repeatable)")
    p.add_argument("--rpc-share", type=float, default=0.25, help="share of each per-IP budget")
    p.add_argument("--out", type=Path, required=True, help="new directory for all outputs")
    p.add_argument("--key-file", type=Path, required=True, help="bench wallet key (JSON, 0600)")
    p.add_argument("--signer", type=Path, required=True, help="bench-pq-signer executable")
    p.add_argument("--signer-threads", type=int, default=4)
    p.add_argument("--auth-tag", required=True, help="the network's 32-byte AUTH tag (hex)")
    p.add_argument("--build", type=Path, default=hopbench.ROOT / "build")
    p.add_argument("--wallet-code", type=Path, help="precompiled wallet BOC instead of --build")
    p.add_argument("--wallets", type=int, required=True, help="load wallets")
    p.add_argument("--batch", type=int, default=100, help="transfers per external (1..255)")
    p.add_argument("--start-rate", type=float, default=100.0, help="transfers/s of step 0")
    p.add_argument("--factor", type=float, default=2.0, help="rate multiplier per step")
    p.add_argument("--steps", type=int, default=6)
    p.add_argument("--step-seconds", type=int, default=300)
    p.add_argument("--warmup", type=int, default=30, help="seconds not measured at step start")
    p.add_argument("--layout-repeats", type=int, default=1)
    p.add_argument("--transfer-value", type=float, default=0.001, help="TOS per transfer")
    p.add_argument("--wallet-funding", type=float, required=True, help="TOS per load wallet")
    p.add_argument("--max-cost", type=float, required=True, help="TOS the run may cost at most")
    p.add_argument("--max-transfers", type=int, required=True)
    p.add_argument("--tolerance", type=float, default=0.01, help="completed vs offered")
    p.add_argument("--p95-limit", type=float, default=30.0, help="seconds")
    p.add_argument("--backlog-slack", type=int, help="transfers (default: one batch)")
    p.add_argument("--lifetime", type=int, default=60, help="seconds a load request is valid")
    p.add_argument(
        "--deadline-grace",
        type=float,
        default=DEADLINE_GRACE,
        help="chain seconds past a request's deadline before its wallet is reused",
    )
    p.add_argument("--drain", type=float, default=120.0, help="seconds to drain after a step")
    p.add_argument("--finality-wait", type=float, default=120.0)
    p.add_argument("--deploy-wait", type=float, default=900.0)
    p.add_argument("--poll", type=float, default=0.5)
    p.add_argument("--tick", type=float, default=0.1)
    p.add_argument("--stop-file", type=Path, help="stop new submissions once this file exists")
    p.add_argument("--return-to", help="basechain address for the load wallets' leftovers")
    p.add_argument("--no-sweep", action="store_true", help="leave the load wallets funded")
    a = p.parse_args(argv)
    if not 0 < a.rpc_share <= 1:
        p.error("--rpc-share must be in (0, 1]")
    if not 1 <= a.lifetime <= 3000:
        p.error("--lifetime must be in [1, 3000] seconds")
    for name in ("deadline_grace", "drain", "finality_wait", "deploy_wait", "poll", "tick"):
        value = getattr(a, name)
        if not (math.isfinite(value) and value >= 0):
            p.error(f"--{name.replace('_', '-')} must be a finite non-negative number")
    try:
        a.auth = bytes.fromhex(a.auth_tag)
    except ValueError:
        p.error("--auth-tag must be hex")
    if len(a.auth) != 32:
        p.error("--auth-tag must be 32 bytes")
    return a


def nano(value: float) -> int:
    return round(value * NANO)


def load_code(a: argparse.Namespace, scratch: Path) -> Cell:
    if a.wallet_code is not None:
        return Cell.one_from_boc(a.wallet_code.read_bytes())
    from pqbench import contracts

    return contracts.build(a.build, scratch)["quantum"]


def plan_of(a: argparse.Namespace, deploy_batch: int) -> Plan:
    return Plan(
        wallets=a.wallets,
        batch=a.batch,
        start_rate=a.start_rate,
        factor=a.factor,
        steps=a.steps,
        step_seconds=a.step_seconds,
        warmup=a.warmup,
        repeats=a.layout_repeats,
        transfer_value=nano(a.transfer_value),
        wallet_funding=nano(a.wallet_funding),
        deploy_batch=deploy_batch,
    )


# ─── exit statuses ───────────────────────────────────────────────────
#
# 0 PASSED   the ramp ran as specified: every step counted and passed, or it
#            ended at the first counted failing step (the stated rate is the
#            last passing step's, None when step 0 failed);
# 1 FAILED   the ledger saw an anomaly or a duplicate: a transfer or external
#            the chain showed does not match what was sent, so no rate holds;
# 3 REFUSED  refused before anything was sent (shard.remote.REFUSED): a plan
#            or bound over its limit, or no fee bound, with no out directory;
# 4 STOPPED  stopped after sending without an answer (shard.remote.INCONCLUSIVE):
#            a stop file, a stalled head, no stable layout within the repeats,
#            the fee horizon reached, a real fee over its derived bound, a
#            funding or activation failure, or an unexpected error.
PASSED = 0
FAILED = 1
STOPPED = remote.INCONCLUSIVE


def exit_status(stop_reason: str | None, anomalies: int, duplicates: int) -> int:
    """The process status of a ramp that sent something; a ledger anomaly outranks a stop."""
    if anomalies or duplicates:
        return FAILED
    if stop_reason is not None:
        return STOPPED
    return PASSED


# ─── preparation: survey, bound, funding ─────────────────────────────


class Stopped(Exception):
    """The run stopped after it sent something, before the ramp could start."""


@dataclass
class Survey:
    """What the load wallets need, read before anything is sent."""

    actions: list[MessageAny]
    amounts: list[int]
    deployed: int
    topped: int
    stats: list[tuple[int, int, int, int] | None]


async def survey(
    bench: BenchWallet, remote_: Remote, wallets: list[LoadWallet], plan: Plan
) -> Survey:
    """Read every load wallet; the actions that deploy or top it up to its funding. Reads only."""
    out = Survey([], [], 0, 0, [])
    for w in wallets:
        state = await remote_.account(w.wallet.address)
        balance = int(state.get("balance", 0))
        stat = remote.storage_stat(state)
        if state.get("state") == "active":
            data = state.get("data")
            if not isinstance(data, str) or not data:
                raise ValueError(f"load wallet {w.index} is active but has no data")
            if stat is None:
                raise ValueError(
                    f"the node reports no storage statistics for load wallet {w.index}"
                )
            w.nonce = primary_nonce(Cell.one_from_boc(base64.b64decode(data)))
            if balance < plan.wallet_funding:
                amount = plan.wallet_funding - balance
                out.actions.append(transfer_message(bench.address, w.wallet.address, amount))
                out.amounts.append(amount)
                out.topped += 1
        else:
            out.actions.append(w.wallet.deployment_message(bench.address, plan.wallet_funding))
            out.amounts.append(plan.wallet_funding)
            out.deployed += 1
        out.stats.append(stat)
    return out


async def fund(
    bench: BenchWallet,
    remote_: Remote,
    wallets: list[LoadWallet],
    plan: Plan,
    found: Survey,
    fees: RampFees,
    deploy_wait: float,
) -> dict[str, Any]:
    """Send the surveyed funding, checking every external's real fee against its bound."""
    paid: list[int] = []
    for k, i in enumerate(range(0, len(found.actions), plan.deploy_batch)):
        chunk = found.actions[i : i + plan.deploy_batch]
        attached = sum(found.amounts[i : i + plan.deploy_batch])
        try:
            spent = await bench.send(chunk, "load-wallet funding", deploy_wait, fees.horizon)
        except (remote.HorizonPassed, RuntimeError, ValueError, RpcError, RateLimited) as error:
            raise Stopped(f"funding external {k}: {error}") from error
        fee = spent - attached
        paid.append(fee)
        # Cross-check the fee model on a real transaction: no funding external may
        # cost more than its own bound plus all the storage the bench wallet may owe.
        limit = fees.funding[k].total + fees.bench_storage.fee
        if fee > limit:
            raise Stopped(
                f"funding external {k} cost {fee} nanotos in fees, over its bound {limit}"
            )
    missing = await remote_.wait_active([w.wallet.address for w in wallets], deploy_wait)
    if missing:
        raise Stopped(f"{len(missing)} load wallets never became active")
    return {
        "deployed": found.deployed,
        "topped_up": found.topped,
        "funding_attached": sum(found.amounts),
        "funding_fees": paid,
        "funding_fee_bounds": [x.total + fees.bench_storage.fee for x in fees.funding],
    }


async def sweep(ramp: Ramp, target: Address) -> dict[str, Any]:
    """Return each load wallet's balance to ``target`` with one external (mode 130)."""
    await asyncio.gather(*(ramp.resync(w) for w in ramp.wallets))
    out: dict[str, Any] = {"accepted": 0, "refused": 0, "ambiguous": 0, "skipped": 0}
    ready: list[tuple[LoadWallet, Cell]] = []
    now = ramp.chain_now()
    deadline = min(now + ramp.a.lifetime, ramp.horizon)
    if deadline <= now:
        out |= {"skipped": len(ramp.wallets), "not_executed": 0, "reason": "past the fee horizon"}
        return out
    for w in ramp.wallets:
        if w.resync:
            out["skipped"] += 1
            continue
        message = transfer_message(w.wallet.address, target, 0)
        ready.append((w, w.wallet.request(w.nonce, [message], deadline, mode=SWEEP_MODE)))
    signatures = await asyncio.to_thread(
        ramp.signer.sign, [(w.seed, request.hash) for w, request in ready]
    )
    sent: list[LoadWallet] = []
    for (w, request), signature in zip(ready, signatures):
        boc = base64.b64encode(w.wallet.external(request, signature).serialize().to_boc())
        try:
            await ramp.reader.call("sendBoc", {"boc": boc.decode()})
            out["accepted"] += 1
            sent.append(w)
        except RpcError as error:
            definite = classify_send_error(error)[0]
            out["refused" if definite else "ambiguous"] += 1
            if not definite:
                sent.append(w)
        except Exception:
            out["ambiguous"] += 1
            sent.append(w)
    # Wait until every sweep that may have reached the network has executed or expired.
    pending = {w.index: w.nonce for w in sent}
    give_up = time.monotonic() + ramp.a.drain + ramp.a.lifetime
    while pending and time.monotonic() < give_up:
        for w in [ramp.wallets[i] for i in pending]:
            state = await ramp.reader.call("getAddressInformation", {"address": w.address})
            data = state.get("data") if isinstance(state, dict) else None
            if isinstance(data, str) and data:
                if primary_nonce(Cell.one_from_boc(base64.b64decode(data))) > pending[w.index]:
                    pending.pop(w.index)
        if pending:
            await asyncio.sleep(ramp.a.poll or 0.05)
    out["not_executed"] = len(pending)
    return out


def refuse(why: str) -> int:
    print(f"refused: {why}", file=sys.stderr)
    return REFUSED


async def run(a: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory() as scratch:
        try:
            code = load_code(a, Path(scratch))
            transfer_bytes, deploy_batch, deploy_bytes = size_plan(
                code, max(1, min(a.batch, 255)), nano(a.transfer_value), nano(a.wallet_funding)
            )
            plan = validate_plan(plan_of(a, max(1, deploy_batch)))
            rule = StepRule(
                a.tolerance, a.p95_limit, plan.batch if a.backlog_slack is None else a.backlog_slack
            )
            return_to = Address(a.return_to) if a.return_to else None
        except (ValueError, OSError) as error:
            return refuse(str(error))
    # Nothing is read before this first check: the funding alone must fit.
    bound = work_bound(plan)
    sizes = {"transfer_external_bytes": transfer_bytes, "deploy_external_bytes": deploy_bytes}
    print(
        json.dumps({"work_bound": bound.as_dict(), "plan": asdict(plan), "sizes": sizes}, indent=2),
        flush=True,
    )
    why = refusal(bound, nano(a.max_cost), a.max_transfers)
    if transfer_bytes > EXT_MESSAGE_BUDGET:
        why = (
            why + "; " if why else ""
        ) + f"a {plan.batch}-transfer external is {transfer_bytes} bytes"
    if deploy_batch < 1:
        why = (why + "; " if why else "") + "no deployment fits one external"
    if why is not None:
        return refuse(why)

    try:
        key = remote.load_key(a.key_file)
        bench_signer = remote.Signer(a.signer, key)
        signer = BatchSigner(a.signer, a.signer_threads)
    except (ValueError, OSError) as error:
        return refuse(str(error))
    endpoints = []
    for url in a.rpc:
        reader = PacedRpc(url, a.rpc_share)
        endpoints.append(
            Endpoint(url, reader, PacedRpc(url, a.rpc_share, attempts=1, budget=reader.budget))
        )
    remote_ = Remote([e.rpc for e in endpoints], a.poll)

    # Reads only from here to the second check: the configuration, the bench
    # wallet and every load wallet, and the fee bound derived from them.
    try:
        header = await remote_.mc_header()
        now, global_id = int(header["gen_utime"]), int(header["global_id"])
        bench = BenchWallet(
            remote.bench_wallet(code, global_id, a.auth, key, bench_signer.public_key()),
            bench_signer,
            remote_,
        )
        seeds = [load_seed(key.seed, i) for i in range(plan.wallets)]
        keys = await asyncio.to_thread(signer.public_keys, seeds)
        wallets = [
            LoadWallet(i, load_wallet(code, global_id, a.auth, i, pk, key.rescue_public_key), s)
            for i, (s, pk) in enumerate(zip(seeds, keys))
        ]
        if len({w.address for w in wallets}) != len(wallets):
            raise ValueError("two load wallets share an address")
        config = await remote_.fee_config(0)
        balance_before, bench_nonce = await bench.state()
        bench_stat = await bench.storage()
        found = await survey(bench, remote_, wallets, plan)
        funding_externals = externals_for(len(found.actions), plan.deploy_batch)
        horizon = fee_horizon(now, plan, a, funding_externals)
        fees = derive_fees(
            config,
            plan,
            horizon,
            now,
            bench,
            bench_nonce is not None,
            bench_stat,
            found.actions,
            found.amounts,
            [w.wallet for w in wallets],
            found.stats,
            return_to if return_to is not None else bench.address,
        )
    except (ValueError, RpcError, RateLimited, RuntimeError) as error:
        return refuse(f"no fee bound: {error}")
    bound = work_bound(plan, fees)
    print(
        json.dumps(
            {
                "work_bound": bound.as_dict(),
                "fee_bound": fees.as_dict(),
                "fee_config": config.as_dict(),
            },
            indent=2,
        ),
        flush=True,
    )
    why = refusal(bound, nano(a.max_cost), a.max_transfers)
    if why is not None:
        return refuse(why)
    if balance_before < bound.cost:
        return refuse(
            f"the bench wallet holds {balance_before} nanotos; the run may cost {bound.cost}"
        )

    a.out = a.out.resolve()
    a.out.mkdir(parents=True, exist_ok=False)
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s][%(asctime)s][%(name)s] %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler(a.out / "bench.log")],
        force=True,
    )
    log.info("bench wallet %s on global id %d", raw(bench.address), global_id)
    record: dict[str, Any] = {
        "scope": "REMOTE: T4 transfer ramp over JSON-RPC",
        "source_commit": remote.source_commit(),
        "endpoints": a.rpc,
        "global_id": global_id,
        "plan": asdict(plan),
        "rule": asdict(rule),
        "work_bound": bound.as_dict(),
        "fee_bound": fees.as_dict(),
        "fee_config": config.as_dict(),
        "fee_horizon": horizon,
        "sizes": sizes,
        "bench_wallet": raw(bench.address),
        "wallet_code_hash": code.hash.hex(),
        "load_wallets": [w.address for w in wallets],
    }
    out_record = a.out / "results.json"

    def write() -> None:
        out_record.write_text(json.dumps(record, indent=2) + "\n")

    try:
        record["preparation"] = await fund(
            bench, remote_, wallets, plan, found, fees, a.deploy_wait
        )
    except Stopped as error:
        record |= {"stopped": str(error), "exit_status": STOPPED}
        write()
        log.error(record["stopped"])
        return STOPPED

    ledger = Ledger(w.address for w in wallets)
    ramp = Ramp(
        a,
        plan,
        rule,
        endpoints,
        signer,
        wallets,
        ledger,
        horizon,
        {k: x.total for k, x in fees.transfers.items()},
        [x.fee for x in fees.load_storage],
    )
    first = (await t2collect.read_masterchain(ramp.reader, (h := await ramp.head()), h))[0]
    ramp.follower = Follower(ramp.reader, ledger, ramp.included, first, a.poll)
    follower_task = asyncio.ensure_future(ramp.follower.run())
    record["config_start"] = await ramp.config()
    try:
        await ramp.ramp()
    finally:
        # Wait for every submission to answer, then for every request to expire on chain.
        if ramp.tasks:
            await asyncio.gather(*list(ramp.tasks), return_exceptions=True)
        latest = max([e.deadline for e in ledger.externals] or [0])
        wait_until = time.monotonic() + a.drain + a.lifetime + a.deadline_grace
        while ramp.chain_now() <= latest + a.deadline_grace and time.monotonic() < wait_until:
            await asyncio.sleep(a.poll or 0.05)
        needed = max(
            [ramp.follower.last.seqno, *(m for e in ledger.externals for m in e.recipient_mc if m)]
        )
        finalized = await t2collect.wait_finalized(
            [e.rpc for e in endpoints], needed, a.finality_wait, a.poll
        )
        ramp.follower.closed = True
        await follower_task
    with (a.out / "ledger.jsonl").open("w") as f:
        for row in ledger.rows(finalized):
            f.write(json.dumps(row) + "\n")
    (a.out / "masterchain.json").write_text(
        json.dumps([asdict(m) for m in ramp.follower.mcs]) + "\n"
    )
    status = exit_status(ramp.stop_reason, len(ledger.anomalies), ledger.duplicates)
    record |= {
        "steps": ramp.steps_done,
        "stated_rate": ramp.stated_rate,
        "stated_layout": next(
            (s["layout"]["layout"] for s in reversed(ramp.steps_done) if s["passed"]), None
        ),
        "stopped": ramp.stop_reason,
        "exit_status": status,
        "finalized_mc": finalized,
        "outcomes": ledger.counts(finalized),
        "anomalies": ledger.anomalies[:1000],
        "anomaly_count": len(ledger.anomalies),
        "duplicates": ledger.duplicates,
        "foreign_externals": ledger.foreign_externals,
        "fee_check": {
            "overruns": ramp.fee_overruns[:1000],
            "overrun_count": len(ramp.fee_overruns),
            "unreported": ramp.fees_unreported,
        },
        "follower": {
            "errors": ramp.follower.errors,
            "incomplete_blocks": ramp.follower.incomplete_blocks,
            "mc_from": ramp.follower.mcs[0].seqno,
            "mc_to": ramp.follower.last.seqno,
        },
        "config_end": await ramp.config(),
    }
    if not a.no_sweep:
        target = return_to if return_to is not None else bench.address
        record["sweep"] = {"to": raw(target), **await sweep(ramp, target)}
    balance_after, _ = await bench.state()
    record["wallet_balance"] = {
        "before": balance_before,
        "after": balance_after,
        "spent": balance_before - balance_after,
        "cost_bound": bound.cost,
    }
    record["rpc"] = [e.rpc.stats() for e in endpoints]
    write()
    log.info("stated rate %s; outcomes %s", ramp.stated_rate, record["outcomes"])
    return status


def main(argv: list[str]) -> int:
    os.umask(0o077)
    try:
        return asyncio.run(run(parse_args(argv)))
    except Exception:
        # A crash is not a verdict: exit 1 would read as a failed ramp.
        log.exception("the ramp stopped on an unexpected error")
        return STOPPED
