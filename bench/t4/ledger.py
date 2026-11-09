"""The T4 per-transfer ledger and the step pass rule.

A transfer is keyed by (wallet, seqno, action):

- ``wallet`` is the load wallet's index (``NO_WALLET`` when no wallet was free
  to carry it);
- ``seqno`` is the wallet's submission number: one per external the sender
  built for that wallet, so a refused external and the one that later reuses
  its PRIMARY nonce keep distinct keys. The nonce signed into the request is
  recorded next to it;
- ``action`` is the transfer's index in that external's action list.

The record binds the transfer to its external (the message cell hash the
sender computed), that external to the transaction that executed it on the
sending wallet, the action to the internal message that transaction emitted
(matched by destination and value, which are distinct within one external),
and that message to the recipient transaction whose inbound message has the
emitted message's hash. Each transfer then ends in exactly one outcome:

- ``completed``: the recipient transaction is in a block at or below the
  finalized masterchain seqno, and the server shows it executed the message:
  not aborted, with a compute phase that succeeded or was skipped for want
  of state (``t2collect.phase_failure``);
- ``delivered_failed``: the recipient transaction is bound and final, but it
  aborted or its compute phase failed, with the reason recorded. Counted on
  its own, never as completed;
- ``refused``: the submission was refused, with the reason recorded (the rate
  gate's ``-32005`` or HTTP 429, an external rejection, a seqno conflict, or a
  local refusal when no wallet or send budget was free);
- ``skipped_or_failed``: the external executed in a finalized block, but this
  action emitted no message (skipped under send mode +2, a failed action
  phase, or an aborted transaction);
- ``unknown``: the submission was ambiguous (no answer, a transport error or an
  unclassified error). It stays unknown even when the chain later shows the
  external, and it is never resent;
- ``pending``: the submission was accepted but the chain has not yet shown a
  finalized result.
"""

import math
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from shard import t2check
from shard.t2check import McRecord, Tx

COMPLETED = "completed"
DELIVERED_FAILED = "delivered_failed"
REFUSED = "refused"
SKIPPED = "skipped_or_failed"
UNKNOWN = "unknown"
PENDING = "pending"
OUTCOMES = (COMPLETED, DELIVERED_FAILED, REFUSED, SKIPPED, UNKNOWN, PENDING)

# What the sender knows about one external's submission.
BUILT = "built"
ACCEPTED = "accepted"
SUBMIT_REFUSED = "refused"
AMBIGUOUS = "ambiguous"
SUBMISSIONS = (BUILT, ACCEPTED, SUBMIT_REFUSED, AMBIGUOUS)

NO_WALLET = -1
MAX_ACTIONS = 255


@dataclass(eq=False)
class External:
    """One external the sender built, and everything the chain showed about it."""

    wallet: int
    seqno: int
    nonce: int
    step: int
    intended: float  # wall time the schedule placed it at
    sender: str  # raw address of the sending wallet ("" when no wallet carried it)
    destinations: tuple[str, ...]
    values: tuple[int, ...]
    deadline: int = 0
    msg_hash: str = ""
    submission: str = BUILT
    reason: str | None = None
    endpoint: str | None = None
    sent_at: float | None = None
    tx_hash: str | None = None
    tx_mc: int | None = None
    tx_utime: int | None = None
    fee_bound: int | None = None  # the external's derived fee bound, storage aside
    tx_fee: int | None = None  # total_fees of its transaction, when the node reports it
    expired: bool = False  # journaled as past its deadline with no transaction
    failure: list[str | None] = field(default_factory=list)
    emitted: list[str | None] = field(default_factory=list)
    recipient_tx: list[str | None] = field(default_factory=list)
    recipient_mc: list[int | None] = field(default_factory=list)
    recipient_utime: list[int | None] = field(default_factory=list)
    # Why each bound recipient transaction did not execute its message (None when it did).
    receipt_failure: list[str | None] = field(default_factory=list)

    def __post_init__(self) -> None:
        n = len(self.destinations)
        if not 1 <= n <= MAX_ACTIONS or len(self.values) != n:
            raise ValueError(f"an external carries 1..{MAX_ACTIONS} actions, one value each")
        if any(type(v) is not int or v <= 0 for v in self.values):
            raise ValueError("every transfer value must be a positive integer")
        if len(set(zip(self.destinations, self.values))) != n:
            raise ValueError("actions of one external need distinct (destination, value) pairs")
        if self.sender and self.sender in self.destinations:
            raise ValueError("a load wallet never transfers to itself")
        self.failure = [None] * n
        self.emitted = [None] * n
        self.recipient_tx = [None] * n
        self.recipient_mc = [None] * n
        self.recipient_utime = [None] * n
        self.receipt_failure = [None] * n

    @property
    def size(self) -> int:
        return len(self.destinations)

    @property
    def key(self) -> tuple[int, int]:
        return (self.wallet, self.seqno)

    def settled(self) -> bool:
        """Nothing more can be learnt about it from the chain."""
        if self.submission in (SUBMIT_REFUSED, BUILT):
            return True
        if self.tx_hash is None:
            return False
        return all(f is not None or r is not None for f, r in zip(self.failure, self.recipient_tx))

    def outcome(self, action: int, finalized: int | None) -> tuple[str, str | None]:
        """The transfer's outcome and its reason, judged against ``finalized``."""
        if self.submission in (SUBMIT_REFUSED, BUILT):
            return REFUSED, self.reason or "never submitted"
        if self.submission == AMBIGUOUS:
            return UNKNOWN, self.reason
        if self.tx_hash is None or self.tx_mc is None:
            return PENDING, "external not seen on chain"
        failure = self.failure[action]
        if failure is not None:
            if finalized is None or self.tx_mc > finalized:
                return PENDING, "external above the finalized masterchain seqno"
            return SKIPPED, failure
        mc = self.recipient_mc[action]
        if self.recipient_tx[action] is None or mc is None:
            return PENDING, "recipient transaction not seen"
        if finalized is None or mc > finalized:
            return PENDING, "recipient transaction above the finalized masterchain seqno"
        receipt = self.receipt_failure[action]
        if receipt is not None:
            return DELIVERED_FAILED, receipt
        return COMPLETED, None


class Ledger:
    """Every external the sender built, indexed by what the chain can show of it."""

    def __init__(self, load_wallets: Iterable[str]):
        self.wallets = set(load_wallets)
        self.externals: list[External] = []
        self._keys: set[tuple[int, int]] = set()
        self._by_hash: dict[str, External] = {}
        self._by_emitted: dict[str, tuple[External, int]] = {}
        # Deliveries from a load wallet seen before the transaction that emitted them.
        self._orphans: dict[str, tuple[Tx, int, int]] = {}
        self.anomalies: list[dict[str, Any]] = []
        self.duplicates = 0
        self.foreign_externals = 0
        # Called with (external, action) when an action's recipient transaction is bound.
        self.on_delivery: Callable[[External, int], None] | None = None

    # ─── what the sender did ────────────────────────────────────────

    def add(self, ext: External) -> External:
        if ext.wallet != NO_WALLET:
            if ext.key in self._keys:
                raise ValueError(f"transfer key {ext.key} is already in the ledger")
            self._keys.add(ext.key)
        self.externals.append(ext)
        return ext

    def submitted(self, ext: External, msg_hash: str, endpoint: str, sent_at: float) -> None:
        """Record the attempt; a second submission of the same message is refused outright."""
        if ext.submission != BUILT or ext.msg_hash:
            raise ValueError("an external is submitted at most once")
        if msg_hash in self._by_hash:
            raise ValueError("this message was already submitted; it is never resent")
        ext.msg_hash, ext.endpoint, ext.sent_at = msg_hash, endpoint, sent_at
        self._by_hash[msg_hash] = ext

    def known(self, msg_hash: str) -> bool:
        """Whether an external with this message hash was already submitted."""
        return msg_hash in self._by_hash

    def accept(self, ext: External) -> None:
        self._settle(ext, ACCEPTED, None)

    def refuse(self, ext: External, reason: str) -> None:
        self._settle(ext, SUBMIT_REFUSED, reason)

    def ambiguous(self, ext: External, reason: str) -> None:
        self._settle(ext, AMBIGUOUS, reason)

    def _settle(self, ext: External, state: str, reason: str | None) -> None:
        if ext.submission != BUILT:
            raise ValueError(f"the submission is already {ext.submission}")
        ext.submission, ext.reason = state, reason

    # ─── what the chain showed ──────────────────────────────────────

    def _anomaly(self, reason: str, **detail: Any) -> None:
        self.anomalies.append({"reason": reason, **detail})

    def observe(self, txs: Iterable[tuple[Tx, int, int]]) -> list[External]:
        """Bind transactions, each with its committing masterchain seqno and time.

        Externals are bound before deliveries, so a delivery in the same batch
        as its emitting transaction is matched. Returns the externals that
        were newly seen executed.
        """
        batch = list(txs)
        included: list[External] = []
        for tx, mc, utime in batch:
            if tx.in_msg is not None and tx.in_msg.kind == "external":
                ext = self._external(tx, mc, utime)
                if ext is not None:
                    included.append(ext)
        for tx, mc, utime in batch:
            if tx.in_msg is not None and tx.in_msg.kind == "internal":
                self._delivery(tx, mc, utime)
        return included

    def _external(self, tx: Tx, mc: int, utime: int) -> External | None:
        assert tx.in_msg is not None
        ext = self._by_hash.get(tx.in_msg.hash)
        if ext is None:
            if tx.account in self.wallets:
                self.foreign_externals += 1
            return None
        if ext.tx_hash is not None:
            self.duplicates += 1
            self._anomaly("external executed twice", msg=ext.msg_hash, tx=tx.hash)
            return None
        if tx.account != ext.sender:
            self._anomaly("external executed on another account", msg=ext.msg_hash, tx=tx.hash)
            return None
        if ext.submission == SUBMIT_REFUSED:
            self._anomaly("a refused external executed", msg=ext.msg_hash, tx=tx.hash)
        ext.tx_hash, ext.tx_mc, ext.tx_utime, ext.tx_fee = tx.hash, mc, utime, tx.fee
        if tx.aborted or tx.action_success is not True:
            why = "transaction aborted" if tx.aborted else "action phase failed"
            ext.failure = [why] * ext.size
            if tx.out_msgs:
                self._anomaly("a failed external emitted messages", tx=tx.hash)
            return ext
        slots = {(d, v): i for i, (d, v) in enumerate(zip(ext.destinations, ext.values))}
        for message in tx.out_msgs:
            i = slots.get((message.destination or "", message.value or 0))
            if (
                message.kind != "internal"
                or message.source != ext.sender
                or i is None
                or ext.emitted[i] is not None
            ):
                self._anomaly("an emitted message matches no action", tx=tx.hash, msg=message.hash)
                continue
            ext.emitted[i] = message.hash
            self._by_emitted[message.hash] = (ext, i)
            orphan = self._orphans.pop(message.hash, None)
            if orphan is not None:
                self._delivery(*orphan)
        missing = sum(1 for e in ext.emitted if e is None)
        if missing != tx.skipped_actions:
            self._anomaly(
                "actions without a message differ from the skipped count",
                tx=tx.hash,
                missing=missing,
                skipped=tx.skipped_actions,
            )
        for i, e in enumerate(ext.emitted):
            if e is None:
                ext.failure[i] = "action skipped"
        return ext

    def _delivery(self, tx: Tx, mc: int, utime: int) -> None:
        message = tx.in_msg
        assert message is not None
        hit = self._by_emitted.get(message.hash)
        if hit is None:
            if message.source in self.wallets:
                self._orphans[message.hash] = (tx, mc, utime)
            return
        ext, i = hit
        if ext.recipient_tx[i] is not None:
            self.duplicates += 1
            self._anomaly("a transfer was delivered twice", msg=message.hash, tx=tx.hash)
            return
        if tx.account != ext.destinations[i] or message.bounced:
            self._anomaly("a delivery does not match its action", msg=message.hash, tx=tx.hash)
            return
        ext.recipient_tx[i], ext.recipient_mc[i], ext.recipient_utime[i] = tx.hash, mc, utime
        ext.receipt_failure[i] = tx.phase_failure
        if self.on_delivery is not None:
            self.on_delivery(ext, i)

    # ─── reports ────────────────────────────────────────────────────

    def counts(self, finalized: int | None, step: int | None = None) -> dict[str, int]:
        out = Counter({o: 0 for o in OUTCOMES})
        for ext in self.externals:
            if step is None or ext.step == step:
                for i in range(ext.size):
                    out[ext.outcome(i, finalized)[0]] += 1
        return dict(out)

    def rows(self, finalized: int | None) -> Iterable[dict[str, Any]]:
        """One record per external, with every action's outcome and binding."""
        for ext in self.externals:
            actions = []
            for i in range(ext.size):
                state, reason = ext.outcome(i, finalized)
                actions.append(
                    {
                        "action": i,
                        "destination": ext.destinations[i],
                        "value": ext.values[i],
                        "outcome": state,
                        "reason": reason,
                        "emitted": ext.emitted[i],
                        "recipient_tx": ext.recipient_tx[i],
                        "recipient_mc": ext.recipient_mc[i],
                        "recipient_utime": ext.recipient_utime[i],
                        "receipt_failure": ext.receipt_failure[i],
                    }
                )
            yield {
                "wallet": ext.wallet,
                "seqno": ext.seqno,
                "nonce": ext.nonce,
                "step": ext.step,
                "intended": ext.intended,
                "sent_at": ext.sent_at,
                "endpoint": ext.endpoint,
                "deadline": ext.deadline,
                "external": ext.msg_hash,
                "submission": ext.submission,
                "reason": ext.reason,
                "tx": ext.tx_hash,
                "tx_mc": ext.tx_mc,
                "tx_utime": ext.tx_utime,
                "fee_bound": ext.fee_bound,
                "tx_fee": ext.tx_fee,
                "actions": actions,
            }


# ─── per-step metrics and the pass rule ──────────────────────────────


@dataclass(frozen=True)
class StepRule:
    """A step passes when completed matches offered within ``tolerance``, the
    backlog rises by at most ``backlog_slack`` transfers across the window, and
    p95 inclusion latency is at most ``p95_limit`` seconds."""

    tolerance: float = 0.01
    p95_limit: float = 30.0
    backlog_slack: int = 0

    def __post_init__(self) -> None:
        if not 0 <= self.tolerance < 1:
            raise ValueError("the throughput tolerance must be in [0, 1)")
        if not self.p95_limit > 0:
            raise ValueError("the p95 limit must be positive")
        if type(self.backlog_slack) is not int or self.backlog_slack < 0:
            raise ValueError("the backlog slack must be a non-negative integer")


def percentile(values: list[float], q: float) -> float | None:
    """Nearest-rank percentile; None for no values."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(q * len(ordered)))
    return ordered[rank - 1]


def _resolved_at(ext: External, action: int, finalized: int | None) -> float:
    """When the transfer stopped being in flight, on the chain's clock (inf if it has not)."""
    state, _ = ext.outcome(action, finalized)
    if state == COMPLETED:
        return float(ext.recipient_utime[action] or 0)
    if state == SKIPPED:
        return float(ext.tx_utime or 0)
    if state == DELIVERED_FAILED:
        return float(ext.recipient_utime[action] or 0)
    return math.inf


def step_metrics(
    externals: Iterable[External],
    start: int,
    end: int,
    finalized: int | None,
    rule: StepRule,
) -> dict[str, Any]:
    """Offered, completed, backlog and latency over the measurement interval [start, end).

    Offered counts transfers the schedule placed in the interval, whatever
    became of them. Completed counts transfers whose finalized recipient
    transaction is in a block dated inside the interval, so completions in
    the drain after the window do not count. The backlog at a time is the
    number of transfers sent before it and not yet completed, skipped or
    failed at the recipient by it; unknown and pending transfers never leave
    it. Latency runs from the send to the recipient block's time; a transfer
    sent in the interval that never completed counts as unbounded, and a
    skipped or failed one takes no latency sample.
    """
    if type(start) is not int or type(end) is not int or end <= start:
        raise ValueError("a measurement interval needs integer start < end")
    exts = list(externals)
    length = end - start
    offered = completed = 0
    backlog_start = backlog_end = 0
    latencies: list[float] = []
    refused: Counter[str] = Counter()
    for ext in exts:
        in_interval = start <= ext.intended < end
        in_flight = ext.submission in (ACCEPTED, AMBIGUOUS) and ext.sent_at is not None
        for i in range(ext.size):
            state, reason = ext.outcome(i, finalized)
            if in_interval:
                offered += 1
                if state == REFUSED:
                    refused[reason or ""] += 1
            if state == COMPLETED and start <= (ext.recipient_utime[i] or 0) < end:
                completed += 1
            if not in_flight:
                continue
            assert ext.sent_at is not None
            done = _resolved_at(ext, i, finalized)
            if ext.sent_at < start and done >= start:
                backlog_start += 1
            if ext.sent_at < end and done >= end:
                backlog_end += 1
            if in_interval and state not in (SKIPPED, DELIVERED_FAILED):
                latencies.append(done - ext.sent_at if state == COMPLETED else math.inf)
    p50, p95 = percentile(latencies, 0.50), percentile(latencies, 0.95)
    throughput_ok = offered > 0 and abs(completed - offered) <= rule.tolerance * offered
    backlog_ok = backlog_end - backlog_start <= rule.backlog_slack
    latency_ok = p95 is not None and p95 <= rule.p95_limit
    finite = lambda x: None if x is None or math.isinf(x) else round(max(0.0, x), 3)  # noqa: E731
    return {
        "interval": [start, end],
        "offered": offered,
        "completed_in_window": completed,
        "offered_per_s": offered / length,
        "completed_per_s": completed / length,
        "backlog_at_start": backlog_start,
        "backlog_at_end": backlog_end,
        "latency_samples": len(latencies),
        "latency_unbounded": sum(1 for x in latencies if math.isinf(x)),
        "p50_s": finite(p50),
        "p95_s": finite(p95),
        "refused_in_window": dict(refused),
        "checks": {
            "throughput_within_tolerance": throughput_ok,
            "backlog_not_growing": backlog_ok,
            "p95_within_limit": latency_ok,
        },
        "passed": throughput_ok and backlog_ok and latency_ok,
    }


def step_layout(mcs: Iterable[McRecord], mc_from: int, mc_to: int) -> dict[str, Any]:
    """Whether the basechain layout stayed the same across masterchain blocks [mc_from, mc_to].

    A layout change, a missing masterchain block or an unreadable layout
    makes the step not count; it is repeated at a stable layout. Every seqno
    of the interval, both endpoints included, must have been read: a block
    missing at either end could hide a change as well as one inside.
    """
    if type(mc_from) is not int or type(mc_to) is not int or mc_from > mc_to:
        raise ValueError("a layout interval needs integer mc_from <= mc_to")
    rows = [m for m in mcs if mc_from <= m.seqno <= mc_to]
    read = {m.seqno for m in rows}
    missing = [s for s in range(mc_from, mc_to + 1) if s not in read]
    changes, verdict = t2check.layout_changes(rows)
    stable = verdict.status == t2check.PASS and not changes and not missing
    return {
        "mc_from": mc_from,
        "mc_to": mc_to,
        "stable": stable,
        "missing": missing[:100],
        "missing_count": len(missing),
        "status": verdict.status,
        "changes": [c.as_dict() for c in changes],
        "gaps": verdict.gaps,
        "failures": verdict.failures,
        "layout": verdict.stats.get("final_layout"),
    }
