"""The pre-broadcast journal of the remote benches, and the wallet lock that guards it.

Every value-moving external the remote benches sign (the shard bench's
deployment and start, the T4 ramp's funding and transfers) is
written to a run journal and fsynced before its send starts, and every later
fact about it is appended as it is learnt. The journal is the source of
truth; a run's ``results.json`` and ledger are summaries.

The run journal
---------------

``<out>/journal.jsonl`` is append-only, one JSON object per line.
``Journal.append`` writes whole lines and fsyncs the file before it
returns, and the directory is fsynced when the file is created, so a record
``append`` returned for survives a crash of the process. Records, by
``type``:

- ``run``: the first line. ``version``, ``tool``, ``wallet`` (the bench
  wallet), ``mc_start`` (the masterchain head before the first signature),
  ``deadline_grace``, and whatever the tool adds;
- ``attempt``: one signed external, written before its send starts. ``id``,
  ``role``, ``sender`` (raw address), ``wallet`` (a load wallet index, None
  for the bench wallet), ``seqno`` (the sender's submission number in this
  run), ``nonce`` (the signed nonce), ``deadline``, ``external`` (the message
  cell hash, hex), ``boc`` (the signed external, base64, so the hash can be
  checked again), ``actions`` (``destination``, ``value``, ``mode`` each),
  ``fee_bound`` (None where the tool checks a whole-run bound instead),
  ``signed_at`` (a chain time read before signing, so no transaction of the
  external can be older), ``prior`` (the refused attempt on the same wallet and nonce this one
  follows, or None) and tool fields such as ``step``;
- ``sent``: the send's answer. ``id``, ``state`` (``accepted``, ``refused``
  or ``ambiguous``) and ``reason``;
- ``observed``: the transaction that executed the external. ``id``, ``tx``,
  ``tx_mc`` or ``lt``, ``utime``, ``fee`` and what its phases showed;
- ``delivered``: one action's recipient transaction (``id``, ``action``,
  ``recipient_tx``, ``recipient_mc``, and ``receipt_failure``: why that
  transaction did not execute the message, None when it did);
- ``expired``: the external was not executed by its deadline plus the grace,
  proven by a complete read up to a later chain time (``id``, ``chain_now``);
- ``unknown``: the tool stopped waiting with the outcome unproven (``id``,
  ``reason``). It is never resent;
- ``end``: the run wrote its summaries (``exit_status``).

A kill can leave the last line without its newline. The reader drops such a
torn tail and reports it; any other malformed line is an error.

The wallet state
----------------

``<state-dir>/<wallet>/`` holds, for one bench wallet (and the load wallets
derived from its key):

- ``lock``: an exclusive ``flock`` held for the whole run, so two
  invocations against one wallet never sign concurrently. The kernel drops
  it when the process dies;
- ``journals``: the path of every run journal, registered (and fsynced)
  before that run's first signature;
- ``resolved``: what a later invocation proved about an earlier run's
  unsettled attempts.

Before a run signs anything, ``WalletState.reconcile`` reads every
registered journal and looks up each attempt that is neither refused,
observed, expired nor resolved by the transaction that consumed its
external (``find_attempt``). Each one is resolved as ``executed`` or
``not_executed`` (its deadline and the grace passed with a complete read of
the sender's transactions), or stays ``undetermined``. Any attempt that
needed reconciling makes the invocation refuse, after recording what it
proved: the next invocation is then the explicit request for new
signatures, and nothing is ever resent.
"""

import argparse
import asyncio
import base64
import fcntl
import json
import os
import sys
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pytosiq_core import Cell

from shard import t2collect
from shard.rpc import PacedRpc, RateLimited, RpcError
from shard.t2check import Tx

VERSION = 1
NAME = "journal.jsonl"
TYPES = (
    "run",
    "attempt",
    "sent",
    "observed",
    "delivered",
    "expired",
    "unknown",
    "end",
)
SENT_STATES = ("accepted", "refused", "ambiguous")
# Settled for good: nothing more can happen to the attempt on chain.
TERMINAL = ("observed", "expired")
# The wallets refuse a request whose deadline is more than this past their chain time.
MAX_REQUEST_LIFETIME = 3600
# Chain seconds past a request's deadline after which no block can still execute it.
DEADLINE_GRACE = 30.0
# The wallet's error code for a request whose nonce is not the current one.
BAD_NONCE = 1804
TX_PAGE = 100
MAX_TX_PAGES = 64
STATE_TYPES = ("register", "resolved")

Now = Callable[[], Awaitable[int]]


def attempt_id(role: str, wallet: int | None, seqno: int) -> str:
    if not role.isidentifier():
        raise ValueError(f"an attempt role must be an identifier, not {role!r}")
    return f"{role}:{'bench' if wallet is None else wallet}:{seqno}"


def _encode(record: dict[str, Any], types: tuple[str, ...]) -> bytes:
    if record.get("type") not in types:
        raise ValueError(f"unknown journal record type {record.get('type')!r}")
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Journal:
    """An append-only file of JSON lines; every append is fsynced before it returns.

    ``create`` makes a new file and refuses an existing one, so a run never
    appends to another run's journal. Otherwise the file is opened for
    append, and a torn last line left by a crash is closed off first, so the
    next record starts on its own line.
    """

    def __init__(self, path: Path, create: bool = True, types: tuple[str, ...] = TYPES):
        self.path, self.types = path, types
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | (os.O_EXCL if create else 0)
        existed = path.exists()
        self.fd = os.open(path, flags, 0o600)
        self.records = 0
        if not existed:
            _fsync_dir(path.parent)
        elif not create:
            with path.open("rb") as f:
                f.seek(0, os.SEEK_END)
                if f.tell() > 0:
                    f.seek(-1, os.SEEK_END)
                    if f.read(1) != b"\n":
                        self._write(b"\n")

    def _write(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(self.fd, view)
            if written <= 0:
                raise OSError("the journal write made no progress")
            view = view[written:]
        os.fsync(self.fd)

    def append(self, *records: dict[str, Any]) -> None:
        """Write the records as whole lines and fsync; raises OSError when that fails."""
        if self.fd < 0:
            raise OSError("the journal is closed")
        if records:
            self._write(b"".join(_encode(r, self.types) for r in records))
            self.records += len(records)

    def event(self, kind: str, attempt: str, **fields: Any) -> None:
        self.append({"type": kind, "id": attempt, "time": time.time(), **fields})

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def attempt_record(
    *,
    role: str,
    sender: str,
    wallet: int | None,
    seqno: int,
    nonce: int,
    deadline: int,
    cell: Cell,
    actions: Iterable[tuple[str, int, int]],
    fee_bound: int | None = None,
    prior: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """The record of one signed external, from its serialized message cell."""
    return {
        **extra,
        "type": "attempt",
        "id": attempt_id(role, wallet, seqno),
        "role": role,
        "sender": sender,
        "wallet": wallet,
        "seqno": seqno,
        "nonce": nonce,
        "deadline": deadline,
        "external": cell.hash.hex(),
        "boc": base64.b64encode(cell.to_boc()).decode(),
        "actions": [{"destination": d, "value": v, "mode": m} for d, v, m in actions],
        "fee_bound": fee_bound,
        "prior": prior,
        "time": time.time(),
    }


# ─── reading ─────────────────────────────────────────────────────────


@dataclass
class JournalRead:
    path: Path
    run: dict[str, Any] | None = None
    attempts: dict[str, dict[str, Any]] = field(default_factory=dict)  # by id, in write order
    events: dict[str, list[dict[str, Any]]] = field(default_factory=dict)  # by attempt id
    end: dict[str, Any] | None = None
    lines: int = 0
    torn_tail: bool = False
    errors: list[str] = field(default_factory=list)

    def sent(self, attempt: str) -> dict[str, Any] | None:
        """The attempt's journaled send answer, None when none was written."""
        return next((e for e in self.events.get(attempt, []) if e["type"] == "sent"), None)

    def settled(self, attempt: str) -> bool:
        """Refused, or executed or expired as the run itself proved."""
        sent = self.sent(attempt)
        if sent is not None and sent["state"] == "refused":
            return True
        return any(e["type"] in TERMINAL for e in self.events.get(attempt, []))


def _attempt_problem(n: int, record: dict[str, Any]) -> str | None:
    for key in ("id", "role", "sender", "external", "boc"):
        if not isinstance(record.get(key), str):
            return f"line {n}: attempt without {key}"
    for key in ("seqno", "nonce", "deadline"):
        if type(record.get(key)) is not int:
            return f"line {n}: attempt without an integer {key}"
    actions = record.get("actions")
    if not isinstance(actions, list) or not actions:
        return f"line {n}: attempt without actions"
    for a in actions:
        if not isinstance(a, dict) or not isinstance(a.get("destination"), str):
            return f"line {n}: an action without a destination"
        if type(a.get("value")) is not int or a["value"] < 0 or type(a.get("mode")) is not int:
            return f"line {n}: an action without a value and a mode"
    try:
        digest = Cell.one_from_boc(base64.b64decode(record["boc"], validate=True)).hash.hex()
    except Exception:
        return f"line {n}: the attempt's boc does not decode"
    if digest != record["external"]:
        return f"line {n}: the attempt's boc hashes to {digest}, not {record['external']}"
    return None


def _lines(path: Path) -> tuple[list[bytes], bool]:
    """The complete lines of a file, and whether a torn last line followed them."""
    lines = path.read_bytes().split(b"\n")
    tail = lines.pop()  # what follows the last newline: empty unless the last write was torn
    return lines, tail != b""


def read_journal(path: Path) -> JournalRead:
    """Every record of a run journal; a torn last line is dropped and reported, never guessed."""
    out = JournalRead(path)
    lines, out.torn_tail = _lines(path)
    externals: dict[str, str] = {}
    for n, line in enumerate(lines, 1):
        out.lines = n
        try:
            record = json.loads(line)
        except ValueError:
            out.errors.append(f"line {n}: not JSON")
            continue
        if not isinstance(record, dict) or record.get("type") not in TYPES:
            out.errors.append(f"line {n}: not a journal record")
            continue
        kind = record["type"]
        if kind == "run":
            if n != 1:
                out.errors.append(f"line {n}: a run record that is not the first line")
            elif record.get("version") != VERSION or type(record.get("mc_start")) is not int:
                out.errors.append(f"line {n}: an unsupported run record")
            else:
                out.run = record
            continue
        if kind == "end":
            out.end = record
            continue
        if kind == "attempt":
            problem = _attempt_problem(n, record)
            if problem is None and record["id"] in out.attempts:
                problem = f"line {n}: attempt {record['id']} journaled twice"
            if problem is None and record["external"] in externals:
                problem = (
                    f"line {n}: attempt {record['id']} repeats the external of"
                    f" {externals[record['external']]}"
                )
            if problem is not None:
                out.errors.append(problem)
                continue
            out.attempts[record["id"]] = record
            externals[record["external"]] = record["id"]
            continue
        attempt = record.get("id")
        if not isinstance(attempt, str) or attempt not in out.attempts:
            out.errors.append(f"line {n}: a {kind} record for an unjournaled attempt")
        elif kind == "sent" and record.get("state") not in SENT_STATES:
            out.errors.append(f"line {n}: an unknown send state")
        elif kind == "sent" and out.sent(attempt) is not None:
            out.errors.append(f"line {n}: a second send answer for {attempt}")
        else:
            out.events.setdefault(attempt, []).append(record)
    if out.run is None and not any("run record" in e for e in out.errors):
        out.errors.append("the journal has no run record")
    return out


def read_state(path: Path) -> list[dict[str, Any]]:
    """The records of a wallet state file.

    A record there is written before the step it enables, so a torn or
    malformed line only loses a step that never ran: it is skipped.
    """
    if not path.exists():
        return []
    out = []
    for line in _lines(path)[0]:
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict) and record.get("type") in STATE_TYPES:
            out.append(record)
    return out


# ─── send answers ────────────────────────────────────────────────────


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


def send_outcome(error: BaseException | None) -> tuple[str, str | None]:
    """The journaled send state and reason for a sendBoc that returned or raised ``error``."""
    if error is None:
        return "accepted", None
    if isinstance(error, RateLimited):
        return "refused", f"rate gate: {error.reason}"
    if isinstance(error, RpcError):
        definite, reason = classify_send_error(error)
        return ("refused" if definite else "ambiguous"), reason
    return "ambiguous", f"no answer: {type(error).__name__}"


# ─── finding the transaction that consumed an external ───────────────


@dataclass(frozen=True)
class AccountTx:
    tx: Tx
    utime: int
    compute_success: bool
    raw: dict[str, Any]


def _prev_of(item: dict[str, Any]) -> tuple[int, bytes]:
    """(prev_trans_lt, prev_trans_hash) from a transaction's serialized cell."""
    data = item.get("data")
    if not isinstance(data, str):
        raise ValueError("a transaction carries no data to page from")
    s = Cell.one_from_boc(base64.b64decode(data, validate=True)).begin_parse()
    if s.load_uint(4) != 0b0111:
        raise ValueError("a transaction's data is not a transaction")
    s.skip_bits(256 + 64)
    prev_hash = s.load_bytes(32)
    return s.load_uint(64), prev_hash


def account_tx(item: Any) -> AccountTx:
    """One getTransactions entry as a ``Tx``; the transaction id carries its lt and hash."""
    if not isinstance(item, dict):
        raise ValueError("a transaction is not an object")
    tid = item.get("transaction_id")
    if not isinstance(tid, dict):
        raise ValueError("a transaction has no transaction_id")
    block = t2collect.parse_block_id(item.get("block_id"))
    norm = {**item, "hash": tid.get("hash"), "lt": tid.get("lt")}
    if item.get("in_msg") is None and isinstance(item.get("in_msg_hash"), str):
        norm["in_msg"] = {"hash": item["in_msg_hash"], "kind": "external"}
    tx = t2collect.parse_transaction(norm, block.key)
    compute = item.get("compute")
    success = isinstance(compute, dict) and compute.get("success") is True
    utime = item.get("utime")
    if type(utime) is not int:
        raise ValueError("a transaction has no utime")
    return AccountTx(tx, utime, success, item)


def _entry(item: Any) -> tuple[AccountTx, int, str]:
    """One getTransactions entry, with the lt and hash (hex) of its predecessor.

    A non-object entry, or one missing any field, raises ValueError.
    """
    try:
        found = account_tx(item)
        prev_lt, prev_hash = _prev_of(item)
    except ValueError:
        raise
    except Exception as error:  # a malformed entry is an error, never a skipped one
        raise ValueError(f"a malformed transaction entry: {type(error).__name__}") from None
    return found, prev_lt, prev_hash.hex()


async def account_transactions(
    rpc: PacedRpc, address: str, since: int, max_pages: int = MAX_TX_PAGES
) -> tuple[list[AccountTx], bool]:
    """The account's transactions from the newest back to chain time ``since``.

    Returns (transactions, complete). Complete is True only on explicit
    proof that the read covers everything back to ``since``: a transaction
    older than it, the account's first transaction (no predecessor), or an
    empty first page, which the server answers only for an account with no
    transaction at all. Each transaction must be the predecessor the one
    before it names, so a page that skips one, or ends before the boundary,
    is an error (ValueError), as is a non-object entry or a missing field.
    Complete is False when the page bound ran out first, so an absence there
    proves nothing.
    """
    out: list[AccountTx] = []
    params: dict[str, Any] = {"address": address, "limit": TX_PAGE}
    expect: tuple[int, str] | None = None  # (lt, hash) of the next transaction to read
    for _ in range(max_pages):
        page = await rpc.call("getTransactions", params)
        if not isinstance(page, list):
            raise ValueError("getTransactions did not answer a list")
        entries = [_entry(x) for x in page]
        if out and entries and entries[0][0].tx.hash == out[-1].tx.hash:
            entries = entries[1:]  # a node may repeat the transaction a page starts from
        if not entries:
            if expect is None:
                return out, True
            raise ValueError(
                f"the transaction history stops at lt {expect[0]}, before the account's"
                f" first transaction and chain time {since}"
            )
        for found, prev_lt, prev_hash in entries:
            if expect is not None and (found.tx.lt, found.tx.hash) != expect:
                raise ValueError(
                    f"the transaction history skips lt {expect[0]}: the next one read is"
                    f" lt {found.tx.lt}"
                )
            out.append(found)
            if found.utime < since or prev_lt == 0:
                return out, True
            expect = (prev_lt, prev_hash)
        assert expect is not None
        params = {
            "address": address,
            "limit": TX_PAGE,
            "lt": str(expect[0]),
            "hash": base64.b64encode(bytes.fromhex(expect[1])).decode(),
        }
    return out, False


def emission_problems(found: AccountTx, attempt: dict[str, Any]) -> list[str]:
    """Why the transaction does not show the attempt executed as signed (empty when it does).

    Every phase is checked, and every action must have emitted its internal
    message from the sender: to its destination with its value, or any value
    when its mode carries the remaining balance (+128).
    """
    tx = found.tx
    problems = []
    if tx.aborted:
        problems.append("transaction aborted")
    if not found.compute_success:
        problems.append("compute phase did not succeed")
    if tx.action_success is not True:
        problems.append("action phase did not succeed")
    unused = [m for m in tx.out_msgs if m.kind == "internal" and m.source == attempt["sender"]]
    for i, action in enumerate(attempt["actions"]):
        carry_all = action["mode"] & 128 != 0
        match = next(
            (
                m
                for m in unused
                if m.destination == action["destination"]
                and (carry_all or m.value == action["value"])
            ),
            None,
        )
        if match is None:
            problems.append(f"action {i} emitted no message to {action['destination']}")
        else:
            unused.remove(match)
    return problems


@dataclass
class Verdict:
    """What the chain shows about one attempt.

    ``executed``: the transaction whose inbound message is the external
    (``found``), with ``problems`` listing failed phases or missing messages;
    ``not_executed``: none, and a complete read at a chain time past the
    deadline plus the grace; ``undetermined``: neither could be proven.
    """

    state: str
    reason: str | None = None
    found: AccountTx | None = None
    problems: list[str] = field(default_factory=list)
    duplicates: int = 0
    chain_now: int | None = None

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"verdict": self.state, "reason": self.reason}
        out["chain_now"] = self.chain_now
        if self.found is not None:
            tx = self.found.tx
            out |= {
                "tx": tx.hash,
                "lt": tx.lt,
                "utime": self.found.utime,
                "fee": tx.fee,
                "block": list(tx.block),
                "problems": self.problems,
                "out_msgs": [
                    {"hash": m.hash, "destination": m.destination, "value": m.value}
                    for m in tx.out_msgs
                ],
            }
        if self.duplicates:
            out["duplicates"] = self.duplicates
        return out


async def find_attempt(
    rpc: PacedRpc, attempt: dict[str, Any], now: Now, grace: float = DEADLINE_GRACE
) -> Verdict:
    """Look the attempt up by its external's hash among the sender's transactions.

    Chain time is read before the transactions, so a transaction that
    executed by the deadline is in the state the read covers once that time
    is past the deadline plus the grace. The read goes back to the earliest
    chain time the request could have executed at (``signed_at``).
    """
    try:
        chain_now = await now()
        signed_at = attempt.get("signed_at")
        # No transaction of the external is older than the chain time read before signing;
        # without that record, the oldest time the wallet could have accepted its deadline.
        since = signed_at if type(signed_at) is int else attempt["deadline"] - MAX_REQUEST_LIFETIME
        txs, complete = await account_transactions(rpc, attempt["sender"], since)
    except (RpcError, RateLimited, ValueError) as error:
        return Verdict("undetermined", f"read failed: {type(error).__name__}: {error}")
    matches = [
        t
        for t in txs
        if t.tx.in_msg is not None
        and t.tx.in_msg.kind == "external"
        and t.tx.in_msg.hash == attempt["external"]
        and t.tx.account == attempt["sender"]
    ]
    if matches:
        found = matches[-1]  # the earliest: a repeat would be the anomaly
        return Verdict(
            "executed",
            None,
            found,
            emission_problems(found, attempt),
            len(matches) - 1,
            chain_now,
        )
    if not complete:
        return Verdict("undetermined", "the sender's history exceeds the page bound", None)
    if chain_now <= attempt["deadline"] + grace:
        return Verdict(
            "undetermined",
            f"not executed yet; chain time {chain_now} has not passed deadline"
            f" {attempt['deadline']} + {grace:g}",
            chain_now=chain_now,
        )
    return Verdict("not_executed", "deadline passed with no transaction", chain_now=chain_now)


async def confirm(
    rpc: PacedRpc,
    attempt: dict[str, Any],
    now: Now,
    timeout: float,
    poll: float,
    grace: float = DEADLINE_GRACE,
) -> Verdict:
    """Wait for ``find_attempt`` to prove the attempt executed or expired, up to ``timeout``."""
    give_up = time.monotonic() + timeout
    while True:
        verdict = await find_attempt(rpc, attempt, now, grace)
        if verdict.state != "undetermined" or time.monotonic() >= give_up:
            return verdict
        await asyncio.sleep(max(poll, 0.02))


async def deliveries(
    rpc: PacedRpc, verdict: Verdict, attempt: dict[str, Any]
) -> list[dict[str, Any]]:
    """For an executed attempt: each emitted message's recipient transaction, when shown."""
    found = verdict.found
    if found is None:
        return []
    out = []
    for m in found.tx.out_msgs:
        if m.kind != "internal" or m.destination is None:
            continue
        row: dict[str, Any] = {"message": m.hash, "destination": m.destination, "value": m.value}
        try:
            txs, complete = await account_transactions(rpc, m.destination, found.utime - 1)
        except (RpcError, RateLimited, ValueError) as error:
            out.append(row | {"delivery": "undetermined", "reason": type(error).__name__})
            continue
        hit = next(
            (
                t
                for t in txs
                if t.tx.in_msg is not None
                and t.tx.in_msg.hash == m.hash
                and t.tx.account == m.destination
            ),
            None,
        )
        if hit is not None:
            inbound = hit.tx.in_msg
            ok = inbound is not None and not inbound.bounced and hit.tx.phase_failure is None
            row |= {"delivery": "delivered" if ok else "failed", "recipient_tx": hit.tx.hash}
            if hit.tx.phase_failure is not None:
                row["receipt_failure"] = hit.tx.phase_failure
        else:
            row |= {"delivery": "not_seen" if complete else "undetermined"}
        out.append(row)
    return out


# ─── the wallet state: lock, registry, resolutions ───────────────────


class WalletLocked(Exception):
    """Another invocation holds the wallet's lock."""


class WalletState:
    """The lock, the journal registry and the resolutions of one bench wallet."""

    def __init__(self, state_dir: Path, wallet: str):
        self.dir = state_dir / wallet.replace(":", "_")
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock_fd = os.open(self.dir / "lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.lock_fd)
            self.lock_fd = -1
            raise WalletLocked(f"another invocation holds the lock of wallet {wallet}") from None
        self.wallet = wallet

    def release(self) -> None:
        if self.lock_fd >= 0:
            os.close(self.lock_fd)  # closing the descriptor drops the flock
            self.lock_fd = -1

    def journals(self) -> list[Path]:
        return [
            Path(r["journal"])
            for r in read_state(self.dir / "journals")
            if r["type"] == "register" and isinstance(r.get("journal"), str)
        ]

    def resolved(self) -> dict[tuple[str, str], dict[str, Any]]:
        return {
            (r["journal"], r["id"]): r
            for r in read_state(self.dir / "resolved")
            if r["type"] == "resolved" and isinstance(r.get("journal"), str)
        }

    def register(self, journal: Path) -> None:
        """Record a run journal; called after its run record and before any signature."""
        if self.lock_fd < 0:
            raise OSError("the wallet lock is not held")
        state = Journal(self.dir / "journals", create=False, types=STATE_TYPES)
        try:
            state.append({"type": "register", "journal": str(journal), "time": time.time()})
        finally:
            state.close()

    async def reconcile(self, rpc: PacedRpc, now: Now) -> dict[str, Any]:
        """Resolve every unsettled attempt of every registered journal against the chain.

        Returns the report; ``clean`` is True only when no attempt needed
        resolving, and only then may the caller sign.
        """
        if self.lock_fd < 0:
            raise OSError("the wallet lock is not held")
        resolved = self.resolved()
        report: dict[str, Any] = {"journals": 0, "attempts": [], "errors": []}
        writer: Journal | None = None
        try:
            for path in self.journals():
                report["journals"] += 1
                if not path.exists():
                    report["errors"].append(f"registered journal {path} is missing")
                    continue
                read = read_journal(path)
                report["errors"] += [f"{path}: {e}" for e in read.errors]
                grace = float((read.run or {}).get("deadline_grace", DEADLINE_GRACE))
                for key, attempt in read.attempts.items():
                    if read.settled(key):
                        continue
                    previous = resolved.get((str(path), key))
                    if previous is not None and previous["verdict"] != "undetermined":
                        continue
                    verdict = await find_attempt(rpc, attempt, now, grace)
                    row = {
                        "journal": str(path),
                        "id": key,
                        "external": attempt["external"],
                        "journaled": (read.sent(key) or {}).get("state"),
                        **verdict.as_dict(),
                    }
                    report["attempts"].append(row)
                    if writer is None:
                        writer = Journal(self.dir / "resolved", create=False, types=STATE_TYPES)
                    writer.append({"type": "resolved", "time": time.time(), **row})
        finally:
            if writer is not None:
                writer.close()
        report["clean"] = not report["attempts"] and not report["errors"]
        report["undetermined"] = sum(
            1 for r in report["attempts"] if r["verdict"] == "undetermined"
        )
        return report


def refusal_of(report: dict[str, Any]) -> str | None:
    """Why a wallet's earlier attempts forbid a new signature now, or None."""
    if report["clean"]:
        return None
    parts = []
    if report["errors"]:
        parts.append(f"{len(report['errors'])} journal errors: {report['errors'][:3]}")
    counts: dict[str, int] = {}
    for r in report["attempts"]:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    if counts:
        parts.append(
            "earlier attempts needed reconciling ("
            + ", ".join(f"{n} {v}" for v, n in sorted(counts.items()))
            + "); the resolution is recorded, so check it and run again"
            + (" once their deadlines pass" if report["undetermined"] else "")
        )
    return "; ".join(parts)


def default_state_dir(key_file: Path) -> Path:
    return key_file.parent / (key_file.name + ".state")


async def now_of(rpc: PacedRpc) -> int:
    info = await rpc.call("getMasterchainInfo")
    last = t2collect.parse_block_id(info.get("last"))
    header = await rpc.call(
        "getBlockHeader",
        {"workchain": -1, "shard": str(t2collect.MASTERCHAIN_SHARD), "seqno": last.seqno},
    )
    return int(header["gen_utime"])


async def head_of(rpc: PacedRpc) -> int:
    info = await rpc.call("getMasterchainInfo")
    return t2collect.parse_block_id(info.get("last")).seqno


# ─── read-only reconciliation of one run journal ─────────────────────

RECONCILED = 0
RECONCILE_ANOMALY = 1
RECONCILE_UNDETERMINED = 4


async def reconcile_journal(rpc: PacedRpc, path: Path) -> dict[str, Any]:
    """Classify every journaled attempt of one run against the chain; reads only."""
    read = read_journal(path)
    grace = float((read.run or {}).get("deadline_grace", DEADLINE_GRACE))

    async def now() -> int:
        return await now_of(rpc)

    rows = []
    anomalies: list[str] = list(read.errors)
    for key, attempt in read.attempts.items():
        verdict = await find_attempt(rpc, attempt, now, grace)
        sent = read.sent(key)
        row = {
            "id": key,
            "role": attempt["role"],
            "sender": attempt["sender"],
            "nonce": attempt["nonce"],
            "deadline": attempt["deadline"],
            "external": attempt["external"],
            "journaled": None if sent is None else sent["state"],
            "journaled_reason": None if sent is None else sent.get("reason"),
            **verdict.as_dict(),
        }
        if verdict.state == "executed":
            row["deliveries"] = await deliveries(rpc, verdict, attempt)
            if sent is not None and sent["state"] == "refused":
                anomalies.append(f"{key}: a refused external executed")
            if verdict.duplicates:
                anomalies.append(f"{key}: the external executed more than once")
        rows.append(row)
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    if anomalies:
        status = RECONCILE_ANOMALY
    elif counts.get("undetermined"):
        status = RECONCILE_UNDETERMINED
    else:
        status = RECONCILED
    return {
        "journal": str(path),
        "torn_tail": read.torn_tail,
        "ended": read.end is not None,
        "attempts": rows,
        "counts": counts,
        "anomalies": anomalies,
        "exit_status": status,
    }


def reconcile_main(argv: list[str], prog: str) -> int:
    """``<tool> reconcile``: classify a run journal's attempts against the chain, read-only."""
    p = argparse.ArgumentParser(prog=f"{prog} reconcile", description=reconcile_main.__doc__)
    p.add_argument("--out", type=Path, required=True, help="the run's out directory")
    p.add_argument("--rpc", required=True, help="JSON-RPC URL")
    p.add_argument("--rpc-share", type=float, default=0.25)
    a = p.parse_args(argv)
    path = a.out / NAME
    if not path.is_file():
        print(f"no journal at {path}", file=sys.stderr)
        return RECONCILE_UNDETERMINED
    report = asyncio.run(reconcile_journal(PacedRpc(a.rpc, a.rpc_share), path))
    print(json.dumps(report, indent=2))
    return report["exit_status"]
