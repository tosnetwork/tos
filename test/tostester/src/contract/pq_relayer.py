"""Explicit non-refundable attempts with durable nonce/race bookkeeping.

A transport implementation must read validated chain state and transaction
receipts. A broadcast identifier alone never proves account execution. SQLite
prevents duplicate submissions from this journal, not competition by other
relayers. Unknown broadcasts remain reserved until reconciled from the chain.
"""
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
import sqlite3
import secrets

from pytosiq_core import Address, Cell
from .pq_auth import AuthRequest, AuthState, PqSigner, MAX_COINS, address, key_bytes

LOSS_ACK = "I_ACCEPT_NONREFUNDABLE_AUTHORIZATION_ATTEMPTS"


@dataclass(frozen=True)
class FundingBudget:
    module_compute: int
    forwarding: int
    account_execution: int
    margin: int
    cap: int

    @property
    def total(self) -> int:
        values = (self.module_compute, self.forwarding, self.account_execution, self.margin, self.cap)
        if any(type(v) is not int or not 0 < v <= MAX_COINS for v in values):
            raise ValueError("positive integral funding components required")
        total = sum(values[:4])
        if total > min(self.cap, MAX_COINS):
            raise ValueError("funding exceeds the explicitly approved cap")
        return total


@dataclass(frozen=True)
class ChainSnapshot:
    network: int
    version: int
    chain_time: int
    account: Address
    module: Address
    auth: AuthState
    module_public_key: bytes
    block_id: str


@dataclass(frozen=True)
class AttemptReceipt:
    request_hash: str
    module: Address
    account: Address
    module_success: bool | None
    account_success: bool | None
    account_nonce_consumed: bool | None
    module_transaction: str | None = None
    account_transaction: str | None = None

    @property
    def status(self) -> str:
        if self.module_success is False and self.module_transaction:
            return "module_rejected"
        if self.module_success is True and self.module_transaction and self.account_transaction:
            if self.account_success is True and self.account_nonce_consumed is True:
                return "executed"
            if self.account_success is False and self.account_nonce_consumed is not None:
                return "account_rejected"
        return "pending"


class RelayTransport(Protocol):
    async def snapshot(self, account: Address, module: Address) -> ChainSnapshot: ...
    async def estimate(self, request: AuthRequest, module: Address) -> FundingBudget: ...
    async def submit_internal(self, module: Address, body: Cell, value: int) -> str: ...
    async def receipt(self, broadcast_id: str, request: AuthRequest, module: Address) -> AttemptReceipt: ...


# A nonce that a finished attempt did not consume may be authorized again, but
# only after that attempt is known to be final. The history is kept rather than
# deleted, because retiring an attempt is a judgement that needs its evidence.
LIVE = ("reserved", "unknown", "broadcast", "pending")
RETIRABLE = ("module_rejected", "account_rejected")
# One-way for ordinary reconciliation. A late or partial observation may not
# move a settled attempt backwards; a reorg is a separate question and is not
# answered by an ordinary pending receipt.
TRANSITIONS = {
    "reserved": {"unknown", "broadcast"},
    "unknown": {"unknown", "broadcast", "pending", "module_rejected", "account_rejected", "executed"},
    "broadcast": {"broadcast", "pending", "module_rejected", "account_rejected", "executed"},
    "pending": {"pending", "module_rejected", "account_rejected", "executed"},
    # Repeating an identical observation is harmless; changing a settled one is not.
    "module_rejected": {"module_rejected"},
    "account_rejected": {"account_rejected"},
    "executed": {"executed"},
    "retired": set(),
}


class AttemptJournal:
    def __init__(self, path: Path):
        self.db = sqlite3.connect(path, timeout=10)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS attempts (network INTEGER, account TEXT, epoch TEXT,"
                        " nonce TEXT, attempt INTEGER, digest TEXT, status TEXT, broadcast TEXT,"
                        " PRIMARY KEY(network, account, epoch, nonce, attempt))")
        self.db.commit()

    @staticmethod
    def identity(request: AuthRequest) -> tuple:
        return (request.network, request.account.to_str(False), str(request.epoch), str(request.nonce))

    def _latest(self, request: AuthRequest):
        row = self.db.execute("SELECT attempt, digest, status, broadcast FROM attempts WHERE network=?"
                              " AND account=? AND epoch=? AND nonce=? ORDER BY attempt DESC LIMIT 1",
                              self.identity(request)).fetchone()
        return row

    def reserve(self, request: AuthRequest):
        row = self._latest(request)
        if row is not None and row[2] != "retired":
            raise ValueError("nonce already reserved; reconcile, then retire the finished attempt")
        attempt = 1 if row is None else row[0] + 1
        with self.db:
            self.db.execute("INSERT INTO attempts VALUES (?, ?, ?, ?, ?, ?, 'reserved', NULL)",
                            (*self.identity(request), attempt, request.commitment.hex()))

    def update(self, request: AuthRequest, status: str, broadcast: str | None = None):
        if status not in TRANSITIONS or status == "retired":
            raise ValueError("invalid attempt status")
        row = self._latest(request)
        if row is None or row[1] != request.commitment.hex() or row[2] == "retired":
            raise ValueError("unreserved or mismatched request")
        attempt, _, current, recorded = row
        if status not in TRANSITIONS[current]:
            raise ValueError(f"illegal attempt transition {current} -> {status}")
        # The broadcast identity is bound once: a receipt carrying a different
        # one describes a different attempt and must not silently replace it.
        if broadcast is not None and recorded is not None and broadcast != recorded:
            raise ValueError("receipt belongs to a different broadcast")
        with self.db:
            cursor = self.db.execute("UPDATE attempts SET status=?, broadcast=COALESCE(?,broadcast)"
                                     " WHERE network=? AND account=? AND epoch=? AND nonce=? AND attempt=?",
                                     (status, broadcast, *self.identity(request), attempt))
            if cursor.rowcount != 1:
                raise ValueError("unreserved or mismatched request")

    def retire(self, request: AuthRequest):
        """Release a nonce whose attempt finished without consuming it."""
        row = self._latest(request)
        if row is None or row[1] != request.commitment.hex():
            raise ValueError("unreserved or mismatched request")
        attempt, _, current, _ = row
        if current == "executed":
            raise ValueError("an executed attempt consumed the nonce; it cannot be retired")
        if current not in RETIRABLE:
            raise ValueError(f"attempt is not finished: {current}")
        with self.db:
            self.db.execute("UPDATE attempts SET status='retired' WHERE network=? AND account=?"
                            " AND epoch=? AND nonce=? AND attempt=?", (*self.identity(request), attempt))

    def close(self):
        self.db.close()


class PqRelayer:
    def __init__(self, transport: RelayTransport, journal: AttemptJournal, funding_cap: int):
        # The owner's ceiling, not the estimator's. A transport that quotes the
        # cost must not also decide how much it is allowed to quote.
        if type(funding_cap) is not int or not 0 < funding_cap <= MAX_COINS:
            raise ValueError("an explicit positive funding cap is required")
        self.transport, self.journal, self.funding_cap = transport, journal, funding_cap

    async def submit(self, request: AuthRequest, module: Address, signer: PqSigner,
                     loss_ack: str, classical_signature: bytes | None = None) -> str:
        if loss_ack != LOSS_ACK:
            raise ValueError("non-refundable funding loss model must be explicitly accepted")
        address(module)
        request.serialize()
        snapshot = await self.transport.snapshot(request.account, module)
        if snapshot.network != request.network or snapshot.version < 16 or not snapshot.block_id:
            raise ValueError("wrong network, unactivated VM or unanchored snapshot")
        if snapshot.account != request.account or snapshot.module != module:
            raise ValueError("snapshot identity mismatch")
        if module.wc != request.account.wc or module == request.account:
            raise ValueError("module must be distinct and in the same workchain")
        if snapshot.auth.module_hash != module.hash_part or snapshot.auth.mode not in (2, 3):
            raise ValueError("account is not registered with this strict authentication root")
        if (request.epoch, request.nonce) != (snapshot.auth.epoch, snapshot.auth.nonce):
            raise ValueError("stale epoch/nonce; rebuild and re-authorize")
        if request.nonce == (1 << 64) - 1 or not 30 <= request.valid_until - snapshot.chain_time <= 3600:
            raise ValueError("nonce exhausted or insufficient expiry margin")
        if key_bytes(signer.public_key(), 1312) != snapshot.module_public_key:
            raise ValueError("signing key does not match deployed module")
        if (snapshot.auth.mode == 3) != (classical_signature is not None):
            raise ValueError("hybrid AND cosignature requirement not satisfied")
        budget = await self.transport.estimate(request, module)
        value = budget.total
        if value > self.funding_cap:
            raise ValueError("estimate exceeds the owner-approved funding cap")
        body = request.submission(signer.sign(request.commitment), classical_signature, secrets.randbits(64))
        # Reserve before touching the transport. Do not release on an ambiguous timeout.
        self.journal.reserve(request)
        try:
            broadcast = await self.transport.submit_internal(module, body, value)
            if not broadcast:
                raise RuntimeError("transport returned no broadcast identifier")
        except BaseException:
            self.journal.update(request, "unknown")
            raise
        self.journal.update(request, "broadcast", broadcast)
        return broadcast

    async def retire(self, request: AuthRequest, module: Address, broadcast_id: str) -> AttemptReceipt:
        """Free a nonce for re-authorization, on a fresh receipt, never on a timeout."""
        receipt = await self.reconcile(request, module, broadcast_id)
        if receipt.status not in ("module_rejected", "account_rejected"):
            raise ValueError("attempt is not finished; only a settled rejection frees the nonce")
        if receipt.account_nonce_consumed:
            raise ValueError("the account consumed this nonce; rebuild against the new state")
        self.journal.retire(request)
        return receipt

    async def reconcile(self, request: AuthRequest, module: Address, broadcast_id: str) -> AttemptReceipt:
        receipt = await self.transport.receipt(broadcast_id, request, module)
        if (receipt.request_hash != request.commitment.hex() or receipt.account != request.account
                or receipt.module != module):
            raise ValueError("receipt does not belong to this authorization attempt")
        self.journal.update(request, receipt.status, broadcast_id)
        return receipt
