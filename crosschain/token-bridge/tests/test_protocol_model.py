#!/usr/bin/env python3
"""Dependency-free protocol invariants for the TOS oracle token bridge.

This model is intentionally smaller than the contracts. It checks the invariants
that must agree across the TVM and EVM halves: quorum, replay protection, supply
conservation, fee/suspension gates, and domain separation.
"""

from __future__ import annotations

import hashlib
import unittest
from dataclasses import dataclass, field

MAX_JETTON_UNITS = (1 << 120) - 1
# The last lock nonce the EVM side allocates; 2^64 - 1 is the TOS sentinel.
MAX_LOCK_NONCE = (1 << 64) - 2
SWAP_WINDOW = 16


def quorum(oracle_count: int) -> int:
    if oracle_count < 3:
        raise ValueError("the upstream bridge requires at least three oracles")
    return (2 * oracle_count + 2) // 3


def vote_digest(contract: str, chain_id: int, kind: str, payload: bytes) -> bytes:
    # Python's SHA3 implementation is used only as a deterministic model. The
    # Solidity source uses keccak256 and is tested separately by Hardhat.
    return hashlib.sha3_256(
        b"TOS_TOKEN_BRIDGE" + contract.encode() + chain_id.to_bytes(32, "big") + kind.encode() + payload
    ).digest()


@dataclass
class Lock:
    locker: str
    token: str
    amount: int
    generation: int
    refunded: bool = False


@dataclass
class EvmBridgeModel:
    oracles: tuple[int, ...]
    allow_lock: bool = False
    disabled_tokens: set[str] = field(default_factory=lambda: {"0x0"})
    balances: dict[str, int] = field(default_factory=dict)
    finished: set[bytes] = field(default_factory=set)
    generation: int = 0
    generations: dict[int, tuple[str, int, int]] = field(default_factory=dict)
    lock_nonce: int = 0
    locks: dict[int, Lock] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if len(self.oracles) < 3 or len(set(self.oracles)) != len(self.oracles):
            raise ValueError("invalid oracle set")
        if 0 in self.oracles:
            raise ValueError("zero oracle")

    def new_generation(self, generation: int, tos_bridge: str, tos_life: int, digest: bytes, signatures: tuple[int, ...]) -> None:
        self.authorize(digest, signatures)
        if generation != self.generation + 1:
            raise ValueError("a generation follows the current one")
        if not tos_bridge or tos_life == 0:
            raise ValueError("a generation names a TOS bridge life")
        self.generation = generation
        self.generations[generation] = (tos_bridge, tos_life, self.lock_nonce)

    def lock(self, locker: str, token: str, requested: int, actually_received: int) -> int:
        if not self.allow_lock:
            raise PermissionError("lock paused")
        if self.generation == 0:
            raise PermissionError("no active generation")
        if self.lock_nonce > MAX_LOCK_NONCE:
            raise OverflowError("lock nonces exhausted")
        if token in self.disabled_tokens:
            raise PermissionError("token disabled")
        if requested <= 0 or actually_received <= 0 or actually_received > requested:
            raise ValueError("invalid transfer")
        new_balance = self.balances.get(token, 0) + actually_received
        if new_balance > MAX_JETTON_UNITS:
            raise OverflowError("jetton supply bound")
        self.balances[token] = new_balance
        n = self.lock_nonce
        self.lock_nonce = n + 1
        self.locks[n] = Lock(locker, token, actually_received, self.generation)
        return n

    def authorize(self, digest: bytes, signatures: tuple[int, ...]) -> None:
        if digest in self.finished:
            raise RuntimeError("replay")
        if len(signatures) < quorum(len(self.oracles)):
            raise PermissionError("insufficient quorum")
        if tuple(sorted(signatures)) != signatures or len(set(signatures)) != len(signatures):
            raise ValueError("signatures must be strictly sorted")
        if any(signer not in self.oracles for signer in signatures):
            raise PermissionError("unauthorized signer")
        self.finished.add(digest)

    def refund_lock(self, n: int, tos: "TosBridgeModel", signatures: tuple[int, ...]) -> None:
        lock = self.locks.get(n)
        if lock is None or lock.refunded:
            raise RuntimeError("lock is not refundable")
        # Oracles sign a refund only for a cancellation the lock's own
        # generation logged on TOS; without one there is no quorum to present.
        if (lock.generation, n) not in tos.cancel_logs:
            raise PermissionError("no cancellation logged for this lock")
        self.authorize(vote_digest("0xbridge", 1, "refund", n.to_bytes(8, "big")), signatures)
        lock.refunded = True
        self.balances[lock.token] -= lock.amount

    def unlock(self, token: str, amount: int, digest: bytes, signatures: tuple[int, ...]) -> None:
        self.authorize(digest, signatures)
        if amount <= 0 or self.balances.get(token, 0) < amount:
            raise ValueError("insufficient locked balance")
        self.balances[token] -= amount


PAID, PREPARING, CONSUMED, CANCELLED = "paid", "preparing", "consumed", "cancelled"


@dataclass
class TosBridgeModel:
    """The TOS bridge's swap channel: one generation, a window over n."""

    life: int
    generation: int = 0
    watermark: int = 0
    swaps: dict[int, str] = field(default_factory=dict)
    payers: dict[int, int] = field(default_factory=dict)
    cancel_logs: list[tuple[int, int]] = field(default_factory=list)
    total_supply: dict[str, int] = field(default_factory=dict)
    refunded_fees: int = 0

    def activate(self, generation: int, life: int, start: int) -> None:
        if self.generation != 0:
            raise RuntimeError("activated once")
        if life != self.life:
            raise PermissionError("names another bridge life")
        self.generation = generation
        self.watermark = start

    def _open(self, generation: int, n: int) -> None:
        if self.generation == 0 or generation != self.generation:
            raise PermissionError("wrong generation")
        if n > MAX_LOCK_NONCE or n < self.watermark:
            raise RuntimeError("not admissible")
        if n >= self.watermark + SWAP_WINDOW:
            raise RuntimeError("window full")

    def pay_swap(self, generation: int, n: int, value: int) -> None:
        self._open(generation, n)
        if n in self.swaps:
            raise RuntimeError("already paid or decided")
        self.swaps[n] = PAID
        self.payers[n] = value

    def vote_swap(self, generation: int, n: int) -> None:
        self._open(generation, n)
        if self.swaps.get(n) != PAID:
            raise RuntimeError("unpaid or decided")
        self.swaps[n] = PREPARING

    def complete(self, n: int, token: str, amount: int) -> None:
        if self.swaps.get(n) != PREPARING:
            raise RuntimeError("not preparing")
        new_supply = self.total_supply.get(token, 0) + amount
        if new_supply > MAX_JETTON_UNITS:
            raise OverflowError("jetton supply bound")
        self.total_supply[token] = new_supply
        self.swaps[n] = CONSUMED
        self._fold()

    def cancel_lock(self, generation: int, n: int) -> None:
        self._open(generation, n)
        state = self.swaps.get(n)
        if state in (PREPARING, CONSUMED, CANCELLED):
            raise RuntimeError("cancellation refused")
        if state == PAID:
            self.refunded_fees += self.payers.pop(n)
        self.swaps[n] = CANCELLED
        self.cancel_logs.append((self.generation, n))
        self._fold()

    def _fold(self) -> None:
        while self.swaps.get(self.watermark) in (CONSUMED, CANCELLED):
            del self.swaps[self.watermark]
            self.watermark += 1


class ProtocolModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.oracles = (11, 22, 33, 44)
        self.evm = EvmBridgeModel(self.oracles)
        self.tos = TosBridgeModel(life=5)

    def activate(self, generation: int = 1) -> None:
        self.evm.new_generation(generation, "tos-bridge", 5, f"gen{generation}".encode(), (11, 22, 33))
        self.tos.activate(generation, 5, self.evm.generations[generation][2])
        self.evm.allow_lock = True

    def test_quorum_matches_upstream_formula(self) -> None:
        self.assertEqual([quorum(n) for n in range(3, 10)], [2, 3, 4, 4, 5, 6, 6])

    def test_oracle_set_rejects_duplicates_zero_and_short_sets(self) -> None:
        for invalid in ((1, 2), (0, 1, 2), (1, 1, 2)):
            with self.assertRaises(ValueError):
                EvmBridgeModel(invalid)

    def test_lock_starts_paused_and_needs_a_generation(self) -> None:
        with self.assertRaises(PermissionError):
            self.evm.lock("a", "USDT", 100, 100)
        self.evm.allow_lock = True
        with self.assertRaises(PermissionError):
            self.evm.lock("a", "USDT", 100, 100)

    def test_locks_are_numbered_densely_and_never_wrap(self) -> None:
        self.activate()
        self.assertEqual([self.evm.lock("a", "USDT", 1, 1) for _ in range(3)], [0, 1, 2])
        self.evm.lock_nonce = MAX_LOCK_NONCE
        self.assertEqual(self.evm.lock("a", "USDT", 1, 1), MAX_LOCK_NONCE)
        with self.assertRaises(OverflowError):
            self.evm.lock("a", "USDT", 1, 1)

    def test_generations_only_move_forward_and_start_above_every_lock(self) -> None:
        self.activate()
        self.evm.lock("a", "USDT", 1, 1)
        with self.assertRaises(ValueError):
            self.evm.new_generation(3, "b", 6, b"g3", (11, 22, 33))
        self.evm.new_generation(2, "b", 6, b"g2", (11, 22, 33))
        self.assertEqual(self.evm.generations[2][2], 1)

    def test_lock_accounts_for_actual_received_amount(self) -> None:
        self.activate()
        self.evm.lock("a", "USDT", 100, 99)
        self.assertEqual(self.evm.balances["USDT"], 99)

    def test_disabled_token_is_rejected(self) -> None:
        self.activate()
        self.evm.disabled_tokens.add("USDT")
        with self.assertRaises(PermissionError):
            self.evm.lock("a", "USDT", 100, 100)

    def test_supply_limit_is_enforced(self) -> None:
        self.activate()
        self.evm.balances["USDT"] = MAX_JETTON_UNITS
        with self.assertRaises(OverflowError):
            self.evm.lock("a", "USDT", 1, 1)

    def test_signature_quorum_and_ordering(self) -> None:
        digest = b"d" * 32
        with self.assertRaises(PermissionError):
            self.evm.authorize(digest, (11, 22))
        with self.assertRaises(ValueError):
            self.evm.authorize(digest, (22, 11, 33))
        self.evm.authorize(digest, (11, 22, 33))

    def test_unauthorized_oracle_is_rejected(self) -> None:
        with self.assertRaises(PermissionError):
            self.evm.authorize(b"x" * 32, (11, 22, 55))

    def test_finished_vote_cannot_replay(self) -> None:
        digest = b"r" * 32
        self.evm.authorize(digest, (11, 22, 33))
        with self.assertRaises(RuntimeError):
            self.evm.authorize(digest, (11, 22, 33))

    def test_digest_changes_with_evm_chain_and_contract(self) -> None:
        payload = b"burn"
        a = vote_digest("0xabc", 1, "unlock", payload)
        self.assertNotEqual(a, vote_digest("0xabc", 56, "unlock", payload))
        self.assertNotEqual(a, vote_digest("0xdef", 1, "unlock", payload))

    def test_activation_names_this_bridge_life_and_happens_once(self) -> None:
        with self.assertRaises(PermissionError):
            self.tos.activate(1, 4, 0)
        self.tos.activate(1, 5, 0)
        with self.assertRaises(RuntimeError):
            self.tos.activate(2, 5, 0)

    def test_payments_only_inside_the_window_and_only_once(self) -> None:
        self.activate()
        with self.assertRaises(RuntimeError):
            self.tos.pay_swap(1, SWAP_WINDOW, 17)
        with self.assertRaises(PermissionError):
            self.tos.pay_swap(2, 0, 17)
        self.tos.pay_swap(1, 0, 17)
        with self.assertRaises(RuntimeError):
            self.tos.pay_swap(1, 0, 17)

    def test_an_unpaid_gap_is_cancelled_and_the_window_reopens(self) -> None:
        self.activate()
        for n in range(1, SWAP_WINDOW):
            self.tos.pay_swap(1, n, 17)
        with self.assertRaises(RuntimeError):
            self.tos.pay_swap(1, SWAP_WINDOW, 17)
        self.tos.cancel_lock(1, 0)
        self.assertEqual(self.tos.cancel_logs, [(1, 0)])
        self.tos.pay_swap(1, SWAP_WINDOW, 17)
        # below the watermark nothing is evaluated, and nothing is logged again
        with self.assertRaises(RuntimeError):
            self.tos.cancel_lock(1, 0)
        self.assertEqual(len(self.tos.cancel_logs), 1)

    def test_cancellation_and_consumption_are_exclusive(self) -> None:
        self.activate()
        self.tos.pay_swap(1, 0, 17)
        self.tos.vote_swap(1, 0)
        with self.assertRaises(RuntimeError):
            self.tos.cancel_lock(1, 0)
        self.tos.complete(0, "USDT", 10)
        with self.assertRaises(RuntimeError):
            self.tos.vote_swap(1, 0)

    def test_a_paid_cancelled_lock_returns_its_fee(self) -> None:
        self.activate()
        self.tos.pay_swap(1, 0, 17)
        self.tos.cancel_lock(1, 0)
        self.assertEqual(self.tos.refunded_fees, 17)

    def test_refunds_follow_cancellations_only_and_happen_once(self) -> None:
        self.activate()
        consumed = self.evm.lock("a", "USDT", 10, 10)
        cancelled = self.evm.lock("a", "USDT", 5, 5)
        self.tos.pay_swap(1, consumed, 17)
        self.tos.vote_swap(1, consumed)
        self.tos.complete(consumed, "USDT", 10)
        self.tos.cancel_lock(1, cancelled)
        with self.assertRaises(PermissionError):
            self.evm.refund_lock(consumed, self.tos, (11, 22, 33))
        self.evm.refund_lock(cancelled, self.tos, (11, 22, 33))
        with self.assertRaises(RuntimeError):
            self.evm.refund_lock(cancelled, self.tos, (11, 22, 33))

    def test_a_recreated_bridge_cannot_act_on_old_locks(self) -> None:
        self.activate()
        old = self.evm.lock("a", "USDT", 10, 10)
        self.tos.pay_swap(1, old, 17)
        self.tos.vote_swap(1, old)
        self.tos.complete(old, "USDT", 10)
        self.evm.new_generation(2, "tos-bridge-2", 9, b"gen2", (11, 22, 33))
        recreated = TosBridgeModel(life=9)
        recreated.activate(2, 9, self.evm.generations[2][2])
        for attempt in (lambda: recreated.pay_swap(1, old, 17), lambda: recreated.pay_swap(2, old, 17),
                        lambda: recreated.cancel_lock(2, old)):
            with self.assertRaises((PermissionError, RuntimeError)):
                attempt()
        self.assertEqual(recreated.cancel_logs, [])

    def test_end_to_end_conserves_value(self) -> None:
        self.activate()
        minted = self.evm.lock("a", "USDT", 1_000_000, 1_000_000)
        refunded = self.evm.lock("a", "USDT", 7, 7)
        self.tos.pay_swap(1, minted, 17)
        self.tos.vote_swap(1, minted)
        self.tos.complete(minted, "USDT", 1_000_000)
        self.tos.cancel_lock(1, refunded)
        self.evm.refund_lock(refunded, self.tos, (11, 22, 33))
        self.assertEqual(self.evm.balances["USDT"], self.tos.total_supply["USDT"])
        digest = vote_digest("0xbridge", 1, "unlock", (1_000_000).to_bytes(16, "big"))
        self.tos.total_supply["USDT"] -= 1_000_000
        self.evm.unlock("USDT", 1_000_000, digest, (11, 22, 33))
        self.assertEqual(self.evm.balances["USDT"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
