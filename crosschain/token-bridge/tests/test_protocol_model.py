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


def quorum(oracle_count: int) -> int:
    if oracle_count < 3:
        raise ValueError("the upstream bridge requires at least three oracles")
    return (2 * oracle_count + 2) // 3


def query_id(block_time: int, block_hash: str, tx_hash: str, log_index: int) -> int:
    timeout = block_time + 30 * 24 * 60 * 60 + 2
    event_id = f"{block_hash}_{tx_hash}_{log_index}".encode()
    suffix = int.from_bytes(hashlib.sha256(event_id).digest()[:4], "big")
    return (timeout << 32) | suffix


def vote_digest(contract: str, chain_id: int, kind: str, payload: bytes) -> bytes:
    # Python's SHA3 implementation is used only as a deterministic model. The
    # Solidity source uses keccak256 and is tested separately by Hardhat.
    return hashlib.sha3_256(
        b"TOS_TOKEN_BRIDGE" + contract.encode() + chain_id.to_bytes(32, "big") + kind.encode() + payload
    ).digest()


@dataclass
class EvmBridgeModel:
    oracles: tuple[int, ...]
    allow_lock: bool = False
    disabled_tokens: set[str] = field(default_factory=lambda: {"0x0"})
    balances: dict[str, int] = field(default_factory=dict)
    finished: set[bytes] = field(default_factory=set)

    def __post_init__(self) -> None:
        if len(self.oracles) < 3 or len(set(self.oracles)) != len(self.oracles):
            raise ValueError("invalid oracle set")
        if 0 in self.oracles:
            raise ValueError("zero oracle")

    def lock(self, token: str, requested: int, actually_received: int) -> int:
        if not self.allow_lock:
            raise PermissionError("lock paused")
        if token in self.disabled_tokens:
            raise PermissionError("token disabled")
        if requested <= 0 or actually_received <= 0 or actually_received > requested:
            raise ValueError("invalid transfer")
        new_balance = self.balances.get(token, 0) + actually_received
        if new_balance > MAX_JETTON_UNITS:
            raise OverflowError("jetton supply bound")
        self.balances[token] = new_balance
        return actually_received

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

    def unlock(self, token: str, amount: int, digest: bytes, signatures: tuple[int, ...]) -> None:
        self.authorize(digest, signatures)
        if amount <= 0 or self.balances.get(token, 0) < amount:
            raise ValueError("insufficient locked balance")
        self.balances[token] -= amount


@dataclass
class TosBridgeModel:
    mint_fee: int
    burn_fee: int
    swaps_suspended: bool = False
    burns_suspended: bool = False
    paid_swaps: set[int] = field(default_factory=set)
    minted_swaps: set[int] = field(default_factory=set)
    total_supply: dict[str, int] = field(default_factory=dict)

    def pay_swap(self, qid: int, value: int) -> None:
        if value != self.mint_fee:
            raise ValueError("exact mint fee required")
        self.paid_swaps.add(qid)

    def mint(self, token: str, amount: int, qid: int) -> None:
        if self.swaps_suspended:
            raise PermissionError("swaps suspended")
        if qid not in self.paid_swaps or qid in self.minted_swaps:
            raise RuntimeError("unpaid or replayed mint")
        if amount <= 0:
            raise ValueError("zero mint")
        new_supply = self.total_supply.get(token, 0) + amount
        if new_supply > MAX_JETTON_UNITS:
            raise OverflowError("jetton supply bound")
        self.total_supply[token] = new_supply
        self.minted_swaps.add(qid)

    def burn(self, token: str, amount: int, value: int) -> None:
        if self.burns_suspended:
            raise PermissionError("burns suspended")
        if value != self.burn_fee:
            raise ValueError("exact burn fee required")
        if amount <= 0 or self.total_supply.get(token, 0) < amount:
            raise ValueError("invalid burn")
        self.total_supply[token] -= amount


class ProtocolModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.oracles = (11, 22, 33, 44)
        self.evm = EvmBridgeModel(self.oracles)
        self.tos = TosBridgeModel(mint_fee=17, burn_fee=13)

    def test_quorum_matches_upstream_formula(self) -> None:
        self.assertEqual([quorum(n) for n in range(3, 10)], [2, 3, 4, 4, 5, 6, 6])

    def test_oracle_set_rejects_duplicates_zero_and_short_sets(self) -> None:
        for invalid in ((1, 2), (0, 1, 2), (1, 1, 2)):
            with self.assertRaises(ValueError):
                EvmBridgeModel(invalid)

    def test_lock_starts_paused(self) -> None:
        with self.assertRaises(PermissionError):
            self.evm.lock("USDT", 100, 100)

    def test_lock_accounts_for_actual_received_amount(self) -> None:
        self.evm.allow_lock = True
        self.assertEqual(self.evm.lock("USDT", 100, 99), 99)
        self.assertEqual(self.evm.balances["USDT"], 99)

    def test_disabled_token_is_rejected(self) -> None:
        self.evm.allow_lock = True
        self.evm.disabled_tokens.add("USDT")
        with self.assertRaises(PermissionError):
            self.evm.lock("USDT", 100, 100)

    def test_supply_limit_is_enforced(self) -> None:
        self.evm.allow_lock = True
        self.evm.balances["USDT"] = MAX_JETTON_UNITS
        with self.assertRaises(OverflowError):
            self.evm.lock("USDT", 1, 1)

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

    def test_query_id_is_event_unique_and_timeout_scoped(self) -> None:
        a = query_id(1_700_000_000, "a", "b", 0)
        b = query_id(1_700_000_000, "a", "b", 1)
        self.assertNotEqual(a, b)
        self.assertGreater(a >> 32, 1_700_000_000)

    def test_exact_fees_are_required(self) -> None:
        with self.assertRaises(ValueError):
            self.tos.pay_swap(1, 16)
        self.tos.pay_swap(1, 17)
        self.tos.mint("USDT", 10, 1)
        with self.assertRaises(ValueError):
            self.tos.burn("USDT", 1, 12)

    def test_suspension_flags_stop_each_direction(self) -> None:
        self.tos.pay_swap(1, 17)
        self.tos.swaps_suspended = True
        with self.assertRaises(PermissionError):
            self.tos.mint("USDT", 10, 1)
        self.tos.total_supply["USDT"] = 10
        self.tos.burns_suspended = True
        with self.assertRaises(PermissionError):
            self.tos.burn("USDT", 1, 13)

    def test_mint_requires_paid_swap_and_is_single_use(self) -> None:
        with self.assertRaises(RuntimeError):
            self.tos.mint("USDT", 10, 1)
        self.tos.pay_swap(1, 17)
        self.tos.mint("USDT", 10, 1)
        with self.assertRaises(RuntimeError):
            self.tos.mint("USDT", 10, 1)

    def test_end_to_end_lock_mint_burn_unlock_conserves_value(self) -> None:
        token = "USDT"
        amount = 1_000_000
        self.evm.allow_lock = True
        locked = self.evm.lock(token, amount, amount)
        qid = query_id(1_700_000_000, "block", "tx", 7)
        self.tos.pay_swap(qid, 17)
        self.tos.mint(token, locked, qid)
        self.assertEqual(self.evm.balances[token], self.tos.total_supply[token])

        self.tos.burn(token, amount, 13)
        digest = vote_digest("0xbridge", 1, "unlock", amount.to_bytes(16, "big"))
        self.evm.unlock(token, amount, digest, (11, 22, 33))
        self.assertEqual(self.evm.balances[token], 0)
        self.assertEqual(self.tos.total_supply[token], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
