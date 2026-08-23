#!/usr/bin/env python3
"""Dependency-free protocol invariants for the TOS oracle coin bridge.

This model is intentionally smaller than the contracts. It checks the rules
that must agree across the TVM and EVM halves: the ceiling(2n/3) mint quorum,
strictly sorted oracle signatures, chain and contract domain separation,
per-digest replay protection, the burn switch, oracle-set rotation, and
native/wrapped supply conservation.
"""

from __future__ import annotations

import hashlib
import unittest
from dataclasses import dataclass, field


def quorum(oracle_count: int) -> int:
    if oracle_count < 3:
        raise ValueError("the upstream bridge requires at least three oracles")
    # Ceiling: a floor threshold is satisfied by half the set at sizes that
    # are not multiples of three. Mirrors Bridge.sol.
    return (2 * oracle_count + 2) // 3


def vote_digest(contract: str, chain_id: int, kind: str, payload: bytes) -> bytes:
    # Python's SHA3 implementation is used only as a deterministic model. The
    # Solidity source uses keccak256 and is tested separately by Truffle.
    if chain_id <= 0:
        raise ValueError("chain ID must be positive")
    return hashlib.sha3_256(
        b"TOS_COIN_BRIDGE"
        + contract.encode()
        + chain_id.to_bytes(32, "big")
        + kind.encode()
        + payload
    ).digest()


def tvm_query_digest(wallet_id: int, destination: str, payload: bytes) -> bytes:
    """Model the TVM multisig query hash's deployment and destination binding."""
    return hashlib.sha3_256(
        wallet_id.to_bytes(4, "big") + destination.encode() + payload
    ).digest()


@dataclass
class WrappedTosBridgeModel:
    """Models Bridge.sol + WrappedTOS.sol from the pinned Solidity plane."""

    oracles: tuple[int, ...]
    allow_burn: bool = False
    total_supply: int = 0
    balances: dict[str, int] = field(default_factory=dict)
    finished: set[bytes] = field(default_factory=set)

    def __post_init__(self) -> None:
        self._install_set(self.oracles)

    def _install_set(self, new_set: tuple[int, ...]) -> None:
        if len(new_set) <= 2:
            raise ValueError("new set is too short")
        if len(set(new_set)) != len(new_set):
            raise ValueError("duplicate oracle in set")
        if 0 in new_set:
            raise ValueError("zero oracle")
        self.oracles = new_set

    def general_vote(self, digest: bytes, signatures: tuple[int, ...]) -> None:
        if len(signatures) < quorum(len(self.oracles)):
            raise PermissionError("not enough signatures")
        if digest in self.finished:
            raise RuntimeError("vote is already finished")
        last_signer = 0
        for signer in signatures:
            if signer not in self.oracles:
                raise PermissionError("unauthorized signer")
            if signer <= last_signer:
                raise ValueError("signatures are not sorted")
            last_signer = signer
        self.finished.add(digest)

    def vote_for_minting(
        self, receiver: str, amount: int, digest: bytes, signatures: tuple[int, ...]
    ) -> None:
        if amount <= 0:
            raise ValueError("invalid amount")
        self.general_vote(digest, signatures)
        self.balances[receiver] = self.balances.get(receiver, 0) + amount
        self.total_supply += amount

    def vote_for_new_oracle_set(
        self, new_set: tuple[int, ...], digest: bytes, signatures: tuple[int, ...]
    ) -> None:
        self.general_vote(digest, signatures)
        self._install_set(new_set)

    def vote_for_switch_burn(
        self, new_status: bool, digest: bytes, signatures: tuple[int, ...]
    ) -> None:
        self.general_vote(digest, signatures)
        self.allow_burn = new_status

    def burn(self, account: str, amount: int) -> None:
        if not self.allow_burn:
            raise PermissionError("burn is currently disabled")
        if amount <= 0 or self.balances.get(account, 0) < amount:
            raise ValueError("insufficient balance")
        self.balances[account] -= amount
        self.total_supply -= amount


@dataclass
class TvmBridgeModel:
    """Models the locked-coin side of bridge_code.fc."""

    locked: int = 0

    def lock(self, amount: int, fee: int) -> int:
        if amount <= fee or fee < 0:
            raise ValueError("value does not cover the flat bridge fee")
        transferred = amount - fee
        self.locked += transferred
        return transferred

    def unlock(self, amount: int) -> None:
        if amount <= 0 or amount > self.locked:
            raise ValueError("cannot unlock more than is locked")
        self.locked -= amount


ORACLES = (11, 22, 33)
CHAIN_ID = 7001


class DomainSeparationTest(unittest.TestCase):
    def test_evm_chain_and_contract_are_both_bound(self) -> None:
        base = vote_digest("bridge-a", CHAIN_ID, "swap", b"tx1")
        self.assertNotEqual(base, vote_digest("bridge-a", 7002, "swap", b"tx1"))
        self.assertNotEqual(base, vote_digest("bridge-b", CHAIN_ID, "swap", b"tx1"))

    def test_legacy_format_is_not_the_new_digest(self) -> None:
        legacy = hashlib.sha3_256(b"TOS_COIN_BRIDGE" + b"bridge" + b"swap" + b"tx1").digest()
        self.assertNotEqual(legacy, vote_digest("bridge", CHAIN_ID, "swap", b"tx1"))

    def test_tvm_wallet_and_destination_are_both_bound(self) -> None:
        eth_wallet_id = 0x45544831
        bsc_wallet_id = 0x42534331
        base = tvm_query_digest(eth_wallet_id, "ethereum-bridge", b"unlock")
        self.assertNotEqual(
            base, tvm_query_digest(bsc_wallet_id, "ethereum-bridge", b"unlock")
        )
        self.assertNotEqual(
            base, tvm_query_digest(eth_wallet_id, "bsc-bridge", b"unlock")
        )


class QuorumTest(unittest.TestCase):
    def test_ceiling_two_thirds(self) -> None:
        # Shared vector with the Solidity threshold matrix test.
        expected = {3: 2, 4: 3, 5: 4, 6: 4, 7: 5, 8: 6, 9: 6, 10: 7, 11: 8, 12: 8}
        for size, need in expected.items():
            self.assertEqual(quorum(size), need, f"set size {size}")

    def test_tiny_sets_rejected(self) -> None:
        with self.assertRaises(ValueError):
            quorum(2)


class MintVoteTest(unittest.TestCase):
    def setUp(self) -> None:
        self.bridge = WrappedTosBridgeModel(ORACLES)

    def test_happy_path_mints(self) -> None:
        digest = vote_digest("bridge", CHAIN_ID, "swap", b"tx1")
        self.bridge.vote_for_minting("alice", 100, digest, (11, 22))
        self.assertEqual(self.bridge.balances["alice"], 100)
        self.assertEqual(self.bridge.total_supply, 100)

    def test_replay_rejected(self) -> None:
        digest = vote_digest("bridge", CHAIN_ID, "swap", b"tx1")
        self.bridge.vote_for_minting("alice", 100, digest, (11, 22))
        with self.assertRaises(RuntimeError):
            self.bridge.vote_for_minting("alice", 100, digest, (11, 22))
        self.assertEqual(self.bridge.total_supply, 100)

    def test_insufficient_quorum_rejected(self) -> None:
        digest = vote_digest("bridge", CHAIN_ID, "swap", b"tx2")
        with self.assertRaises(PermissionError):
            self.bridge.vote_for_minting("alice", 100, digest, (11,))

    def test_unknown_signer_rejected(self) -> None:
        digest = vote_digest("bridge", CHAIN_ID, "swap", b"tx3")
        with self.assertRaises(PermissionError):
            self.bridge.vote_for_minting("alice", 100, digest, (11, 44))

    def test_unsorted_or_duplicate_signers_rejected(self) -> None:
        digest = vote_digest("bridge", CHAIN_ID, "swap", b"tx4")
        with self.assertRaises(ValueError):
            self.bridge.vote_for_minting("alice", 100, digest, (22, 11))
        with self.assertRaises(ValueError):
            self.bridge.vote_for_minting("alice", 100, digest, (11, 11))

    def test_zero_amount_rejected(self) -> None:
        digest = vote_digest("bridge", CHAIN_ID, "swap", b"tx5")
        with self.assertRaises(ValueError):
            self.bridge.vote_for_minting("alice", 0, digest, (11, 22))


class BurnSwitchTest(unittest.TestCase):
    def setUp(self) -> None:
        self.bridge = WrappedTosBridgeModel(ORACLES)
        self.bridge.vote_for_minting(
            "alice", 100, vote_digest("bridge", CHAIN_ID, "swap", b"tx1"), (11, 22)
        )

    def test_burn_disabled_by_default(self) -> None:
        with self.assertRaises(PermissionError):
            self.bridge.burn("alice", 50)

    def test_burn_after_vote(self) -> None:
        self.bridge.vote_for_switch_burn(
            True, vote_digest("bridge", CHAIN_ID, "burn-status", b"nonce1"), (11, 22)
        )
        self.bridge.burn("alice", 60)
        self.assertEqual(self.bridge.balances["alice"], 40)
        self.assertEqual(self.bridge.total_supply, 40)

    def test_burn_beyond_balance_rejected(self) -> None:
        self.bridge.vote_for_switch_burn(
            True, vote_digest("bridge", CHAIN_ID, "burn-status", b"nonce1"), (11, 22)
        )
        with self.assertRaises(ValueError):
            self.bridge.burn("alice", 101)

    def test_switch_nonce_replay_rejected(self) -> None:
        digest = vote_digest("bridge", CHAIN_ID, "burn-status", b"nonce1")
        self.bridge.vote_for_switch_burn(True, digest, (11, 22))
        with self.assertRaises(RuntimeError):
            self.bridge.vote_for_switch_burn(False, digest, (11, 22))
        self.assertTrue(self.bridge.allow_burn)


class OracleRotationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.bridge = WrappedTosBridgeModel(ORACLES)

    def test_rotation_replaces_set(self) -> None:
        new_set = (44, 55, 66, 77)
        self.bridge.vote_for_new_oracle_set(
            new_set, vote_digest("bridge", CHAIN_ID, "set", b"set1"), (11, 22)
        )
        self.assertEqual(self.bridge.oracles, new_set)
        digest = vote_digest("bridge", CHAIN_ID, "swap", b"tx1")
        with self.assertRaises(PermissionError):
            self.bridge.vote_for_minting("alice", 100, digest, (11, 22))
        self.bridge.vote_for_minting("alice", 100, digest, (44, 55, 66))
        self.assertEqual(self.bridge.total_supply, 100)

    def test_short_or_duplicate_set_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.bridge.vote_for_new_oracle_set(
                (44, 55), vote_digest("bridge", CHAIN_ID, "set", b"set2"), (11, 22)
            )
        with self.assertRaises(ValueError):
            self.bridge.vote_for_new_oracle_set(
                (44, 44, 55), vote_digest("bridge", CHAIN_ID, "set", b"set3"), (11, 22)
            )


class SupplyConservationTest(unittest.TestCase):
    def test_locked_equals_minted_over_round_trip(self) -> None:
        tvm = TvmBridgeModel()
        evm = WrappedTosBridgeModel(ORACLES)

        transferred = tvm.lock(1_000_000_000, fee=5_000_000)
        evm.vote_for_minting(
            "alice", transferred, vote_digest("bridge", CHAIN_ID, "swap", b"lock1"), (11, 22)
        )
        self.assertEqual(tvm.locked, evm.total_supply)

        evm.vote_for_switch_burn(
            True, vote_digest("bridge", CHAIN_ID, "burn-status", b"n1"), (11, 22)
        )
        evm.burn("alice", 400_000_000)
        tvm.unlock(400_000_000)
        self.assertEqual(tvm.locked, evm.total_supply)

    def test_unlock_cannot_exceed_locked(self) -> None:
        tvm = TvmBridgeModel()
        tvm.lock(100, fee=10)
        with self.assertRaises(ValueError):
            tvm.unlock(91)

    def test_lock_must_cover_fee(self) -> None:
        tvm = TvmBridgeModel()
        with self.assertRaises(ValueError):
            tvm.lock(10, fee=10)


if __name__ == "__main__":
    unittest.main()
