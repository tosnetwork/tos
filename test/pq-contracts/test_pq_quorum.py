#!/usr/bin/env python3
"""pq-quorum-signatures through a harness contract, as real transactions at global version 16.

usage: test_pq_quorum.py --build <build-dir> --signer <test-pq-contracts-sign> [--harness <source>]

The harness exposes each library entry point as an internal message (see
pq-quorum-harness.fc). Every case asserts the exit code and the stored state afterwards,
and the cases that must fail cheaply also assert that no verification was paid for.
"""

import argparse
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pqtest  # noqa: E402
from pqtest import Cell, make_dict  # noqa: E402

parser = argparse.ArgumentParser()
parser.add_argument("--build", required=True)
parser.add_argument("--signer", required=True)
parser.add_argument("--harness", default=str(HERE / "pq-quorum-harness.fc"))
parser.add_argument("--report", help="write measured gas as JSON here")
parser.add_argument("--results", help="write the structured test outcome as JSON here")
ARGS, REST = parser.parse_known_args()
native = pqtest.configure(ARGS.build, ARGS.signer)

CONTEXT = b"TOS-PQ-QUORUM-v1"
GLOBAL_ID = native.GLOBAL_ID
ADDRESS = (0, 0x5151 << 240)
SENDER = (0, 0x7777 << 240)
FUNDING = 100_000_000_000
VERIFICATION_GAS = 50_000  # the instruction's base charge, paid before decoding anything

ERR = {
    "invalid_config": 0x1B01,
    "duplicate_verifier": 0x1B02,
    "unknown_signer": 0x1B03,
    "malformed_signature": 0x1B04,
    "invalid_signature": 0x1B05,
    "wrong_signature_count": 0x1B06,
    "expired": 0x1B07,
    "invalid_target": 0x1B08,
    "key_id_mismatch": 0x1B09,
    "pq_key_length": 62,
    "pq_malformed_key": 63,
}
MAX_VERIFIERS = 64
MAX_QUORUM = 12
REPORT = {}

with tempfile.TemporaryDirectory() as tmp:
    CODE = pqtest.compile_source(ARGS.harness, Path(tmp) / "harness.boc")


def empty_state():
    return Cell().uint(0, 1).uint(0, 8).uint(0, 8).uint(0, 32).uint(0, 256)


def verifier_set(keys):
    return make_dict(
        {
            pqtest.key_id(pqtest.public_key(k)): Cell().ref(pqtest.stored(pqtest.public_key(k)))
            for k in keys
        },
        256,
    )


def signatures(entries, message):
    """entries: list of (signing key, key filed under)."""
    return make_dict(
        {
            pqtest.key_id(pqtest.public_key(filed)): Cell().ref(
                pqtest.stored(pqtest.sign(k, message, CONTEXT))
            )
            for k, filed in entries
        },
        256,
    )


def hash_bytes(n):
    return bytes([n]) * 32


class Harness:
    def __init__(self, version=16):
        self.emulator = native.Emulator(global_version=version)
        self.shard = native.active_account(ADDRESS, CODE, empty_state(), FUNDING)

    def data_hash(self):
        return native.account_data(self.shard)[0].hash

    def send(self, body, value=50_000_000_000):
        """Runs one transaction and adopts the account the executor returns, whatever the
        outcome, so a refusal is judged on the state it actually left behind."""
        before = self.data_hash()
        result = self.emulator.send(self.shard, native.internal(SENDER, ADDRESS, body, value))
        details = pqtest.details_of(result)
        self.shard = pqtest.from_boc(result["shard_account"])
        details["data_changed"] = self.data_hash() != before
        return details

    def state(self):
        data, _ = native.account_data(self.shard)
        s = data.slice()
        verifiers = s.maybe()
        return {
            "verifiers": verifiers,
            "count": s.uint(8),
            "quorum": s.uint(8),
            "checks": s.uint(32),
            "last_hash": s.uint(256),
        }

    def configure(self, keys, quorum):
        return self.send(
            Cell().uint(1, 32).maybe(verifier_set(keys) if keys else None).uint(quorum, 8)
        )

    def check(self, message, sigs):
        return self.send(Cell().uint(3, 32).uint(int.from_bytes(message, "big"), 256).maybe(sigs))


class PqQuorumTest(unittest.TestCase):
    def assertExit(self, details, name):
        """A refusal must leave the contract's data exactly as it was; a success must have
        completed both phases."""
        code = ERR[name] if isinstance(name, str) else name
        self.assertEqual(details["exit"], code, details)
        if code == 0:
            self.assertTrue(details["compute_success"] and not details["aborted"], details)
            self.assertTrue(details["action"] and details["action"]["success"], details)
        else:
            self.assertFalse(details["data_changed"], details)

    def first_verification_gas(self, h, message):
        """Gas of a well-formed 3-of-5 request whose first verified entry is invalid: one
        verification paid. A request refused earlier must cost clearly less."""
        signers = [0, 1, 2]
        first = min(signers, key=lambda k: pqtest.key_id(pqtest.public_key(k)))
        entries = pqtest.read_dict(
            signatures([(k, k) for k in signers if k != first], message), 256
        )
        entries[pqtest.key_id(pqtest.public_key(first))] = Cell().ref(
            pqtest.stored(pqtest.sign(first, hash_bytes(99), CONTEXT))
        )
        d = h.check(message, make_dict(entries, 256))
        self.assertExit(d, "invalid_signature")
        return d["gas"]

    def assertNoVerification(self, h, message, details):
        self.assertLess(
            details["gas"] + VERIFICATION_GAS - 10_000,
            self.first_verification_gas(h, message),
            details,
        )

    def configured(self, keys, quorum):
        h = Harness()
        self.assertExit(h.configure(keys, quorum), 0)
        return h

    def test_quorum_met_with_exactly_quorum_signatures(self):
        h = self.configured(range(5), 3)
        message = hash_bytes(1)
        d = h.check(message, signatures([(0, 0), (2, 2), (4, 4)], message))
        self.assertExit(d, 0)
        self.assertEqual(h.state()["checks"], 1)
        REPORT["three_of_five_gas"] = d["gas"]

    def test_wrong_count_refused_before_any_verification(self):
        h = self.configured(range(5), 3)
        message = hash_bytes(2)
        for entries in ([(0, 0), (1, 1)], [(0, 0), (1, 1), (2, 2), (3, 3)]):
            d = h.check(message, signatures(entries, message))
            self.assertExit(d, "wrong_signature_count")
            self.assertNoVerification(h, message, d)
        self.assertExit(h.check(message, None), "wrong_signature_count")
        self.assertEqual(h.state()["checks"], 0)

    def test_count_stops_at_the_first_entry_past_the_quorum(self):
        # The walk is the gas bound on a request: forty entries must cost about what four do.
        h = self.configured(range(5), 3)
        message = hash_bytes(9)
        filler = Cell().ref(pqtest.stored(pqtest.sign(0, message, CONTEXT)))
        gas = {}
        for n in (4, 40):
            d = h.check(message, make_dict({(i + 1) << 200: filler for i in range(n)}, 256))
            self.assertExit(d, "wrong_signature_count")
            gas[n] = d["gas"]
        self.assertLess(gas[40] - gas[4], 2_000, gas)

    def test_unknown_signer_refused_before_any_verification(self):
        h = self.configured(range(5), 3)
        message = hash_bytes(3)
        d = h.check(message, signatures([(0, 0), (1, 1), (9, 9)], message))
        self.assertExit(d, "unknown_signer")
        self.assertNoVerification(h, message, d)

    def test_bad_signatures_reject_the_whole_request(self):
        h = self.configured(range(5), 3)
        message = hash_bytes(4)
        # key 3's signature filed under key 2's id
        self.assertExit(
            h.check(message, signatures([(0, 0), (1, 1), (3, 2)], message)), "invalid_signature"
        )
        # valid signatures over another message
        self.assertExit(
            h.check(message, signatures([(0, 0), (1, 1), (2, 2)], hash_bytes(5))),
            "invalid_signature",
        )
        # valid signature under another context
        bad = signatures([(0, 0), (1, 1)], message)
        entries = pqtest.read_dict(bad, 256)
        entries[pqtest.key_id(pqtest.public_key(2))] = Cell().ref(
            pqtest.stored(pqtest.sign(2, message, b"TOS-AUTH-ML-DSA-44-v1"))
        )
        self.assertExit(h.check(message, make_dict(entries, 256)), "invalid_signature")
        self.assertEqual(h.state()["checks"], 0)

    def test_malformed_signatures_refused_before_any_verification(self):
        h = self.configured(range(5), 3)
        message = hash_bytes(6)
        good = pqtest.sign(2, message, CONTEXT)
        # The wrapper is checked before anything is verified.
        early = [
            Cell().ref(Cell().uint(len(good) - 1, 32).ref(pqtest.chain(good[:-1]))),
            Cell().ref(Cell().uint(len(good), 16).ref(pqtest.chain(good))),
            Cell().ref(Cell().uint(len(good), 32)),
            Cell().uint(1, 1).ref(pqtest.stored(good)),
            Cell(),
        ]
        for value in early:
            entries = pqtest.read_dict(signatures([(0, 0), (1, 1)], message), 256)
            entries[pqtest.key_id(pqtest.public_key(2))] = value
            d = h.check(message, make_dict(entries, 256))
            self.assertExit(d, "malformed_signature")
            self.assertNoVerification(h, message, d)
        # The chain itself is the verifier's to refuse: a short or long one, or a chunk
        # boundary off the canonical 127 bytes, throws cell underflow.
        off_boundary = Cell().raw(good[:100]).ref(pqtest.chain(good[100:]))
        for chain in (pqtest.chain(good[:-1]), pqtest.chain(good + b"\x00"), off_boundary):
            entries = pqtest.read_dict(signatures([(0, 0), (1, 1)], message), 256)
            entries[pqtest.key_id(pqtest.public_key(2))] = Cell().ref(
                Cell().uint(len(good), 32).ref(chain)
            )
            self.assertExit(h.check(message, make_dict(entries, 256)), 9)
        self.assertEqual(h.state()["checks"], 0)

    def test_config_checks_every_entry_against_its_key(self):
        h = Harness()
        key0, key1 = pqtest.public_key(0), pqtest.public_key(1)
        # one key filed under two ids
        twice = make_dict(
            {
                pqtest.key_id(key0): Cell().ref(pqtest.stored(key0)),
                pqtest.key_id(key1): Cell().ref(pqtest.stored(key0)),
            },
            256,
        )
        self.assertExit(h.send(Cell().uint(1, 32).maybe(twice).uint(2, 8)), "key_id_mismatch")
        # an entry that is not a single reference
        shaped = make_dict({pqtest.key_id(key0): Cell().uint(1, 1).ref(pqtest.stored(key0))}, 256)
        self.assertExit(h.send(Cell().uint(1, 32).maybe(shaped).uint(1, 8)), "invalid_config")
        # quorum and size bounds
        self.assertExit(h.configure([0, 1], 0), "invalid_config")
        self.assertExit(h.configure([0, 1], 3), "invalid_config")
        self.assertExit(h.configure([], 1), "invalid_config")
        self.assertExit(h.configure(range(MAX_QUORUM + 1), MAX_QUORUM + 1), "invalid_config")
        self.assertExit(h.configure(range(MAX_VERIFIERS + 1), 1), "invalid_config")
        self.assertEqual(h.state()["count"], 0)

    def test_add_verifier_and_replacements_keep_the_invariants(self):
        h = self.configured([0, 1], 2)
        self.assertExit(h.send(Cell().uint(2, 32).ref(pqtest.stored(pqtest.public_key(2)))), 0)
        self.assertEqual(h.state()["count"], 3)
        self.assertExit(
            h.send(Cell().uint(2, 32).ref(pqtest.stored(pqtest.public_key(2)))),
            "duplicate_verifier",
        )
        self.assertExit(
            h.send(Cell().uint(2, 32).ref(pqtest.stored(pqtest.public_key(3)[:-1]))),
            "pq_key_length",
        )
        self.assertExit(h.send(Cell().uint(5, 32).uint(3, 8)), 0)
        self.assertExit(h.send(Cell().uint(5, 32).uint(4, 8)), "invalid_config")
        # a smaller set may not leave the quorum unreachable
        self.assertExit(
            h.send(Cell().uint(6, 32).maybe(verifier_set([0, 1])).uint(0, 0)), "invalid_config"
        )
        self.assertExit(h.send(Cell().uint(6, 32).maybe(verifier_set([4, 5, 6])).uint(0, 0)), 0)
        state = h.state()
        self.assertEqual((state["count"], state["quorum"]), (3, 3))

    def test_signing_hash_binds_network_domain_target_nonce_expiry(self):
        h = Harness()
        payload = Cell().uint(7, 8)
        target = (0, 0x1111 << 240)
        d = h.send(
            Cell().uint(4, 32).uint(9, 32).addr(target).uint(5, 64).uint(2000, 32).ref(payload)
        )
        self.assertExit(d, 0)
        expected = (
            Cell()
            .sint(GLOBAL_ID, 32)
            .uint(9, 32)
            .addr(target)
            .uint(5, 64)
            .uint(2000, 32)
            .ref(payload)
            .hash
        )
        self.assertEqual(h.state()["last_hash"], int.from_bytes(expected, "big"))
        # FunC only: Tol's address type cannot hold anything but addr_std
        if ARGS.harness.endswith(".fc"):
            none_target = (
                Cell().uint(4, 32).uint(9, 32).uint(0, 2).uint(5, 64).uint(2000, 32).ref(payload)
            )
            self.assertExit(h.send(none_target), "invalid_target")

    def test_expiry(self):
        h = Harness()
        self.assertExit(h.send(Cell().uint(7, 32).uint(native.NOW, 32)), 0)
        self.assertExit(h.send(Cell().uint(7, 32).uint(native.NOW - 1, 32)), "expired")

    def test_largest_quorum_fits_one_transaction_at_a_full_set(self):
        h = self.configured(range(MAX_VERIFIERS), MAX_QUORUM)
        message = hash_bytes(7)
        signers = list(range(0, MAX_VERIFIERS, MAX_VERIFIERS // MAX_QUORUM))[:MAX_QUORUM]
        d = h.check(message, signatures([(k, k) for k in signers], message))
        self.assertExit(d, 0)
        REPORT["max_quorum_gas"] = d["gas"]
        REPORT["max_quorum"] = MAX_QUORUM
        REPORT["gas_limit"] = d["gas_limit"]
        # The library must leave room for the contract that calls it: about 250,000 gas at
        # this sample, the margin the documentation states.
        self.assertGreaterEqual(d["gas_limit"] - d["gas"], 250_000, d)

    def test_an_unconfigured_state_authorizes_nothing(self):
        # The stored state before any config: no set, count 0, quorum 0.
        h = Harness()
        self.assertExit(h.check(hash_bytes(30), None), "invalid_config")

    def test_trusted_config_precondition_is_real(self):
        # A set stored without config(): one key filed under two ids satisfies 2-of-2 alone.
        # The native verifier cannot see ids, so only config() and its siblings prevent
        # this; a contract must never persist a set they did not produce.
        h = Harness()
        key0 = pqtest.public_key(0)
        forged_id = pqtest.key_id(pqtest.public_key(1))
        twice = make_dict(
            {
                pqtest.key_id(key0): Cell().ref(pqtest.stored(key0)),
                forged_id: Cell().ref(pqtest.stored(key0)),
            },
            256,
        )
        self.assertExit(h.send(Cell().uint(8, 32).maybe(twice).uint(2, 8).uint(2, 8)), 0)
        message = hash_bytes(31)
        signature = Cell().ref(pqtest.stored(pqtest.sign(0, message, CONTEXT)))
        sigs = make_dict({pqtest.key_id(key0): signature, forged_id: signature}, 256)
        self.assertExit(h.check(message, sigs), 0)
        # and config() refuses that very set
        self.assertExit(h.send(Cell().uint(1, 32).maybe(twice).uint(2, 8)), "key_id_mismatch")

    def test_membership_query(self):
        h = self.configured([0, 1], 1)
        for key, expected in ((1, 1), (2, 0)):
            self.assertExit(
                h.send(Cell().uint(9, 32).uint(pqtest.key_id(pqtest.public_key(key)), 256)), 0
            )
            self.assertEqual(h.state()["last_hash"], expected)

    def test_single_key_changes(self):
        h = self.configured([0, 1, 2], 2)

        def add(key):
            return h.send(Cell().uint(10, 32).ref(pqtest.stored(pqtest.public_key(key))))

        def remove(key):
            return h.send(Cell().uint(11, 32).uint(pqtest.key_id(pqtest.public_key(key)), 256))

        self.assertExit(add(3), 0)
        self.assertExit(add(3), "duplicate_verifier")
        self.assertExit(remove(0), 0)
        self.assertExit(remove(0), "unknown_signer")
        self.assertExit(remove(1), 0)
        self.assertEqual((h.state()["count"], h.state()["quorum"]), (2, 2))
        # the set may not drop below the quorum
        self.assertExit(remove(2), "invalid_config")
        # nor grow past the bound
        full = self.configured(range(MAX_VERIFIERS), 1)
        self.assertExit(
            full.send(Cell().uint(10, 32).ref(pqtest.stored(pqtest.public_key(200)))),
            "invalid_config",
        )

    def test_approved_rotation_fits_one_transaction(self):
        # The largest quorum approves replacing one key of a full set in one transaction.
        h = self.configured(range(MAX_VERIFIERS), MAX_QUORUM)
        message = hash_bytes(32)
        signers = list(range(MAX_QUORUM))
        body = (
            Cell()
            .uint(12, 32)
            .uint(int.from_bytes(message, "big"), 256)
            .maybe(signatures([(k, k) for k in signers], message))
            .ref(pqtest.stored(pqtest.public_key(200)))
            .uint(pqtest.key_id(pqtest.public_key(63)), 256)
        )
        d = h.send(body)
        self.assertExit(d, 0)
        self.assertEqual(h.state()["count"], MAX_VERIFIERS)
        REPORT["approved_rotation_gas"] = d["gas"]

    def test_configuring_a_full_set_costs(self):
        h = Harness()
        d = h.configure(range(MAX_VERIFIERS), 1)
        self.assertExit(d, 0)
        REPORT["config_64_gas"] = d["gas"]

    def test_malformed_keys_refused(self):
        key = pqtest.public_key(5)
        cases = [
            (Cell().uint(len(key) - 1, 32).ref(pqtest.chain(key[:-1])), "pq_key_length"),
            (Cell().uint(len(key), 32).ref(pqtest.chain(key[:-1])), "pq_malformed_key"),
            (
                Cell().uint(len(key), 32).ref(Cell().raw(key[:100]).ref(pqtest.chain(key[100:]))),
                "pq_malformed_key",
            ),
            (Cell().uint(len(key), 32).ref(pqtest.chain(key)).ref(Cell()), 9),
        ]
        for stored, error in cases:
            h = Harness()
            self.assertExit(h.send(Cell().uint(2, 32).ref(stored)), error)
            entry = make_dict({pqtest.key_id(key): Cell().ref(stored)}, 256)
            self.assertExit(h.send(Cell().uint(1, 32).maybe(entry).uint(1, 8)), error)

    def test_version_15_cannot_verify(self):
        # Key ids derive with an instruction older than 16; verification exists only from 16.
        h = Harness(version=15)
        self.assertExit(h.configure([0], 1), 0)
        message = hash_bytes(8)
        self.assertExit(h.check(message, signatures([(0, 0)], message)), 6)
        self.assertEqual(h.state()["checks"], 0)

    def test_gas_per_signature(self):
        """Measures what one more signature costs, so MAX_QUORUM rests on numbers."""
        gas = {}
        for quorum in (1, 2, 4):
            h = self.configured(range(MAX_VERIFIERS), quorum)
            message = hash_bytes(20 + quorum)
            d = h.check(message, signatures([(k, k) for k in range(quorum)], message))
            self.assertExit(d, 0)
            gas[quorum] = d["gas"]
        REPORT["gas_by_quorum_full_set"] = gas
        REPORT["gas_per_signature"] = (gas[4] - gas[1]) // 3


if __name__ == "__main__":
    sys.exit(pqtest.run(REPORT, [sys.argv[0]] + REST, ARGS.results, ARGS.report))
