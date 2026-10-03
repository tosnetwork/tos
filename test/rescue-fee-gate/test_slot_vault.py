"""EXPERIMENT: a rescue fee vault whose LMS leaf is fixed by chain time, so that a fee key
restored from the mnemonic alone (its leaf counter lost with the device) can pay without ever
reusing a leaf. Real transactions in the native emulator.

Signer rule under test: sign only with leaf = current slot; a device that cannot rule out an
earlier signature in the current slot (a restored one) waits for the next slot boundary.

Environment: as test_fee_gate.py. LMS_TALL=1 also measures H20 (slow key generation).
"""

# ruff: noqa: E402
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
from cells import Cell, from_boc
from native import (
    NOW,
    GLOBAL_ID,
    Emulator,
    account_data,
    active_account,
    compile_contract,
    external,
    outgoing,
)

VAULT = (0, 0x5A5A << 240 | 0x1234)
TARGET = (0, 0xBEEF << 240 | 0x77)
OTHER = (0, 0xDEAD << 240 | 0x99)
CREDIT = 10_000
SLOT = 3600
START_SLOT = 5
EPOCH0 = NOW - START_SLOT * SLOT - 10  # NOW lies 10 s into slot 5
MAX_VALUE = 2_000_000_000
RESCUE_SUBMIT = 0x534C4831
RESULTS = []


def chain(data):
    parts = [data[i : i + 127] for i in range(0, len(data), 127)] or [b""]
    tail = None
    for part in reversed(parts):
        node = Cell().raw(part)
        if tail is not None:
            node.ref(tail)
        tail = node
    return tail


def at_slot(slot, offset=10):
    return EPOCH0 + slot * SLOT + offset


class Device:
    """One holder of the fee key, as the reference implementation's demo tool keeps it."""

    def __init__(self, workdir, name):
        self.dir, self.name = Path(workdir), name

    def run(self, *args):
        subprocess.run(
            [os.environ["HASH_SIGS_DEMO"], *args], cwd=self.dir, check=True, capture_output=True
        )

    @classmethod
    def generate(cls, workdir, name, params):
        device = cls(workdir, name)
        device.run("genkey", name, params)
        device.public = (device.dir / f"{name}.pub").read_bytes()
        assert len(device.public) == 60
        device.leaf = 0
        return device

    def restore(self, name):
        """A second device holding the key exactly as freshly derived: leaf counter at 0."""
        clone = Device(self.dir, name)
        for suffix in (".pub", ".aux"):
            shutil.copy(self.dir / f"{self.name}{suffix}", self.dir / f"{name}{suffix}")
        shutil.copy(self.dir / f"{self.name}.prv.seed", self.dir / f"{name}.prv")
        clone.public, clone.leaf = self.public, 0
        return clone

    def keep_seed(self):
        shutil.copy(self.dir / f"{self.name}.prv", self.dir / f"{self.name}.prv.seed")

    def sign_at(self, leaf, message):
        """Sign with exactly this leaf; the demo tool refuses to go backwards."""
        if leaf < self.leaf:
            raise ValueError("leaf already passed")
        if leaf > self.leaf:
            self.run("advance", self.name, str(leaf - self.leaf))
            self.leaf = leaf
        path = self.dir / f"{self.name}_m{leaf}_{message.hex()[:8]}"
        path.write_bytes(message)
        self.run("sign", self.name, path.name)
        signature = path.with_name(path.name + ".sig").read_bytes()
        assert int.from_bytes(signature[4:8], "big") == leaf
        self.leaf = leaf + 1
        return signature


def intent(
    leaf,
    value=1_000_000_000,
    valid_until=None,
    vault=VAULT,
    op=RESCUE_SUBMIT,
    now=NOW,
    network=GLOBAL_ID,
):
    valid_until = valid_until if valid_until is not None else now + 600
    return (
        Cell()
        .sint(network, 32)
        .addr(vault)
        .uint(leaf, 32)
        .uint(valid_until, 32)
        .coins(value)
        .ref(Cell().uint(op, 32).uint(0xABCD, 16))
    )


def body(intent_cell, signature, digest=None):
    digest = digest if digest is not None else intent_cell.hash
    return Cell().ref(intent_cell).ref(chain(digest)).ref(chain(b"")).ref(chain(signature))


class SlotVaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        source = os.environ.get("VAULT_SOURCE", "rescue-fee-vault-slot.fc")
        cls.code = compile_contract(source, Path(cls.tmp.name) / "vault.boc")
        cls.emulator = Emulator(global_version=19)
        cls.count = 0

    @classmethod
    def tearDownClass(cls):
        cls.emulator.close()
        cls.tmp.cleanup()

    def setUp(self):
        self.clock(NOW)

    def clock(self, t):
        self.emulator.lib.transaction_emulator_set_unixtime(self.emulator.ptr, t)

    def device(self, params="10/4"):
        SlotVaultTests.count += 1
        d = Device.generate(self.tmp.name, f"k{self.count}_{params.replace('/', '_')}", params)
        d.keep_seed()
        return d

    def vault(self, key, next_leaf=0, balance=100_000_000_000):
        data = (
            Cell()
            .sint(GLOBAL_ID, 32)
            .uint(EPOCH0, 32)
            .uint(SLOT, 32)
            .uint(next_leaf, 32)
            .coins(MAX_VALUE)
            .addr(TARGET)
            .ref(chain(key.public))
            .uint(0, 32)
        )
        return active_account(VAULT, self.code, data, balance=balance)

    def submit(self, shard, message_body):
        return self.emulator.send(shard, external(VAULT, message_body))

    def admitted(self, result):
        return result["success"] and result["details"]["compute_success"]

    def state(self, result):
        data, _ = account_data(from_boc(result["shard_account"]))
        s = data.slice()
        s.sint(32), s.uint(32), s.uint(32)
        next_leaf = s.uint(32)
        s.coins(), s.addr(), s.ref()
        return next_leaf, s.uint(32)

    def assert_refused(self, result, exit_code, name):
        self.assertFalse(result["success"], f"{name} must not be admitted")
        self.assertEqual(result.get("vm_exit_code"), exit_code, name)

    def test_current_slot_admitted_within_credit_and_paid_to_pinned_target(self):
        profiles = ["10/4", "15/4", "15/2"]
        if os.environ.get("LMS_TALL") == "1":
            profiles.append("20/2")
        profiles = os.environ.get("LMS_PROFILES", ",".join(profiles)).split(",")
        for params in profiles:
            with self.subTest(params=params):
                key = self.device(params)
                shard = self.vault(key)
                i = intent(START_SLOT)
                result = self.submit(shard, body(i, key.sign_at(START_SLOT, i.hash)))
                self.assertTrue(self.admitted(result), result.get("error"))
                next_leaf, gas = self.state(result)
                self.assertEqual(next_leaf, START_SLOT + 1)
                self.assertGreater(gas, 0)
                self.assertLessEqual(gas, CREDIT)
                sent = outgoing(from_boc(result["transaction"]))
                self.assertEqual(len(sent), 1)
                s = sent[0].slice()
                self.assertEqual(s.uint(4), 0b0110)  # int_msg_info, ihr off, bounce on
                self.assertEqual(s.addr(), VAULT)  # src, filled in by the action phase
                self.assertEqual(s.addr(), TARGET)
                self.assertEqual(s.coins(), 1_000_000_000)
                RESULTS.append((params, len(key.public), gas, result["details"]["gas"]))

    def test_slot_window(self):
        key = self.device()
        shard = self.vault(key)
        # The previous slot's leaf is still accepted (delivery delay)...
        prev = intent(START_SLOT - 1)
        prev_sig = key.sign_at(START_SLOT - 1, prev.hash)
        # ...one older than that is not, and neither is the next slot's leaf.
        stale_key = self.device()
        old = intent(START_SLOT - 2)
        future = intent(START_SLOT + 1)
        cases = {
            "leaf two slots old": (body(old, stale_key.sign_at(START_SLOT - 2, old.hash)), 2009),
            "leaf of the next slot": (
                body(future, stale_key.sign_at(START_SLOT + 1, future.hash)),
                2009,
            ),
        }
        stale_shard = self.vault(stale_key)
        for name, (message, code) in cases.items():
            with self.subTest(case=name):
                self.assert_refused(self.submit(stale_shard, message), code, name)
        self.assertTrue(self.admitted(self.submit(shard, body(prev, prev_sig))))

    def test_rejections_each_with_a_valid_signature(self):
        key = self.device()
        shard = self.vault(key)
        # Each message is signed by a fresh key holding the vault's identity would be ideal;
        # one key and successive in-window leaves is enough: each breaks exactly one rule.
        cases = []
        for name, kwargs, code in (
            ("value above the cap", {"value": MAX_VALUE + 1}, 2010),
            ("payload is not a rescue submission", {"op": 0xC0FFEE}, 2011),
            ("other vault", {"vault": OTHER}, 2002),
            ("valid_until beyond two slots", {"valid_until": NOW + 2 * SLOT + 1}, 2003),
            ("already expired", {"valid_until": NOW}, 2003),
            ("other network", {"network": GLOBAL_ID + 1}, 2001),
        ):
            k = self.device()
            i = intent(START_SLOT, **kwargs)
            cases.append((name, k, body(i, k.sign_at(START_SLOT, i.hash)), code))
        for name, k, message, code in cases:
            with self.subTest(case=name):
                self.assert_refused(self.submit(self.vault(k), message), code, name)
        forged = self.device()
        signed_a = intent(START_SLOT, value=1)
        a_sig = forged.sign_at(START_SLOT, signed_a.hash)
        flipped = bytearray(a_sig)
        flipped[200] ^= 1
        swapped_b = intent(START_SLOT, value=MAX_VALUE)
        for name, message, code in (
            ("signature bit flip", body(signed_a, bytes(flipped)), 2007),
            ("signed digest attached to another intent", body(swapped_b, a_sig, signed_a.hash), 2006),
        ):
            with self.subTest(case=name):
                self.assert_refused(self.submit(self.vault(forged), message), code, name)
        poor = self.device()
        i = intent(START_SLOT)
        message = body(i, poor.sign_at(START_SLOT, i.hash))
        self.assert_refused(
            self.submit(self.vault(poor, balance=1_000_000_000), message), 2008, "balance"
        )
        # Positive control for the shared shape: an untouched intent is admitted.
        good = intent(START_SLOT)
        self.assertTrue(self.admitted(self.submit(shard, body(good, key.sign_at(START_SLOT, good.hash)))))

    def test_restore_from_mnemonic_waits_for_next_slot(self):
        phone = self.device()
        shard = self.vault(phone)
        paid = intent(START_SLOT, value=1)
        first = self.submit(shard, body(paid, phone.sign_at(START_SLOT, paid.hash)))
        self.assertTrue(self.admitted(first))
        shard = from_boc(first["shard_account"])
        # The phone is lost. A device restored from the seed knows only the clock.
        restored = phone.restore("restored")
        slot_now = (NOW - EPOCH0) // SLOT
        # Hazard the wait prevents: signing in the current slot reuses the phone's leaf.
        hazard = intent(slot_now, value=2)
        hazard_sig = phone.restore("hazard").sign_at(slot_now, hazard.hash)
        first_sig = (Path(self.tmp.name) / f"{phone.name}_m{START_SLOT}_{paid.hash.hex()[:8]}.sig").read_bytes()
        self.assertEqual(hazard_sig[:8], first_sig[:8], "same leaf: one-time key reused")
        self.assertNotEqual(hazard_sig, first_sig)
        self.assert_refused(self.submit(shard, body(hazard, hazard_sig)), 2004, "reused leaf")
        # A restored signer that ignores the clock signs the current slot's intent with its own
        # counter (leaf 0): the vault must refuse the mismatch rather than book the slot.
        naive = phone.restore("naive")
        careless = intent(slot_now + 1, value=4, now=at_slot(slot_now + 1))
        self.clock(at_slot(slot_now + 1))
        self.assert_refused(
            self.submit(shard, body(careless, naive.sign_at(0, careless.hash))), 2005, "q != leaf"
        )
        self.clock(NOW)
        # Rule: wait for the next boundary, then sign with that slot's leaf.
        t = at_slot(slot_now + 1, offset=1)
        self.clock(t)
        rescue = intent(slot_now + 1, value=3, now=t)
        second = self.submit(shard, body(rescue, restored.sign_at(slot_now + 1, rescue.hash)))
        self.assertTrue(self.admitted(second), second.get("error"))
        self.assertEqual(self.state(second)[0], slot_now + 2)

    def test_unmined_signature_expires_with_its_window(self):
        key = self.device()
        shard = self.vault(key)
        i = intent(START_SLOT, valid_until=NOW + 2 * SLOT)
        message = body(i, key.sign_at(START_SLOT, i.hash))
        # Disclosed in slot 5, held back by the relay until slot 7.
        self.clock(at_slot(START_SLOT + 2, offset=0) - 20)  # still slot 6: admitted
        self.assertTrue(self.admitted(self.submit(shard, message)))
        self.clock(at_slot(START_SLOT + 2, offset=0))
        self.assert_refused(self.submit(shard, message), 2009, "after its window")

    def test_replay_and_second_intent_same_slot(self):
        key = self.device()
        shard = self.vault(key)
        i = intent(START_SLOT)
        sig = key.sign_at(START_SLOT, i.hash)
        result = self.submit(shard, body(i, sig))
        self.assertTrue(self.admitted(result))
        after = from_boc(result["shard_account"])
        self.assert_refused(self.submit(after, body(i, sig)), 2004, "replay")
        # The honest signer has nothing more to sign this slot; the next slot works.
        self.clock(at_slot(START_SLOT + 1))
        j = intent(START_SLOT + 1, now=at_slot(START_SLOT + 1))
        self.assertTrue(self.admitted(self.submit(after, body(j, key.sign_at(START_SLOT + 1, j.hash)))))


if __name__ == "__main__":
    program = unittest.main(verbosity=2, exit=False)
    for params, pk, accept_gas, total_gas in RESULTS:
        print(f"profile H/W={params}: pk={pk}B gas at ACCEPT={accept_gas} total compute gas={total_gas}")
    sys.exit(0 if program.result.wasSuccessful() else 1)
