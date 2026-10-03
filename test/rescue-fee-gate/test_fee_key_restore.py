"""EXPERIMENT: mnemonic-only restore of the fee key, end to end in the native emulator.

The wallet master and the public fee_tree_id (read back from chain state) are the only inputs
of the restored signer. Its key must equal the one the vault holds, and its signature, made by
an implementation independent of the native verifier, must be admitted under the time-slot
rule. Environment: as test_fee_gate.py (HASH_SIGS_DEMO is not used).
"""

# ruff: noqa: E402
import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fee_key
import test_slot_vault as slot
from cells import from_boc

MASTER = bytes(range(32))
NETWORK_TAG = bytes(range(32, 64))
TREE = bytes([0x5C]) * 32


class Derived:
    """Adapter giving a derived key the shape the slot-vault helpers expect."""

    def __init__(self, master, tree=TREE, account_index=0):
        seed, ident = fee_key.derive_fee_seed(master, NETWORK_TAG, slot.GLOBAL_ID, account_index, 0, tree)
        self.key = fee_key.LmsKey(seed, ident)
        self.public = self.key.hss_public

    def sign_at(self, leaf, message):
        return self.key.sign(leaf, message, os.urandom(32))


class FeeKeyRestoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        slot.SlotVaultTests.setUpClass()
        cls.phone = Derived(MASTER)

    @classmethod
    def tearDownClass(cls):
        slot.SlotVaultTests.tearDownClass()

    def setUp(self):
        self.h = slot.SlotVaultTests("test_slot_window")
        self.h.setUp()

    def test_derivation_is_deterministic_and_separated(self):
        self.assertEqual(Derived(MASTER).public, self.phone.public)
        self.assertNotEqual(Derived(MASTER, tree=bytes([0x5D]) * 32).public, self.phone.public)
        self.assertNotEqual(Derived(MASTER, account_index=1).public, self.phone.public)
        other = bytearray(MASTER)
        other[31] ^= 1
        self.assertNotEqual(Derived(bytes(other)).public, self.phone.public)

    def test_restored_signer_pays_through_the_native_verifier(self):
        shard = self.h.vault(self.phone)
        i = slot.intent(slot.START_SLOT)
        first = self.h.submit(shard, slot.body(i, self.phone.sign_at(slot.START_SLOT, i.hash)))
        self.assertTrue(self.h.admitted(first), first.get("error"))
        shard = from_boc(first["shard_account"])
        # Phone lost. The restored device has the mnemonic and reads fee_tree_id from chain.
        restored = Derived(MASTER)
        self.assertEqual(restored.public, self.phone.public)
        t = slot.at_slot(slot.START_SLOT + 1, offset=1)
        self.h.clock(t)
        j = slot.intent(slot.START_SLOT + 1, now=t)
        second = self.h.submit(shard, slot.body(j, restored.sign_at(slot.START_SLOT + 1, j.hash)))
        self.assertTrue(self.h.admitted(second), second.get("error"))
        # Negative control: the same signer with one master bit changed is refused.
        wrong = Derived(bytes([MASTER[0] ^ 1]) + MASTER[1:])
        k = slot.intent(slot.START_SLOT + 1, value=5, now=t)
        bad = self.h.submit(self.h.vault(self.phone), slot.body(k, wrong.sign_at(slot.START_SLOT + 1, k.hash)))
        self.assertFalse(bad["success"])
        self.assertEqual(bad.get("vm_exit_code"), 2007)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(verbosity=2, exit=False).result.wasSuccessful() else 1)
