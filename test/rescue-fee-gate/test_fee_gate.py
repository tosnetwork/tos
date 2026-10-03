"""PROTOTYPE: the rescue fee vault admits an external message only after a native HSS/LMS
check inside the external gas credit. Real transactions in the native emulator.

Environment: FUNC_PATH, FIFT_PATH, EMULATOR_PATH (native build), HASH_SIGS_DEMO (the `demo`
binary of cisco/hash-sigs, used only to make test signatures). Keys and signatures are
PUBLIC TEST DATA generated per run.
"""

# ruff: noqa: E402
import os
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
CREDIT = 10_000
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


class Key:
    """An LMS key held by the reference implementation's demo tool; it tracks the leaf."""

    def __init__(self, workdir, name, params):
        self.dir, self.name, self.leaf = Path(workdir), name, 0
        self.run("genkey", name, params)
        self.public = (self.dir / f"{name}.pub").read_bytes()
        assert len(self.public) == 60

    def run(self, *args):
        subprocess.run(
            [os.environ["HASH_SIGS_DEMO"], *args], cwd=self.dir, check=True, capture_output=True
        )

    def sign(self, message):
        path = self.dir / f"msg{self.leaf}"
        path.write_bytes(message)
        self.run("sign", self.name, path.name)
        signature = (self.dir / f"msg{self.leaf}.sig").read_bytes()
        assert int.from_bytes(signature[4:8], "big") == self.leaf
        self.leaf += 1
        return signature


def intent(leaf, value=1_000_000_000, valid_until=NOW + 600, vault=VAULT, network=GLOBAL_ID):
    payload = Cell().uint(0xC0FFEE, 32)
    return (
        Cell()
        .sint(network, 32)
        .addr(vault)
        .uint(leaf, 32)
        .uint(valid_until, 32)
        .addr(TARGET)
        .coins(value)
        .ref(payload)
    )


def body(intent_cell, signature, digest=None):
    digest = digest if digest is not None else intent_cell.hash
    return Cell().ref(intent_cell).ref(chain(digest)).ref(chain(b"")).ref(chain(signature))


class FeeGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        source = os.environ.get("VAULT_SOURCE", "rescue-fee-vault.fc")
        cls.code = compile_contract(source, Path(cls.tmp.name) / "vault.boc")
        cls.emulator = Emulator(global_version=19)

    @classmethod
    def tearDownClass(cls):
        cls.emulator.close()
        cls.tmp.cleanup()

    def vault(self, key, next_leaf=0):
        data = Cell().sint(GLOBAL_ID, 32).uint(next_leaf, 32).ref(chain(key.public)).uint(0, 32)
        return active_account(VAULT, self.code, data)

    def submit(self, shard, message_body):
        return self.emulator.send(shard, external(VAULT, message_body))

    def admitted(self, result):
        return result["success"] and result["details"]["compute_success"]

    def key(self, params):
        return Key(self.tmp.name, f"k{len(RESULTS)}_{params.replace('/', '_')}", params)

    def test_valid_intent_fits_credit_and_pays(self):
        for params in ("10/4", "10/2", "5/4"):
            with self.subTest(params=params):
                key = self.key(params)
                shard = self.vault(key)
                i = intent(0)
                result = self.submit(shard, body(i, key.sign(i.hash)))
                self.assertTrue(self.admitted(result), result.get("error"))
                after = from_boc(result["shard_account"])
                data, _ = account_data(after)
                s = data.slice()
                s.sint(32)
                self.assertEqual(s.uint(32), 1)  # leaf consumed
                s.ref()
                gas_at_accept = s.uint(32)
                self.assertGreater(gas_at_accept, 0)
                self.assertLessEqual(gas_at_accept, CREDIT)
                sent = outgoing(from_boc(result["transaction"]))
                self.assertEqual(len(sent), 1)
                RESULTS.append((params, gas_at_accept, result["details"]["gas"]))
                # Replaying the admitted message must fail before ACCEPT: the leaf is spent.
                again = self.submit(after, body(i, (key.dir / "msg0.sig").read_bytes()))
                self.assertFalse(again["success"], "replay must not be admitted")

    def test_rejections_before_accept(self):
        # Every case carries a signature that is valid for what it signs, and breaks exactly
        # one rule, so that each guard is the only thing standing between it and admission.
        key = self.key("10/4")
        shard = self.vault(key)
        good = intent(key.leaf)
        good_sig = key.sign(good.hash)
        flipped = bytearray(good_sig)
        flipped[200] ^= 1
        expired = intent(key.leaf, valid_until=NOW - 1)
        expired_sig = key.sign(expired.hash)
        elsewhere = intent(key.leaf, vault=TARGET)
        elsewhere_sig = key.sign(elsewhere.hash)
        # The owner signed A's digest; an attacker attaches A's digest and signature to B.
        a_leaf = key.leaf
        signed_a = intent(a_leaf, value=1)
        a_sig = key.sign(signed_a.hash)
        # Same leaf as A's signature, so only the digest binding can tell them apart.
        swapped_b = intent(a_leaf, value=9_000_000_000)
        cases = {
            "signature bit flip": (body(good, bytes(flipped)), 2007),
            "intent changed, digest recomputed": (
                body(intent(0, value=2_000_000_000), good_sig),
                2007,
            ),
            "expired but correctly signed": (body(expired, expired_sig), 2003),
            "other vault but correctly signed": (body(elsewhere, elsewhere_sig), 2002),
            "signed digest attached to another intent": (
                body(swapped_b, a_sig, digest=signed_a.hash),
                2006,
            ),
        }
        for name, (message, exit_code) in cases.items():
            with self.subTest(case=name):
                result = self.submit(shard, message)
                self.assertFalse(result["success"], f"{name} must not be admitted")
                self.assertEqual(result.get("vm_exit_code"), exit_code, name)
        # Positive control on the same vault: the untouched message is admitted.
        self.assertTrue(self.admitted(self.submit(shard, body(good, good_sig))))

    def test_negative_control_valid_but_over_credit(self):
        # W8 charges about 3 x 8,460 compressions: a VALID signature must still be refused,
        # proving that admission above really happened inside the credit.
        key = self.key("10/8")
        shard = self.vault(key)
        i = intent(0)
        result = self.submit(shard, body(i, key.sign(i.hash)))
        self.assertFalse(result["success"], "a valid W8 signature must exceed the external credit")


if __name__ == "__main__":
    program = unittest.main(verbosity=2, exit=False)
    for params, accept_gas, total_gas in RESULTS:
        print(f"profile H/W={params}: gas at ACCEPT={accept_gas} total compute gas={total_gas}")
    sys.exit(0 if program.result.wasSuccessful() else 1)
