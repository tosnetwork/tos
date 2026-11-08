"""Bench Quantum messages match the self-pay wire format; the batch signer is sound.

Run: uv run python bench/tests/test_workload.py [--signer PATH] [--key-tool PATH]
"""

import argparse
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "bench"), str(ROOT / "test/tostester/src"), str(ROOT / "scripts")]

from pqbench.signer import BatchSigner  # noqa: E402
from pqbench.workload import (  # noqa: E402
    QSP_EXECUTE_TAG,
    QSP_PRIMARY_CONTEXT,
    QSP_REQUEST,
    QuantumWallet,
    byte_chain,
    derive_seed,
    out_list,
    primary_nonce,
    quantum_seed,
    sinks,
)
from pytosiq_core import Address, Builder  # noqa: E402

_parser = argparse.ArgumentParser(add_help=False)
_parser.add_argument("--signer")
_parser.add_argument("--key-tool")
ARGS, _REST = _parser.parse_known_args()
SEED = bytes(range(32))
CODE = Builder().store_uint(0xC0DE, 16).end_cell()
NETWORK = bytes([0x42]) * 32
KEY = bytes(range(256)) * 5 + bytes(32)


def wallet(index=0, **kw):
    return QuantumWallet.derive(
        CODE, 1, NETWORK, SEED, "t", index, KEY, quantum_seed(SEED, "t", index), **kw
    )


class WorkloadTests(unittest.TestCase):
    def test_seed_derivation_is_deterministic_and_tagged(self):
        self.assertEqual(derive_seed(SEED, "a", 1), derive_seed(SEED, "a", 1))
        self.assertNotEqual(derive_seed(SEED, "a", 1), derive_seed(SEED, "b", 1))
        self.assertNotEqual(derive_seed(SEED, "a", 1), derive_seed(SEED, "a", 2))
        for bad in (b"short", SEED + b"x"):
            with self.assertRaises(ValueError):
                derive_seed(bad, "a", 0)
        for bad in (-1, 1 << 32):
            with self.assertRaises(ValueError):
                derive_seed(SEED, "a", bad)

    def test_state_matches_the_public_self_pay_fixture_builder(self):
        # The genesis fixture generator is the reference for the account layout.
        import quantum_self_pay_fixture as fixture

        rescue = bytes([0x33]) * 32
        reference = fixture.accounts(CODE, KEY, rescue)["active"]
        mine = wallet(0, rescue=rescue)
        self.assertEqual(mine.data().hash.hex(), reference["data_hash"])
        self.assertEqual(mine.address.to_str(False).lower(), reference["address"].lower())

    def test_request_layout_binds_identity_nonce_deadline_and_actions(self):
        w = wallet()
        dest = Address("0:" + "11" * 32)
        r = w.request(7, [w.transfer(dest, 5)], 1234)
        s = r.begin_parse()
        self.assertEqual(s.load_uint(32), QSP_REQUEST)
        self.assertEqual(s.load_int(32), 1)
        self.assertEqual(s.load_bytes(32), NETWORK)
        self.assertEqual(s.load_address(), w.address)
        self.assertEqual(s.load_bytes(32), w.authority.hash)
        self.assertEqual(
            (s.load_uint(8), s.load_uint(64), s.load_uint(64), s.load_uint(32), s.load_uint(8)),
            (1, 0, 7, 1234, 0),
        )
        payload = s.load_ref().begin_parse()
        self.assertEqual(payload.load_uint(32), QSP_EXECUTE_TAG)
        self.assertEqual(payload.load_ref().hash, out_list([w.transfer(dest, 5)]).hash)
        for nonce, deadline in ((-1, 1), (1 << 64, 1), (0, 1 << 32)):
            with self.assertRaises(ValueError):
                w.request(nonce, [w.transfer(dest, 1)], deadline)

    def test_external_carries_request_and_signature_chain(self):
        w = wallet()
        r = w.request(0, [w.transfer(sinks(1, SEED)[0], 1)], 99)
        ext = w.external(r, bytes(2420))
        self.assertEqual(ext.info.dest, w.address)
        self.assertEqual(ext.body.refs[0].hash, r.hash)
        self.assertEqual(ext.body.refs[1].hash, byte_chain(bytes(2420)).hash)
        with self.assertRaises(ValueError):
            w.external(r, bytes(2419))

    def test_primary_nonce_reads_fresh_state(self):
        self.assertEqual(primary_nonce(wallet().data()), 0)

    def test_action_list_bounds(self):
        w = wallet()
        dest = Address("0:" + "11" * 32)
        with self.assertRaises(ValueError):
            out_list([])
        with self.assertRaises(ValueError):
            out_list([w.transfer(dest, 1)] * 256)
        self.assertEqual(len(out_list([w.transfer(dest, 1)] * 255).refs), 2)

    def test_distinct_wallets_and_sinks(self):
        self.assertNotEqual(wallet(0).address, wallet(1).address)
        s = sinks(64, SEED)
        self.assertEqual(len({a.hash_part for a in s}), 64)
        with self.assertRaises(ValueError):
            sinks(0, SEED)
        with self.assertRaises(ValueError):
            QuantumWallet.derive(CODE, 1, NETWORK, SEED, "t", 0, KEY[:-1], SEED)


@unittest.skipUnless(ARGS.signer, "needs --signer")
class SignerTests(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.signer = BatchSigner(Path(ARGS.signer), 4)

    def test_deterministic_batch_in_order(self):
        seeds = [derive_seed(SEED, "s", i) for i in range(8)]
        jobs = [(s, bytes([i]) * 32) for i, s in enumerate(seeds)]
        a = self.signer.sign(jobs, QSP_PRIMARY_CONTEXT)
        b = self.signer.sign(list(reversed(jobs)), QSP_PRIMARY_CONTEXT)
        self.assertEqual(a, list(reversed(b)))
        self.assertEqual(len(set(a)), 8)
        self.assertNotEqual(a[0], self.signer.sign(jobs[:1], b"other-context")[0])
        self.assertEqual(len(set(self.signer.public_keys(seeds))), 8)

    def test_malformed_input_fails_whole_batch(self):
        with self.assertRaises(ValueError):
            self.signer.sign([(b"short", b"x")], QSP_PRIMARY_CONTEXT)
        with self.assertRaises(ValueError):
            self.signer.sign([(SEED, b"")], QSP_PRIMARY_CONTEXT)
        result = subprocess.run(
            [str(ARGS.signer), "sign", QSP_PRIMARY_CONTEXT.hex()],
            input="zz 00\n",
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    @unittest.skipUnless(ARGS.key_tool, "needs --key-tool")
    def test_public_key_matches_the_reference_key_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "seed"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(fd, SEED)
            os.close(fd)
            reference = subprocess.run(
                [str(ARGS.key_tool), "public", str(path)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        self.assertEqual(self.signer.public_keys([SEED])[0].hex(), reference)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0], *_REST])
