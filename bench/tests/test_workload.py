"""Bench message construction matches the reference client types; the batch signer is sound.

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
sys.path[:0] = [str(ROOT / "bench"), str(ROOT / "test/tostester/src")]

from pytosiq_core import Address, Builder  # noqa: E402

from contract import WalletV5  # noqa: E402
from contract.pq_auth import CONTEXT  # noqa: E402
from pqbench.signer import BatchSigner  # noqa: E402
from pqbench.workload import (  # noqa: E402
    ClassicalWallet,
    PqWallet,
    derive_seed,
    out_list,
    pq_seed,
    sinks,
    submission,
)

_parser = argparse.ArgumentParser(add_help=False)
_parser.add_argument("--signer")
_parser.add_argument("--key-tool")
ARGS, _REST = _parser.parse_known_args()
SEED = bytes(range(32))
CODE = Builder().store_uint(0xC0DE, 16).end_cell()
MODULE = Builder().store_uint(0xBEEF, 16).end_cell()


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

    def test_single_action_list_equals_the_reference_transfer_payload(self):
        w = ClassicalWallet.derive(CODE, 3, SEED, "t", 0)
        dest = Address("0:" + "11" * 32)
        reference = WalletV5(None, w.address, 3, w.key).transfer_payload(dest, 5)
        self.assertEqual(out_list([w.transfer(dest, 5)]).hash, reference.hash)

    def test_action_list_bounds(self):
        w = ClassicalWallet.derive(CODE, 3, SEED, "t", 0)
        dest = Address("0:" + "11" * 32)
        with self.assertRaises(ValueError):
            out_list([])
        with self.assertRaises(ValueError):
            out_list([w.transfer(dest, 1)] * 256)
        node = out_list([w.transfer(dest, i + 1) for i in range(3)])
        depth = 0
        while node.refs:
            node = node.refs[0]
            depth += 1
        self.assertEqual(depth, 3)

    def test_classical_external_is_the_reference_signed_body(self):
        w = ClassicalWallet.derive(CODE, 3, SEED, "t", 0)
        dest = Address("0:" + "11" * 32)
        ext = w.external(7, [w.transfer(dest, 9)], 1000)
        from contract import WalletV5State
        view = WalletV5(None, w.address, 3, w.key)
        expected = view.sign(view.transfer_payload(dest, 9), WalletV5State(True, 7, 0, w.key.verify_key.encode()), 1000)
        self.assertEqual(ext.body.hash, expected.hash)
        self.assertEqual(ext.info.dest, w.address)

    def test_pq_wallet_binds_its_module_and_request_identity(self):
        pk = bytes(1312)
        w = PqWallet.derive(CODE, MODULE, 3, SEED, 0, pk, pq_seed(SEED, 0))
        from contract import WalletV5State
        state = WalletV5State.parse(w.wallet.state_init.data)
        self.assertEqual(state.auth.module_hash, w.module.address.hash_part)
        self.assertEqual((state.auth.mode, state.auth.epoch, state.auth.nonce), (2, 1, 0))
        dest = sinks(1, SEED)[0]
        r = w.request(4, dest, 9, 1234)
        self.assertEqual((r.account, r.nonce, r.epoch, r.valid_until, r.kind), (w.address, 4, 1, 1234, 0))
        msg = submission(Address("0:" + "22" * 32), w.module.address, r, bytes(2420), 100, 5)
        self.assertEqual(msg.info.dest, w.module.address)
        self.assertEqual(msg.body.hash, r.submission(bytes(2420), None, 5).hash)

    def test_sinks_are_distinct_and_bounded(self):
        s = sinks(64, SEED)
        self.assertEqual(len({a.hash_part for a in s}), 64)
        with self.assertRaises(ValueError):
            sinks(0, SEED)


@unittest.skipUnless(ARGS.signer, "needs --signer")
class SignerTests(unittest.TestCase):
    def setUp(self):
        self.signer = BatchSigner(Path(ARGS.signer), 4)

    def test_deterministic_batch_in_order(self):
        seeds = [derive_seed(SEED, "s", i) for i in range(8)]
        jobs = [(s, bytes([i]) * 32) for i, s in enumerate(seeds)]
        a, b = self.signer.sign(jobs), self.signer.sign(list(reversed(jobs)))
        self.assertEqual(a, list(reversed(b)))
        self.assertEqual(len(set(a)), 8)
        keys = self.signer.public_keys(seeds)
        self.assertEqual(len(set(keys)), 8)

    def test_malformed_input_fails_whole_batch(self):
        with self.assertRaises(ValueError):
            self.signer.sign([(b"short", b"x")])
        with self.assertRaises(ValueError):
            self.signer.sign([(SEED, b"")])
        result = subprocess.run([str(ARGS.signer), "sign", CONTEXT.hex()], input="zz 00\n",
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    @unittest.skipUnless(ARGS.key_tool, "needs --key-tool")
    def test_public_key_matches_the_reference_key_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "seed"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(fd, SEED)
            os.close(fd)
            reference = subprocess.run([str(ARGS.key_tool), "public", str(path)], check=True,
                                       capture_output=True, text=True).stdout.strip()
        self.assertEqual(self.signer.public_keys([SEED])[0].hex(), reference)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0], *_REST])
