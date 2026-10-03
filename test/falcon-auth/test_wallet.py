"""Wallet boundary tests with a real native signer and compiled deployment manifest."""

# Repository-local imports require the explicit path bootstrap below.
# ruff: noqa: E402

import argparse
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

R = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(R / "tools/falcon"), str(R / "test/tostester/src")]
import nacl.signing
from backend import Backend, KeyHandle
from backup import association, encrypt, restore
from contract.falcon_auth import Falcon512ModuleBlueprint, request_identity
from contract.pq_auth import AuthState
from contract.wallet_v5 import WalletV5State
from provider import (
    AuthProvider,
    MultiHopReceipt,
    TrustedChainSnapshot,
    TrustedModuleSnapshot,
    buildMigrationRequest,
)
from pytosiq_core import Address, Cell

ARGS = None


class WalletTests(unittest.TestCase):
    def setUp(self):
        self.b = Backend(ARGS.library)
        self.h = self.b.generate_key()
        self.addCleanup(self.h.close)
        self.manifest = json.loads((ARGS.artifacts / "contracts.json").read_text())
        self.p = AuthProvider(self.b, self.manifest)
        code = Cell.one_from_boc((ARGS.artifacts / "module-func.boc").read_bytes())
        self.module = Falcon512ModuleBlueprint(
            code, 0, 42, self.h.public_key, self.b.validate_public_key
        )
        self.account = Address((0, b"a" * 32))
        self.classic = nacl.signing.SigningKey(b"C" * 32)
        self.state = WalletV5State(
            True,
            0,
            0,
            self.classic.verify_key.encode(),
            auth=AuthState(2, 1, 0, self.module.address.hash_part),
        )
        self.snapshot = TrustedChainSnapshot(
            42,
            19,
            1000,
            self.account,
            Cell.one_from_boc((ARGS.artifacts / "wallet-func.boc").read_bytes()),
            self.state.serialize(),
            self.module.address,
            code,
            self.module.state_init.data,
        )
        self.intent = dict(kind=0, payload=Cell.empty(), valid_until=1600)
        self.request = self.p.buildSigningRequest(self.snapshot, self.account, self.intent)

    def test_signed_request_and_funded_internal_submission(self):
        proof = self.p.sign(self.h, self.request)
        self.assertTrue(self.p.verifyLocal(self.request, proof))
        msg = self.p.fundedSubmission(self.request, proof, Address((0, b"b" * 32)), 1000000000)
        self.assertEqual(msg.info.dest, self.module.address)
        self.assertEqual(msg.body.begin_parse().load_uint(32), 0x46414C31)
        # Independent mutation of the request commitment and selected root.
        for bad in [
            replace(self.request, root=Address((0, b"r" * 32))),
            replace(self.request, request=replace(self.request.request, nonce=1)),
            replace(self.request, request=replace(self.request.request, network=43)),
        ]:
            self.assertFalse(self.p.verifyLocal(bad, proof))
            with self.assertRaises(ValueError):
                self.p.buildSubmission(bad, proof)
        self.assertEqual(
            request_identity(self.request.request), request_identity(self.request.request)
        )
        self.assertNotEqual(
            self.b.sign(self.h, self.request.message), self.b.sign(self.h, self.request.message)
        )

    def test_capabilities_never_fall_back_to_classical(self):
        for snapshot in [
            replace(self.snapshot, global_version=18),
            replace(self.snapshot, network=43),
            replace(self.snapshot, module_code=Cell.empty()),
            replace(self.snapshot, account_code=Cell.empty()),
            replace(self.snapshot, root=Address((0, b"r" * 32))),
            replace(self.snapshot, account_status="frozen"),
            replace(self.snapshot, module_status="deleted"),
            replace(self.snapshot, account_data=replace(self.state, auth=None).serialize()),
            replace(
                self.snapshot,
                account_data=replace(
                    self.state, auth=AuthState(2, 1, (1 << 64) - 1, self.module.address.hash_part)
                ).serialize(),
            ),
        ]:
            with self.assertRaises(ValueError):
                self.p.buildSigningRequest(snapshot, self.account, self.intent)
        with self.assertRaises(TypeError):
            self.p.buildSigningRequest({"rpc_supports_falcon": True}, self.account, self.intent)
        with self.assertRaises(ValueError):
            AuthProvider(
                self.b,
                {
                    **self.manifest,
                    "module-func": {**self.manifest["module-func"], "profile": "FN-DSA-mock-v1"},
                },
            )

    def test_hybrid_is_and_on_same_commitment(self):
        state = replace(self.state, auth=AuthState(3, 1, 0, self.module.address.hash_part))
        req = self.p.buildSigningRequest(
            replace(self.snapshot, account_data=state.serialize()), self.account, self.intent
        )
        proof = self.p.sign(self.h, req)
        with self.assertRaises(ValueError):
            self.p.buildSubmission(req, proof)
        co = self.classic.sign(req.request.commitment).signature
        self.p.buildSubmission(req, proof, co)
        wrong = self.classic.sign(bytes(32)).signature
        with self.assertRaises(nacl.exceptions.BadSignatureError):
            self.p.buildSubmission(req, proof, wrong)
        with self.b.generate_key() as other:
            with self.assertRaises(ValueError):
                self.p.sign(other, req)

    def test_backup_restores_exact_key_and_association(self):
        password = b"correct horse battery PQ"
        a = self.account.to_str(is_user_friendly=False)
        r = self.module.address.to_str(is_user_friendly=False)
        raw = encrypt(self.h, password, 42, a, r)
        with restore(raw, password, self.b, association(42, a, r)) as recovered:
            self.assertEqual(recovered.public_key, self.h.public_key)
            self.assertTrue(
                self.b.verify(
                    self.request.message,
                    self.b.sign(recovered, self.request.message),
                    self.h.public_key,
                )
            )
        self.assertEqual(len(self.p.verifyRecovery(raw, password, self.snapshot)), 64)
        with self.assertRaises(Exception):
            restore(raw, b"wrong password here", self.b)
        with self.assertRaises(ValueError):
            restore(raw, password, self.b, association(43, a, r))
        for field, value in [
            ("version", 2),
            ("profile", "FN-DSA-mock-v1"),
            ("fingerprint", "0" * 64),
            ("key_encoding", "expanded"),
        ]:
            altered = json.loads(raw)
            altered["metadata"][field] = value
            with self.assertRaises(Exception):
                restore(json.dumps(altered).encode(), password, self.b)
        for field, value in [("n", 1 << 30), ("r", 1024), ("p", 999)]:
            altered = json.loads(raw)
            altered["metadata"]["kdf"][field] = value
            with self.assertRaises(ValueError):
                restore(json.dumps(altered).encode(), password, self.b)
        altered = json.loads(raw)
        altered["metadata"]["association"]["network"] = 43
        with self.assertRaises(Exception):
            restore(json.dumps(altered).encode(), password, self.b)
        with self.assertRaises(ValueError):
            restore(b'{"metadata":1,"metadata":2}', password, self.b)
        with self.assertRaises(ValueError):
            encrypt(self.h, b"short", 42, a, r)
        with patch("backup.os.urandom", side_effect=[b"x", b"n" * 12]):
            with self.assertRaises(ValueError):
                encrypt(self.h, password, 42, a, r)
        for field, name in [("kdf", "salt"), ("aead", "nonce")]:
            altered = json.loads(raw)
            text = altered["metadata"][field][name]
            altered["metadata"][field][name] = "  " + text[2:]
            # A malformed canonical field must fail before allocating KDF work.
            with patch("backup.derive", side_effect=AssertionError("KDF must not run")):
                with self.assertRaises(ValueError):
                    restore(json.dumps(altered).encode(), password, self.b)

    def test_secret_redaction_rng_failure_and_local_self_check(self):
        self.assertEqual(repr(self.h), "FalconKeyHandle(<redacted>)")
        for failure in [OSError("unavailable"), b"x"]:
            with patch(
                "backend.os.urandom",
                side_effect=failure if isinstance(failure, Exception) else None,
                return_value=failure,
            ):
                with self.assertRaises(Exception):
                    self.b.generate_key()
                with self.assertRaises(Exception):
                    self.b.sign(self.h, self.request.message)
        with self.b.generate_key() as other:
            wrong = KeyHandle(self.h._secret, other.public_key)
            self.addCleanup(wrong.close)
            with self.assertRaises(RuntimeError):
                self.b.sign(wrong, self.request.message)
        self.h.close()
        self.assertTrue(all(x == 0 for x in self.h._secret))
        with self.assertRaises(ValueError):
            self.b.sign(self.h, self.request.message)

    def test_cutover_requires_new_key_backup_and_explicit_factor_choice(self):
        password = b"correct horse battery PQ"
        with self.b.generate_key() as new_key:
            proposed = Falcon512ModuleBlueprint(
                self.snapshot.module_code, 0, 42, new_key.public_key, self.b.validate_public_key
            )
            backup = encrypt(
                new_key,
                password,
                42,
                self.account.to_str(is_user_friendly=False),
                proposed.address.to_str(is_user_friendly=False),
            )
            destination = TrustedModuleSnapshot(
                42,
                19,
                1000,
                proposed.address,
                self.snapshot.module_code,
                proposed.state_init.data,
                "active",
            )

            def prepare(raw=backup, mode=2, confirm=False, code=None, proof=None):
                observed = proof or replace(destination, code=code or destination.code)
                return buildMigrationRequest(
                    self.p, self.snapshot, observed, raw, password, mode, 1600, confirm
                )

            request = prepare()
            self.assertEqual((request.kind, request.epoch, request.nonce), (1, 1, 0))
            # The request remains for the old key/root, even though possession of the new key was proven.
            old_signing = replace(self.request, request=request)
            proof = self.p.sign(self.h, old_signing)
            self.assertTrue(self.p.verifyLocal(old_signing, proof))
            with self.assertRaises(ValueError):
                self.p.sign(new_key, old_signing)
            with self.assertRaises(ValueError):
                prepare(mode=3)
            self.assertEqual(prepare(mode=3, confirm=True).kind, 1)
            with self.assertRaises(Exception):
                prepare(raw=b"{}")
            with self.assertRaises(ValueError):
                prepare(code=Cell.empty())
            for bad in [
                replace(destination, status="uninitialized"),
                replace(destination, status="frozen"),
                replace(destination, status="deleted"),
                replace(destination, network=43),
                replace(destination, global_version=18),
                replace(destination, now=999),
            ]:
                with self.assertRaises(ValueError):
                    prepare(proof=bad)
            with self.assertRaises(TypeError):
                prepare(proof={"rpc_supports_falcon": True})

    def test_multihop_receipts_require_final_state(self):
        identity = request_identity(self.request.request)
        self.assertEqual(MultiHopReceipt.from_evidence(identity, None).state, "waiting for relayer")
        e = dict(
            identity=identity,
            module=dict(compute_success=True, action_success=True, relay_observed=True),
        )
        self.assertEqual(self.p.trackReceipt(self.request, e).state, "waiting for target")
        e["target"] = dict(compute_success=False, nonce_consumed=True)
        self.assertEqual(
            self.p.trackReceipt(self.request, e).state,
            "target consumed nonce but refused operation",
        )
        e["target"] = dict(compute_success=True, action_success=True, nonce_consumed=True)
        self.assertEqual(self.p.trackReceipt(self.request, e).state, "target outcome incomplete")
        e["target"]["final_state_verified"] = True
        self.assertEqual(self.p.trackReceipt(self.request, e).state, "actions completed")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--library", required=True)
    p.add_argument("--artifacts", type=Path, required=True)
    ARGS = p.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(WalletTests)
    )
    sys.exit(0 if result.wasSuccessful() else 1)
