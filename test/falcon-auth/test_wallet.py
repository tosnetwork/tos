"""Wallet boundary tests with a real native signer and compiled deployment manifest."""

# Repository-local imports require the explicit path bootstrap below.
# ruff: noqa: E402

import argparse
import contextlib
import io
import json
import sys
import tempfile
import unittest
from dataclasses import fields, replace
from pathlib import Path
from unittest.mock import patch

R = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(R / "tools/falcon"), str(R / "test/tostester/src")]
import nacl.signing
from backend import PROFILE, Backend, KeyHandle
from backup import association, encrypt, restore
from contract.falcon_auth import (
    Falcon512ModuleBlueprint,
    read_chain,
    request_identity,
    signing_message,
)
from contract.pq_auth import AuthRequest, AuthState
from contract.wallet_v5 import WalletV5State
from provider import (
    AuthProof,
    AuthProvider,
    MultiHopReceipt,
    TrustedChainSnapshot,
    TrustedModuleSnapshot,
    buildMigrationRequest,
)
from pytosiq_core import Address, Builder, Cell, MessageAny

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
            16,
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
            replace(self.snapshot, global_version=15),
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

    def test_signing_cannot_bypass_prepared_snapshot(self):
        for forged in [
            replace(self.request, root=Address((0, b"r" * 32))),
            replace(self.request, account_mode=1),
            replace(self.request, classical_public_key=b"k" * 32),
            replace(self.request, snapshot_commitment="f" * 64),
            replace(self.request, request=replace(self.request.request, nonce=1)),
            replace(self.request, request=replace(self.request.request, network=43)),
            replace(
                self.request, request=replace(self.request.request, account=Address((0, b"d" * 32)))
            ),
            replace(
                self.request,
                request=replace(
                    self.request.request, payload=Builder().store_uint(1, 1).end_cell()
                ),
            ),
        ]:
            proof = AuthProof(
                PROFILE,
                request_identity(forged.request),
                forged.root.to_str(is_user_friendly=False),
                self.b.sign(self.h, forged.message),
            )
            self.assertTrue(self.p.verifyLocal(forged, proof))
            with self.assertRaises(ValueError):
                self.p.sign(self.h, forged)
            with self.assertRaises(ValueError):
                self.p.buildSubmission(forged, proof)
        detached = AuthProvider(self.b, self.manifest)
        with self.assertRaises(ValueError):
            detached.sign(self.h, self.request)
        prepared = detached.buildSigningRequest(self.snapshot, self.account, self.intent)
        proof = detached.sign(self.h, prepared)
        detached.buildSubmission(prepared, proof)
        # Keep memory bounded; a displaced request must be prepared again.
        for nonce in range(1, 129):
            state = replace(self.state, auth=AuthState(2, 1, nonce, self.module.address.hash_part))
            detached.buildSigningRequest(
                replace(self.snapshot, account_data=state.serialize()), self.account, self.intent
            )
        self.assertEqual(len(detached._prepared_requests), 128)
        with self.assertRaises(ValueError):
            detached.sign(self.h, prepared)

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
                16,
                1000,
                proposed.address,
                self.snapshot.module_code,
                proposed.state_init.data,
                "active",
            )
            forged = replace(
                self.request,
                request=replace(
                    self.request.request,
                    kind=1,
                    payload=Builder().store_uint(2, 2).store_address(proposed.address).end_cell(),
                ),
            )
            # A generic raw configure intent cannot bypass the recovery/deployment
            # checks by constructing a SigningRequest or a locally valid proof.
            with self.assertRaises(ValueError):
                self.p.buildSigningRequest(
                    self.snapshot,
                    self.account,
                    dict(kind=1, payload=forged.request.payload, valid_until=1600),
                )
            with self.assertRaises(ValueError):
                self.p.sign(self.h, forged)
            raw_proof = AuthProof(
                PROFILE,
                request_identity(forged.request),
                self.module.address.to_str(is_user_friendly=False),
                self.b.sign(self.h, forged.message),
            )
            self.assertTrue(self.p.verifyLocal(forged, raw_proof))
            with self.assertRaises(ValueError):
                self.p.buildSubmission(forged, raw_proof)

            def prepare(raw=backup, mode=2, confirm=False, code=None, proof=None):
                observed = proof or replace(destination, code=code or destination.code)
                return buildMigrationRequest(
                    self.p, self.snapshot, observed, raw, password, mode, 1600, confirm
                )

            request = prepare()
            self.assertEqual((request.kind, request.epoch, request.nonce), (1, 1, 0))
            # The request remains for the old key/root, even though possession of the new key was proven.
            old_signing = self.p.buildSigningRequest(
                self.snapshot,
                self.account,
                dict(kind=1, payload=request.payload, valid_until=request.valid_until),
            )
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
                replace(destination, global_version=15),
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
        # Phase success and a genuine nonce/state do not prove the requested
        # operation. A skipped or partial batch can have all these booleans.
        for counts in (
            {},
            {"skipped_actions": 1, "msgs_created": 0},
            {"skipped_actions": 1, "msgs_created": 1},
        ):
            e["target"].update(counts)
            self.assertEqual(
                self.p.trackReceipt(self.request, e).state, "target outcome incomplete"
            )
            self.assertNotIn("separately observed", self.p.trackReceipt(self.request, e).funds)

    def test_migration_cli_rehearses_recovery_and_signs_with_current_root(self):
        import wallet

        password = b"correct horse battery PQ"
        account = self.account.to_str(is_user_friendly=False)
        with (
            tempfile.TemporaryDirectory(dir=ARGS.artifacts) as directory,
            self.b.generate_key() as new,
        ):
            root = Path(directory)
            proposed = Falcon512ModuleBlueprint(
                self.snapshot.module_code, 0, 42, new.public_key, self.b.validate_public_key
            )
            destination = TrustedModuleSnapshot(
                42,
                16,
                1000,
                proposed.address,
                self.snapshot.module_code,
                proposed.state_init.data,
                "active",
            )

            def save_snapshot(filename, state):
                document = {}
                for field in fields(state):
                    value = getattr(state, field.name)
                    if isinstance(value, Cell):
                        value = value.to_boc().hex()
                    if isinstance(value, Address):
                        value = value.to_str(is_user_friendly=False)
                    document[field.name] = value
                (root / filename).write_text(json.dumps(document))

            save_snapshot("snapshot.json", self.snapshot)
            save_snapshot("destination.json", destination)
            (root / "manifest.json").write_text(json.dumps(self.manifest))
            (root / "current.backup").write_bytes(
                encrypt(
                    self.h,
                    password,
                    42,
                    account,
                    self.module.address.to_str(is_user_friendly=False),
                )
            )
            (root / "new.backup").write_bytes(
                encrypt(new, password, 42, account, proposed.address.to_str(is_user_friendly=False))
            )
            command = [
                "wallet",
                "--library",
                str(ARGS.library),
                "migrate",
                "--snapshot",
                str(root / "snapshot.json"),
                "--destination",
                str(root / "destination.json"),
                "--manifest",
                str(root / "manifest.json"),
                "--backup",
                str(root / "current.backup"),
                "--new-backup",
                str(root / "new.backup"),
                "--target-mode",
                "2",
                "--valid-until",
                "1600",
                "--relayer",
                "0:" + "62" * 32,
                "--funding",
                "1000000000",
                "--out",
                str(root / "submit.boc"),
            ]
            with (
                patch("sys.argv", command),
                patch("getpass.getpass", return_value=password.decode()),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                wallet.main()
            raw = (root / "submit.boc").read_bytes()
            message = MessageAny.deserialize(Cell.one_from_boc(raw).begin_parse())
            self.assertEqual(message.info.dest, self.module.address)
            body = message.body.begin_parse()
            self.assertEqual(body.load_uint(32), 0x46414C31)
            body.load_uint(64)
            envelope, signature = body.load_ref().begin_parse(), read_chain(body.load_ref(), 666)
            self.assertEqual(envelope.load_uint(32), 0x41555448)
            decoded = envelope.load_ref().begin_parse()
            request = AuthRequest(
                decoded.load_int(32),
                decoded.load_address(),
                decoded.load_uint(64),
                decoded.load_uint(64),
                decoded.load_uint(32),
                decoded.load_uint(8),
                decoded.load_ref(),
            )
            self.assertEqual(request.kind, 1)
            self.assertTrue(
                self.b.verify(
                    signing_message(self.module.address, request), signature, self.h.public_key
                )
            )
            self.assertFalse(
                self.b.verify(
                    signing_message(self.module.address, request), signature, new.public_key
                )
            )
            with (
                patch("sys.argv", command),
                patch("getpass.getpass", return_value=password.decode()),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                with self.assertRaises(FileExistsError):
                    wallet.main()
            self.assertEqual((root / "submit.boc").read_bytes(), raw)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--library", required=True)
    p.add_argument("--artifacts", type=Path, required=True)
    ARGS = p.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(WalletTests)
    )
    sys.exit(0 if result.wasSuccessful() else 1)
