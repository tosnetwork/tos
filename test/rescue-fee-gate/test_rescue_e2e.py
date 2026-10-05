"""EXPERIMENT: the minimal rescue loop in real transactions, native emulator.

fee vault (LMS, external) -> dual-root module (SLH-DSA or ML-DSA, internal) -> V5R2 account.
Every hop is a separate transaction fed with the previous one's actual outgoing message.

Environment: as test_slot_vault.py, plus SLH_TOOL and MLDSA_TOOL (test-only signers built from the
pinned slhdsa-c and the vendored mldsa-native). OPENSSL (an OpenSSL 3.5+ command) adds an
independent SLH-DSA signer, so suite 3 is not only checked against its own backend.
"""

# ruff: noqa: E402
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_slot_vault as slot
from cells import Cell, from_boc
from native import (
    GLOBAL_ID,
    NOW,
    account_data,
    active_account,
    compile_contract,
    internal,
    outgoing,
)

MODULE = slot.TARGET
ACCOUNT = (0, 0xACC0 << 240 | 0x55)
RELAYER = (0, 0x7E1A << 240 | 0x01)
PAYEE = (0, 0xBEEF << 240 | 0xFE)
NETWORK_TAG = bytes(range(32, 64))
SUB1, AU2R = 0x53554231, 0x41553252
EXEC, CONF, LOCK, MIGR = 0x45584543, 0x434F4E46, 0x4C4F434B, 0x4D494752
PRIMARY, RESCUE = 1, 2
K_EXECUTE, K_CONFIGURE, K_LOCK, K_MIGRATE = 0, 1, 3, 4
READY, REQUIRED = 1, 2
CTX_PRIMARY = b"TOS-AUTH-V2-ML-DSA-44-v1"
CTX_RESCUE = b"TOS-AUTH-SLH-DSA-SHA2-128S-v1"
RESULTS = []


def run(*args):
    return subprocess.run([str(a) for a in args], check=True, capture_output=True, text=True).stdout


class Signers:
    def __init__(self, workdir):
        self.dir = Path(workdir)
        self.ml_pk, self.ml_sk = self.dir / "ml.pk", self.dir / "ml.sk"
        run(os.environ["MLDSA_TOOL"], "keygen", "11" * 32, self.ml_pk, self.ml_sk)
        pk, self.slh_sk = run(os.environ["SLH_TOOL"], "keygen", "22" * 48).split()
        self.slh_pk = bytes.fromhex(pk)
        other_pk, self.other_slh_sk = run(os.environ["SLH_TOOL"], "keygen", "33" * 48).split()
        self.n = 0

    def _files(self, digest):
        self.n += 1
        m, s = self.dir / f"m{self.n}", self.dir / f"s{self.n}"
        m.write_bytes(digest)
        return m, s

    def ml(self, digest):
        m, s = self._files(digest)
        run(os.environ["MLDSA_TOOL"], "sign", self.ml_sk, CTX_PRIMARY.hex(), m, s)
        return s.read_bytes()

    def slh(self, digest, sk=None):
        m, s = self._files(digest)
        run(os.environ["SLH_TOOL"], "sign", sk or self.slh_sk, CTX_RESCUE.hex(), m, s)
        return s.read_bytes()


def request(
    role,
    kind,
    payload,
    epoch=0,
    nonce=0,
    root=MODULE,
    account=ACCOUNT,
    now=NOW,
    valid_until=None,
    network_tag=NETWORK_TAG,
):
    return (
        Cell()
        .uint(AU2R, 32)
        .sint(GLOBAL_ID, 32)
        .raw(network_tag)
        .addr(account)
        .uint(root[1], 256)
        .uint(role, 8)
        .uint(epoch, 64)
        .uint(nonce, 64)
        .uint(valid_until if valid_until is not None else now + 600, 32)
        .uint(kind, 8)
        .ref(payload)
    )


def digest(req):
    return Cell().uint(0x544F532D41555448, 64).ref(req).hash


def pay(to, value, mode=1):
    out = Cell().uint(0x10, 6).addr(to).coins(value).uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)
    return Cell().uint(EXEC, 32).ref(Cell().uint(mode, 8).ref(out))


def submission(req, signature):
    return Cell().uint(SUB1, 32).ref(req).ref(slot.chain(signature))


class RescueLoopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        slot.SlotVaultTests.setUpClass()
        cls.tmp = tempfile.TemporaryDirectory()
        module = os.environ.get("MODULE_SOURCE", "rescue-dual-module.fc")
        account = os.environ.get("ACCOUNT_SOURCE", "rescue-v5r2-account.fc")
        cls.module_code = compile_contract(module, Path(cls.tmp.name) / "module.boc")
        cls.account_code = compile_contract(account, Path(cls.tmp.name) / "account.boc")
        cls.sign = Signers(cls.tmp.name)

    @classmethod
    def tearDownClass(cls):
        slot.SlotVaultTests.tearDownClass()
        cls.tmp.cleanup()

    def setUp(self):
        self.h = slot.SlotVaultTests("test_slot_window")
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)
        self.em = slot.SlotVaultTests.emulator
        self.fee = self.h.device()
        # A rescue takes several fee payments in one sitting: four leaves per slot.
        self.vault = self.h.vault(self.fee, per_slot=4)
        self.leaf = slot.START_SLOT * 4

    def module(self, policy=READY, slh_pk=None):
        data = (
            Cell()
            .uint(1, 8)
            .sint(GLOBAL_ID, 32)
            .raw(NETWORK_TAG)
            .uint(1, 8)
            .ref(slot.chain(self.sign.ml_pk.read_bytes()))
            .raw(slh_pk or self.sign.slh_pk)
            .uint(policy, 8)
        )
        return active_account(MODULE, self.module_code, data, balance=1_000_000_000)

    def account(self, policy=READY, epoch=0, local_retired=0):
        fee_route = Cell().uint(slot.VAULT[1], 256).uint(1, 8)
        data = (
            Cell()
            .uint(2, 8)
            .uint(2, 2)
            .uint(MODULE[1], 256)
            .uint(MODULE[1], 256)
            .uint(1, 8)
            .uint(policy, 8)
            .uint(local_retired, 16)
            .uint(epoch, 64)
            .uint(0, 64)
            .uint(0, 64)
            .ref(fee_route)
        )
        return active_account(ACCOUNT, self.account_code, data, balance=50_000_000_000)

    def state(self, shard):
        data, balance = account_data(shard)
        s = data.slice()
        s.uint(8)
        st = {"mode": s.uint(2), "root": s.uint(256)}
        s.uint(256)
        st.update(daily=s.uint(8), policy=s.uint(8), retired=s.uint(16), epoch=s.uint(64))
        st.update(primary_nonce=s.uint(64), rescue_nonce=s.uint(64), balance=balance)
        return st

    def through_vault(self, sub, value=slot.MAX_VALUE):
        i = slot.rescue_intent(self.leaf, sub, value=value)
        r = self.h.submit(self.vault, slot.body(i, self.fee.sign_at(self.leaf, i.hash)))
        self.assertTrue(self.h.admitted(r), r.get("error"))
        self.vault = from_boc(r["shard_account"])
        self.leaf += 1
        (msg,) = outgoing(from_boc(r["transaction"]))
        return msg

    def deliver(self, shard, msg):
        r = self.em.send(shard, msg)
        sent = outgoing(from_boc(r["transaction"])) if r["success"] else []
        return r, sent

    def hop(self, module_shard, account_shard, msg, label):
        """Module then account; returns (module result, account result, new shards)."""
        mr, msent = self.deliver(module_shard, msg)
        self.assertTrue(mr["success"], mr.get("error"))
        d = mr["details"]
        RESULTS.append((label, "module", d["exit"], d["gas"]))
        if not d["compute_success"]:
            return mr, None, module_shard, account_shard
        (relay,) = msent
        ar, _ = self.deliver(account_shard, relay)
        self.assertTrue(ar["success"], ar.get("error"))
        RESULTS.append((label, "account", ar["details"]["exit"], ar["details"]["gas"]))
        return mr, ar, from_boc(mr["shard_account"]), from_boc(ar["shard_account"])

    def test_rescue_lock_through_the_fee_vault(self):
        req = request(RESCUE, K_LOCK, Cell().uint(LOCK, 32).uint(1, 8))
        msg = self.through_vault(submission(req, self.sign.slh(digest(req))))
        _, ar, _, acc = self.hop(self.module(), self.account(), msg, "rescue lock via vault")
        self.assertTrue(ar["details"]["compute_success"], ar["details"])
        st = self.state(acc)
        self.assertEqual(st["retired"], 1 << 1)
        self.assertEqual(st["epoch"], 1)
        self.assertEqual((st["primary_nonce"], st["rescue_nonce"]), (0, 0))

    def test_primary_spends_until_locked_then_is_refused(self):
        mod, acc = self.module(), self.account()
        req = request(PRIMARY, K_EXECUTE, pay(PAYEE, 1_000_000_000))
        msg = internal(
            RELAYER, MODULE, submission(req, self.sign.ml(digest(req))), value=1_000_000_000
        )
        mr, ar, mod, acc = self.hop(mod, acc, msg, "primary execute direct")
        self.assertTrue(ar["details"]["compute_success"], ar["details"])
        self.assertEqual(len(outgoing(from_boc(ar["transaction"]))), 1)
        self.assertEqual(self.state(acc)["primary_nonce"], 1)
        # Replaying the module's relay is refused by the nonce.
        (relay,) = outgoing(from_boc(mr["transaction"]))
        again, _ = self.deliver(acc, relay)
        self.assertEqual(again["details"]["exit"], 1804)
        # RESCUE locks the daily suite.
        lock = request(RESCUE, K_LOCK, Cell().uint(LOCK, 32).uint(1, 8))
        mr, ar, mod, acc = self.hop(
            mod, acc, self.through_vault(submission(lock, self.sign.slh(digest(lock)))), "lock"
        )
        self.assertTrue(ar["details"]["compute_success"])
        # The lock's own relay, delivered again, is stale: the epoch moved.
        (relay,) = outgoing(from_boc(mr["transaction"]))
        again, _ = self.deliver(acc, relay)
        self.assertEqual(again["details"]["exit"], 1803)
        # A PRIMARY request with every other field current is refused by the local bit.
        req = request(PRIMARY, K_EXECUTE, pay(PAYEE, 1_000_000_000), epoch=1, nonce=0)
        msg = internal(
            RELAYER, MODULE, submission(req, self.sign.ml(digest(req))), value=1_000_000_000
        )
        _, ar, _, _ = self.hop(mod, acc, msg, "primary after lock")
        self.assertFalse(ar["details"]["compute_success"])
        self.assertEqual(ar["details"]["exit"], 1813)

    def test_primary_funded_by_the_fee_vault_is_refused(self):
        req = request(PRIMARY, K_EXECUTE, pay(PAYEE, 1_000_000_000))
        msg = self.through_vault(submission(req, self.sign.ml(digest(req))))
        _, ar, _, _ = self.hop(self.module(), self.account(), msg, "primary via vault")
        self.assertFalse(ar["details"]["compute_success"])
        self.assertEqual(ar["details"]["exit"], 1818)

    def test_signature_role_and_key_binding_at_the_module(self):
        cases = []
        lock = request(RESCUE, K_LOCK, Cell().uint(LOCK, 32).uint(1, 8))
        cases.append(
            ("ML-DSA signature claiming RESCUE", submission(lock, self.sign.ml(digest(lock))), 9)
        )
        cases.append(
            (
                "another SLH key",
                submission(lock, self.sign.slh(digest(lock), self.sign.other_slh_sk)),
                1808,
            )
        )
        bad = request(PRIMARY, K_LOCK, Cell().uint(LOCK, 32).uint(1, 8))
        cases.append(
            ("PRIMARY control operation", submission(bad, self.sign.ml(digest(bad))), 1812)
        )
        mismatch = request(RESCUE, K_LOCK, Cell().uint(EXEC, 32))
        cases.append(
            ("payload of another kind", submission(mismatch, self.sign.slh(digest(mismatch))), 1814)
        )
        for name, req, code in (
            (
                "request for another root",
                request(RESCUE, K_LOCK, Cell().uint(LOCK, 32).uint(1, 8), root=(0, 5)),
                1802,
            ),
            (
                "expired request",
                request(RESCUE, K_LOCK, Cell().uint(LOCK, 32).uint(1, 8), valid_until=NOW),
                1805,
            ),
            (
                "ttl beyond one hour",
                request(RESCUE, K_LOCK, Cell().uint(LOCK, 32).uint(1, 8), valid_until=NOW + 3601),
                1805,
            ),
            (
                "other network tag",
                request(RESCUE, K_LOCK, Cell().uint(LOCK, 32).uint(1, 8), network_tag=bytes(32)),
                1801,
            ),
            (
                "masterchain account",
                request(RESCUE, K_LOCK, Cell().uint(LOCK, 32).uint(1, 8), account=(-1, 7)),
                1802,
            ),
        ):
            cases.append((name, submission(req, self.sign.slh(digest(req))), code))
        for name, sub, code in cases:
            with self.subTest(case=name):
                mr, _ = self.deliver(
                    self.module(), internal(RELAYER, MODULE, sub, value=2_000_000_000)
                )
                self.assertTrue(mr["success"])
                self.assertFalse(mr["details"]["compute_success"], name)
                self.assertEqual(mr["details"]["exit"], code, name)
        # A PRIMARY execute whose ML-DSA signature has one bit flipped.
        req = request(PRIMARY, K_EXECUTE, pay(PAYEE, 1))
        sig = bytearray(self.sign.ml(digest(req)))
        sig[100] ^= 1
        mr, _ = self.deliver(
            self.module(),
            internal(RELAYER, MODULE, submission(req, bytes(sig)), value=2_000_000_000),
        )
        self.assertEqual(mr["details"]["exit"], 1808, "tampered ML-DSA signature")
        # REQUIRED policy: PRIMARY refused at the module even for execute.
        req = request(PRIMARY, K_EXECUTE, pay(PAYEE, 1))
        mr, _ = self.deliver(
            self.module(policy=REQUIRED),
            internal(RELAYER, MODULE, submission(req, self.sign.ml(digest(req)))),
        )
        self.assertEqual(mr["details"]["exit"], 1817)

    @unittest.skipUnless(os.environ.get("OPENSSL"), "OPENSSL (3.5+) not set")
    def test_independent_openssl_signature_is_accepted_and_context_bound(self):
        d = Path(self.tmp.name)
        openssl = os.environ["OPENSSL"]
        run(openssl, "genpkey", "-algorithm", "SLH-DSA-SHA2-128s", "-out", d / "o.pem")
        run(openssl, "pkey", "-in", d / "o.pem", "-pubout", "-outform", "DER", "-out", d / "o.der")
        slh_pk = (d / "o.der").read_bytes()[-32:]

        def openssl_sign(message, context):
            (d / "o.msg").write_bytes(message)
            args = [
                openssl,
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                d / "o.pem",
                "-in",
                d / "o.msg",
                "-out",
                d / "o.sig",
            ]
            if context:
                args += ["-pkeyopt", "context-string:" + context.decode("ascii")]
            run(*args)
            return (d / "o.sig").read_bytes()

        lock = request(RESCUE, K_LOCK, Cell().uint(LOCK, 32).uint(1, 8))
        # Without the AUTH context the same key and message must not verify.
        no_ctx = submission(lock, openssl_sign(digest(lock), b""))
        mr, _ = self.deliver(
            self.module(slh_pk=slh_pk), internal(RELAYER, MODULE, no_ctx, value=2_000_000_000)
        )
        self.assertEqual(mr["details"]["exit"], 1808, "context must be bound")
        sub = submission(lock, openssl_sign(digest(lock), CTX_RESCUE))
        _, ar, _, acc = self.hop(
            self.module(slh_pk=slh_pk),
            self.account(),
            self.through_vault(sub),
            "openssl rescue lock",
        )
        self.assertTrue(ar["details"]["compute_success"], ar["details"])
        self.assertEqual(self.state(acc)["retired"], 1 << 1)

    def test_account_accepts_relays_only_from_its_module(self):
        # Anyone can send the relay constructor; without the sender check no signature at all
        # would stand between a forged request and the account.
        req = request(RESCUE, K_EXECUTE, pay(PAYEE, 5_000_000_000))
        forged = Cell().uint(0x41553242, 32).ref(req).uint(0, 1).addr(RELAYER)
        ar, _ = self.deliver(self.account(), internal(RELAYER, ACCOUNT, forged))
        self.assertTrue(ar["success"])
        self.assertFalse(ar["details"]["compute_success"])
        self.assertEqual(ar["details"]["exit"], 1800)
        # Positive control: the same relay from the module is executed.
        ok, _ = self.deliver(self.account(), internal(MODULE, ACCOUNT, forged))
        self.assertTrue(ok["details"]["compute_success"], ok["details"])

    def test_rescue_execute_and_migration_cut_the_old_root(self):
        mod, acc = self.module(), self.account()
        req = request(RESCUE, K_EXECUTE, pay(PAYEE, 3_000_000_000))
        _, ar, mod, acc = self.hop(
            mod,
            acc,
            self.through_vault(submission(req, self.sign.slh(digest(req)))),
            "rescue execute",
        )
        self.assertTrue(ar["details"]["compute_success"], ar["details"])
        (paid,) = outgoing(from_boc(ar["transaction"]))
        s = paid.slice()
        s.uint(4), s.addr()
        self.assertEqual(s.addr(), PAYEE)
        self.assertEqual(self.state(acc)["rescue_nonce"], 1)
        new_root = 0xD00D << 240 | 0x42
        payload = (
            Cell()
            .uint(MIGR, 32)
            .uint(new_root, 256)
            .uint(new_root, 256)
            .uint(REQUIRED, 8)
            .uint(1, 8)
            .uint(0, 256)
            .ref(Cell().uint(0xFEE, 256))
        )
        # A successor whose address is not the hash of its StateInit is refused.
        bad_payload = (
            Cell().uint(MIGR, 32).uint(new_root, 256).uint(new_root + 1, 256).uint(REQUIRED, 8)
        )
        bad_payload.uint(1, 8).uint(0, 256).ref(Cell().uint(0xFEE, 256))
        bad = request(RESCUE, K_MIGRATE, bad_payload, nonce=1)
        _, ar, _, _ = self.hop(
            mod,
            acc,
            self.through_vault(submission(bad, self.sign.slh(digest(bad)))),
            "bad successor",
        )
        self.assertEqual(ar["details"]["exit"], 1815)
        mig = request(RESCUE, K_MIGRATE, payload, nonce=1)
        _, ar, mod, acc = self.hop(
            mod, acc, self.through_vault(submission(mig, self.sign.slh(digest(mig)))), "migrate"
        )
        self.assertTrue(ar["details"]["compute_success"], ar["details"])
        st = self.state(acc)
        self.assertEqual((st["root"], st["policy"], st["epoch"]), (new_root, REQUIRED, 1))
        # The old module is no longer the root: its relays are refused.
        req = request(RESCUE, K_EXECUTE, pay(PAYEE, 1), epoch=1)
        _, ar, _, _ = self.hop(
            mod, acc, self.through_vault(submission(req, self.sign.slh(digest(req)))), "old root"
        )
        self.assertFalse(ar["details"]["compute_success"])
        self.assertEqual(ar["details"]["exit"], 1800)


if __name__ == "__main__":
    program = unittest.main(verbosity=2, exit=False)
    print("step | contract | exit | gas")
    for row in RESULTS:
        print(" | ".join(str(x) for x in row))
    sys.exit(0 if program.result.wasSuccessful() else 1)
