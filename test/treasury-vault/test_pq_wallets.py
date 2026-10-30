"""Treasury regressions driven end to end through post-quantum signing wallets.

The business and guardian roles are ML-DSA-44 high-volume wallet accounts
with distinct keys from the TEST ONLY signer in test/pq-contracts. Every step
signs a relayed request, executes the wallet on the native emulator at global
version 16, checks in the VM log that a post-quantum verification actually ran,
and delivers the wallet's actual emitted internal message to the vault
unchanged. The cold multisig leg is a separate deployment-acceptance gate.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
sys.path.insert(0, str(ROOT / "test/pq-contracts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pqtest  # noqa: E402
import test_native  # noqa: E402
from cells import Cell, from_boc  # noqa: E402
from native import (  # noqa: E402
    GLOBAL_ID,
    account_data,
    active_account,
    internal,
    outgoing,
    state_init,
)
from test_native import COLD, PAUSER, SOURCE, TARGET, Vault, compile_fresh  # noqa: E402
from wire import APPROVE, COIN, SUBMIT, decode_message, envelope, payment, roles  # noqa: E402

WALLET_SOURCE = ROOT / "crypto/smartcont/pq-highload-wallet-code.fc"
CONTEXT = b"TOS-PQ-HIGHLOAD-v1"
SUBMIT_OP = 0x50514857
SEND_MSG = 0x0EC3C86D
INVALID_SIGNATURE = 0x1C0C
RELAYER = (0, 77)
SUBWALLET, TIMEOUT = 7, 3600
RELAY_VALUE = 10 * COIN
WALLET_CODE = None


class PqWallet:
    """An ML-DSA-44 high-volume wallet on workchain 0; a relayer carries its requests."""

    def __init__(self, key):
        self.key = key
        data = (
            Cell()
            .ref(pqtest.stored(pqtest.public_key(key)))
            .uint(SUBWALLET, 32)
            .maybe(None)
            .maybe(None)
            .uint(0, 64)
            .uint(TIMEOUT, 22)
        )
        self.address = (0, int.from_bytes(state_init(WALLET_CODE, data).hash, "big"))
        self.shard = active_account(self.address, WALLET_CODE, data, balance=100 * COIN)
        self.query_id = 1

    def request(self, destination, body, value, now):
        message = (
            Cell()
            .uint(0, 1)
            .uint(1, 1)
            .uint(0, 1)
            .uint(0, 1)
            .uint(0, 2)
            .addr(destination)
            .coins(value)
            .uint(0, 1)
            .coins(0)
            .coins(0)
            .uint(0, 64)
            .uint(0, 32)
            .uint(0, 1)
            .uint(1, 1)
            .ref(body)
        )
        actions = Cell().ref(Cell()).uint(SEND_MSG, 32).uint(1, 8).ref(message)
        return (
            Cell()
            .sint(GLOBAL_ID, 32)
            .addr(self.address)
            .uint(SUBWALLET, 32)
            .uint(self.query_id, 23)
            .uint(now - 10, 64)
            .uint(TIMEOUT, 22)
            .ref(actions)
        )

    def send(self, vault, body, *, value=COIN // 2, key=None, expected=0):
        """Sign a request, relay it to the wallet and return the wallet's emitted messages
        other than the relayer refund."""
        req = self.request(vault.address, body, value, vault.now)
        signature = pqtest.stored(
            pqtest.sign(key if key is not None else self.key, req.hash, CONTEXT)
        )
        submission = Cell().uint(SUBMIT_OP, 32).uint(self.query_id, 64).ref(req).ref(signature)
        before = account_data(self.shard)[0].hash
        result = vault.e.send(self.shard, internal(RELAYER, self.address, submission, RELAY_VALUE))
        details = pqtest.details_of(result)
        self.shard = from_boc(result["shard_account"])
        assert details["exit"] == expected, (
            f"expected wallet exit {expected}, got {details}\n{result.get('vm_log', '')[-6000:]}"
        )
        assert details["verifications"] == 1, "exactly one post-quantum verification must run"
        messages = outgoing(from_boc(result["transaction"]))
        if expected:
            assert account_data(self.shard)[0].hash == before, "a refused request changed state"
            assert not messages, "a refused request emitted messages"
            return []
        assert not details["aborted"], details
        assert details["action"] is None or details["action"]["success"], details
        self.query_id += 1
        refunds = [m for m in messages if decode_message(m)["target"] == RELAYER]
        assert len(refunds) == 1, "the wallet refunds the relayer exactly once"
        return [m for m in messages if decode_message(m)["target"] != RELAYER]


class PqWalletTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global WALLET_CODE
        for key in ("FUNC_PATH", "FIFT_PATH", "EMULATOR_PATH", "PQ_TEST_SIGNER"):
            if not os.environ.get(key):
                raise RuntimeError(
                    f"{key} is required; post-quantum wallet tests cannot be skipped"
                )
        cls.tmp = tempfile.TemporaryDirectory(prefix="treasury-pq-wallets-")
        test_native.CODE = compile_fresh(SOURCE, Path(cls.tmp.name) / "treasury.boc")
        WALLET_CODE = pqtest.compile_source(WALLET_SOURCE, Path(cls.tmp.name) / "pq-wallet.boc")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.business, self.guardian = PqWallet(11), PqWallet(12)
        self.assertNotEqual(self.business.address, self.guardian.address)
        role_cell = roles(self.business.address, self.guardian.address, COLD, PAUSER)
        self.v = Vault(role_cell=role_cell)
        self.addCleanup(self.v.close)

    def deliver(self, wallet, messages, expected=0):
        """Hand the wallet's single emitted message to the vault unchanged."""
        self.assertEqual(len(messages), 1)
        msg = decode_message(messages[0])
        self.assertEqual((msg["source"], msg["target"]), (wallet.address, self.v.address))
        self.assertEqual(msg["value"], COIN // 2)
        return self.v.send(message=messages[0], expected=expected)

    def test_pq_signed_business_and_guardian_wallets_pay(self):
        v = self.v
        req = v.req()
        self.deliver(self.business, self.business.send(v, envelope(SUBMIT, req)))
        self.assertEqual(v.state["payment"].hash, req.hash)
        approval = self.guardian.send(v, envelope(APPROVE, req))
        payout = self.deliver(self.guardian, approval)
        self.assertEqual(len(payout), 1)
        msg = decode_message(payout[0])
        self.assertEqual((msg["source"], msg["target"], msg["value"]), (v.address, TARGET, COIN))
        self.assertEqual(v.budget()["cumulative"], COIN)
        self.assertEqual(v.state["payment_nonce"], 1)
        self.assertIsNone(v.state["payment"])
        # The same emitted approval cannot be delivered a second time.
        self.v.send(message=approval[0], expected=2410)
        self.assertEqual(v.budget()["cumulative"], COIN)

    def test_pq_business_wallet_cannot_approve_its_own_proposal(self):
        v = self.v
        req = v.req()
        self.deliver(self.business, self.business.send(v, envelope(SUBMIT, req)))
        self.deliver(self.business, self.business.send(v, envelope(APPROVE, req)), expected=2401)
        self.assertEqual(v.budget()["cumulative"], 0)
        self.assertEqual(v.state["payment"].hash, req.hash)

    def test_pq_guardian_wallet_approval_binds_the_exact_request(self):
        v = self.v
        req = v.req()
        self.deliver(self.business, self.business.send(v, envelope(SUBMIT, req)))
        for other in (payment(0, 2 * COIN, TARGET), payment(0, COIN, PAUSER)):
            approval = self.guardian.send(v, envelope(APPROVE, v.req(other)))
            self.deliver(self.guardian, approval, expected=2407)
        self.assertEqual(v.budget()["cumulative"], 0)
        self.deliver(self.guardian, self.guardian.send(v, envelope(SUBMIT, req)), expected=2401)
        payout = self.deliver(self.guardian, self.guardian.send(v, envelope(APPROVE, req)))
        self.assertEqual(len(payout), 1)
        self.assertEqual(v.budget()["cumulative"], COIN)

    def test_pq_wrong_key_is_refused_by_the_wallet_before_the_vault(self):
        v = self.v
        req = v.req()
        body = envelope(SUBMIT, req)
        refused = self.business.send(v, body, key=self.guardian.key, expected=INVALID_SIGNATURE)
        self.assertEqual(refused, [])
        self.assertEqual(self.business.query_id, 1)
        self.assertIsNone(v.state["payment"])
        self.deliver(self.business, self.business.send(v, body))
        approval = envelope(APPROVE, req)
        refused = self.guardian.send(v, approval, key=self.business.key, expected=INVALID_SIGNATURE)
        self.assertEqual(refused, [])
        self.assertEqual(v.budget()["cumulative"], 0)
        self.assertEqual(v.state["payment"].hash, req.hash)


if __name__ == "__main__":
    result = unittest.main(verbosity=2, exit=False).result
    report = dict(
        source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        wallet_source_sha256=hashlib.sha256(WALLET_SOURCE.read_bytes()).hexdigest(),
        tests=result.testsRun,
        failures=len(result.failures),
        errors=len(result.errors),
        skipped=len(result.skipped),
        code_hash=test_native.CODE.hash.hex() if test_native.CODE is not None else None,
        wallet_code_hash=WALLET_CODE.hash.hex() if WALLET_CODE is not None else None,
    )
    path = os.environ.get("TREASURY_PQ_WALLET_RESULTS")
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if result.testsRun and result.wasSuccessful() and not result.skipped else 1)
