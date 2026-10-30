"""Treasury regressions driven end to end through real signing wallets.

The business and guardian roles are wallet-v5 accounts holding distinct
Ed25519 keys. Every step signs an external message, executes that wallet on
the native emulator and delivers the wallet's actual emitted internal message
to the vault unchanged, so the authenticated-sender boundary is exercised with
the wallet code that produces it rather than with a synthetic sender address.
The cold multisig leg is a separate deployment-acceptance gate.
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
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_native  # noqa: E402
from cells import Cell, from_boc  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from native import (  # noqa: E402
    GLOBAL_ID,
    account_data,
    active_account,
    compile_contract,
    external,
    internal,
    outgoing,
    state_init,
)
from test_native import COLD, PAUSER, SOURCE, TARGET, Vault, compile_fresh  # noqa: E402
from wire import APPROVE, COIN, SUBMIT, decode_message, envelope, payment, roles  # noqa: E402

SIGNED_EXTERNAL = 0x7369676E
SEND_ACTION = 0x0EC3C86D
WALLET_CODE = None


class Wallet:
    """A wallet-v5 account on workchain 0 whose owner key signs every request."""

    def __init__(self, seed):
        self.key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
        public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        data = Cell().uint(1, 1).uint(0, 32).uint(0, 32).uint(int.from_bytes(public, "big"), 256)
        data.maybe(None)
        self.address = (0, int.from_bytes(state_init(WALLET_CODE, data).hash, "big"))
        self.shard = active_account(self.address, WALLET_CODE, data, balance=100 * COIN)

    @property
    def seqno(self):
        s = account_data(self.shard)[0].slice()
        s.uint(1)
        return s.uint(32)

    def signed(self, destination, body, value, now, key=None):
        message = internal(self.address, destination, body, value)
        action = Cell().uint(SEND_ACTION, 32).uint(3, 8).ref(Cell()).ref(message)
        unsigned = (
            Cell()
            .uint(SIGNED_EXTERNAL, 32)
            .sint(GLOBAL_ID, 32)
            .uint(0, 32)
            .uint(now + 600, 32)
            .uint(self.seqno, 32)
            .maybe(action)
            .uint(0, 1)
        )
        signature = (key or self.key).sign(unsigned.hash)
        return Cell(unsigned.bits + "".join(f"{x:08b}" for x in signature), unsigned.refs)

    def send(self, vault, body, *, value=COIN // 2, key=None, expected=0):
        """Sign and execute an external; return the wallet's emitted messages."""
        signed = self.signed(vault.address, body, value, vault.now, key)
        result = vault.e.send(self.shard, external(self.address, signed))
        if not result["success"]:
            assert expected, result
            assert result.get("vm_exit_code") == expected, result
            return []
        details = result["details"]
        assert details["exit"] == expected, (
            f"expected wallet exit {expected}, got {details}\n{result.get('vm_log', '')[-6000:]}"
        )
        self.shard = from_boc(result["shard_account"])
        assert not details["aborted"], details
        assert details["action"] is None or details["action"]["success"], details
        return outgoing(from_boc(result["transaction"]))


class WalletTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global WALLET_CODE
        for key in ("FUNC_PATH", "FIFT_PATH", "EMULATOR_PATH"):
            if not os.environ.get(key):
                raise RuntimeError(f"{key} is required; wallet tests cannot be skipped")
        cls.tmp = tempfile.TemporaryDirectory(prefix="treasury-wallets-")
        test_native.CODE = compile_fresh(SOURCE, Path(cls.tmp.name) / "treasury.boc")
        WALLET_CODE = compile_contract("wallet-v5-code.fc", Path(cls.tmp.name) / "wallet.boc")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.business, self.guardian = Wallet(0x51), Wallet(0x52)
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

    def test_signed_business_and_guardian_wallets_pay(self):
        v = self.v
        req = v.req()
        self.deliver(self.business, self.business.send(v, envelope(SUBMIT, req)))
        self.assertEqual(v.state["payment"].hash, req.hash)
        self.assertEqual(self.business.seqno, 1)
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

    def test_business_wallet_cannot_approve_its_own_proposal(self):
        v = self.v
        req = v.req()
        self.deliver(self.business, self.business.send(v, envelope(SUBMIT, req)))
        self.deliver(self.business, self.business.send(v, envelope(APPROVE, req)), expected=2401)
        self.assertEqual(v.budget()["cumulative"], 0)
        self.assertEqual(v.state["payment"].hash, req.hash)

    def test_guardian_wallet_approval_binds_the_exact_request(self):
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

    def test_wrong_key_is_refused_by_the_wallet_before_the_vault(self):
        v = self.v
        req = v.req()
        body = envelope(SUBMIT, req)
        self.assertEqual(self.business.send(v, body, key=self.guardian.key, expected=135), [])
        self.assertEqual(self.business.seqno, 0)
        self.assertIsNone(v.state["payment"])
        self.deliver(self.business, self.business.send(v, body))
        approval = envelope(APPROVE, req)
        self.assertEqual(self.guardian.send(v, approval, key=self.business.key, expected=135), [])
        self.assertEqual(v.budget()["cumulative"], 0)
        self.assertEqual(v.state["payment"].hash, req.hash)


if __name__ == "__main__":
    result = unittest.main(verbosity=2, exit=False).result
    report = dict(
        source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        wallet_source_sha256=hashlib.sha256(
            (ROOT / "crypto/smartcont/wallet-v5-code.fc").read_bytes()
        ).hexdigest(),
        tests=result.testsRun,
        failures=len(result.failures),
        errors=len(result.errors),
        skipped=len(result.skipped),
        code_hash=test_native.CODE.hash.hex() if test_native.CODE is not None else None,
        wallet_code_hash=WALLET_CODE.hash.hex() if WALLET_CODE is not None else None,
    )
    path = os.environ.get("TREASURY_WALLET_RESULTS")
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if result.testsRun and result.wasSuccessful() and not result.skipped else 1)
