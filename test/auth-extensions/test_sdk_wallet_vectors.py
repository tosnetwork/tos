"""The JS SDK's wallet messages, executed against the wallet code compiled here.

sdk/js/packages/wallets/test-vectors/network-bound-transfers.json holds the
signed external messages the SDK builds for V3R2 and V4R2 (its own test keeps
the file equal to what the SDK produces). Here each one runs through the native
emulator on a network whose ConfigParam 19 is 42, against code compiled from
crypto/smartcont: a message signed for 42 must transfer, one signed for 43 must
be refused with exit 36 and change nothing. The same holds for the body the
SDK's sendDeploy submits, sent with the SDK's StateInit to a funded,
uninitialized account: signed for 42 it deploys the wallet, signed for 43 the
account stays undeployed.
"""

import base64
import json
import tempfile
import unittest
from pathlib import Path

from cells import Cell, from_boc
from native import (
    GLOBAL_ID,
    NOW,
    ROOT,
    Emulator,
    account_data,
    active_account,
    compile_contract,
    external,
    outgoing,
    state_init,
)

VECTORS = ROOT / "sdk/js/packages/wallets/test-vectors/network-bound-transfers.json"
SOURCES = {"V3R2": "wallet3-code.fc", "V4R2": "wallet-v4-code.fc"}


def raw_address(text):
    workchain, account = text.split(":")
    return int(workchain), int(account, 16)


def boc(text):
    return from_boc(base64.b64decode(text))


def uninitialized_account(address, balance=100_000_000_000):
    """A funded account with no code yet (account_uninit$00)."""
    account = (
        Cell()
        .uint(1, 1)
        .addr(address)
        .varuint(0, 7)
        .varuint(0, 7)
        .uint(0, 3)
        .uint(NOW, 32)
        .uint(0, 1)
        .uint(0, 64)
        .coins(balance)
        .uint(0, 1)
        .uint(0, 2)
    )
    return Cell().uint(0, 256).uint(0, 64).ref(account)


def external_with_init(destination, init, body):
    """ext_in_msg_info with the StateInit and the body each in a reference."""
    return (
        Cell()
        .uint(8, 4)
        .addr(destination)
        .coins(0)
        .uint(1, 1)
        .uint(1, 1)
        .ref(init)
        .uint(1, 1)
        .ref(body)
    )


class SdkWalletVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads(VECTORS.read_text())
        cls.tmp = tempfile.TemporaryDirectory()
        cls.code = {
            name: compile_contract(source, Path(cls.tmp.name) / f"{name}.boc")
            for name, source in SOURCES.items()
        }

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_vectors_were_built_for_this_emulated_network_and_clock(self):
        self.assertEqual(self.vectors["emulated_network"], GLOBAL_ID)
        self.assertEqual(self.vectors["now"], NOW)
        self.assertEqual(
            sorted({(v["wallet"], v["network"]) for v in self.vectors["vectors"]}),
            [
                ("V3R2", GLOBAL_ID),
                ("V3R2", GLOBAL_ID + 1),
                ("V4R2", GLOBAL_ID),
                ("V4R2", GLOBAL_ID + 1),
            ],
        )

    def test_the_sdk_deploys_the_code_compiled_from_source(self):
        for vector in self.vectors["vectors"]:
            with self.subTest(wallet=vector["wallet"], network=vector["network"]):
                code = boc(vector["code"])
                self.assertEqual(code.hash, self.code[vector["wallet"]].hash)
                address = raw_address(vector["address"])
                expected = int.from_bytes(state_init(code, boc(vector["data"])).hash, "big")
                self.assertEqual(address[1], expected, "SDK address must be the StateInit hash")

    def run_vector(self, vector):
        code, data = self.code[vector["wallet"]], boc(vector["data"])
        address = raw_address(vector["address"])
        emulator = Emulator(6)
        self.addCleanup(emulator.close)
        shard = active_account(address, code, data)
        return emulator.send(shard, external(address, boc(vector["body"]))), data

    def test_a_message_signed_for_this_network_transfers(self):
        for vector in self.vectors["vectors"]:
            if vector["network"] != GLOBAL_ID:
                continue
            with self.subTest(wallet=vector["wallet"]):
                result, before = self.run_vector(vector)
                self.assertTrue(result["success"], result)
                details = result["details"]
                self.assertEqual(details["exit"], 0, details)
                self.assertFalse(details["aborted"], details)
                self.assertTrue(details["action"] and details["action"]["success"], details)
                after, _ = account_data(from_boc(result["shard_account"]))
                self.assertEqual(
                    after.slice().uint(32), before.slice().uint(32) + 1, "seqno advances"
                )
                messages = outgoing(from_boc(result["transaction"]))
                self.assertEqual(len(messages), 1)
                s = messages[0].slice()
                self.assertEqual(s.uint(4) & 0b1000, 0, "an internal message")
                s.addr()  # source, filled in by the executor
                self.assertEqual(s.addr(), raw_address(vector["destination"]))
                self.assertEqual(s.coins(), int(vector["value"]))

    def test_a_message_signed_for_another_network_is_refused(self):
        for vector in self.vectors["vectors"]:
            if vector["network"] == GLOBAL_ID:
                continue
            with self.subTest(wallet=vector["wallet"]):
                result, _ = self.run_vector(vector)
                if result["success"]:
                    exit_code = result["details"]["exit"]
                else:
                    exit_code = result.get("vm_exit_code")
                self.assertEqual(exit_code, 36, result)
                self.assertFalse(
                    result["success"] and not result["details"]["aborted"],
                    "a refused external message must not commit",
                )

    def deploy_vector(self, vector):
        code, data = self.code[vector["wallet"]], boc(vector["data"])
        address = raw_address(vector["address"])
        emulator = Emulator(6)
        self.addCleanup(emulator.close)
        message = external_with_init(address, state_init(code, data), boc(vector["deploy"]))
        return emulator.send(uninitialized_account(address), message), data

    def test_a_deploy_signed_for_this_network_deploys_the_wallet(self):
        for vector in self.vectors["vectors"]:
            if vector["network"] != GLOBAL_ID:
                continue
            with self.subTest(wallet=vector["wallet"]):
                result, data = self.deploy_vector(vector)
                self.assertTrue(result["success"], result)
                details = result["details"]
                self.assertEqual(details["exit"], 0, details)
                self.assertFalse(details["aborted"], details)
                after, _ = account_data(from_boc(result["shard_account"]))
                self.assertEqual(after.slice().uint(32), 1, "deployed with seqno 1")
                self.assertEqual(
                    outgoing(from_boc(result["transaction"])), [], "a deploy sends nothing"
                )

    def test_a_deploy_signed_for_another_network_is_refused(self):
        for vector in self.vectors["vectors"]:
            if vector["network"] == GLOBAL_ID:
                continue
            with self.subTest(wallet=vector["wallet"]):
                result, _ = self.deploy_vector(vector)
                if result["success"]:
                    exit_code = result["details"]["exit"]
                    s = from_boc(result["shard_account"]).refs[0].slice()
                    # account$1 addr storage_stat last_trans_lt balance, up to the state
                    s.uint(1)
                    s.addr()
                    s.varuint(7)
                    s.varuint(7)
                    s.uint(3)
                    s.uint(32)
                    s.uint(1)
                    s.uint(64)
                    s.coins()
                    s.uint(1)
                    self.assertEqual(s.uint(2), 0, "the account must stay uninitialized")
                else:
                    exit_code = result.get("vm_exit_code")
                self.assertEqual(exit_code, 36, result)


if __name__ == "__main__":
    import sys

    result = unittest.main(verbosity=2, exit=False)
    sys.exit(0 if result.result.wasSuccessful() else 1)
