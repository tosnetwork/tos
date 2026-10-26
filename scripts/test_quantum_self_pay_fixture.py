"""Schema controls only; live cryptographic acceptance is exercised by the capture runner."""

import base64
import importlib.util
import unittest
from pathlib import Path

from pytosiq_core import Builder
from quantum_self_pay_fixture import GLOBAL_ID, NAMESPACE, accounts, byte_chain, one_cell


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.code = Builder().store_uint(17, 8).end_cell()
        self.primary = bytes(index % 256 for index in range(1312))
        self.rescue = bytes(range(32))
        self.records = accounts(self.code, self.primary, self.rescue)
        spec = importlib.util.spec_from_file_location(
            "capture", Path(__file__).with_name("capture-quantum-self-pay.py")
        )
        self.capture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.capture)

    def test_three_distinct_birth_identities_preserve_public_authority(self):
        self.assertEqual(len({r["address"] for r in self.records.values()}), 3)
        for wallet_id, record in enumerate(self.records.values()):
            identity = one_cell(base64.b64decode(record["identity_boc"])).begin_parse()
            self.assertEqual(identity.load_uint(32), 0x51534931)
            address = identity.load_bytes(32)
            init = identity.load_ref()
            self.assertEqual(init.hash, address)
            self.assertEqual(record["address"], "0:" + address.hex())
            self.assertEqual(identity.remaining_bits, 0)
            self.assertEqual(identity.remaining_refs, 0)
            state_init = init.begin_parse()
            self.assertEqual(state_init.load_uint(5), 6)
            self.assertEqual(state_init.load_ref().hash, self.code.hash)
            data = state_init.load_ref().begin_parse()
            self.assertEqual(data.load_uint(8), 1)
            self.assertEqual(data.load_uint(32), 0)
            self.assertEqual(data.load_uint(32), wallet_id)
            self.assertEqual(data.load_uint(16 + 64 * 3), 0)
            authority = data.load_ref().begin_parse()
            self.assertEqual(authority.load_uint(8), 1)
            self.assertEqual(authority.load_int(32), GLOBAL_ID)
            self.assertEqual(authority.load_bytes(32), NAMESPACE)
            self.assertEqual(authority.load_uint(8), 1)
            cell = authority.load_ref()
            key = b""
            while True:
                part = cell.begin_parse()
                key += part.load_bytes(part.remaining_bits // 8)
                if part.remaining_refs == 0:
                    break
                self.assertEqual(part.remaining_refs, 1)
                cell = part.load_ref()
            self.assertEqual(key, self.primary)
            self.assertEqual(authority.load_bytes(32), self.rescue)
            self.assertEqual(authority.load_uint(8), 1)
            self.assertEqual(authority.remaining_bits, 0)
            self.assertEqual(authority.remaining_refs, 0)

    def test_invalid_key_lengths_refuse(self):
        for primary, rescue in [
            (b"", self.rescue),
            (self.primary[:-1], self.rescue),
            (self.primary, self.rescue[:-1]),
        ]:
            with self.assertRaisesRegex(ValueError, "public key lengths"):
                accounts(self.code, primary, rescue)
        with self.assertRaisesRegex(ValueError, "byte length"):
            byte_chain(b"")

    def prefunded_read(self, tag=0):
        record = self.records["prefunded"]
        account = (
            Builder()
            .store_bit(1)
            .store_address(record["address"])
            .store_uint(0, 6)
            .store_uint(0, 3)
            .store_uint(0, 32)
            .store_bit(0)
            .store_uint(0, 64)
            .store_coins(record["balance"])
            .store_bit(0)
            .store_uint(tag, 2)
            .end_cell()
        )
        return {
            "account": {
                "address": record["address"],
                "exists": True,
                "active": False,
                "balance": str(record["balance"]),
                "state_boc": base64.b64encode(account.to_boc()).decode(),
            }
        }

    def test_prefunded_state_must_be_uninitialized_and_bound(self):
        record = self.records["prefunded"]
        self.capture.validate_account(self.prefunded_read(), record, self.code.hash.hex())
        with self.assertRaisesRegex(ValueError, "expected uninitialized"):
            self.capture.validate_account(self.prefunded_read(tag=1), record, self.code.hash.hex())
        for field, bad in [
            ("address", self.records["absent"]["address"]),
            ("balance", "0"),
            ("active", True),
            ("exists", False),
        ]:
            value = self.prefunded_read()
            value["account"][field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.capture.validate_account(value, record, self.code.hash.hex())


if __name__ == "__main__":
    unittest.main()
