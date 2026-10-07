"""Independent TL-B config cells exercise the candidate readback acceptance boundary."""

import importlib.util
import unittest
from pathlib import Path

from pytosiq_core import Builder


class CandidateReadbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).with_name("check-v5r2-candidate-network.py")
        spec = importlib.util.spec_from_file_location("candidate_readback", path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def cells(
        self,
        version=18,
        global_id=1,
        network=0x42,
        credit=20000,
        gas_price=436907,
        flat_price=667,
        freeze_due=100000000,
    ):
        def gas(mc):
            values = (
                [655360000, 1000000, 70000000, 10000, 2500000, 100000000, 1000000000]
                if mc
                else [gas_price, 30000000, 30000000, credit, 60000000, freeze_due, 1000000000]
            )
            b = (
                Builder()
                .store_uint(0xD1, 8)
                .store_uint(100, 64)
                .store_uint(1000000 if mc else flat_price, 64)
                .store_uint(0xDE, 8)
            )
            for value in values:
                b.store_uint(value, 64)
            return b.end_cell()

        return {
            8: Builder().store_uint(0xC4, 8).store_uint(version, 32).store_uint(0, 64).end_cell(),
            19: Builder().store_int(global_id, 32).end_cell(),
            48: Builder()
            .store_uint(0xA1, 8)
            .store_bytes(bytes([network]) * 32)
            .store_uint(0, 64)
            .store_uint(0, 16)
            .store_bit(0)
            .store_bytes(bytes(32))
            .end_cell(),
            20: gas(True),
            21: gas(False),
        }

    def test_exact_candidate_fields_accept(self):
        result = self.module.validate(self.cells())
        self.assertEqual(result["20"]["gas_credit"], 10000)
        self.assertEqual(result["21"]["gas_credit"], 20000)

    def test_wrong_versions_identity_namespace_credit_and_price_refuse(self):
        for kwargs in [
            dict(version=19),
            dict(global_id=3),
            dict(network=0x43),
            dict(credit=10000),
            dict(gas_price=10),
            dict(flat_price=666),
            dict(freeze_due=1),
        ]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.module.validate(self.cells(**kwargs))


if __name__ == "__main__":
    unittest.main()
