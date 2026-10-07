"""Independent TL-B config cells exercise the candidate readback acceptance boundary."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pytosiq_core import Builder
from pytosiq_core.boc.deserialize import Boc


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

    def test_installed_account_proof_binds_all_roles_and_checkpoint(self):
        fixture = json.loads(
            (
                Path(__file__).parents[1] / "test/wallet-v5r2/fixtures/public-genesis-accounts.json"
            ).read_text()
        )
        point = {
            "workchain": -1,
            "shard": "8000000000000000",
            "seqno": 1,
            "root_hash": "11" * 32,
            "file_hash": "22" * 32,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def invoke(corruption=None):
                def run(command, **kwargs):
                    name = Path(command[command.index("--request") + 1]).name.split("-proof-")[0]

                    def cell(field):
                        return Boc(bytes.fromhex(field)).deserialize()[0]

                    account = {
                        "address": "0:" + cell(fixture["output"][name + "_init"]).hash.hex(),
                        "exists": True,
                        "active": True,
                        "balance": "100",
                        "gen_utime": 100,
                        "code_hash": cell(fixture["input"][name + "_code"]).hash.hex(),
                        "data_hash": cell(fixture["output"][name + "_data"]).hash.hex(),
                    }
                    target = dict(point)
                    if corruption == "code":
                        account["code_hash"] = "00" * 32
                    if corruption == "inactive":
                        account["active"] = False
                    if corruption == "checkpoint":
                        target["seqno"] = 2
                    value = {
                        "status": "verified",
                        "interface": "tos-proof-verify/1",
                        "mode": "live",
                        "target": target,
                        "account": account,
                    }
                    return SimpleNamespace(
                        returncode=0, stdout=json.dumps(value).encode(), stderr=b""
                    )

                with patch.object(self.module.subprocess, "run", side_effect=run):
                    return self.module.verify_installed_accounts(
                        root, root, root, root, fixture, point
                    )

            self.assertEqual(set(invoke()), {"wallet", "module", "vault"})
            for corruption in ("code", "inactive", "checkpoint"):
                with self.subTest(corruption=corruption), self.assertRaises(ValueError):
                    invoke(corruption)

    def test_live_proof_result_must_match_readback(self):
        cells = self.cells()
        result = {
            "status": "verified",
            "mode": "live",
            "interface": "tos-proof-verify/1",
            "config_params": [{"index": k, "cell_hash": v.hash.hex()} for k, v in cells.items()],
            "account": {"address": self.module.ABSENT_ACCOUNT, "exists": False},
            "target": {"seqno": 1},
            "chain": {"links": 1},
            "live": {"age_seconds": 1},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def invoke(value, code=0):
                with (
                    patch.object(self.module.subprocess, "check_output", return_value=b"{}"),
                    patch.object(
                        self.module.subprocess,
                        "run",
                        return_value=SimpleNamespace(
                            stdout=json.dumps(value).encode(), stderr=b"", returncode=code
                        ),
                    ),
                ):
                    return self.module.verify_live_config(root, root, root, root, cells)

            self.assertEqual(invoke(result)["target"], {"seqno": 1})
            altered = json.loads(json.dumps(result))
            altered["config_params"][0]["cell_hash"] = "00" * 32
            with self.assertRaisesRegex(ValueError, "differs from RPC"):
                invoke(altered)
            with self.assertRaisesRegex(ValueError, "proof refused"):
                invoke(result, 1)
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                invoke(dict(result, mode="historical"))
            for account in [
                {"address": "0:" + "00" * 32, "exists": False},
                {"address": self.module.ABSENT_ACCOUNT, "exists": True},
                {},
            ]:
                with self.assertRaisesRegex(ValueError, "basechain absence proof"):
                    invoke(dict(result, account=account))


if __name__ == "__main__":
    unittest.main()
