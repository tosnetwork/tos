"""Export framing tests use synthetic metadata; native proof acceptance is separate."""

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from pytosiq_core.boc.deserialize import Boc


class ExportTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).with_name("export-v5r2-genesis-proof-fixture.py")
        spec = importlib.util.spec_from_file_location("proof_export", path)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sdk = path.parents[1] / "test/wallet-v5r2/fixtures/public-genesis-accounts.json"
        fixture = json.loads(self.sdk.read_text())
        self.capture = self.root / "capture"
        self.capture.mkdir()
        anchor = {"kind": "zerostate"}
        (self.capture / "anchor.json").write_text(json.dumps(anchor))
        target = {
            "workchain": -1,
            "shard": "8000000000000000",
            "seqno": 1,
            "root_hash": "11" * 32,
            "file_hash": "22" * 32,
        }

        def cell(value):
            return Boc(bytes.fromhex(value)).deserialize()[0]

        for role in ("wallet", "module", "vault"):
            address = "0:" + cell(fixture["output"][role + "_init"]).hash.hex()
            request = json.dumps({"mode": "live", "target": target, "account": address}).encode()
            (self.capture / f"{role}-proof-request.json").write_bytes(request)
            result = {
                "status": "verified",
                "mode": "live",
                "interface": "tos-proof-verify/1",
                "anchor": anchor,
                "request_sha256": hashlib.sha256(request).hexdigest(),
                "target": target,
                "live": {"now": 100},
                "account": {
                    "address": address,
                    "exists": True,
                    "active": True,
                    "code_hash": cell(fixture["input"][role + "_code"]).hash.hex(),
                    "data_hash": cell(fixture["output"][role + "_data"]).hash.hex(),
                },
            }
            (self.capture / f"{role}-proof-result.json").write_text(json.dumps(result))
            material = self.capture / f"{role}-material"
            material.mkdir()
            (material / "account.tl").write_bytes(b"PUBLIC MOCK: NOT CRYPTOGRAPHIC PROOF")

    def test_export_preserves_raw_material_and_refuses_overwrite(self):
        out = self.root / "output"
        self.module.export(self.capture, self.sdk, out)
        manifest = json.loads((out / "manifest.json").read_text())
        self.assertEqual(manifest["controlled_now"], 100)
        self.assertIn("wallet/material/account.tl", manifest["files"])
        with self.assertRaisesRegex(ValueError, "fresh fixture"):
            self.module.export(self.capture, self.sdk, out)

    def test_wrong_request_checkpoint_and_sdk_identity_refuse(self):
        path = self.capture / "wallet-proof-result.json"
        original = json.loads(path.read_text())
        for field in ("request", "checkpoint", "code"):
            value = json.loads(json.dumps(original))
            if field == "request":
                value["request_sha256"] = "00" * 32
            if field == "checkpoint":
                value["target"]["seqno"] = 2
            if field == "code":
                value["account"]["code_hash"] = "00" * 32
            path.write_text(json.dumps(value))
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.module.export(self.capture, self.sdk, self.root / field)
        path.write_text(json.dumps(original))

    def test_unexpected_material_files_refuse(self):
        (self.capture / "wallet-material/private-key.bin").write_bytes(b"PUBLIC TEST PLACEHOLDER")
        with self.assertRaisesRegex(ValueError, "unexpected raw proof"):
            self.module.export(self.capture, self.sdk, self.root / "output")


if __name__ == "__main__":
    unittest.main()
