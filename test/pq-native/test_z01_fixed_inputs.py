"""Commitment and explicit Genesis input controls; no nodes or Fift execution."""

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "test/tostester/src"))
from scripts.z01_fixed_inputs import load, SCHEMA


class CustodyInputs(unittest.TestCase):
    def make_inputs(self, directory):
        def entry(index):
            path = directory / f"seed-{index}"
            raw = bytes([index]) * 32
            path.write_bytes(raw)
            path.chmod(0o600)
            return {"path": path.name, "sha256": hashlib.sha256(raw).hexdigest()}
        manifest = {"schema": SCHEMA, "scope": "development-fixed",
                    "genesis_time": 1790395200, "wallet_seed": entry(1),
                    "validators": [{"validator_id": f"{index + 1:064x}",
                                    "adnl_seed": entry(2 + index * 2),
                                    "pq_seed": entry(3 + index * 2)} for index in range(4)]}
        path = directory / "inputs.json"
        path.write_text(json.dumps(manifest))
        return path, hashlib.sha256(path.read_bytes()).hexdigest(), manifest

    def test_public_receipt_excludes_private_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            path, digest, _ = self.make_inputs(Path(temp))
            public, private = load(path, digest)
            self.assertEqual(private["wallet_seed"], bytes([1]) * 32)
            self.assertEqual(public["genesis_time"], 1790395200)
            self.assertFalse(public["final_signed_genesis"])
            self.assertNotIn("wallet_seed", public)
            self.assertNotIn("adnl_seed", public["validators"][0])
            self.assertEqual(len(public["validators"]), 4)

    def test_single_byte_custody_tamper_refused_at_commitment(self):
        with tempfile.TemporaryDirectory() as temp:
            path, digest, _ = self.make_inputs(Path(temp))
            (Path(temp) / "seed-3").write_bytes(bytes([17]) * 32)
            with self.assertRaisesRegex(ValueError, "differs from commitment: validator0.pq"):
                load(path, digest)

    def test_group_readable_custody_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            path, digest, _ = self.make_inputs(Path(temp))
            (Path(temp) / "seed-2").chmod(0o640)
            with self.assertRaisesRegex(ValueError, "owner-only0600: validator0.adnl"):
                load(path, digest)

    def test_cross_role_seed_reuse_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            path, _, manifest = self.make_inputs(Path(temp))
            manifest["validators"][1]["pq_seed"] = manifest["validators"][0]["adnl_seed"]
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "ADNL and PQ custody roles"):
                load(path, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_final_label_cannot_replace_signature(self):
        with tempfile.TemporaryDirectory() as temp:
            path, _, manifest = self.make_inputs(Path(temp))
            manifest["scope"] = "final"
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "cannot claim final signed Genesis"):
                load(path, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_manifest_tamper_refused_before_custody(self):
        with tempfile.TemporaryDirectory() as temp:
            path, digest, manifest = self.make_inputs(Path(temp))
            manifest["genesis_time"] += 1
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "differs from committed SHA-256"):
                load(path, digest)


class FixedGenerator(unittest.TestCase):
    def test_epoch_and_wallet_are_consumed_before_fift(self):
        from tostester.zerostate import NetworkConfig, create_zerostate
        from tostester.key import Key
        from nacl.signing import SigningKey
        seed = bytes([19]) * 32
        config = NetworkConfig(validator_economics_profile=True,
                               genesis_time=1790395200, genesis_wallet_seed=seed)
        keys = [Key(SigningKey(bytes([index + 20]) * 32)) for index in range(4)]
        captured = {}

        def stop_at_fift(install, code, directory, **kwargs):
            captured.update(code=code, kwargs=kwargs)
            self.assertEqual((directory / "main-wallet.pk").read_bytes(), seed)
            self.assertEqual((directory / "main-wallet.pk").stat().st_mode & 0o777, 0o600)
            raise RuntimeError("fixed-input-boundary")

        with tempfile.TemporaryDirectory() as temp, patch("tostester.zerostate.run_fift", stop_at_fift):
            with self.assertRaisesRegex(RuntimeError, "fixed-input-boundary"):
                create_zerostate(None, Path(temp), config, keys)
        self.assertIn("basestate0_fhash 1790395200", captured["code"])
        self.assertIn("1790395200 dup 131072 + 4 config.validators!", captured["code"])
        self.assertEqual(captured["kwargs"]["env"]["SOURCE_DATE_EPOCH"], "1790395200")
        self.assertTrue(captured["kwargs"]["retain_script"])

    def test_incomplete_or_out_of_range_freeze_refused_before_fift(self):
        from tostester.zerostate import NetworkConfig, create_zerostate
        cases = [(NetworkConfig(genesis_time=1790395200), "both time and wallet"),
                 (NetworkConfig(genesis_time=1 << 32, genesis_wallet_seed=bytes(32)), "fit uint32"),
                 (NetworkConfig(genesis_time=True, genesis_wallet_seed=bytes(32)), "fit uint32")]
        with tempfile.TemporaryDirectory() as temp, patch("tostester.zerostate.run_fift") as fift:
            for config, message in cases:
                with self.assertRaisesRegex(ValueError, message):
                    create_zerostate(None, Path(temp), config, [])
            fift.assert_not_called()


if __name__ == "__main__":
    unittest.main()
