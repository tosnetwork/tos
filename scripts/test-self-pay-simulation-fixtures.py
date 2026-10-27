#!/usr/bin/env python3
"""Exercise content and source-closure refusals in the simulation input gate."""

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "simulation_inputs", ROOT / "scripts/check-self-pay-simulation-fixtures.py"
)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class SimulationInputGate(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "inputs"
        shutil.copytree(ROOT / "test/pq-native/data/self-pay-simulation", self.directory)
        self.manifest_path = self.directory / "manifest.json"
        self.manifest = json.loads(self.manifest_path.read_text())

    def reject(self, reason):
        self.manifest_path.write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(ValueError, reason):
            CHECKER.check(self.directory)

    def test_current_inputs(self):
        CHECKER.check(self.directory)

    def test_missing_generating_source(self):
        self.manifest["sources"].pop("crypto/smartcont/wallet-quantum-self-pay.fc")
        self.reject("source closure differs")

    def test_missing_assembler_source(self):
        self.manifest["sources"].pop("crypto/fift/lib/Asm.fif")
        self.reject("source closure differs")

    def test_changed_content(self):
        (self.directory / "config.boc").write_bytes(b"damaged")
        self.reject("content differs")

    def test_wrong_code_profile(self):
        self.manifest["code_hash"] = "00" * 32
        self.reject("code profile differs")

    def test_source_outside_repository(self):
        self.manifest["sources"]["../outside"] = "00" * 32
        self.reject("source closure differs")


if __name__ == "__main__":
    unittest.main()
