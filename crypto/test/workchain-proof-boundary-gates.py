#!/usr/bin/env python3
"""Enforce the reviewed host-side raw-backend call boundary (offline)."""
import argparse
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class Boundary(unittest.TestCase):
    def test_profile_permissions_are_explicit_sets(self):
        source = (ROOT / "crypto/block/workchain-resource-policy.h").read_text()
        for method, expected in {
            "permits_fee_settlement": "resources_.admission_version==3||resources_.admission_version==4",
            "requires_proof_operation_meter": "resources_.admission_version==4",
        }.items():
            matches = re.findall(r"bool " + method + r"\(\) const \{\s*return (.*?);\s*\}", source, re.S)
            self.assertEqual(len(matches), 1, method)
            self.assertEqual(re.sub(r"\s", "", matches[0]), expected, method)

    def test_only_wrapper_names_raw_abi(self):
        hits = []
        for directory in [ROOT / "crypto/block", ROOT / "validator", ROOT / "validator-engine", ROOT / "uno"]:
            for path in sorted(directory.rglob("*")):
                if path.suffix not in {".h", ".hpp", ".cpp", ".cc", ".c", ".rs"}:
                    continue
                relative = path.relative_to(ROOT)
                if "tests" in relative.parts or "target" in relative.parts or relative == Path("uno/crypto/src/tests.rs"):
                    continue
                if re.search(r"\buno_crypto_verify_v2\b", path.read_text()):
                    hits.append(str(path.relative_to(ROOT)))
        self.assertEqual(hits, ["crypto/block/workchain-proof-backend.cpp",
                                "uno/crypto/include/uno_crypto.h", "uno/crypto/src/ffi.rs"])
        source = (ROOT / hits[0]).read_text()
        self.assertEqual(source.count("uno_crypto_verify_v2(&request)"), 1)

    def test_no_test_capability_in_host(self):
        hits = []
        for directory in [ROOT / "crypto/block", ROOT / "validator", ROOT / "validator-engine", ROOT / "uno"]:
            for path in sorted(directory.rglob("*")):
                if path.suffix not in {".h", ".hpp", ".cpp", ".cc"}:
                    continue
                relative = path.relative_to(ROOT)
                if "tests" in relative.parts or "target" in relative.parts:
                    continue
                source = path.read_text()
                self.assertNotIn("workchain-proof-test-access.h", source, str(path))
                if "WorkchainProofTestAccess" in source:
                    hits.append(str(path.relative_to(ROOT)))
        self.assertEqual(hits, ["crypto/block/workchain-proof-work.h"])
        source = (ROOT / hits[0]).read_text()
        self.assertEqual(source.count("WorkchainProofTestAccess"), 1)
        self.assertIn("friend struct WorkchainProofTestAccess;", source)


if __name__ == "__main__":
    unittest.main()
