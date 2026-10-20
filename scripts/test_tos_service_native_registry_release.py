#!/usr/bin/env python3
"""The deployment entry points pin the registry hash the release manifest pins.

Positive control: the committed frozen BOC's root cell hash equals the manifest's
code hash, and the shared check accepts it. Negative control: a manifest pinning
another hash is refused, and so is an artifact whose hash differs. Static
control: the Gate C deploy script and the scripts that import its constant carry
no hash literal of their own, so a re-freeze cannot leave one of them stale.

Runs with the standard library only: python3 scripts/test_tos_service_native_registry_release.py
"""

from __future__ import annotations

import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = load(
    "tos_service_native_registry_release", "scripts/tos_service_native_registry_release.py"
)
# The removed-escrow guard carries a standard-library BOC parser; its root hash is the
# TVM representation hash the manifest records.
guard = load("check_no_legacy_escrow", "scripts/check-no-legacy-escrow.py")

HASH_LITERAL = re.compile(r'"[0-9a-f]{64}"')
GATE = ROOT / "scripts/tos-service-native-registry-local-gate-c.py"
IMPORTERS = (
    ROOT / "scripts/tos-service-agentpacket-buyer-deploy.py",
    ROOT / "scripts/tos-service-paid-demand-native-fixture.py",
    ROOT / "scripts/tos-service-software-work-capability-deploy.py",
)


class ReleasedHash(unittest.TestCase):
    def test_the_frozen_artifact_carries_the_released_code_hash(self):
        expected = release.release_code_hash()
        actual = guard.boc_root_hash(release.frozen_code_bytes()).hex()
        self.assertEqual(actual, expected)
        release.require_code_hash(actual, expected)
        release.require_code_hash(actual.upper(), expected)

    def test_another_artifact_is_refused(self):
        expected = release.release_code_hash()
        with self.assertRaisesRegex(RuntimeError, "frozen code hash mismatch"):
            release.require_code_hash("00" * 32, expected)

    def test_a_manifest_pinning_another_hash_refuses_the_frozen_artifact(self):
        manifest = json.loads(release.RELEASE_MANIFEST.read_text())
        manifest["code_hash"] = release.CODE_HASH_PREFIX + "11" * 32
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release.json"
            path.write_text(json.dumps(manifest))
            pinned = release.release_code_hash(path)
        actual = guard.boc_root_hash(release.frozen_code_bytes()).hex()
        with self.assertRaises(RuntimeError):
            release.require_code_hash(actual, pinned)

    def test_a_malformed_manifest_is_refused(self):
        for value in ("c7958fb6", "sha256:" + "22" * 32, 7, None):
            manifest = json.loads(release.RELEASE_MANIFEST.read_text())
            manifest["code_hash"] = value
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "release.json"
                path.write_text(json.dumps(manifest))
                with self.subTest(value=value), self.assertRaises(RuntimeError):
                    release.release_code_hash(path)


class DeploymentEntryPoints(unittest.TestCase):
    def test_the_gate_derives_its_hash_from_the_manifest(self):
        source = GATE.read_text()
        self.assertIn("CODE_HASH = release_code_hash()", source)
        self.assertIn("require_code_hash(code.hash.hex(), CODE_HASH)", source)
        self.assertIsNone(HASH_LITERAL.search(source), "the gate carries a hash literal")

    def test_the_importers_check_against_the_gate_constant_and_carry_no_literal(self):
        for script in IMPORTERS:
            with self.subTest(script=script.name):
                source = script.read_text()
                self.assertIn("gate.CODE_HASH", source)
                self.assertIsNone(
                    HASH_LITERAL.search(source), f"{script.name} carries a hash literal"
                )


if __name__ == "__main__":
    unittest.main()
