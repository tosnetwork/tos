#!/usr/bin/env python3
"""Verify the integrity gate's successful control and tampered-input refusal."""
import importlib.util
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("verify_build_tool", Path(__file__).with_name("verify-build-tool.py"))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

class IntegrityTests(unittest.TestCase):
    def test_every_pin_refuses_tampered_tool_before_execution(self):
        pins = json.loads(verifier.PINS.read_text())
        for name in pins:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                tool = Path(d)/"tool"
                tool.write_bytes(b"tampered tool; must never execute")
                with self.assertRaisesRegex(ValueError, "integrity check failed"):
                    verifier.verify(name, tool)

    def test_valid_bytes_and_mutated_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            tool = Path(d)/"tool"
            manifest = Path(d)/"pins.json"
            tool.write_bytes(b"approved tool")
            manifest.write_text(json.dumps({"fixture":{"sha256":hashlib.sha256(tool.read_bytes()).hexdigest()}}))
            verifier.verify("fixture", tool, manifest)
            tool.write_bytes(b"substituted tool")
            with self.assertRaises(ValueError):
                verifier.verify("fixture", tool, manifest)

if __name__ == "__main__": unittest.main()
