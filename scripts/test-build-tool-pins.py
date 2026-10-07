#!/usr/bin/env python3
"""Verify the integrity gate's successful control and tampered-input refusal."""

import hashlib
import importlib.util
import json
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "verify_build_tool", Path(__file__).with_name("verify-build-tool.py")
)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

# Running a fetched installer or trusting a key fetched at build time. The
# pinned replacements are scripts/install-llvm-toolchain.sh (committed key) and
# verify-build-tool.py (committed digests).
UNVERIFIED = [
    (re.compile(r"llvm\.sh"), "apt.llvm.org installer script"),
    (re.compile(r"apt-key\s+add"), "apt-key with a downloaded key"),
    (re.compile(r"\|\s*(sudo\s+)?(ba|z)?sh\b"), "download piped into a shell"),
]
PIP_INSTALL = re.compile(r"\bpip\s+install\s+(.*)$")
# Options whose next word is a value, not a package.
PIP_VALUE_OPTIONS = {"--python", "-r", "--requirement", "-c", "--constraint", "--index-url", "-i"}


def unpinned_pip_packages(arguments: str) -> list[str]:
    words = shlex.split(arguments, comments=True)
    unpinned = []
    skip = False
    for word in words:
        if skip:
            skip = False
            continue
        if word in PIP_VALUE_OPTIONS:
            skip = True
            continue
        if word.startswith("-") or "/" in word or word.startswith("."):
            continue
        if not re.fullmatch(r"[A-Za-z0-9._-]+(\[[A-Za-z0-9,._-]+\])?==[A-Za-z0-9.+!-]+", word):
            unpinned.append(word)
    return unpinned


def workflow_findings(text: str) -> list[str]:
    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for pattern, what in UNVERIFIED:
            if pattern.search(line):
                findings.append(f"{number}: {what}")
        install = PIP_INSTALL.search(line)
        if install:
            for package in unpinned_pip_packages(install.group(1)):
                findings.append(f"{number}: unpinned pip package {package}")
    return findings


class IntegrityTests(unittest.TestCase):
    def test_every_pin_refuses_tampered_tool_before_execution(self):
        pins = json.loads(verifier.PINS.read_text())
        for name in pins:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                tool = Path(d) / "tool"
                tool.write_bytes(b"tampered tool; must never execute")
                with self.assertRaisesRegex(ValueError, "integrity check failed"):
                    verifier.verify(name, tool)

    def test_valid_bytes_and_mutated_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            tool = Path(d) / "tool"
            manifest = Path(d) / "pins.json"
            tool.write_bytes(b"approved tool")
            manifest.write_text(
                json.dumps({"fixture": {"sha256": hashlib.sha256(tool.read_bytes()).hexdigest()}})
            )
            verifier.verify("fixture", tool, manifest)
            tool.write_bytes(b"substituted tool")
            with self.assertRaises(ValueError):
                verifier.verify("fixture", tool, manifest)

    def test_upstream_sha1_is_checked_when_recorded(self):
        with tempfile.TemporaryDirectory() as d:
            tool = Path(d) / "tool"
            manifest = Path(d) / "pins.json"
            tool.write_bytes(b"approved tool")
            pin = {"sha256": hashlib.sha256(tool.read_bytes()).hexdigest()}
            pin["upstream_sha1"] = hashlib.sha1(tool.read_bytes()).hexdigest()
            manifest.write_text(json.dumps({"fixture": pin}))
            verifier.verify("fixture", tool, manifest)
            pin["upstream_sha1"] = "0" * 40
            manifest.write_text(json.dumps({"fixture": pin}))
            with self.assertRaisesRegex(ValueError, "upstream SHA-1"):
                verifier.verify("fixture", tool, manifest)

    def test_scripts_download_the_pinned_url(self):
        pins = json.loads(verifier.PINS.read_text())
        for name, pin in pins.items():
            with self.subTest(name=name):
                self.assertTrue(pin["url"].startswith("https://"))
                self.assertNotIn("/continuous/", pin["url"])
                printed = subprocess.run(
                    [sys.executable, str(ROOT / "scripts/verify-build-tool.py"), "--url", name],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()
                self.assertEqual(printed, pin["url"])
        for script in [
            "assembly/appimage/create-appimages.sh",
            "assembly/android/build-android-toslib.sh",
        ]:
            with self.subTest(script=script):
                text = (ROOT / script).read_text()
                self.assertIn('verify-build-tool.py" --url', text)
                self.assertNotRegex(text, r"https://\S*(appimagetool|android-ndk)")


class WorkflowInstallTests(unittest.TestCase):
    def test_no_workflow_runs_unverified_installers(self):
        findings = {}
        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            found = workflow_findings(workflow.read_text())
            if found:
                findings[workflow.name] = found
        self.assertEqual(findings, {})

    def test_guard_detects_each_unverified_form(self):
        refused = [
            "wget -q https://apt.llvm.org/llvm.sh",
            "wget -qO- https://example.invalid/key | sudo apt-key add -",
            "curl -LsSf https://example.invalid/install.sh | sh",
            "curl -fsSL https://example.invalid/x | sudo bash",
            "python3 -m pip install jsonschema",
            "python3 -m pip install 'jsonschema>=4'",
        ]
        accepted = [
            "sudo scripts/install-llvm-toolchain.sh 21 all",
            "python3 -m pip install jsonschema==4.26.0",
            "uv pip install --python .venv/bin/python -e test/tostester",
            "python -m pip install bitarray==3.7.2 PyNaCl==1.5.0",
            "# wget https://apt.llvm.org/llvm.sh",
        ]
        for line in refused:
            with self.subTest(line=line):
                self.assertTrue(workflow_findings(line))
        for line in accepted:
            with self.subTest(line=line):
                self.assertEqual(workflow_findings(line), [])


if __name__ == "__main__":
    unittest.main()
