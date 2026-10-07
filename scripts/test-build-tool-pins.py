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
GITHUB = ROOT / ".github"


def workflow_files() -> list[Path]:
    """Workflows and the composite actions they call."""
    return sorted(
        list((GITHUB / "workflows").glob("*.yml"))
        + list((GITHUB / "workflows").glob("*.yaml"))
        + list((GITHUB / "actions").glob("*/action.yml"))
        + list((GITHUB / "actions").glob("*/action.yaml"))
    )


# Running a fetched installer or trusting a key fetched at build time. The
# pinned replacements are scripts/install-llvm-toolchain.sh (committed key) and
# verify-build-tool.py (committed digests).
UNVERIFIED = [
    (re.compile(r"llvm\.sh"), "apt.llvm.org installer script"),
    (re.compile(r"apt-key\s+add"), "apt-key with a downloaded key"),
    (
        re.compile(
            r"\|\s*(sudo(\s+-\S+)*\s+)?(env(\s+[A-Za-z_][A-Za-z0-9_]*=\S*)*\s+)?(ba|z|da|k)?sh\b"
        ),
        "download piped into a shell",
    ),
    (
        re.compile(r"\|\s*(sudo(\s+-\S+)*\s+)?(python3?|perl|ruby|node)\b"),
        "download piped into an interpreter",
    ),
]
PIP_INSTALL = re.compile(r"\bpip3?\s+install\s+(.*)$")
# Options whose next word (or "=value") is a value, not a package.
PIP_VALUE_OPTIONS = {"--python", "--upgrade-strategy"}
# Options that fetch packages from somewhere other than the default index.
PIP_REFUSED_OPTIONS = {"-i", "--index-url", "--extra-index-url", "-f", "--find-links"}
# Options whose value names something to install; it must be a local path.
PIP_PATH_OPTIONS = {"-e", "--editable", "-r", "--requirement", "-c", "--constraint"}
PINNED_PACKAGE = re.compile(r"[A-Za-z0-9._-]+(\[[A-Za-z0-9,._-]+\])?==[A-Za-z0-9.+!-]+")
REMOTE_PREFIXES = ("git" + "+", "http", "file:")


def is_local_path(word: str) -> bool:
    if "://" in word or "@" in word or word.startswith(REMOTE_PREFIXES):
        return False
    return word.startswith(("./", "../", "/")) or "/" in word


def unpinned_pip_packages(arguments: str) -> list[str]:
    """Install arguments that fetch something not pinned by version or path."""
    words = shlex.split(arguments, comments=True)
    refused = []
    expect = None
    for word in words:
        if expect is not None:
            if expect == "path" and not is_local_path(word):
                refused.append(word)
            expect = None
            continue
        option, has_value, value = word.partition("=")
        # A short option may carry its value attached: -rfile, -e./path.
        if (
            not word.startswith("--")
            and len(word) > 2
            and word[:2] in PIP_PATH_OPTIONS | PIP_VALUE_OPTIONS | PIP_REFUSED_OPTIONS
        ):
            option, has_value, value = word[:2], "=", word[2:]
        if word.startswith("-") and option in PIP_REFUSED_OPTIONS:
            refused.append(word)
            if not has_value:
                expect = "value"
            continue
        if word.startswith("-") and option in PIP_PATH_OPTIONS | PIP_VALUE_OPTIONS:
            kind = "path" if option in PIP_PATH_OPTIONS else "value"
            if not has_value:
                expect = kind
            elif kind == "path" and not is_local_path(value):
                refused.append(value)
            continue
        if word.startswith("-"):
            continue
        if not (is_local_path(word) or PINNED_PACKAGE.fullmatch(word)):
            refused.append(word)
    return refused


UV_WITH = re.compile(r"\buv\s+run\b.*?--with(?:=|\s+)(\S+)")
TOOL_RUNNERS = re.compile(r"\b(?:uv\s+tool\s+(?:install|run)|uvx|pipx\s+(?:install|run))\s+(.*)$")
NPX = re.compile(r"\bnpx\s+(.*)$")
CARGO_INSTALL = re.compile(r"\bcargo\s+install\b(.*)$")
PINNED_TOOL = re.compile(r"[A-Za-z0-9._-]+(==|@)[0-9][A-Za-z0-9.+!-]*")
PINNED_NPM = re.compile(r"(@[a-z0-9._-]+/)?[a-z0-9._-]+@[0-9][A-Za-z0-9.+-]*")


def first_argument(arguments: str) -> str | None:
    for word in shlex.split(arguments, comments=True):
        if not word.startswith("-"):
            return word
    return None


def installer_findings(line: str) -> list[str]:
    """Other package runners must name an exact version."""
    findings = []
    for package in UV_WITH.findall(line):
        if not PINNED_PACKAGE.fullmatch(package):
            findings.append(f"unpinned uv --with package {package}")
    match = TOOL_RUNNERS.search(line)
    if match:
        tool = first_argument(match.group(1))
        if tool is None or not PINNED_TOOL.fullmatch(tool):
            findings.append(f"unpinned tool {tool}")
    match = NPX.search(line)
    if match:
        package = first_argument(match.group(1))
        if package is None or not PINNED_NPM.fullmatch(package):
            findings.append(f"unpinned npx package {package}")
    match = CARGO_INSTALL.search(line)
    if match and not ("--locked" in match.group(1) and "--version" in match.group(1)):
        findings.append("cargo install without --locked --version")
    return findings


def logical_lines(text: str):
    """Lines with backslash continuations joined, numbered by their first line."""
    pending, start = "", None
    for number, line in enumerate(text.splitlines(), 1):
        if start is None:
            start = number
        if line.rstrip().endswith("\\"):
            pending += line.rstrip()[:-1] + " "
            continue
        yield start, pending + line
        pending, start = "", None
    if start is not None:
        yield start, pending


def workflow_findings(text: str) -> list[str]:
    findings = []
    for number, line in logical_lines(text):
        if line.lstrip().startswith("#"):
            continue
        findings.extend(f"{number}: {what}" for what in installer_findings(line))
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
        for workflow in workflow_files():
            found = workflow_findings(workflow.read_text())
            if found:
                findings[str(workflow.relative_to(ROOT))] = found
        self.assertEqual(findings, {})
        self.assertTrue(any(f.name == "action.yml" for f in workflow_files()))

    def test_guard_detects_each_unverified_form(self):
        refused = [
            "wget -q https://apt.llvm.org/llvm.sh",
            "wget -qO- https://example.invalid/key | sudo apt-key add -",
            "curl -LsSf https://example.invalid/install.sh | sh",
            "curl -fsSL https://example.invalid/x | sudo bash",
            "python3 -m pip install jsonschema",
            "python3 -m pip install 'jsonschema>=4'",
            "pip install https://example.invalid/pkg.whl",
            "pip install git+https://example.invalid/repo",
            "pip install 'pkg @ https://example.invalid/pkg.whl'",
            "pip install -e https://example.invalid/repo",
            "pip install --editable=git+https://example.invalid/repo",
            "pip install -r https://example.invalid/requirements.txt",
            "pip install -c https://example.invalid/constraints.txt pkg==1.0",
            "pip install -rhttps://example.invalid/requirements.txt",
            "pip install -egit+https://example.invalid/repo",
            "pip install -chttps://example.invalid/constraints.txt pkg==1.0",
            "curl -fsSL https://example.invalid/x | sudo -E bash",
            "curl -fsSL https://example.invalid/x | env A=1 sh",
            "curl -fsSL https://example.invalid/x | python3",
            "wget -qO- https://example.invalid/x | sudo perl",
            "pip3 install jsonschema",
            "pip install --index-url https://example.invalid/simple pkg==1.0",
            "pip install -ihttps://example.invalid/simple pkg==1.0",
            "pip install --extra-index-url=https://example.invalid/simple pkg==1.0",
            "pip install -f https://example.invalid/wheels pkg==1.0",
            "pip install pkg==1.0 \\\n  other",
            "uv run --with requests python x.py",
            "uv run --with=requests>=2 python x.py",
            "uv tool install ruff",
            "uvx ruff check",
            "pipx run black",
            "npx prettier --check .",
            "npx @scope/tool",
            "cargo install cargo-audit",
            "cargo install --locked cargo-audit",
        ]
        accepted = [
            "sudo scripts/install-llvm-toolchain.sh 21 all",
            "python3 -m pip install jsonschema==4.26.0",
            "uv pip install --python .venv/bin/python -e test/tostester",
            "python -m pip install bitarray==3.7.2 PyNaCl==1.5.0",
            "pip install -q --upgrade -r requirements/ci.txt",
            "pip install ./tools/package",
            "pip install -rrequirements/ci.txt -e./tools/package",
            "python3 -m pip install --require-hashes -r tools/x/requirements-ci.txt",
            "pip install --upgrade-strategy eager pkg==1.0",
            "pip install pkg==1.0 \\\n  other==2.0",
            "uv run --frozen --no-dev python x.py",
            "uv run --with requests==2.32.5 python x.py",
            "uv tool install ruff==0.14.2",
            "uvx ruff@0.14.2 check",
            "npx prettier@3.3.3 --check .",
            "npx @scope/tool@1.2.3",
            "cargo install --locked --version 0.21.1 cargo-audit",
            "curl -fsSL https://example.invalid/x -o x.tar.gz",
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
