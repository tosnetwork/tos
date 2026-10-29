#!/usr/bin/env python3
"""Self-test of the security-remediation mutation runner and native test runner.

Checks that a stale or duplicated mutation anchor stops the runner before it
mutates anything, and that a native test that crashes with non-UTF-8 output is
reported as a failure of the test, not as a decode error of the runner.
"""

import contextlib
import functools
import importlib.util
import io
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mutations = load("security_remediation_mutations", "test-security-remediation-mutations.py")
boundaries = load("run_security_boundaries", "run-security-boundaries.py")

# What a crashing native test prints: the crash handler dumps raw stack bytes.
BACKTRACE = (
    b"Running test Test_SecurityBoundaries_X\n    #19  \x10\xba\x81\xbe\xfc\x7f (unknown+0xfff\n"
)
OLD_INTEGRITY_ANCHOR = 'digest.hexdigest() != pin["sha256"]'


def child(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def write_backtrace_code() -> str:
    return f"import sys; sys.stdout.buffer.write({BACKTRACE!r}); sys.stdout.buffer.flush()"


def run_binary(test_args: list[str]) -> tuple[bytes, str, object]:
    """Run run_test_binary and return (stdout bytes, stderr text, exit code or None)."""
    stdout = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    stderr = io.StringIO()
    code = None
    with mock.patch.object(sys, "stdout", stdout), mock.patch.object(sys, "stderr", stderr):
        try:
            boundaries.run_test_binary(test_args, ROOT)
        except SystemExit as exit_:
            code = exit_.code
    stdout.flush()
    raw = stdout.buffer
    assert isinstance(raw, io.BytesIO)
    return raw.getvalue(), stderr.getvalue(), code


class AnchorCheck(unittest.TestCase):
    @functools.cached_property
    def root(self) -> Path:
        """A fresh tree per test, removed when the test ends."""
        tmp = tempfile.TemporaryDirectory(prefix="mutation-anchors-")
        self.addCleanup(tmp.cleanup)
        return Path(tmp.name)

    def put(self, relative: str, text: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode())
        return path

    def copy_real(self, relative: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, path)
        return path

    def test_real_table_applies(self):
        self.assertEqual(mutations.anchor_problems(ROOT), [])

    def test_stale_anchor_is_reported(self):
        self.put(
            "scripts/verify-build-tool.py",
            f"    if {OLD_INTEGRITY_ANCHOR}:\n        raise ValueError\n",
        )
        problems = mutations.anchor_problems(
            self.root, {"integrity": mutations.CASES["integrity"]}, []
        )
        self.assertEqual(
            problems,
            ["integrity: scripts/verify-build-tool.py: anchor found 0 times, expected 1"],
        )

    def test_extra_copy_is_reported(self):
        path, before, _after, _command = mutations.CASES["dispatch"]
        self.put(path, f"if ({before}) {{}}\n// {before}\n")
        problems = mutations.anchor_problems(
            self.root, {"dispatch": mutations.CASES["dispatch"]}, []
        )
        self.assertEqual(problems, [f"dispatch: {path}: anchor found 2 times, expected 1"])

    def test_pinned_double_count_is_enforced(self):
        path, before, _after, _command = mutations.CASES["http"]
        self.put(path, f"{before}\n")
        problems = mutations.anchor_problems(self.root, {"http": mutations.CASES["http"]}, [])
        self.assertEqual(problems, [f"http: {path}: anchor found 1 times, expected 2"])

    def test_missing_file_and_noop_edit_are_reported(self):
        cases = {
            "gone": ("missing.txt", "x", "y", []),
            "noop": ("missing.txt", "x", "x", []),
        }
        self.assertEqual(
            mutations.anchor_problems(self.root, cases, []),
            [
                "gone: missing.txt: file is missing",
                "noop: missing.txt: mutation leaves the anchor unchanged",
            ],
        )

    def test_connect_anchors_are_checked(self):
        bridge_path = mutations.CONNECT_EDITS[0][0]
        for path, _before, _after in mutations.CONNECT_EDITS:
            self.copy_real(path)
        self.assertEqual(mutations.anchor_problems(self.root, {}), [])
        bridge = self.root / bridge_path
        bridge.write_bytes(
            bridge.read_bytes().replace(b"!this.walletPublicKey ||", b"!this.key ||")
        )
        self.assertEqual(
            mutations.anchor_problems(self.root, {}),
            [f"connect: {bridge_path}: anchor found 0 times, expected 1"],
        )

    def test_every_problem_is_reported(self):
        cases = {name: mutations.CASES[name] for name in ("integrity", "dispatch")}
        problems = mutations.anchor_problems(self.root, cases)
        self.assertEqual(len(problems), 4, problems)
        self.assertEqual(
            [p.split(":")[0] for p in problems], ["integrity", "dispatch"] + ["connect"] * 2
        )

    def test_cli_refuses_before_mutating(self):
        runner = "scripts/test-security-remediation-mutations.py"
        self.copy_real(runner)
        paths = sorted({path for _name, path, *_rest in mutations.anchor_table()})
        for path in paths:
            self.copy_real(path)
        stale = self.root / "scripts/verify-build-tool.py"
        stale.write_bytes(
            stale.read_bytes().replace(b"sha256.hexdigest() != pin", b"digest.hexdigest() != pin")
        )
        before = {path: (self.root / path).read_bytes() for path in paths}
        logs = self.root / "logs"
        for args in (["--check-anchors"], ["integrity", "--logs", str(logs)]):
            result = subprocess.run(
                [sys.executable, str(self.root / runner), *args],
                cwd=self.root,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn(
                "integrity: scripts/verify-build-tool.py: anchor found 0 times, expected 1",
                result.stderr,
            )
            self.assertNotIn("MUTATION_ANCHORS_OK", result.stdout)
        self.assertEqual({path: (self.root / path).read_bytes() for path in paths}, before)
        self.assertFalse(logs.exists())


class NativeRunner(unittest.TestCase):
    def test_non_utf8_failure_is_reported(self):
        out, err, code = run_binary(child(write_backtrace_code() + "; sys.exit(1)"))
        self.assertEqual(code, 1)
        self.assertEqual(out, BACKTRACE)
        self.assertEqual(err, "native test exited with status 1\n")

    def test_abort_reports_signal(self):
        code_text = (
            "import os, resource; resource.setrlimit(resource.RLIMIT_CORE, (0, 0)); "
            + write_backtrace_code()
            + "; os.abort()"
        )
        out, err, code = run_binary(child(code_text))
        self.assertEqual(code, 134)
        self.assertEqual(out, BACKTRACE)
        self.assertEqual(err, "native test killed by signal SIGABRT (6)\n")

    def test_green_requires_executed_tests(self):
        out, err, code = run_binary(child("print('1 test(s) passed')"))
        self.assertIsNone(code)
        self.assertEqual(out, b"1 test(s) passed\n")
        self.assertEqual(err, "")
        _out, _err, code = run_binary(child("print('0 test(s) passed')"))
        self.assertEqual(code, "native filter executed no tests")


class MutationEndToEnd(unittest.TestCase):
    def test_mutation_red_green_with_non_utf8_log(self):
        code = (
            "import sys\n"
            "if 'GUARD' in open('target.txt').read():\n"
            "    print('1 test(s) passed')\n"
            "    sys.exit(0)\n"
            f"sys.stdout.buffer.write({BACKTRACE!r})\n"
            "sys.exit(1)\n"
        )
        with tempfile.TemporaryDirectory(prefix="mutation-e2e-") as tmp:
            root = Path(tmp)
            target = root / "target.txt"
            target.write_bytes(b"GUARD\n")
            logs = root / "logs"
            logs.mkdir()
            printed = io.StringIO()
            with mock.patch.object(mutations, "ROOT", root), contextlib.redirect_stdout(printed):
                mutations.mutation(
                    "X", "target.txt", "GUARD", "", child(code) + ["--filter", "X"], logs
                )
            self.assertEqual(printed.getvalue(), "X: red exit 1\nX: green exit 0\n")
            self.assertEqual(target.read_bytes(), b"GUARD\n")
            self.assertEqual((logs / "X-red.log").read_bytes(), BACKTRACE)


if __name__ == "__main__":
    unittest.main()
