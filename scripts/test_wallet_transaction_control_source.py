#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Real Git ownership/dirty-source regressions for wallet runtime controls."""

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "wallet_controls", Path(__file__).with_name("test-wallet-transaction-controls.py")
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ControlSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name).resolve()
        self.checkout, self.build = root / "checkout", root / "build"
        self.checkout.mkdir()
        self.build.mkdir()
        subprocess.run(["git", "init", "--quiet", str(self.checkout)], check=True)
        (self.build / "CMakeCache.txt").write_text(
            f"CMAKE_HOME_DIRECTORY:INTERNAL={self.checkout}\n"
        )

    def test_real_ownership_refusal_is_red_before_command_scoped_fix(self):
        with patch.dict(
            os.environ,
            {
                "GIT_TEST_ASSUME_DIFFERENT_OWNER": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
            },
        ):

            def old_check():
                return subprocess.run(
                    ["git", "diff", "--exit-code"],
                    cwd=self.checkout,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

            before = old_check()
            self.assertEqual(before.returncode, 129)
            self.assertIn("Not a git repository", before.stderr)
            self.assertEqual(module.checked_source(self.build, self.checkout), self.checkout)
            after = old_check()
            self.assertEqual(after.returncode, 129, "Safe-directory exception must not persist")
            self.assertIn("Not a git repository", after.stderr)

    def test_different_compile_source_is_refused_before_any_git_or_write(self):
        copy = self.checkout.parent / "unreviewed-copy"
        copy.mkdir()
        (self.build / "CMakeCache.txt").write_text(f"CMAKE_HOME_DIRECTORY:INTERNAL={copy}\n")
        with (
            patch.object(module.subprocess, "run") as run,
            self.assertRaisesRegex(RuntimeError, "invoked checkout"),
        ):
            module.checked_source(self.build, self.checkout)
        run.assert_not_called()
        self.assertFalse((copy / ".git").exists())

    def test_missing_or_duplicate_configured_source_is_refused(self):
        cache = self.build / "CMakeCache.txt"
        for text in ("", f"CMAKE_HOME_DIRECTORY:INTERNAL={self.checkout}\n" * 2):
            cache.write_text(text)
            with (
                patch.object(module.subprocess, "run") as run,
                self.assertRaisesRegex(RuntimeError, "one configured"),
            ):
                module.checked_source(self.build, self.checkout)
            run.assert_not_called()

    def stage(self):
        path = self.checkout / "tracked.txt"
        path.write_text("original public test text\n")
        subprocess.run(["git", "-C", str(self.checkout), "add", "tracked.txt"], check=True)
        return path

    def test_real_staged_change_is_not_treated_as_clean(self):
        self.stage()
        with self.assertRaises(module.subprocess.CalledProcessError) as failure:
            module.checked_source(self.build, self.checkout)
        self.assertEqual(failure.exception.returncode, 1)
        self.assertIn("--cached", failure.exception.cmd)

    def test_real_unstaged_change_is_not_treated_as_clean(self):
        self.stage().write_text("different public test text\n")
        with self.assertRaises(module.subprocess.CalledProcessError) as failure:
            module.checked_source(self.build, self.checkout)
        self.assertEqual(failure.exception.returncode, 1)
        self.assertNotIn("--cached", failure.exception.cmd)


if __name__ == "__main__":
    unittest.main()
