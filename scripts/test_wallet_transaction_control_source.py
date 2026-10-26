#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Compile-source provenance regressions for the wallet runtime control runner."""

import importlib.util
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
        self.checkout, self.source, self.build = (
            root / "checkout",
            root / "configured-copy",
            root / "build",
        )
        self.build.mkdir()
        for relative in module.CONTROL_FILES:
            for parent in (self.checkout, self.source):
                path = parent / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(relative.encode())
        (self.build / "CMakeCache.txt").write_text(f"CMAKE_HOME_DIRECTORY:INTERNAL={self.source}\n")

    def test_source_copy_without_git_uses_reviewed_checkout_for_git(self):
        self.assertFalse((self.source / ".git").exists())
        with patch.object(module.subprocess, "run") as run:
            self.assertEqual(module.checked_source(self.build, self.checkout), self.source)
        run.assert_called_once_with(["git", "diff", "--exit-code"], cwd=self.checkout, check=True)

    def test_mismatched_compile_source_is_refused_before_mutation(self):
        path = self.source / module.CONTROL_FILES[0]
        path.write_bytes(b"different unreviewed source")
        with (
            patch.object(module.subprocess, "run"),
            self.assertRaisesRegex(RuntimeError, "differs from checkout"),
        ):
            module.checked_source(self.build, self.checkout)
        self.assertEqual(path.read_bytes(), b"different unreviewed source")

    def test_missing_or_duplicate_configured_source_is_refused(self):
        cache = self.build / "CMakeCache.txt"
        for text in ("", f"CMAKE_HOME_DIRECTORY:INTERNAL={self.source}\n" * 2):
            cache.write_text(text)
            with (
                patch.object(module.subprocess, "run") as run,
                self.assertRaisesRegex(RuntimeError, "one configured"),
            ):
                module.checked_source(self.build, self.checkout)
            run.assert_not_called()

    def test_dirty_checkout_refusal_is_not_ignored(self):
        with (
            patch.object(
                module.subprocess,
                "run",
                side_effect=module.subprocess.CalledProcessError(1, ["git"]),
            ),
            self.assertRaises(module.subprocess.CalledProcessError),
        ):
            module.checked_source(self.build, self.checkout)


if __name__ == "__main__":
    unittest.main()
