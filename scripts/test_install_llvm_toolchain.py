#!/usr/bin/env python3
"""The committed LLVM apt signing key is the pinned one, and any other key is refused."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "install-llvm-toolchain.sh"
KEY = HERE / "keys" / "apt-llvm-org.asc"


def check_key(path: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT), "--check-key", str(path)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


class InstallLlvmToolchainKeyTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="llvm-key-")
        self.root = Path(self._tmp.name)
        self.env = dict(os.environ, GNUPGHOME=str(self.root / "gnupg"))
        (self.root / "gnupg").mkdir(mode=0o700)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def other_key(self) -> Path:
        subprocess.run(
            [
                "gpg",
                "--batch",
                "--passphrase",
                "",
                "--quick-gen-key",
                "throwaway <t@example.invalid>",
                "ed25519",
                "sign",
                "1d",
            ],
            env=self.env,
            capture_output=True,
            check=True,
        )
        exported = subprocess.run(
            ["gpg", "--armor", "--export"], env=self.env, capture_output=True, check=True
        )
        path = self.root / "other.asc"
        path.write_bytes(exported.stdout)
        return path

    def test_committed_key_has_the_pinned_fingerprint(self) -> None:
        result = check_key(KEY, self.env)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_another_key_is_refused(self) -> None:
        result = check_key(self.other_key(), self.env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected 6084F3CF814B57C1CF12EFD515CF4D18AF4F7421", result.stderr)

    def test_extra_key_beside_the_pinned_one_is_refused(self) -> None:
        both = self.root / "both.asc"
        both.write_bytes(KEY.read_bytes() + self.other_key().read_bytes())
        result = check_key(both, self.env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected 6084F3CF814B57C1CF12EFD515CF4D18AF4F7421", result.stderr)

    def test_missing_key_is_refused(self) -> None:
        result = check_key(self.root / "absent.asc", self.env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is missing", result.stderr)


if __name__ == "__main__":
    unittest.main()
