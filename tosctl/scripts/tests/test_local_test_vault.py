"""Tests for the no-network, ephemeral SecretsVault test harness."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "local_test_vault.py"


class LocalTestVaultTests(unittest.TestCase):
    def _child(self, directory: Path) -> Path:
        child = directory / "child.py"
        child.write_text(
            "import json, os, pathlib\n"
            "from urllib.parse import urlparse\n"
            "vault_path = pathlib.Path(urlparse(os.environ['VAULT_URL']).path)\n"
            "vault_path.write_text('ciphertext', encoding='utf-8')\n"
            "pathlib.Path(os.environ['CAPTURE']).write_text(json.dumps({\n"
            " 'vault': os.environ.get('VAULT_URL'),\n"
            " 'openfox': os.environ.get('OPENFOX_TOS_VAULT_URL'),\n"
            " 'persistent': os.environ.get('PERSISTENT_TEST_VAULT'),\n"
            "}))\n",
            encoding="utf-8",
        )
        child.chmod(0o700)
        return child

    def test_injects_fresh_capability_and_removes_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = root / "capture.json"
            child = self._child(root)
            environment = dict(os.environ)
            environment.update({
                "CAPTURE": str(capture),
                "VAULT_URL": "file:///persistent?vault=must-not-survive",
                "PERSISTENT_TEST_VAULT": "kept-for-control",
            })
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--directory", str(root),
                 "--also-export", "OPENFOX_TOS_VAULT_URL", "--", sys.executable, str(child)],
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            recorded = json.loads(capture.read_text(encoding="utf-8"))
            self.assertEqual(recorded["vault"], recorded["openfox"])
            self.assertTrue(recorded["vault"].startswith("file://"))
            self.assertNotIn("persistent", recorded["vault"])
            self.assertEqual(recorded["persistent"], "kept-for-control")
            self.assertEqual(list(root.glob("tosctl-test-vault-*")), [])

    def test_kept_vault_is_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child = self._child(root)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--directory", str(root), "--keep", "--",
                 sys.executable, str(child)],
                env={**os.environ, "CAPTURE": str(root / "capture.json")},
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            vault_directories = list(root.glob("tosctl-test-vault-*"))
            self.assertEqual(len(vault_directories), 1)
            mode = stat.S_IMODE(vault_directories[0].stat().st_mode)
            self.assertEqual(mode & 0o077, 0)
            vault_mode = stat.S_IMODE((vault_directories[0] / "vault.json").stat().st_mode)
            self.assertEqual(vault_mode & 0o077, 0)
            self.assertIn(str(vault_directories[0]), result.stderr)

    def test_rejects_invalid_environment_name_before_running_child(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--also-export", "BAD-NAME", "--", sys.executable, "-c", "raise SystemExit(99)"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("environment variable name is invalid", result.stderr)

    def test_rejects_another_principals_writable_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            # A non-sticky group/other-writable base lets another principal
            # replace the child path, so the harness must fail before launch.
            root.chmod(0o777)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--directory", str(root), "--",
                 sys.executable, "-c", "raise SystemExit(99)"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("writable by another principal", result.stderr)


if __name__ == "__main__":
    unittest.main()
