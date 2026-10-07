#!/usr/bin/env python3
"""E2E harnesses keep tosctl's configuration and vault in a private directory.

tosctl refuses to write its configuration or vault where another user could
replace them, which includes any group-writable ancestor directory. Under a
umask of 002 a checkout is group-writable, so the harnesses must not place
these files under it. This test checks, under umask 002, where every harness
puts them, and - when a tosctl binary is available (TOSCTL, or the default
debug build) - that the real writer accepts the private directory and refuses
a group-writable checkout with an actionable message.

The harnesses import the generated TL bindings; run
`uv run test/tostester/generate_tl.py` first.
"""

import importlib.util
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import e2e_private_dir  # noqa: E402

HARNESSES = [
    "agent-query-api-e2e",
    "capability-registry-e2e",
    "agent-task-escrow-e2e",
    "agent-chain-index-e2e",
    "agent-wallet-account-e2e",
    "agent-economy-composed-e2e",
    "dispute-e2e",
    "proof-attestation-e2e",
    "service-actor-e2e",
]
# Harnesses that create their private directory without use_private_dir().
DIRECT_USERS = ["pq-config-wallet-first-stake-e2e"]
SHELL_HARNESSES = ["tosctl/scripts/e2e-test.sh", "tosctl/scripts/e2e-account-permission.sh"]
CONFIG_NAMES = ("CONFIG", "CONFIG_A", "CONFIG_B")
TOSCTL = Path(os.environ.get("TOSCTL", ROOT / "tosctl/src/target/debug/tosctl"))


def load(name: str):
    spec = importlib.util.spec_from_file_location(
        name.replace("-", "_"), ROOT / f"scripts/{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def config_paths(module) -> list[Path]:
    paths = [
        getattr(module, name) for name in CONFIG_NAMES if getattr(module, name, None) is not None
    ]
    return paths + list(getattr(module, "OBSERVER_CONFIGS", ()))


class PrivateDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.old_umask = os.umask(0o002)
        self.scratch = Path(tempfile.mkdtemp(prefix="tos-private-dir-test-"))
        self.old_parent = os.environ.pop(e2e_private_dir.PARENT_ENV, None)

    def tearDown(self):
        os.umask(self.old_umask)
        if self.old_parent is not None:
            os.environ[e2e_private_dir.PARENT_ENV] = self.old_parent
        else:
            os.environ.pop(e2e_private_dir.PARENT_ENV, None)
        subprocess.run(["rm", "-rf", str(self.scratch)], check=True)

    def test_every_harness_uses_a_fresh_private_directory(self):
        # A parent another user cannot modify; under umask 002 a plain
        # mkdir would be group-writable and tosctl would refuse it.
        parent = self.scratch / "parent"
        parent.mkdir(mode=0o700)
        os.environ[e2e_private_dir.PARENT_ENV] = str(parent)
        for name in HARNESSES:
            with self.subTest(harness=name):
                module = load(name)
                self.assertIsNone(module.PRIVATE_DIR, "nothing is created at import time")
                first = module.use_private_dir()
                self.assertEqual(first.parent, parent)
                self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o700)
                paths = config_paths(module)
                self.assertTrue(paths, "the harness has configuration paths")
                for path in paths:
                    self.assertEqual(path.parent, first)
                    # The service keeps its index database next to the config.
                    self.assertEqual(path.with_name("tosctl-indexer.db").parent, first)
                second = module.use_private_dir()
                self.assertNotEqual(first, second)
                self.assertTrue(first.is_dir() and parent.is_dir(), "nothing supplied is removed")

    def test_default_directory_is_outside_the_checkout(self):
        module = load(HARNESSES[0])
        private = module.use_private_dir()
        try:
            self.assertFalse(private.is_relative_to(ROOT))
            self.assertEqual(private.parent, Path(tempfile.gettempdir()))
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
        finally:
            private.rmdir()

    def test_harness_sources_build_vault_urls_from_the_private_directory(self):
        for name in HARNESSES + DIRECT_USERS:
            with self.subTest(harness=name):
                source = (ROOT / f"scripts/{name}.py").read_text()
                for url in re.findall(r'f"file://\{([^}]*)\}', source):
                    self.assertTrue(
                        url in {"PRIVATE_DIR", "vault", "config.parent", "CONFIG_B.parent"},
                        f"vault URL built from {url}",
                    )
                self.assertNotRegex(source, r"WORKDIR / \S*(config|vault|observer)")
                self.assertIn("make_private_dir(", source)

    def test_shell_harnesses_use_a_temporary_directory(self):
        for script in SHELL_HARNESSES:
            with self.subTest(script=script):
                source = (ROOT / script).read_text()
                self.assertIn('TESTDATA_DIR="$(mktemp -d ', source)
                self.assertNotIn('TESTDATA_DIR="$SCRIPT_DIR/testdata"', source)
                subprocess.run(["bash", "-n", str(ROOT / script)], check=True)

    @unittest.skipUnless(TOSCTL.is_file(), f"no tosctl binary at {TOSCTL}")
    def test_real_writer_accepts_private_and_refuses_group_writable(self):
        # A parent another user cannot modify; under umask 002 a plain
        # mkdir would be group-writable and tosctl would refuse it.
        parent = self.scratch / "parent"
        parent.mkdir(mode=0o700)
        os.environ[e2e_private_dir.PARENT_ENV] = str(parent)
        module = load(HARNESSES[0])
        module.use_private_dir()
        generate = [str(TOSCTL), "config", "generate", "-o", str(module.CONFIG), "--force"]
        subprocess.run(generate, check=True, capture_output=True)
        self.assertEqual(stat.S_IMODE(module.CONFIG.stat().st_mode), 0o600)

        checkout = self.scratch / "checkout"
        (checkout / "test/integration").mkdir(parents=True)
        for directory in (checkout, checkout / "test", checkout / "test/integration"):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o775)
        target = checkout / "test/integration/tosctl-e2e-config.json"
        refused = subprocess.run(
            [str(TOSCTL), "config", "generate", "-o", str(target), "--force"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("chmod go-w", refused.stdout + refused.stderr)
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
