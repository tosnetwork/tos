"""Fail-closed localnet entry point tests; no native chain provider is substituted."""

import dataclasses
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/bonded-relayer"))
import br1  # noqa: E402
from native_process import Unavailable  # noqa: E402
from relay_core import Refused, encode  # noqa: E402
from two_operator_harness import profile  # noqa: E402


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.path = self.root / "operator.json"
        self.config = {
            "schema": "tos.br1.localnet.config.v1",
            "mode": "localnet",
            "release": dataclasses.asdict(profile(3)),
            "backend": str(self.root / "missing-backend"),
            "backend_sha256": "ab" * 32,
            "state_dir": str(self.state),
            "journal": str(self.state / "journal.sqlite"),
            "port": 18888,
            "fee": 7,
            "funding_cap": 100,
            "max_reserved": 1000,
            "max_pending": 8,
        }
        self.write()

    def write(self):
        self.path.write_bytes(encode(self.config))
        self.path.chmod(0o600)

    def test_complete_private_configuration_parses(self):
        data = br1.configuration(self.path)
        self.assertEqual(data["release"], profile(3))
        self.assertEqual(data["max_pending"], 8)

    def test_production_mode_or_secret_fields_are_refused(self):
        for key, value in (("mode", "production"), ("seed", "DO-NOT-READ-ME"), ("approved", True)):
            saved = dict(self.config)
            self.config[key] = value
            self.write()
            with self.subTest(key=key), self.assertRaisesRegex(Refused, "localnet configuration"):
                br1.configuration(self.path)
            self.config = saved

    def test_foreign_permissions_links_and_nonregular_files_refuse(self):
        self.path.chmod(0o644)
        with self.assertRaisesRegex(Refused, "private regular"):
            br1.configuration(self.path)
        self.path.chmod(0o600)
        alias = self.root / "alias"
        alias.symlink_to(self.path)
        with self.assertRaisesRegex(Refused, "canonical"):
            br1.configuration(alias)
        os.link(self.path, self.root / "hard")
        with self.assertRaisesRegex(Refused, "private regular"):
            br1.configuration(self.path)
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(Refused, "private regular"):
            br1.configuration(fifo)

    def test_state_and_journal_paths_cannot_escape_private_root(self):
        for key, value in (
            ("journal", str(self.root / "other.sqlite")),
            ("journal", "relative"),
            ("state_dir", str(self.root / "absent")),
        ):
            saved = dict(self.config)
            self.config[key] = value
            self.write()
            with self.subTest(key=key), self.assertRaises((Refused, OSError)):
                br1.configuration(self.path)
            self.config = saved
        self.write()
        self.state.chmod(0o755)
        with self.assertRaisesRegex(Refused, "owned and private"):
            br1.configuration(self.path)

    def test_resource_bounds_and_boolean_numbers_refuse(self):
        for key, value in (
            ("max_pending", 65),
            ("max_pending", True),
            ("funding_cap", 1001),
            ("fee", 0),
            ("port", 80),
        ):
            saved = dict(self.config)
            self.config[key] = value
            self.write()
            with self.subTest(key=key), self.assertRaises(Refused):
                br1.configuration(self.path)
            self.config = saved

    def test_duplicate_members_and_configuration_size_refuse(self):
        self.path.write_bytes(b'{"mode":"localnet","mode":"production"}')
        with self.assertRaises(Refused):
            br1.configuration(self.path)
        self.path.write_bytes(b"x" * (br1.CONFIG_LIMIT + 1))
        with self.assertRaises(Refused):
            br1.configuration(self.path)

    def test_missing_provider_is_exit_two_not_mock_or_ready(self):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = br1.main(["--config", str(self.path), "--check"])
        self.assertEqual(code, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("BR1_UNAVAILABLE", error.getvalue())
        self.assertNotIn(str(self.root), error.getvalue())
        self.assertFalse(Path(self.config["journal"]).exists())

    def test_unavailable_backend_cannot_reach_listener(self):
        with (
            patch.object(br1, "PinnedProgram", side_effect=Unavailable("SECRET")),
            patch.object(br1, "RelayServer") as server,
        ):
            error = io.StringIO()
            with redirect_stderr(error):
                self.assertEqual(br1.main(["--config", str(self.path)]), 2)
            server.assert_not_called()
            self.assertNotIn("SECRET", error.getvalue())


if __name__ == "__main__":
    unittest.main()
