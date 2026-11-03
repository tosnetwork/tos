"""Artifact provenance must notice a change to the code doing the build."""

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = "scripts/build-shielded-mobile.py"
COMMON = "tosctl/src/common/src/info.rs"
SPEC = importlib.util.spec_from_file_location("shielded_builder", ROOT / SCRIPT)
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class SourceIdentityTest(unittest.TestCase):
    def test_modifying_only_the_builder_marks_the_source_dirty(self):
        # A sparse local clone uses the real committed tree, without creating
        # synthetic commits or changing the checkout under test.
        with tempfile.TemporaryDirectory(prefix="shielded-source-test-") as directory:
            source = Path(directory) / "source"
            for command in [
                ["git", "clone", "--shared", "--no-checkout", ROOT, source],
                [
                    "git",
                    "-C",
                    source,
                    "sparse-checkout",
                    "set",
                    "--no-cone",
                    "/" + SCRIPT,
                    "/" + COMMON,
                ],
                ["git", "-C", source, "checkout", "--detach", "HEAD"],
            ]:
                subprocess.run([str(value) for value in command], check=True, capture_output=True)
            clean = BUILDER.source_identity(source)
            self.assertFalse(clean["source_dirty"])
            for name in [SCRIPT, COMMON]:
                path = source / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n// changed build input\n")
                changed = BUILDER.source_identity(source)
                self.assertEqual(clean["source_commit"], changed["source_commit"])
                self.assertTrue(changed["source_dirty"], name)
                path.write_bytes(original)


class BuildDateTest(unittest.TestCase):
    def test_bsd_date_is_replaced_only_for_the_build_environment(self):
        import os
        import shutil

        actual = shutil.which("gdate") or shutil.which("date")
        with tempfile.TemporaryDirectory(prefix="shielded-date-test-") as directory:
            root = Path(directory)
            tools = root / "bin"
            tools.mkdir()
            (tools / "date").write_text("#!/bin/sh\nexit 1\n")
            (tools / "date").chmod(0o755)
            (tools / "gdate").symlink_to(Path(actual).resolve())
            environment = {**os.environ, "PATH": str(tools)}
            version = BUILDER.configure_date(environment, root / "build")
            result = subprocess.run(
                ["date", "-u", "-d", "@0", "+%s"], env=environment, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), "0")
            self.assertIn("GNU", version)
            (tools / "gdate").unlink()
            with self.assertRaisesRegex(RuntimeError, "GNU date is required"):
                BUILDER.configure_date({**os.environ, "PATH": str(tools)}, root / "missing")


if __name__ == "__main__":
    unittest.main()
