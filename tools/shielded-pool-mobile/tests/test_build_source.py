"""Artifact provenance must notice a change to the code doing the build."""

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = "scripts/build-shielded-mobile.py"
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
                ["git", "-C", source, "sparse-checkout", "set", "--no-cone", "/" + SCRIPT],
                ["git", "-C", source, "checkout", "--detach", "HEAD"],
            ]:
                subprocess.run([str(value) for value in command], check=True, capture_output=True)
            clean = BUILDER.source_identity(source)
            self.assertFalse(clean["source_dirty"])
            script = source / SCRIPT
            script.write_text(script.read_text() + "\n# changed build configuration\n")
            changed = BUILDER.source_identity(source)
            self.assertEqual(clean["source_commit"], changed["source_commit"])
            self.assertTrue(changed["source_dirty"])


if __name__ == "__main__":
    unittest.main()
