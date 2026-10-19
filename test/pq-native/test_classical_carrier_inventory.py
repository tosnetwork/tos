"""The inventory must cover raw/checked parsers and classical RPC rendering."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/check-classical-carrier-sites.py"


class ClassicalCarrierInventoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.sources = {
            "lite-client/checked.cpp": "BlockSignatureSet::fetch_lite_checked(value);\n",
            "lite-client/raw.cpp": "BlockSignatureSet::fetch(value);\n",
            "validator-engine/finality.cpp": "link.sig_set->tl_lite();\n",
        }
        self.rows = [
            "lite-client/checked.cpp\tcpp_fetch\t1\thistorical\tchecked carrier parser",
            "lite-client/raw.cpp\tcpp_fetch\t1\thistorical\traw carrier parser",
            "validator-engine/finality.cpp\tcarrier_io\t1\thistorical\tclassical history renderer",
        ]
        for filename, source in self.sources.items():
            self.write(filename, source)
        for suffix in ("cpp", "hpp"):
            self.write(f"validator/manager-disk.{suffix}", "")
        self.write_manifest()
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.track()

    def write(self, filename, source):
        path = self.root / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)

    def write_manifest(self):
        self.write("test/pq-native/classical-carrier-sites.tsv", "\n".join(self.rows) + "\n")

    def track(self):
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)

    def check_inventory(self):
        return subprocess.run(
            [sys.executable, str(CHECKER), str(self.root)],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_raw_checked_and_renderer_sites_are_counted(self):
        result = self.check_inventory()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("entries=3 sites=3", result.stdout)

    def test_unlisted_checked_parser_is_rejected(self):
        self.write("lite-client/new.cpp", self.sources["lite-client/checked.cpp"])
        self.track()
        result = self.check_inventory()
        self.assertEqual(result.returncode, 1)
        self.assertIn("lite-client/new.cpp contains unlisted marker cpp_fetch", result.stderr)

    def test_missing_checked_parser_row_is_rejected(self):
        self.rows.pop(0)
        self.write_manifest()
        result = self.check_inventory()
        self.assertEqual(result.returncode, 1)
        self.assertIn("lite-client/checked.cpp contains unlisted marker cpp_fetch", result.stderr)

    def test_missing_renderer_row_is_rejected(self):
        self.rows.pop()
        self.write_manifest()
        result = self.check_inventory()
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "validator-engine/finality.cpp contains unlisted marker carrier_io", result.stderr
        )

    def test_stale_parser_row_is_rejected(self):
        self.write("lite-client/checked.cpp", "")
        result = self.check_inventory()
        self.assertEqual(result.returncode, 1)
        self.assertIn("lite-client/checked.cpp no longer contains marker cpp_fetch", result.stderr)

    def test_wrong_parser_count_is_rejected(self):
        self.rows[0] = self.rows[0].replace("\t1\t", "\t2\t")
        self.write_manifest()
        result = self.check_inventory()
        self.assertEqual(result.returncode, 1)
        self.assertIn("marker cpp_fetch has 1 sites, inventory says 2", result.stderr)


if __name__ == "__main__":
    unittest.main()
