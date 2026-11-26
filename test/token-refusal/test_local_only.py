"""Offline controls for the local-only build, with no account-state override."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("local_refusal_build", HERE / "build-local-only.py")
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)
ROOT = HERE.parents[1]


class LocalRefusalTests(unittest.TestCase):
    def test_no_public_build_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "local-only-test"
            with self.assertRaisesRegex(ValueError, "local global id"):
                build.stage(ROOT, out, 2)
            self.assertFalse(out.exists())
            with self.assertRaisesRegex(ValueError, "outside the checkout"):
                build.stage(ROOT, Path(directory) / "ordinary-build", 3)
            marker = build.stage(ROOT, out, 3)
            self.assertEqual(marker["label"], "LOCAL-ONLY-TEST-REFUSAL-v1")
            with self.assertRaisesRegex(ValueError, "never overwrite"):
                build.stage(ROOT, out, 3)

    def test_only_authenticated_receiver_refuses(self):
        original = (ROOT / "crosschain/token-bridge/tvm/contracts/token-wallet.fc").read_text()
        changed = build.wallet_source(original)
        self.assertIn("throw_unless(1979, local_test_global_id() == 3);", changed)
        _, _, receiver = changed.partition("() receive_reported_tokens(")
        receiver = receiver.partition("() send_refused(")[0]
        self.assertIn("throw_if(1980", receiver)
        self.assertLess(receiver.index(build.AUTH), receiver.index("throw_if(1980"))
        self.assertIn("test_owner == 0x" + build.REJECT_OWNER, receiver)
        self.assertEqual(changed.count("throw_if(1980"), 1)
        # Funding's ordinary receive_tokens path never hits the test refusal.
        self.assertNotIn("1980", changed.partition("() receive_reported_tokens(")[0])
        with self.assertRaisesRegex(ValueError, "reviewed test base"):
            build.wallet_source(original + "\n")

    def test_release_inputs_do_not_name_test_build(self):
        manifest = ROOT / "scripts/release-artifacts.json"
        self.assertNotIn("token-refusal", manifest.read_text())
        self.assertNotIn("local-only-test", manifest.read_text())
        self.assertNotIn("local-only-test-token-wallet.fif", (ROOT / "CMakeLists.txt").read_text())


if __name__ == "__main__":
    unittest.main()
