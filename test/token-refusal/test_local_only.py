"""Offline controls for the local-only build, with no account-state override."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("local_refusal_build", HERE / "build-local-only.py")
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)
ROOT = HERE.parents[1]
GUARD_SPEC = importlib.util.spec_from_file_location(
    "local_release_guard", HERE / "release_guard.py"
)
guard = importlib.util.module_from_spec(GUARD_SPEC)
GUARD_SPEC.loader.exec_module(guard)


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
        self.assertEqual(
            guard.release_leaks(ROOT, build.REJECT_OWNER, build.TEST_WALLET_CODE_HASH), []
        )

    def test_workflow_and_shipped_tree_leaks_are_caught(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = root / ".github/workflows/create-release.yml"
            workflow.parent.mkdir(parents=True)
            shipped = root / "crypto/smartcont/token-wallet-local-only-test.fc"
            shipped.parent.mkdir(parents=True)
            for marker in ("local-only-test-token-wallet.fif", "token-refusal"):
                workflow.write_text("steps:\n  - run: upload " + marker + "\n")
                self.assertIn(
                    str(workflow.relative_to(root)),
                    guard.release_leaks(root, build.REJECT_OWNER, build.TEST_WALLET_CODE_HASH),
                )
            workflow.write_text("steps: []\n")
            shipped.write_text(
                build.wallet_source(
                    (ROOT / "crosschain/token-bridge/tvm/contracts/token-wallet.fc").read_text()
                )
            )
            self.assertIn(
                str(shipped.relative_to(root)),
                guard.release_leaks(root, build.REJECT_OWNER, build.TEST_WALLET_CODE_HASH),
            )

    def test_every_marker_and_install_rule_is_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "nested/CMakeLists.txt"
            path.parent.mkdir()
            for marker in (
                "local-only-test",
                "token-refusal",
                build.REJECT_OWNER,
                "1980 THROWIF GLOBALID",
                "GLOBALID throw_if(1980, 1)",
            ):
                path.write_text(
                    'set(FILE "' + marker + '")\ninstall(FILES ${FILE} DESTINATION lib)\n'
                )
                self.assertEqual(
                    guard.release_leaks(root, build.REJECT_OWNER, build.TEST_WALLET_CODE_HASH),
                    ["nested/CMakeLists.txt"],
                )

    def test_compiler_hash_is_checked_before_the_marker_claims_it(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "local-only-test"
            build.stage(ROOT, output, 3)
            for actual, accepted in (("00" * 32, False), (build.TEST_WALLET_CODE_HASH, True)):
                calls = [
                    subprocess.CompletedProcess([], 0),
                    subprocess.CompletedProcess([], 0, stdout="HASH " + actual),
                ]
                with mock.patch.object(build.subprocess, "run", side_effect=calls):
                    if accepted:
                        result = build.compile_wallet(ROOT, output, Path("func"), Path("fift"))
                        self.assertEqual(result["wallet_code_hash"], build.TEST_WALLET_CODE_HASH)
                    else:
                        with self.assertRaisesRegex(ValueError, "pinned real build"):
                            build.compile_wallet(ROOT, output, Path("func"), Path("fift"))
                        self.assertNotIn(
                            "wallet_code_hash",
                            json.loads((output / "LOCAL-ONLY-TEST.json").read_text()),
                        )


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--release-root":
        leaks = guard.release_leaks(
            Path(sys.argv[2]), build.REJECT_OWNER, build.TEST_WALLET_CODE_HASH
        )
        if leaks:
            print("local test build leaked into release inputs: " + ", ".join(leaks))
        raise SystemExit(1 if leaks else 0)
    unittest.main()
