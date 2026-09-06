"""Configure-time gates and actual CTest registration, not network acceptance."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]


class UnoBuildWiring(unittest.TestCase):
    def test_cargo_pin_and_offline_environment_are_enforced(self):
        with tempfile.TemporaryDirectory(prefix="uno-cargo-gate-") as directory:
            root = Path(directory)
            cargo = root / "cargo"
            cargo.write_text("#!/bin/sh\n"
                             "test \"$CARGO_NET_OFFLINE\" = true || exit 17\n"
                             "echo \"cargo $UNO_FAKE_VERSION (fixture)\"\n")
            cargo.chmod(0o700)
            script = root / "check.cmake"
            script.write_text(f'include("{REPO}/uno/crypto/RequireCargo.cmake")\n'
                              f'uno_require_cargo("{cargo}" "{root}")\n')
            for version, accepted in (("1.97.1", True), ("1.96.0", False), ("1.97.10", False)):
                with self.subTest(version=version):
                    env = dict(os.environ, UNO_FAKE_VERSION=version, CARGO_NET_OFFLINE="false")
                    result = subprocess.run(["cmake", "-P", str(script)], env=env,
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, accepted, result.stdout + result.stderr)

    def test_actual_ctest_registration_includes_explicit_gates(self):
        with tempfile.TemporaryDirectory(prefix="uno-ctest-gate-") as directory:
            configure = ["cmake", "-S", str(REPO), "-B", directory, "-G", "Ninja",
                         "-DTOS_UNO_CRYPTO_PROTOTYPE_TESTS=ON", "-DTOS_UNO_COUNTER_PYTEST=ON",
                         "-DTOS_UNO_COUNTER_NETWORK_TEST=ON", "-DTOS_UNO_LARGE_SNAPSHOT_TEST=ON"]
            result = subprocess.run(configure, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run(["ctest", "--test-dir", directory, "--show-only=json-v1"],
                                    capture_output=True, text=True, check=True)
            tests = {test["name"]: test for test in json.loads(result.stdout)["tests"]}
            for name in ("test-uno-crypto-rust", "test-uno-crypto-abi-real", "test-uno-crypto-header-guard",
                         "test-counter-python-harness", "test-counter-real-manager-sync",
                         "test-uno-state-snapshot-large"):
                self.assertIn(name, tests)
            # The default snapshot registration must never silently include a
            # resource-heavy experiment that turns into a passing early return.
            result = subprocess.run(configure + ["-DTOS_UNO_LARGE_SNAPSHOT_TEST=OFF"],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run(["ctest", "--test-dir", directory, "--show-only=json-v1"],
                                    capture_output=True, text=True, check=True)
            names = {test["name"] for test in json.loads(result.stdout)["tests"]}
            self.assertNotIn("test-uno-state-snapshot-large", names)
            self.assertIn("test-uno-state-snapshot", names)


if __name__ == "__main__":
    unittest.main()
