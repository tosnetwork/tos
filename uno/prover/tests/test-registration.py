"""Check the actual standalone CTest graph, not comments claiming registration."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Registration(unittest.TestCase):
    def test_standalone_project_runs_both_wallet_gates(self):
        with tempfile.TemporaryDirectory(prefix="wallet-ctest-registration-") as directory:
            configured = subprocess.run(["cmake", "-S", str(ROOT), "-B", directory],
                                        text=True, capture_output=True)
            self.assertEqual(configured.returncode, 0, configured.stdout + configured.stderr)
            listing = subprocess.run(["ctest", "--test-dir", directory, "--show-only=json-v1"],
                                     text=True, capture_output=True)
            self.assertEqual(listing.returncode, 0, listing.stdout + listing.stderr)
            self.assertTrue(listing.stdout.strip(), "CTest returned no registration data")
            try:
                registration = json.loads(listing.stdout)
            except json.JSONDecodeError:
                self.fail("Invalid CTest registration JSON: " + listing.stdout + listing.stderr)
            tests = {t["name"]: t for t in registration["tests"]}
            self.assertEqual(set(tests), {"wallet-prover-rust", "wallet-prover-source-gates",
                                          "wallet-prover-registration"})
            rust = tests["wallet-prover-rust"]["command"]
            self.assertIn("CARGO_NET_OFFLINE=true", rust)
            self.assertIn("--manifest-path", rust)
            for flag in ("--locked", "--offline", "--lib"):
                self.assertIn(flag, rust)
            self.assertEqual(Path(rust[rust.index("--manifest-path") + 1]), ROOT / "Cargo.toml")
            self.assertEqual(Path(tests["wallet-prover-source-gates"]["command"][-1]),
                             ROOT / "tests/source-gates.py")
            for name, pattern in (("wallet-prover-rust", "running 0 tests"),
                                  ("wallet-prover-source-gates", "Ran 0 tests"),
                                  ("wallet-prover-registration", "Ran 0 tests")):
                properties = {p["name"]: p["value"] for p in tests[name]["properties"]}
                self.assertIn("FAIL_REGULAR_EXPRESSION", properties, name)
                self.assertIn(pattern, properties["FAIL_REGULAR_EXPRESSION"])

    def test_workflow_keeps_the_full_standalone_gate(self):
        # Exact wiring contract, not a general-purpose YAML validator.
        workflow = (ROOT.parents[1] / ".github/workflows/uno-wallet-prover.yml").read_text()
        required = (
            "      - name: Configure standalone wallet tests\n"
            "        run: cmake -S uno/prover -B build-wallet-tests\n"
            "      - name: Run wallet tests and source gates\n"
            "        run: ctest --test-dir build-wallet-tests --output-on-failure --no-tests=error -j1\n"
        )
        self.assertEqual(workflow.count(required), 1, "Full unfiltered CTest step is missing or changed")

    def test_successful_command_with_zero_rust_tests_is_not_a_pass(self):
        with tempfile.TemporaryDirectory(prefix="wallet-zero-test-gate-") as directory:
            root = Path(directory)
            cargo = root / "cargo"
            cargo.write_text('#!/bin/sh\n'
                             'if [ "$1" = "--version" ]; then echo "cargo 1.97.1 (fixture)"; exit 0; fi\n'
                             'if [ "$1" = "test" ]; then echo "running $WALLET_FAKE_TEST_COUNT tests"; exit 0; fi\n'
                             'exit 17\n')
            cargo.chmod(0o700)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ.get("PATH", ""))
            configured = subprocess.run(["cmake", "-S", str(ROOT), "-B", str(root / "build")],
                                        env=env, text=True, capture_output=True)
            self.assertEqual(configured.returncode, 0, configured.stdout + configured.stderr)
            for count, accepted in (("1", True), ("0", False)):
                with self.subTest(reported_tests=count):
                    result = subprocess.run(["ctest", "--test-dir", str(root / "build"),
                                             "-R", "^wallet-prover-rust$", "--output-on-failure",
                                             "--no-tests=error"],
                                            env=dict(env, WALLET_FAKE_TEST_COUNT=count),
                                            text=True, capture_output=True)
                    self.assertEqual(result.returncode == 0, accepted, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
