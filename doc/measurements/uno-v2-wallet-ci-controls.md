# Wallet CI negative controls

Baseline: `62771b318`. These are manually run mutation records, not a claim
that CI reapplies mutations. Each mutation was restored before the next one.
Reconstruction independently verified every restored SHA and replacement SHA.
Final standalone CTest: 3/3 passed (Rust proofs, source gates, registration).
Remote workflow execution is not established by this local result.

This Markdown record intentionally quotes forbidden-symbol negative controls.
Renaming it to executable/build-data JSON would trigger the domain guard.
Workflow records below describe the pre-review bytes; review subsequently made
source provisioning explicit and removed an unused path filter.

```json
{
  "baseline": "62771b318",
  "baseline_sources": {".github/workflows/uno-wallet-prover.yml":"name: Confidential wallet proof checks\n\non:\n  push:\n    branches: [main, feature/uno-privacy-workchain-v2]\n    paths:\n      - 'uno/prover/**'\n      - 'uno/crypto/**'\n      - '.cargo/**'\n      - 'rust-toolchain.toml'\n      - 'scripts/install-rust-toolchain.sh'\n      - '.github/workflows/uno-wallet-prover.yml'\n  pull_request:\n    paths:\n      - 'uno/prover/**'\n      - 'uno/crypto/**'\n      - '.cargo/**'\n      - 'rust-toolchain.toml'\n      - 'scripts/install-rust-toolchain.sh'\n      - '.github/workflows/uno-wallet-prover.yml'\n  workflow_dispatch:\n\npermissions:\n  contents: read\n\njobs:\n  wallet:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 20\n    env:\n      CARGO_NET_OFFLINE: 'true'\n      CARGO_BUILD_JOBS: '2'\n    steps:\n      - uses: actions/checkout@v4\n      - name: Install pinned toolchain\n        run: scripts/install-rust-toolchain.sh\n      - name: Provision locked sources\n        env:\n          CARGO_NET_OFFLINE: 'false'\n        run: cargo fetch --locked --manifest-path uno/prover/Cargo.toml\n      - name: Configure standalone wallet tests\n        run: cmake -S uno/prover -B build-wallet-tests\n      - name: Run wallet tests and source gates\n        run: ctest --test-dir build-wallet-tests --output-on-failure --no-tests=error -j1\n"},
  "controls": [
    {
      "name": "source-gate-registration",
      "from": "add_test(NAME wallet-prover-source-gates\n  COMMAND \"${Python3_EXECUTABLE}\" \"${CMAKE_CURRENT_SOURCE_DIR}/tests/source-gates.py\")\nset_tests_properties(wallet-prover-source-gates PROPERTIES\n  TIMEOUT 180 FAIL_REGULAR_EXPRESSION \"Ran 0 tests\")",
      "to": "# Source gate registration removed by a negative control.",
      "test": "Registration.test_standalone_project_runs_both_wallet_gates",
      "path": "uno/prover/CMakeLists.txt",
      "restored_sha256": "202c04dc730e818a00ab5ad271507c065fa38d71491f0f158484083624a35d6b",
      "recorded_mutant_sha256": "bc7c5b361b55df8614abd83c36085860ea2103c4e198521a08fd4ec084a28aae",
      "exit_code": 1,
      "output": "test_standalone_project_runs_both_wallet_gates (__main__.Registration.test_standalone_project_runs_both_wallet_gates) ... FAIL\n\n======================================================================\nFAIL: test_standalone_project_runs_both_wallet_gates (__main__.Registration.test_standalone_project_runs_both_wallet_gates)\n----------------------------------------------------------------------\nTraceback (most recent call last):\n  File \"/home/tomi/tos/uno/prover/tests/test-registration.py\", line 21, in test_standalone_project_runs_both_wallet_gates\n    self.assertEqual(set(tests), {\"wallet-prover-rust\", \"wallet-prover-source-gates\",\n    ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n                                  \"wallet-prover-registration\"})\n                                  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\nAssertionError: Items in the second set but not the first:\n'wallet-prover-source-gates'\n\n----------------------------------------------------------------------\nRan 1 test in 0.292s\n\nFAILED (failures=1)\n"
    },
    {
      "name": "zero-test-rejection",
      "from": "TIMEOUT 600 FAIL_REGULAR_EXPRESSION \"running 0 tests\"",
      "to": "TIMEOUT 600",
      "test": "Registration.test_successful_command_with_zero_rust_tests_is_not_a_pass",
      "path": "uno/prover/CMakeLists.txt",
      "restored_sha256": "202c04dc730e818a00ab5ad271507c065fa38d71491f0f158484083624a35d6b",
      "recorded_mutant_sha256": "ded54a3cf630549575d822317f45cf9a6f04c90485eefe2d33f243944f93fcc0",
      "exit_code": 1,
      "output": "test_successful_command_with_zero_rust_tests_is_not_a_pass (__main__.Registration.test_successful_command_with_zero_rust_tests_is_not_a_pass) ... \n  test_successful_command_with_zero_rust_tests_is_not_a_pass (__main__.Registration.test_successful_command_with_zero_rust_tests_is_not_a_pass) (reported_tests='0') ... FAIL\n\n======================================================================\nFAIL: test_successful_command_with_zero_rust_tests_is_not_a_pass (__main__.Registration.test_successful_command_with_zero_rust_tests_is_not_a_pass) (reported_tests='0')\n----------------------------------------------------------------------\nTraceback (most recent call last):\n  File \"/home/tomi/tos/uno/prover/tests/test-registration.py\", line 55, in test_successful_command_with_zero_rust_tests_is_not_a_pass\n    self.assertEqual(result.returncode == 0, accepted, result.stdout + result.stderr)\n    ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\nAssertionError: True != False : Internal ctest changing into directory: /tmp/wallet-zero-test-gate-6ltf5136/build\nTest project /tmp/wallet-zero-test-gate-6ltf5136/build\n    Start 1: wallet-prover-rust\n1/1 Test #1: wallet-prover-rust ...............   Passed    0.01 sec\n\n100% tests passed, 0 tests failed out of 1\n\nTotal Test time (real) =   0.02 sec\n\n\n----------------------------------------------------------------------\nRan 1 test in 0.300s\n\nFAILED (failures=1)\n"
    },
    {
      "path": ".github/workflows/clear-gh-cache.yml",
      "from": "name: Clear all GH cache\n",
      "to": "name: Clear all GH cache\n# uno\n",
      "restored_sha256": "7bb245266e2fd26d68afcf9f9d50ab2b03ba17cd3d6a0b5f79def962248593ff",
      "recorded_mutant_sha256": "663e3401a007cbaf59a27f876aac7b27c99de3c062967364c3deed2d9f9462c1",
      "exit_code": 1,
      "output": ".github/workflows/clear-gh-cache.yml:2: Uno outside approved engine paths: # uno\nremoved-execution-domain scan failed\n"
    },
    {
      "path": ".github/workflows/uno-wallet-prover.yml",
      "from": "name: Confidential wallet proof checks\n",
      "to": "name: Confidential wallet proof checks\n# UnoToken\n",
      "restored_sha256": "9b0261b483a2162432b7e60b6577fe7623423a177466f6ae2e256ffb2408bab3",
      "recorded_mutant_sha256": "418c2901126cacf47d2deac853fe39ddf3a8706b76869a667929376b9ae2c781",
      "exit_code": 1,
      "output": ".github/workflows/uno-wallet-prover.yml:2: retired implementation symbol: UnoToken: # UnoToken\nremoved-execution-domain scan failed\n"
    }
  ]
}
```
