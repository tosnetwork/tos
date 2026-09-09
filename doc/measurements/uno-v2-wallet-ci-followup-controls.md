# Wallet CI review follow-up controls

Each mutation was applied alone and immediately restored to the recorded SHA.
These are manual controls; the registration tests themselves run in CTest.

## Review disposition

Independent review accepted the wiring with a mandatory guard-first commit
order, which is followed. Suggestions on workflow coverage, all three zero-test
properties, diagnostic output, wallet offline configuration, unused filters,
and explicit provisioning of both lockfiles were applied. The exact workflow
step assertion is a structural contract, not a YAML execution proof.

The optional RESOURCE_LOCK suggestion is deferred: the documented and CI
commands explicitly use `-j1`. Parallel standalone CTest execution is not claimed
as a validated mode; no node CTest graph includes this project.

Final local CTest passed 3/3 after these edits (including three registration
tests). All seven control hashes were independently reconstructed; pre-review
workflow bytes are embedded in the earlier record to keep that evidence
reproducible after cleanup. No consensus path or acceptance status changed.

```json
{
  "controls": [
    {
      "path": ".github/workflows/uno-wallet-prover.yml",
      "from": "        run: ctest --test-dir build-wallet-tests --output-on-failure --no-tests=error -j1",
      "to": "        run: true",
      "test": "Registration.test_workflow_keeps_the_full_standalone_gate",
      "restored_sha256": "ab872e1928a9a31b4b2426c71fe64b70b54c2e9e4b6dce1ee9fd065bd6edaf88",
      "recorded_mutant_sha256": "303472ef42c236b624580126b6e6be52ea39a5c55f32a081ba9ce9cd58c1b0ca",
      "exit_code": 1,
      "output": "test_workflow_keeps_the_full_standalone_gate (__main__.Registration.test_workflow_keeps_the_full_standalone_gate) ... FAIL\n\n======================================================================\nFAIL: test_workflow_keeps_the_full_standalone_gate (__main__.Registration.test_workflow_keeps_the_full_standalone_gate)\n----------------------------------------------------------------------\nTraceback (most recent call last):\n  File \"/home/tomi/tos/uno/prover/tests/test-registration.py\", line 53, in test_workflow_keeps_the_full_standalone_gate\n    self.assertEqual(workflow.count(required), 1, \"Full unfiltered CTest step is missing or changed\")\n    ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\nAssertionError: 0 != 1 : Full unfiltered CTest step is missing or changed\n\n----------------------------------------------------------------------\nRan 1 test in 0.001s\n\nFAILED (failures=1)\n"
    },
    {
      "path": "uno/prover/CMakeLists.txt",
      "from": "  TIMEOUT 180 FAIL_REGULAR_EXPRESSION \"Ran 0 tests\")",
      "to": "  TIMEOUT 180)",
      "test": "Registration.test_standalone_project_runs_both_wallet_gates",
      "restored_sha256": "202c04dc730e818a00ab5ad271507c065fa38d71491f0f158484083624a35d6b",
      "recorded_mutant_sha256": "70b1a42c305c52560109a24078ffa5760e1c5dba4dcd1dc8041deb2aaac475fc",
      "exit_code": 1,
      "output": "test_standalone_project_runs_both_wallet_gates (__main__.Registration.test_standalone_project_runs_both_wallet_gates) ... FAIL\n\n======================================================================\nFAIL: test_standalone_project_runs_both_wallet_gates (__main__.Registration.test_standalone_project_runs_both_wallet_gates)\n----------------------------------------------------------------------\nTraceback (most recent call last):\n  File \"/home/tomi/tos/uno/prover/tests/test-registration.py\", line 41, in test_standalone_project_runs_both_wallet_gates\n    self.assertIn(\"FAIL_REGULAR_EXPRESSION\", properties, name)\n    ~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\nAssertionError: 'FAIL_REGULAR_EXPRESSION' not found in {'TIMEOUT': 180.0, 'WORKING_DIRECTORY': '/tmp/wallet-ctest-registration-77ij0y37'} : wallet-prover-source-gates\n\n----------------------------------------------------------------------\nRan 1 test in 0.300s\n\nFAILED (failures=1)\n"
    },
    {
      "path": "uno/prover/CMakeLists.txt",
      "from": "  TIMEOUT 120 FAIL_REGULAR_EXPRESSION \"Ran 0 tests\")",
      "to": "  TIMEOUT 120)",
      "test": "Registration.test_standalone_project_runs_both_wallet_gates",
      "restored_sha256": "202c04dc730e818a00ab5ad271507c065fa38d71491f0f158484083624a35d6b",
      "recorded_mutant_sha256": "bdb4e7bbaeb3c254d6ffbdcbb828df696cbbe111aab41d72e417a6fd15658b88",
      "exit_code": 1,
      "output": "test_standalone_project_runs_both_wallet_gates (__main__.Registration.test_standalone_project_runs_both_wallet_gates) ... FAIL\n\n======================================================================\nFAIL: test_standalone_project_runs_both_wallet_gates (__main__.Registration.test_standalone_project_runs_both_wallet_gates)\n----------------------------------------------------------------------\nTraceback (most recent call last):\n  File \"/home/tomi/tos/uno/prover/tests/test-registration.py\", line 41, in test_standalone_project_runs_both_wallet_gates\n    self.assertIn(\"FAIL_REGULAR_EXPRESSION\", properties, name)\n    ~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\nAssertionError: 'FAIL_REGULAR_EXPRESSION' not found in {'TIMEOUT': 120.0, 'WORKING_DIRECTORY': '/tmp/wallet-ctest-registration-h8dqar2x'} : wallet-prover-registration\n\n----------------------------------------------------------------------\nRan 1 test in 0.300s\n\nFAILED (failures=1)\n"
    }
  ]
}
```
