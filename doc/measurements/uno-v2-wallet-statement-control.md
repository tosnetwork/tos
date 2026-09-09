# Shared public statement API: manual mutation evidence

These are manual controls, not a CI mutation runner. The test-only prover now uses the shared public statement view. Production wallet proving remains pending. No verifier algorithm or C ABI changed.

## Entropy-source inclusion control

```json
{
  "scope": "Lexical entropy gate includes the new shared statement module; not an execution or whole-program reachability proof",
  "source": "uno/crypto/src/statement.rs",
  "from": "//! Public statement preparation shared with independently built wallet code.",
  "to": "//! Public statement preparation shared with independently built wallet code. rand::rng()",
  "recorded_mutant_sha256": "4d9d40b579a586d62b999eb023f26c9b4543f2dfd1bf3b5056b7243716704cc1",
  "restored_sha256": "19825e1124d6bf808dcb3ce47b5605a3f4fee883fdfea6d02fea1425bc72c150",
  "exit_code": 1,
  "output": "4d9d40b579a586d62b999eb023f26c9b4543f2dfd1bf3b5056b7243716704cc1  uno/crypto/src/statement.rs\ntest_verifier_entry_closure_and_negative_controls (__main__.KernelGates.test_verifier_entry_closure_and_negative_controls) ... FAIL\n\n======================================================================\nFAIL: test_verifier_entry_closure_and_negative_controls (__main__.KernelGates.test_verifier_entry_closure_and_negative_controls)\n----------------------------------------------------------------------\nTraceback (most recent call last):\n  File \"/home/tomi/tos/uno/crypto/tests/kernel-gates.py\", line 70, in test_verifier_entry_closure_and_negative_controls\n    self.assertFalse(rejected(source), path)\n    ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^\nAssertionError: True is not false : src/statement.rs\n\n----------------------------------------------------------------------\nRan 1 test in 0.002s\n\nFAILED (failures=1)\n",
  "reconstructed_mutant_sha256": "4d9d40b579a586d62b999eb023f26c9b4543f2dfd1bf3b5056b7243716704cc1"
}
```

## Prover-first-message binding control

```json
{
  "scope": "Shared public statement API, not production prover acceptance",
  "source": "uno/crypto/src/statement.rs",
  "from": "relation::sigma_transcript(self.0.transcript.clone(), commitments).1",
  "to": "relation::sigma_transcript(self.0.transcript.clone(), &[]).1",
  "recorded_mutant_sha256": "fb11a92e17594c2a15519f685d0068514668506c082014eefaa53286446b4b9b",
  "restored_sha256": "19825e1124d6bf808dcb3ce47b5605a3f4fee883fdfea6d02fea1425bc72c150",
  "reconstructed_mutant_sha256": "fb11a92e17594c2a15519f685d0068514668506c082014eefaa53286446b4b9b",
  "command": "CARGO_NET_OFFLINE=true cargo test --manifest-path uno/crypto/Cargo.toml --locked --release -j48 tests::full_send_and_collect_all_candidate_sizes -- --exact --nocapture",
  "exit_code": 101,
  "output": "warning: unused variable: `commitments`\n  --> src/statement.rs:35:35\n   |\n35 |     pub fn sigma_challenge(&self, commitments: &[[u8; 32]]) -> Scalar {\n   |                                   ^^^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_commitments`\n   |\n   = note: `#[warn(unused_variables)]` (part of `#[warn(unused)]`) on by default\n\nwarning: `tos-uno-crypto-prototype` (lib test) generated 1 warning (run `cargo fix --lib -p tos-uno-crypto-prototype --tests` to apply 1 suggestion)\n    Finished `release` profile [optimized] target(s) in 0.07s\n     Running unittests src/lib.rs (uno/crypto/target/release/deps/tos_uno_crypto_prototype-811c89d907253fc7)\n\nrunning 1 test\n\nthread 'tests::full_send_and_collect_all_candidate_sizes' (547544) panicked at src/tests.rs:92:27:\nassertion `left == right` failed: positive relation k=0\n  left: Err(UNO_CRYPTO_VERIFY)\n right: Ok(())\nnote: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\ntest tests::full_send_and_collect_all_candidate_sizes ... FAILED\n\nfailures:\n\nfailures:\n    tests::full_send_and_collect_all_candidate_sizes\n\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 18 filtered out; finished in 0.14s\n\nerror: test failed, to rerun pass `--lib`\n",
  "final_tests": {
    "chunk_id": "47623c",
    "wall_time_seconds": 0.000005169,
    "exit_code": 0,
    "original_token_count": 444,
    "output": "    Finished `release` profile [optimized] target(s) in 1.64s\n     Running unittests src/lib.rs (uno/crypto/target/release/deps/tos_uno_crypto_prototype-811c89d907253fc7)\n\nrunning 19 tests\ntest system_encryption::tests::system_verify_checks_request_version_independently ... ok\ntest system_encryption::tests::system_encryption_rejects_each_invalid_input ... ok\ntest system_encryption::tests::system_ciphertext_decrypts_to_the_public_amount ... ok\ntest tests::range_residuals_cannot_cancel ... ok\ntest tests::unknown_relation_kind_is_not_collect ... ok\ntest tests::transcript_matches_independent_c_reference ... ok\ntest system_encryption::tests::system_abi_checks_layout_failure_atomicity_and_both_components ... ok\ntest system_encryption::tests::system_encryption_binds_every_public_field ... ok\ntest tests::admission_predicates_have_independent_witnesses ... ok\ntest tests::borrowed_abi_layout_spans_and_panic_recovery ... ok\ntest tests::internal_collect_ceiling_rejects_unsupported_policy_before_input ... ok\ntest tests::concurrent_real_ffi_verification ... ok\ntest tests::policy_and_encoding_boundaries ... ok\ntest tests::nonidentity_handles_are_checked_before_proof_verification ... ok\ntest tests::fee_and_protocol_domain_are_bound_independently_of_equations ... ok\ntest tests::cross_language_vectors_are_frozen ... ok\ntest tests::each_sigma_equation_has_an_independent_negative_witness ... ok\ntest tests::full_send_and_collect_all_candidate_sizes ... ok\ntest tests::every_public_field_and_proof_component_is_bound ... ok\n\ntest result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.74s\n\n   Doc-tests tos_uno_crypto_prototype\n\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n\n"
  },
  "discarded_attempt": "Unqualified exact filter ran zero tests. Not evidence; corrected qualified command above ran one test."
}
```
