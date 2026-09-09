# Wallet prover erasure and module-discovery controls

Removing the erasure feature first stopped at the lockfile guard. That exit is not erasure evidence. The offline compiler run then updated only the lock graph and failed with E0277 at the production call requiring ZeroizeOnDrop. Both manifest and lock were restored byte-for-byte. This establishes a type/feature requirement, not erasure of every compiler temporary or register. Source review separately checks the pinned backend's state and buffer drop implementations.

```json
{
  "manifest": {
    "from": "chacha20 = { version = \"=0.10.2\", default-features = false, features = [\"rng\", \"zeroize\"] }",
    "to": "chacha20 = { version = \"=0.10.2\", default-features = false, features = [\"rng\"] }",
    "restored_sha256": "ac35a6174f1e86c46af88cff839fb87171da416066b5745e892b222c2e2fddbb",
    "reconstructed_mutant_sha256": "522fffe7205531dded5cde80024f244cbf0f75fb7c6b861418804673b903534f"
  },
  "lock": {
    "restored_sha256": "647b9d9a09acd807ebb5077c005ffd0ffb047deae0dd8904560584b2e2e89459",
    "observed_mutant_contents_sha256": "a0ea074e94f2da999039d4970559b9c7705858963b5deb0ed50fa9b7b4e3cd1e",
    "cargo_generated_diff": "--- before\n+++ mutant\n@@ -78,7 +78,6 @@\n  \"cfg-if\",\n  \"cpufeatures 0.3.1\",\n  \"rand_core\",\n- \"zeroize\",\n ]\n \n [[package]]\n"
  },
  "compiler_result": {
    "exit_code": 101,
    "output": "    Checking zeroize v1.9.0\n    Checking strobe-rs v0.10.0\n    Checking curve25519-dalek v5.0.2 (https://github.com/xelis-project/curve25519-dalek?rev=10042b03cfc92e505e9d33d2827d5c0f0d36989a#10042b03)\n    Checking merlin v4.1.0 (https://github.com/xelis-project/merlin?rev=ee857c79347e0e2201e5192523faea13ac9bf451#ee857c79)\n    Checking bulletproofs v5.3.0 (/home/tomi/tos/uno/crypto/vendor/bulletproofs)\n    Checking tos-uno-crypto-prototype v0.1.0 (/home/tomi/tos/uno/crypto)\n    Checking tos-uno-wallet-prover v0.1.0 (/home/tomi/tos/uno/prover)\nerror[E0277]: the trait bound `ChaCha12Rng: ZeroizeOnDrop` is not satisfied\n  --> src/lib.rs:65:45\n   |\n65 |     generate(statement, witness, &prepared, &mut rng)\n   |     --------                                ^^^^^^^^ the trait `ZeroizeOnDrop` is not implemented for `ChaCha12Rng`\n   |     |\n   |     required by a bound introduced by this call\n   |\n   = help: the following other types implement trait `ZeroizeOnDrop`:\n             ()\n             (A, B)\n             (A, B, C)\n             (A, B, C, D)\n             (A, B, C, D, E)\n             (A, B, C, D, E, F)\n             (A, B, C, D, E, F, G)\n             (A, B, C, D, E, F, G, H)\n           and 16 others\nnote: required by a bound in `generate`\n  --> src/lib.rs:93:28\n   |\n93 | fn generate<R: CryptoRng + ZeroizeOnDrop>(statement: &Statement<'_>, witness: &Witness<'_>,\n   |                            ^^^^^^^^^^^^^ required by this bound in `generate`\n\nFor more information about this error, try `rustc --explain E0277`.\nerror: could not compile `tos-uno-wallet-prover` (lib) due to 1 previous error\n"
  },
  "discarded_locked_attempt": {
    "chunk_id": "552362",
    "wall_time_seconds": 0.000009,
    "exit_code": 101,
    "original_token_count": 58,
    "output": "error: cannot update the lock file /home/tomi/tos/uno/prover/Cargo.lock because --locked was passed to prevent this\nhelp: to generate the lock file without accessing the network, remove the --locked flag and use --offline instead.\n"
  },
  "observed_hashes_before_unlocked_build": "522fffe7205531dded5cde80024f244cbf0f75fb7c6b861418804673b903534f  uno/prover/Cargo.toml\n647b9d9a09acd807ebb5077c005ffd0ffb047deae0dd8904560584b2e2e89459  uno/prover/Cargo.lock\n",
  "new_module_control": {
    "path": "uno/crypto/src/entropy_probe.rs",
    "added_contents": "// RandomState::new()\n",
    "result": {
      "chunk_id": "e803df",
      "wall_time_seconds": 0.00000956,
      "exit_code": 1,
      "original_token_count": 205,
      "output": "test_verifier_entry_closure_and_negative_controls (__main__.KernelGates.test_verifier_entry_closure_and_negative_controls) ... FAIL\n\n======================================================================\nFAIL: test_verifier_entry_closure_and_negative_controls (__main__.KernelGates.test_verifier_entry_closure_and_negative_controls)\n----------------------------------------------------------------------\nTraceback (most recent call last):\n  File \"/home/tomi/tos/uno/crypto/tests/kernel-gates.py\", line 73, in test_verifier_entry_closure_and_negative_controls\n    self.assertFalse(rejected(source), path)\n    ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^\nAssertionError: True is not false : src/entropy_probe.rs\n\n----------------------------------------------------------------------\nRan 1 test in 0.001s\n\nFAILED (failures=1)\n"
    },
    "restoration": "Temporary file removed with apply_patch; final source gate passes."
  }
}
```
