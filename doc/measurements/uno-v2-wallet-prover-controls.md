# Wallet prover manual controls

These manual controls are not a default CTest mutation runner. Each replacement was applied alone and restored before the next control. All eight records below independently reconstruct against the current restored source. The four original generator controls were rerun after the erasure and constant-time changes; preliminary results are superseded. Structural source checks do not establish complete side-channel security. The graph-source mutation has one pre-existing occurrence of its replacement substring in the wallet graph read; restoration is checked against the whole-file hash, not an incorrect zero-occurrence assumption.

```json
[
  {
    "name": "witness-equation",
    "from": "if RistrettoPoint::multiscalar_mul(witness.scalars, row) != *target {",
    "to": "if false && RistrettoPoint::multiscalar_mul(witness.scalars, row) != *target {",
    "test": "tests::invalid_witnesses_are_rejected_before_entropy_and_entropy_failure_is_reported",
    "path": "uno/prover/src/lib.rs",
    "exit_code": 101,
    "output": "   Compiling tos-uno-crypto-prototype v0.1.0 (/home/tomi/tos/uno/crypto)\n   Compiling tos-uno-wallet-prover v0.1.0 (/home/tomi/tos/uno/prover)\n    Finished `release` profile [optimized] target(s) in 1.00s\n     Running unittests src/lib.rs (uno/prover/target/release/deps/tos_uno_wallet_prover-5e260dcbac387c2d)\n\nrunning 1 test\n\nthread 'tests::invalid_witnesses_are_rejected_before_entropy_and_entropy_failure_is_reported' (938832) panicked at src/tests.rs:126:5:\nassertion `left == right` failed\n  left: Err(EntropyUnavailable)\n right: Err(WitnessEquation)\nnote: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\ntest tests::invalid_witnesses_are_rejected_before_entropy_and_entropy_failure_is_reported ... FAILED\n\nfailures:\n\nfailures:\n    tests::invalid_witnesses_are_rejected_before_entropy_and_entropy_failure_is_reported\n\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.01s\n\nerror: test failed, to rerun pass `--lib`\n",
    "recorded_mutant_sha256": "4e5763e828b80341db2cc571fa0eb113de2f8819fa798c5c07399e3c1b042ff3",
    "restored_sha256": "3a111d728262b9bc97b482114f8c2c979c722b967e5cb47163660b45b23c50d7",
    "reconstructed_mutant_sha256": "4e5763e828b80341db2cc571fa0eb113de2f8819fa798c5c07399e3c1b042ff3",
    "original_from_count": 1,
    "original_to_count": 0
  },
  {
    "name": "range-opening",
    "from": "if pc.commit(Scalar::from(*value), *blinding).compress() != *expected {",
    "to": "if false && pc.commit(Scalar::from(*value), *blinding).compress() != *expected {",
    "test": "tests::invalid_witnesses_are_rejected_before_entropy_and_entropy_failure_is_reported",
    "path": "uno/prover/src/lib.rs",
    "exit_code": 101,
    "output": "   Compiling tos-uno-wallet-prover v0.1.0 (/home/tomi/tos/uno/prover)\n    Finished `release` profile [optimized] target(s) in 0.95s\n     Running unittests src/lib.rs (uno/prover/target/release/deps/tos_uno_wallet_prover-5e260dcbac387c2d)\n\nrunning 1 test\ntest tests::invalid_witnesses_are_rejected_before_entropy_and_entropy_failure_is_reported ... FAILED\n\nfailures:\n\nfailures:\n    tests::invalid_witnesses_are_rejected_before_entropy_and_entropy_failure_is_reported\n\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.01s\n\n\nthread 'tests::invalid_witnesses_are_rejected_before_entropy_and_entropy_failure_is_reported' (939633) panicked at src/tests.rs:129:5:\nassertion `left == right` failed\n  left: Err(EntropyUnavailable)\n right: Err(RangeOpening)\nnote: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\nerror: test failed, to rerun pass `--lib`\n",
    "recorded_mutant_sha256": "0d9d4bd3087610e923bd21ccaece05880e5d9081713b6f97a94c77c3599b1d29",
    "restored_sha256": "3a111d728262b9bc97b482114f8c2c979c722b967e5cb47163660b45b23c50d7",
    "reconstructed_mutant_sha256": "0d9d4bd3087610e923bd21ccaece05880e5d9081713b6f97a94c77c3599b1d29",
    "original_from_count": 1,
    "original_to_count": 0
  },
  {
    "name": "fresh-masks",
    "from": "witness.scalars.iter().map(|_| Scalar::random(rng)).collect::<Vec<_>>()",
    "to": "witness.scalars.iter().map(|_| Scalar::ZERO).collect::<Vec<_>>()",
    "test": "tests::fresh_entropy_proofs_verify_for_every_supported_size",
    "path": "uno/prover/src/lib.rs",
    "exit_code": 101,
    "output": "   Compiling tos-uno-wallet-prover v0.1.0 (/home/tomi/tos/uno/prover)\n    Finished `release` profile [optimized] target(s) in 0.89s\n     Running unittests src/lib.rs (uno/prover/target/release/deps/tos_uno_wallet_prover-5e260dcbac387c2d)\n\nrunning 1 test\n\nthread 'tests::fresh_entropy_proofs_verify_for_every_supported_size' (940404) panicked at src/tests.rs:100:9:\nassertion `left != right` failed: fresh masks k=0\n  left: [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]\n right: [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]\nnote: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\ntest tests::fresh_entropy_proofs_verify_for_every_supported_size ... FAILED\n\nfailures:\n\nfailures:\n    tests::fresh_entropy_proofs_verify_for_every_supported_size\n\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.31s\n\nerror: test failed, to rerun pass `--lib`\n",
    "recorded_mutant_sha256": "fecc4c263f943be8257e75b06ef4e0e1326290f80bd8e9362a624310b6542116",
    "restored_sha256": "3a111d728262b9bc97b482114f8c2c979c722b967e5cb47163660b45b23c50d7",
    "reconstructed_mutant_sha256": "fecc4c263f943be8257e75b06ef4e0e1326290f80bd8e9362a624310b6542116",
    "original_from_count": 1,
    "original_to_count": 0
  },
  {
    "name": "shared-witness-response",
    "from": "(mask + challenge * secret).to_bytes()",
    "to": "(mask + challenge * secret + Scalar::ONE).to_bytes()",
    "test": "tests::reproduces_all_frozen_send_and_collect_proofs",
    "path": "uno/prover/src/lib.rs",
    "exit_code": 101,
    "output": "   Compiling tos-uno-wallet-prover v0.1.0 (/home/tomi/tos/uno/prover)\n    Finished `release` profile [optimized] target(s) in 0.95s\n     Running unittests src/lib.rs (uno/prover/target/release/deps/tos_uno_wallet_prover-5e260dcbac387c2d)\n\nrunning 1 test\n\nthread 'tests::reproduces_all_frozen_send_and_collect_proofs' (941293) panicked at src/tests.rs:81:75:\nproduction generator: GeneratedProof(UNO_CRYPTO_VERIFY)\nnote: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\ntest tests::reproduces_all_frozen_send_and_collect_proofs ... FAILED\n\nfailures:\n\nfailures:\n    tests::reproduces_all_frozen_send_and_collect_proofs\n\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.13s\n\nerror: test failed, to rerun pass `--lib`\n",
    "recorded_mutant_sha256": "c27ad9c02ff4f70bb9b787358ea776fa3c3fa03928219c1781aa052d2e27ce0d",
    "restored_sha256": "3a111d728262b9bc97b482114f8c2c979c722b967e5cb47163660b45b23c50d7",
    "reconstructed_mutant_sha256": "c27ad9c02ff4f70bb9b787358ea776fa3c3fa03928219c1781aa052d2e27ce0d",
    "original_from_count": 1,
    "original_to_count": 0
  },
  {
    "name": "ct-inner-product-site",
    "path": "uno/crypto/vendor/bulletproofs/src/inner_product_proof.rs",
    "from": "let L = RistrettoPoint::multiscalar_mul(\n                a_L.iter()\n",
    "to": "let L = RistrettoPoint::vartime_multiscalar_mul(\n                a_L.iter()\n",
    "command": "python3 uno/prover/tests/source-gates.py WalletGates.test_nonpublic_inner_product_constructions_use_constant_time_msm",
    "restored_sha256": "19b47ea013a32d1c14be88995ce82ec0b9898dc8affb1a440205b58fa53d0d95",
    "recorded_mutant_sha256": "3c5d71f18df4c8b975315cdbf399459f82191755871f9b1b47064d41ae229224",
    "exit_code": 1,
    "output": "test_nonpublic_inner_product_constructions_use_constant_time_msm (__main__.WalletGates.test_nonpublic_inner_product_constructions_use_constant_time_msm) ... FAIL\n\n======================================================================\nFAIL: test_nonpublic_inner_product_constructions_use_constant_time_msm (__main__.WalletGates.test_nonpublic_inner_product_constructions_use_constant_time_msm)\n----------------------------------------------------------------------\nTraceback (most recent call last):\n  File \"/home/tomi/tos/uno/prover/tests/source-gates.py\", line 43, in test_nonpublic_inner_product_constructions_use_constant_time_msm\n    self.assertEqual(sites, [\"multiscalar_mul\"] * 4)\n    ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\nAssertionError: Lists differ: ['vartime_multiscalar_mul', 'multiscalar_mu[36 chars]mul'] != ['multiscalar_mul', 'multiscalar_mul', 'mul[28 chars]mul']\n\nFirst differing element 0:\n'vartime_multiscalar_mul'\n'multiscalar_mul'\n\n+ ['multiscalar_mul', 'multiscalar_mul', 'multiscalar_mul', 'multiscalar_mul']\n- ['vartime_multiscalar_mul',\n-  'multiscalar_mul',\n-  'multiscalar_mul',\n-  'multiscalar_mul']\n\n----------------------------------------------------------------------\nRan 1 test in 0.001s\n\nFAILED (failures=1)\n",
    "reconstructed_mutant_sha256": "3c5d71f18df4c8b975315cdbf399459f82191755871f9b1b47064d41ae229224",
    "original_from_count": 1,
    "original_to_count": 0
  },
  {
    "name": "separate-runtime-graphs",
    "path": "uno/prover/tests/source-gates.py",
    "from": "for line in graph(KERNEL).splitlines()",
    "to": "for line in graph(ROOT).splitlines()",
    "command": "python3 uno/prover/tests/source-gates.py WalletGates.test_distinct_entropy_graphs",
    "restored_sha256": "37a9016cc658ea4387a80d2f610afd484be58236807c612cb9c274cc4b044ed3",
    "recorded_mutant_sha256": "cec6f6777deb6a45abfbc0b3c916af80aceae8ac21b52296e5090b94c31600fa",
    "exit_code": 1,
    "output": "test_distinct_entropy_graphs (__main__.WalletGates.test_distinct_entropy_graphs) ... FAIL\n\n======================================================================\nFAIL: test_distinct_entropy_graphs (__main__.WalletGates.test_distinct_entropy_graphs)\n----------------------------------------------------------------------\nTraceback (most recent call last):\n  File \"/home/tomi/tos/uno/prover/tests/source-gates.py\", line 24, in test_distinct_entropy_graphs\n    self.assertFalse(verifier & {\"tos-uno-wallet-prover\", \"rand\", \"getrandom\", \"chacha20\"})\n    ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\nAssertionError: {'rand', 'getrandom', 'tos-uno-wallet-prover', 'chacha20'} is not false\n\n----------------------------------------------------------------------\nRan 1 test in 0.181s\n\nFAILED (failures=1)\n",
    "reconstructed_mutant_sha256": "cec6f6777deb6a45abfbc0b3c916af80aceae8ac21b52296e5090b94c31600fa",
    "original_from_count": 1,
    "original_to_count": 1
  },
  {
    "name": "wallet-lock-coverage",
    "path": "uno/prover/Cargo.lock",
    "from": "name = \"zeroize\"\nversion = \"1.9.0\"",
    "to": "name = \"zeroize\"\nversion = \"1.9.1\"",
    "command": "python3 uno/prover/tests/source-gates.py WalletGates.test_external_sources_are_covered_by_kernel_archive_checks",
    "restored_sha256": "647b9d9a09acd807ebb5077c005ffd0ffb047deae0dd8904560584b2e2e89459",
    "recorded_mutant_sha256": "a1e868515780343a8ee30c3b08113cf5c4d8085149d414df40fae9100d21286f",
    "exit_code": 1,
    "output": "test_external_sources_are_covered_by_kernel_archive_checks (__main__.WalletGates.test_external_sources_are_covered_by_kernel_archive_checks) ... FAIL\n\n======================================================================\nFAIL: test_external_sources_are_covered_by_kernel_archive_checks (__main__.WalletGates.test_external_sources_are_covered_by_kernel_archive_checks)\n----------------------------------------------------------------------\nTraceback (most recent call last):\n  File \"/home/tomi/tos/uno/prover/tests/source-gates.py\", line 34, in test_external_sources_are_covered_by_kernel_archive_checks\n    self.assertEqual(sources(ROOT), sources(KERNEL))\n    ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\nAssertionError: Items in the first set but not the second:\n('zeroize', '1.9.1', 'registry+https://github.com/rust-lang/crates.io-index', 'e13c156562582aa81c60cb29407084cdb54c4164760106ab78e6c5b0858cf64e')\nItems in the second set but not the first:\n('zeroize', '1.9.0', 'registry+https://github.com/rust-lang/crates.io-index', 'e13c156562582aa81c60cb29407084cdb54c4164760106ab78e6c5b0858cf64e')\n\n----------------------------------------------------------------------\nRan 1 test in 0.005s\n\nFAILED (failures=1)\n",
    "reconstructed_mutant_sha256": "a1e868515780343a8ee30c3b08113cf5c4d8085149d414df40fae9100d21286f",
    "original_from_count": 1,
    "original_to_count": 0
  },
  {
    "name": "statement-failure-source",
    "path": "uno/prover/src/lib.rs",
    "from": ".map_err(ProverError::Statement)?;",
    "to": ".map_err(|_| ProverError::EntropyUnavailable)?;",
    "command": "CARGO_NET_OFFLINE=true cargo test --manifest-path uno/prover/Cargo.toml --locked --release -j48 tests::invalid_public_statement_is_local_and_precedes_entropy -- --exact --nocapture",
    "restored_sha256": "3a111d728262b9bc97b482114f8c2c979c722b967e5cb47163660b45b23c50d7",
    "recorded_mutant_sha256": "662963e1614c5bbfdd61669dc5482dc9b7254c384dece09204b75cb3fa90a2f4",
    "exit_code": 101,
    "output": "   Compiling bulletproofs v5.3.0 (/home/tomi/tos/uno/crypto/vendor/bulletproofs)\n   Compiling tos-uno-crypto-prototype v0.1.0 (/home/tomi/tos/uno/crypto)\n   Compiling tos-uno-wallet-prover v0.1.0 (/home/tomi/tos/uno/prover)\n    Finished `release` profile [optimized] target(s) in 1.09s\n     Running unittests src/lib.rs (uno/prover/target/release/deps/tos_uno_wallet_prover-5e260dcbac387c2d)\n\nrunning 1 test\n\nthread 'tests::invalid_public_statement_is_local_and_precedes_entropy' (925086) panicked at src/tests.rs:142:5:\nassertion `left == right` failed\n  left: Err(EntropyUnavailable)\n right: Err(Statement(UNO_CRYPTO_ARGUMENTS))\nnote: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\ntest tests::invalid_public_statement_is_local_and_precedes_entropy ... FAILED\n\nfailures:\n\nfailures:\n    tests::invalid_public_statement_is_local_and_precedes_entropy\n\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s\n\nerror: test failed, to rerun pass `--lib`\n",
    "reconstructed_mutant_sha256": "662963e1614c5bbfdd61669dc5482dc9b7254c384dece09204b75cb3fa90a2f4",
    "original_from_count": 1,
    "original_to_count": 1
  }
]
```
