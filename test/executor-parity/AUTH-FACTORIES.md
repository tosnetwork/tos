# Original authentication factory root comparison

The unchanged default authentication and ML-DSA factories retain all native
assertions and calls. The frozen profile records 41 tests and 1,132 calls: 1,115
at version 16 and 17 historical calls. Only version 16 is replayed in Rust:
1,030 Transaction/Account/ShardAccount root triples and 85 VM refusals. These are
individual original-input replays, not continuous Rust Account/cache carry or a
complete instruction/context coverage denominator. Optional factory CLI variants
are outside this fixed profile.

The capture requires clean tracked source and writes a source/tree/harness/profile
receipt with executable paths and SHA-256 digests. `--allow-dirty` and
`--record-profile` are author diagnostics; their dirty/candidate results cannot
pass artifact validation. Executable digests identify tools; they do not alone
prove that arbitrary supplied tools were built from the recorded source. Hosted
execution depends on the reviewed workflow build steps and successful-suite
receipts. Source and tool equivalence must be checked when reusing local binaries.

With `FUNC_PATH`, `FIFT_PATH`, `TOL_PATH` and `EMULATOR_PATH` pointing at built
tools, and cryptography installed, run the collector separately for each family:

```sh
python test/executor-parity/auth_factory_roots.py --family auth \
  --driver build-cargo/debug/examples/pq-tx-parity --output artifacts/auth-factories/auth
python test/executor-parity/auth_factory_roots.py --family mldsa --build build \
  --signer build-auth-signer/test-mldsa44-sign \
  --driver build-cargo/debug/examples/pq-tx-parity --output artifacts/auth-factories/mldsa
python test/executor-parity/test_auth_factory_artifacts.py \
  --artifacts artifacts/auth-factories --output artifacts/auth-factory-controls.json
python test/executor-parity/test_auth_factory_bundle.py \
  --artifacts artifacts/auth-factories --controls artifacts/auth-factory-controls.json \
  --output artifacts/auth-factory-bundle-controls.json
```

Build the separate test-only signer with CMake in `test/mldsa-auth`; signing is
not linked into the VM. The ML-DSA factory uses the native build's emulator,
FunC, Fift and Tolk. Retain their source/build identities with local evidence.

Transport preserves original bytes in canonical blocks of at most 1 MiB, with
256 blocks, a 1 MiB manifest and a 64 MiB aggregate ceiling including the manifest.
The large-account row requires the test adapter's 4 MiB row limit. Existing
generated/wallet artifact budgets remain 16 MiB. Download metadata is bounded
before extraction; logical sizes, block order/population/digests, frozen inputs,
configurations, native roots and Rust transcripts are checked again afterwards.

Each family has 12 content corruption controls, including coherent corruption of
native BOCs and both transcripts. The bundle runner checks 14 transport/identity/
budget corruptions using modeled CI identities. It is not dual-architecture
execution evidence. Final comparison requires actual successful `release-wallet`
receipts and selects their matching artifacts for both architectures; all
supplied candidates are validated, including unselected attempts. Local controls
do not substitute for hosted acceptance or independent review.
