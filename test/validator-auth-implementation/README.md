# Production library checks

These drivers link `validator/auth` and the `tos-validator-auth` crate. They do
not compile the old standalone codec fixtures as substitutes for production
libraries. The Python reference is used as an independent public-data oracle.

Build with `TOS_BUILD_P0_IMPLEMENTATION_TESTS=ON`, then build the targets
`test-p0-implementation`, `test-p0-transfer`, `test-p0-transport` and
`test-p0-cells`. Build the Rust `conformance` binary with the workspace manifest
`tosctl/src/Cargo.toml`, package `tos-validator-auth`.

- `check.py`: exact binary bytes, malformed inputs, cryptographic admission and
  signatures, complete certificate verification, native AuthBytes/BOC bounds.
- `check_lifecycle.py`: per-identity state effects against the frozen reference.
  Authority callbacks are controlled test inputs, not a proof implementation.
- `check_transport.py`: use `--driver` with either the native transport driver or
  the Rust conformance binary. Checks framing, binary shape and correlation.
  Endpoint semantics and authenticated response claims are separate work.
- `mutations.py`: isolated C++ source copies, successful compilation, assertion
  failures and restored baseline. Requires `pkg-config libsodium` and `--rust`.
- `rust_mutations.py`: isolated Rust crate, successful compilation, assertion
  failures and restored baseline. Requires a built native `--cpp` driver and
  dependencies already present in the Cargo cache.
- `cell_mutations.py`: edits only the configured build-tree cell source copy;
  links and executes against the actual native VM. Takes `--build` and `--out`.

Every mutation report records a compiled mutant and an assertion failure.
Abnormal executable exits are harness errors. Never count a compiler failure,
crash, missing dependency or reference-only mutation as production guard proof.

The CI workflow records the actual checked HEAD and uploads evidence. Local
results do not establish Ubuntu or testnet acceptance. The full build remains a
separately authorized manual workflow.
