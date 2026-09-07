# Confidential balance verification kernel

This unactivated kernel implements SEND and COLLECT mathematical relations.
It hides amounts, not account identities or transfer relationships. It is not a
transaction executor, account-state authenticator, custody protocol or activation.

The active Cargo graph no longer contains Orchard/Halo2. The old version-0
symbols are not exported. The retired declaration header exists only so legacy
non-cryptographic tests remain buildable; it is not a compatibility verifier.
Old Note history fixtures are historical measurement data, not kernel vectors.

## Implementation

- Eight SEND equations share six witness responses. Six 64-bit range objects
  are derived from the statement and padded to eight.
- COLLECT has 2k+5 equations and 2k+4 shared witnesses/range objects, padded to
  a power of two. The caller supplies the permitted K; tests cover 1 through 8.
  Eight is a research candidate, not a production constant or default.
  This implementation rejects host policies above 64 before allocation; that
  capability ceiling is not a production resource-budget recommendation.
- Each Sigma equation and both range residuals are checked separately.
  Exact MSM remains available within each equation. No verifier RNG is used.
- The reference prover is test-only and retains random masks. No production
  wallet prover, full transaction transcript codec, rent or host integration is
  supplied here.

The native entry point is `uno_crypto_verify_v1`. See [ABI.md](ABI.md) and
[TRANSFER_TRANSCRIPT.md](TRANSFER_TRANSCRIPT.md). Every limit is explicit.
The caller must obtain those limits and context from the authenticated policy.
A proof does not establish that the supplied context is authentic or complete.

## Build and test

Provision exactly the locked dependencies once, then build offline:

```sh
CARGO_NET_OFFLINE=false cargo fetch --locked
CARGO_NET_OFFLINE=true cargo build --locked --offline --release -j48
CARGO_NET_OFFLINE=true cargo test --locked --offline --release -j48 --lib
python3 tests/kernel-gates.py
```

Configure the parent build with `TOS_UNO_CRYPTO_PROTOTYPE_TESTS=ON`.
The real ABI executable is in `all-tests`; CTest registers the Rust tests,
frozen C++ vectors, dependency/source gates and generated-header drift test.
The option retains its existing opt-in meaning. CI must explicitly enable it.

`tests/run-mutations.py --output <new-evidence-dir> --target-dir <scratch-cargo-dir>`
copies the crate into a temporary source directory, runs positive controls,
removes every independent equation check and restores the source. It rejects
compilation failures as mutation evidence. Logs include actual test results.

The C++ ABI harness installs a Linux seccomp entropy trap before first
verification. A child making a real getrandom call must die with SIGSYS.
This detects OS entropy/device access, not RDRAND or every possible future
call path. The normal dependency graph, source guards, source manifests,
reachable-symbol review and runtime controls must be considered together.
Absence of a rand package alone is not a call-graph proof.

## Source and review

[SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) records exact sources and local changes.
Literal review records belong under `~/memo/reviews/`, not in this repository.
The kernel milestone was independently reviewed; accepted fixes were retested.
See `../../doc/uno-v2-kernel-review-disposition.md`. This does not close full M2
or host activation gates. Existing research timings are not measurements of this build.

Mutation runners and the independent C transcript comparison are manual
point-in-time evidence, not registered CTest enforcement. CTest does enforce
the frozen transcript/vector results, including the vendor set/hash negative
controls. Replacing a frozen reference requires rerunning its independent
generator and review; regenerating expected bytes alone is not validation.
Old ignored archives may still exist under `target/`; only a fresh build of the
current crate supports the statement above about exported symbols.
