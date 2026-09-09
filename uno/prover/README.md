# Wallet proof generator

This independent Rust crate generates the implemented SEND and COLLECT
cryptographic relations. It is not a transaction builder, wallet application,
Native admission rule or network activation mechanism. The model hides amounts,
not account identities or transfer relationships.

`prove` takes authenticated public statement data and the scalar witnesses and
range openings in specification order. It checks all witness equations and
openings, acquires fresh system entropy, creates the shared-witness AND proof
and aggregated range proof, and checks the result with the node verifier before
returning it. Range openings include zero padding. Public fields, fee and the
80-byte protocol domain use the same `PreparedStatement` implementation as the
verifier. No alternate transcript is defined here.

This crate has its own workspace and lockfile. It is not referenced by node
CMake or the verifier manifest, has no C ABI, and must never be added as a node
dependency. The wallet graph may contain entropy providers; the separately built
verifier graph must continue to pass its existing no-entropy gate unchanged.
The vendored range library exposes its explicit-generator proving API without
enabling its test feature. Vendored source checks remain those of `uno/crypto`.

The public API has no seeded-generator option. Tests alone can inject a generator
to reproduce every frozen SEND/COLLECT vector, including COLLECT k=1 through 8.
The production API obtains fresh OS entropy per call and reports acquisition
failure without returning a partial proof. Tests also generate fresh proofs for
all nine shapes and exercise failure before entropy acquisition.

Secret witness checks, AND first messages and the four inner-product L/R
constructions use constant-time MSM, unlike public-scalar verification and
public-challenge generator folding. This includes a recorded local vendored
adaptation; proof and transcript bytes remain unchanged.
The concrete generator is ChaCha12 with its state and buffered-output erasure
feature required by a `ZeroizeOnDrop` bound. The caller-owned seed buffer and
temporary mask vectors are zeroized on drop. Borrowed
secrets remain the caller's responsibility. This is not a claim of complete
process-memory erasure, platform side-channel certification, or recovery from
allocation failure or every possible upstream panic. In particular,
`from_seed(*seed)` passes a by-value seed copy: compiler/callee temporaries are
not guaranteed erased, and recovering that seed can recover witness scalars
from public responses. This residual is not just an incidental derivative.
Wallet integration must
handle its own secret storage and process error boundary.

Run offline with the pinned repository toolchain:

```sh
CARGO_NET_OFFLINE=true cargo test --manifest-path uno/prover/Cargo.toml --locked --release -j48
CARGO_NET_OFFLINE=true python3 uno/crypto/tests/kernel-gates.py
CARGO_NET_OFFLINE=true python3 uno/prover/tests/source-gates.py
```

The wallet has a standalone CTest project, not a default node CTest target:

```sh
cmake -S uno/prover -B build-wallet-tests
CARGO_BUILD_JOBS=48 ctest --test-dir build-wallet-tests --output-on-failure --no-tests=error -j1
```

The dedicated wallet workflow provisions locked sources before running these
tests offline. It includes proof generation, source gates, and registration
checks; a successful command reporting zero Rust tests is rejected. Local
negative-control records are in
`doc/measurements/uno-v2-wallet-ci-controls.md`; those manual mutations are not
reapplied by CI. This does not register an engine or establish M2 acceptance.
