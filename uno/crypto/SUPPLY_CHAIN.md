# Kernel sources and local adaptation

This is source provenance, not a claim that pinning establishes cryptographic
security. Refreshes require source review, vectors, negative controls and a
new review record. No global Cargo patch redirects unrelated dependencies.

| Source | Version/tag | Immutable revision | Annotated tag object |
|---|---|---|---|
| xelis-project/curve25519-dalek | 5.0.2 / v5.0.2 | 10042b03cfc92e505e9d33d2827d5c0f0d36989a | e527e3a83b2647ac8e82fd27158a55593717e25e |
| xelis-project/bulletproofs | 5.3.0 / v5.3.0 | 961bf3f8c2baa1e4d2a87e8e1f5b6f12e7fe6c82 | def04efbf9d435a22306eae2c1a967f15ad43239 |
| xelis-project/merlin | 4.1.0 / v4.1.0 | ee857c79347e0e2201e5192523faea13ac9bf451 | fb9aae0179e42c7e4872d26485f19c1a03710182 |

The tags and peeled commits were rechecked with git ls-remote on 2026-09-07.
Raw annotated tag objects are retained in fixtures; the gate recomputes their
Git object hashes and checks their target commits offline. This detects changes
to the recorded association, not a future remote tag move. Refresh review must
query the remote again. No signature/trusted-release-attestation claim is made.

## Local Bulletproofs delta

The required internal generators and range residual construction are private
upstream APIs. Rather than silently alter an external checkout, this crate
vendors the pinned source (license preserved) and records upstream Git blobs
and adapted SHA-256 hashes in vendor/bulletproofs/SOURCE_MANIFEST.json.

Local differences are limited to:

1. Pin transitive dalek/Merlin dependencies by full revision; omit standalone
   upstream test/benchmark target declarations whose files are not vendored.
2. Add range_proof/deterministic.rs with independent IP/poly checks, retaining
   the original transcript events. No batch_factor, proof factor or fixed
   substitute randomness is used.
3. Import alloc::vec and gate the convenience verify_batch method on std:
   the pinned no-default-features build otherwise references a missing rand.
4. Add kernel-test-only re-exports for the independent residual negative test.
   The normal dependency tree does not enable the test feature or std RNG.

The upstream prover and generic randomized verification APIs remain in the
vendored source for differential tests; they are not called by the kernel.
Keeping their source is not permission to call them in consensus. The local
kernel's verifier call closure and normal dependency graph are separately gated.

## Fork differences requiring continuing review

The prior source comparison is recorded at
~/memo/TOS_CONFIDENTIAL_BALANCE_E_XELIS_RUST_REVIEW.md. These are reviewed
categories, not a proof that every fork modification is harmless:

- dalek contains ECDLP and explicit variable-time scalar functionality, not just
  type compatibility. The kernel does not enable ECDLP. The earlier comparison
  used upstream 07bef73ff85998a206cd2cea7f2605c801d0d1c9 and
  cb0d157fa3149d5e9b6bab68c3b68b45e504cab5; new upstream arithmetic and backend
  changes still need assessment before refresh.
- Bulletproofs v5.0.0 to the selected commit changes batch collection, final
  transcript binding (including final inner-product scalars), RNG traits and
  dependencies. The new deterministic path does not erase those differences.
- Merlin v3.0.0 to the selected commit replaces its local STROBE module with
  strobe-rs, changes label lifetimes and updates RNG traits. Reusing its name
  does not establish byte compatibility; the independent C vector tests it.

Security fixes upstream do not automatically reach any of these forks. Before
a release, recheck upstream changes and advisories, build-script/macro changes,
features, backend selection and licenses. This delivery does not claim a new
complete RustSec audit; cargo-audit was not installed on the build host.

## What the gates establish

For first-party formatting, use `cargo fmt -p tos-uno-crypto-prototype`, not
`cargo fmt --all`: the latter traverses path dependencies and can rewrite the
vendored source. Vendored formatting is retained exactly as authenticated by its
manifest; formatting changes there require the same explicit source review and
manifest update as other dependency changes. Formatting is not a reason to bypass
the source-integrity gate. No blanket formatting of the dependency is authorized.

- Full revision/version identity and cached git checkout status, including
  untracked and ignored files; only Cargo's `.cargo-ok` marker is exempted.
- Every locked registry archive checksum, plus extracted source bytes compared
  with the authenticated archive used by Cargo.
- Exact vendored file set and source byte hashes, including new files.
- No rand/getrandom provider in the normal runtime graph; rand_core traits are
  not themselves an entropy source. Build/prover-test dependencies are separate.
- Conservative lexical checks on kernel entry/independent range code, combined
  with a reviewed call path: FFI -> relation/shape -> shared AND -> independent
  range -> deterministic transcript/generators/field/group operations.
- Real verification under an OS-entropy/file-read trap, with a firing canary.

Neither lexical matching nor successful execution proves every reachable path
is entropy-free. Review the full locked closure (including macros, assembly,
indirect calls and hardware RNG) on each change. Runtime tests are not evidence
for architectures or backends they did not exercise.

## Independent primitive reference

tests/transcript-reference.c was compiled against Avatar
ba0aab1486eaec640c5fb9d53254688faa3db1d1, src/crypto/merlin/at_merlin.c,
using its existing inline Keccak implementation. It matches the Rust known
answer after a 1024-byte message, a nontrivial u64, challenge, response and
second challenge. This covers transcript framing/state evolution only, not
full SEND/COLLECT or Avatar's limited range verifier. The C reference is not
linked into the kernel. Source acquisition is explicit; absence must fail the
manual differential command, not silently skip it. The frozen known answer
runs in every Rust test suite.

The C++ FFI corpus contains independently consumed full Rust-generated proofs
for SEND and COLLECT k=1..8; Rust regenerates and compares the exact bytes.
The test prover uses a fixed seed only for reproducibility. Wallet proving
must use fresh cryptographic randomness.
