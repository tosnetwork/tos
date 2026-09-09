# Kernel sources and local adaptation

This is source provenance, not a claim that pinning establishes cryptographic
security. Refreshes require source review, vectors, negative controls and a
new review record. No global Cargo patch redirects unrelated dependencies.

| Upstream source | Acquisition mirror | Version/tag | Shared immutable revision | Shared annotated tag object |
|---|---|---|---|---|
| xelis-project/curve25519-dalek | tosnetwork/curve25519-dalek | 5.0.2 / v5.0.2 | 10042b03cfc92e505e9d33d2827d5c0f0d36989a | e527e3a83b2647ac8e82fd27158a55593717e25e |
| xelis-project/bulletproofs | tosnetwork/bulletproofs | 5.3.0 / v5.3.0 | 961bf3f8c2baa1e4d2a87e8e1f5b6f12e7fe6c82 | def04efbf9d435a22306eae2c1a967f15ad43239 |
| xelis-project/merlin | tosnetwork/merlin | 4.1.0 / v4.1.0 | ee857c79347e0e2201e5192523faea13ac9bf451 | fb9aae0179e42c7e4872d26485f19c1a03710182 |

The mirror changes acquisition location, not upstream authorship or provenance.
Each mirror must contain the exact commit and original signed annotated tag
object above; creating a replacement tag is not equivalent, even if it peels
to the same commit. Git object identity is content-addressed. The local raw tag
fixtures and `upstream_git_blobs` remain unchanged. Cargo fetches dalek/Merlin
from the mirrors; Bulletproofs remains vendored, with its mirror available for
source acquisition and refresh verification. No cryptographic Rust source is
changed by the acquisition migration.

URL-bearing Cargo manifests and lockfiles necessarily change bytes. The vendored
manifest's `locked-build-inputs` patch declares this URL delta in its `after`
text; subsequent byte offsets and its current-file SHA-256 change accordingly.
Its `before` bytes and upstream blob stay fixed. These expected local metadata
changes must not be confused with changing an upstream commit or signed object.

The tags and peeled commits were rechecked with git ls-remote on 2026-09-07.
Raw annotated tag objects are retained in fixtures; the gate recomputes their
Git object hashes and checks their target commits offline. This detects changes
to the recorded association, not a future remote tag move. Refresh review must
query the remote again. On 2026-09-09, fresh mirror fetches reproduced all
three exact raw tag objects; GitHub's tag API reported `verified=true` and
`reason=valid` for each. This is a recorded remote verification result, not an
offline trust-chain check performed by the source gate or a cryptographic
security endorsement of the release.

## Local Bulletproofs delta

The required internal generators and range residual construction are private
upstream APIs. Rather than silently alter an external checkout, this crate
vendors the pinned source (license preserved) and records upstream Git blobs
and adapted SHA-256 hashes in vendor/bulletproofs/SOURCE_MANIFEST.json.

The manifest's `local_patches` records all five adapted/added files, each with
an ID, path, rationale, upstream Git blob (null for an added file), and exact
before/after UTF-8 edits. Offsets address final file bytes, not character indices;
edits are undone from right to left without fuzzy matching. The gate reconstructs
every upstream file and compares its Git blob identity with the recorded base.
Unpatched files must equal their upstream blobs; an added file must reconstruct
to empty bytes. The required patch IDs/paths are also fixed in the source gate,
so restoring upstream and deleting a required declaration does not pass.

Consequently, updating only current-file SHA-256 hashes no longer permits source
drift, an extra build script, or loss of the constant-time prover adaptation.
Changing the declared edits or upstream base is an explicit review event, not
an automatic refresh operation. The upstream blob map was checked against the
pinned commit when this patch inventory was recorded. The offline gate binds to
that recorded map; it is not a remote attestation or protection against a party
allowed to change the gate and provenance records together. Git SHA-1 is used
only for existing object-ID compatibility; current bytes also retain SHA-256.

Local differences are limited to:

1. Pin transitive dalek/Merlin dependencies by full revision and acquire those
   same objects from the distribution mirrors; omit standalone
   upstream test/benchmark target declarations whose files are not vendored.
2. Add range_proof/deterministic.rs with independent IP/poly checks, retaining
   the original transcript events. No batch_factor, proof factor or fixed
   substitute randomness is used.
3. Import alloc::vec and gate the convenience verify_batch method on std:
   the pinned no-default-features build otherwise references a missing rand.
4. Add kernel-test-only re-exports for the independent residual negative test.
   The normal dependency tree does not enable the test feature or std RNG.
5. Use constant-time MSM for the four inner-product prover L/R constructions
   whose scalars depend on non-public vectors. Public-challenge generator folding
   and verifier equations remain unchanged. This changes the generating algorithm,
   not the proof format, transcript or verifier relation; frozen proofs must stay
   byte-identical. It is not a certification of all platform side channels.

The prover and generic randomized verification APIs remain in the vendored
source; they are not called by the kernel. The separately built wallet prover
uses the explicit-generator proving API, with the local L/R adaptation above.
Keeping their source is not permission to call them in consensus. The local
kernel's verifier call closure and normal dependency graph are separately gated.

## Fork differences requiring continuing review

The source comparison identifies the following review categories. This summary
is not a proof that every fork modification is harmless:

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

The separate wallet graph also relies on chacha20 0.10.2's `zeroize` feature.
Refresh review must inspect both `ChaChaCore::drop` (state/key erasure) and the
generator hook called by `BlockRng::drop` (buffered-output erasure), not merely
the `ZeroizeOnDrop` marker. The marker enforces feature presence, while pinned
archive-byte checks bind the reviewed implementation. Seed-by-value compiler
temporaries remain outside the erasure claim. This wallet dependency is not
introduced into the normal node-verifier graph.

## What the gates establish

For first-party formatting, use `cargo fmt -p tos-uno-crypto-prototype`, not
`cargo fmt --all`: the latter traverses path dependencies and can rewrite the
vendored source. Vendored formatting is retained exactly as authenticated by its
manifest; formatting changes there require the same explicit source review and
manifest update as other dependency changes. Formatting is not a reason to bypass
the source-integrity gate. No blanket formatting of the dependency is authorized.

- Full revision/version identity and cached git checkout status, including
  untracked and ignored files; only Cargo's `.cargo-ok` marker is exempted.
- Exact mirror URLs and unchanged full revisions in the verifier, wallet,
  vendored dependency/dev-dependency declarations and both lockfiles. The
  ordinary offline gate checks the declared acquisition identity, not remote
  availability. Migration testing must separately use fresh Cargo git caches.
- Every locked registry archive checksum, plus extracted source bytes compared
  with the authenticated archive used by Cargo.
- Exact vendored file set and source byte hashes, including new files, plus
  reconstruction of the recorded upstream bytes through the declared local
  patch set. This gate runs both in kernel CTest and via the wallet's source gate.
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
