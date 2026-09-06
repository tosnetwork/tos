# UNO crypto prototype

Not registered in the node, not a production verifier, and not an activation
manifest. This isolated crate starts M2 dependency/API validation without adding
the upstream transaction, consensus or wallet backend to the host.

The [private-transfer transcript candidate](TRANSFER_TRANSCRIPT.md) now derives
a signing digest from typed data and exercises it with a real proof. It is not
yet connected to the C++ ABI or host transaction admission.

## Reproduction

From this directory, run `cargo test --locked --release -j48`. Rust 1.97.1 is selected by
`rust-toolchain.toml`; commit `Cargo.lock` and do not update dependencies implicitly.
The root dependency disables defaults and explicitly enables `circuit`,
`multicore` and `std`.

Candidate Orchard 0.15.5 is pinned to full git revision
`29d1d55db62153dcaeef8ef631c8991c53ed1248` (the peeled 0.15.5 release tag).
The initial lock resolves halo2_gadgets 0.5.0, halo2_proofs 0.3.5,
pasta_curves 0.5.2 and reddsa 0.5.2. Registry checksums and the remaining dependency
versions are recorded in Cargo.lock. This is a reproducible candidate, not a
claim that all dependencies have been audited or approved.

## Explicit profile boundary

Only `BundleVersion::orchard_v2()` paired with
`OrchardCircuitVersion::FixedPostNu6_2` passes the prototype gate. The historical
insecure circuit and subsequent Orchard/Ironwood profiles are rejected, including
mismatched bundle/circuit pairs. A 4-by-3 test matrix checks this boundary;
removing either comparison makes unsupported pairs pass and the test fail.

This function checks selectors only and must not be exposed as a transaction
verification API. `FixedVerifier::new` separately reconstructs an internal VK
using the explicit fixed circuit; callers cannot supply or replace that key.
Its profile check reads the constructed key's circuit version. Key construction
unwinds are converted to an error, not process-abort or out-of-memory failures.
The construction test was mutation-checked by selecting the historical circuit:
the actual key-version assertion failed. This construction check is not a VK
fingerprint or proof of ownership.

A separate [frozen diagnostic snapshot](fixtures/README.md) now hashes the actual
constructed VK's complete Debug representation. This catches key changes that
leave selector checks green, including differing historical key material with a
falsely relabelled selector. It is deliberately test-only, not canonical binary
serialization or a production VK identity manifest.

`validate_proof_shape` is a separate allocation-free precheck for the pinned
profile. It requires nonzero configured action/byte limits and an exact proof
length of `2720 + 2272 * actions`, computed with checked arithmetic. Tests compare
against the pinned dependency for 1–32 actions and reject short/padded proofs,
empty bundles and resource/overflow boundaries. This checks lengths, not proof
contents, and must follow profile selection before expensive verification.

## Typed-bundle cryptographic verification

`FixedVerifier::verify_bundle` checks the profile and configured proof shape,
then verifies the actual proof, every action's spend authorization signature,
and the binding signature against the bundle-derived binding validating key.
Both signature classes use the same caller-supplied 32-byte digest. Verification
is read-only and sequential; no verifier-side random batch acceptance is used.
The input is an already allocated `Bundle<Authorized, i64>`: this is not a wire
decoder, and these checks do not establish pre-allocation bounds at ingress.

The real-proof test constructs a fresh output-only bundle with two padded
actions and a 5000-nanotomi output, proves it with the fixed proving key, and
signs an arbitrary fixture digest. It accepts the valid bundle and rejects a
different digest, a damaged proof, zeroed spend signatures, and a zeroed binding
signature independently. This fixture does not authorize issuance or implement
the TOS transaction digest. Test-only randomness is pinned through `rand`.

The fixture also recovers that nonzero note, builds its depth-32 single-leaf
membership path, and proves a spend with a 4900-nanotomi output and public
valueBalance 100. It signs with the real spending key, not only dummy keys.
Replacing only the real spend's signature is rejected while dummy signatures,
proof and binding signature remain intact. Changing valueBalance to 101 with
the original proof and signatures is rejected by the binding check. Recovery
uses the dependency's encryption solely for this fixture; it is not TOS hybrid
encryption, an authenticated chain anchor, or a host-authorized fee debit.

## Primitive field decoding

`decode::decode_bundle` accepts borrowed, fixed-width Action fields and proof
bytes, not a serialized TOS transaction. It restricts the profile, validates
resource/proof-length limits before copying, parses flags without masking
reserved bits, rejects the asymmetric `i64::MIN` balance, and decodes anchor,
cv_net, nullifier, rk and cmx using the pinned primitive APIs. The checked Action
constructor also rejects identity rk and invalid/identity epk. Ciphertexts and
signature bytes are preserved unchanged. Signature canonicality and validity
remain the verifier's responsibility, not a success claim of decoding.

Tests round-trip both generated real bundles through this decoder and verify
them again. Separate structural fixtures deliberately have invalid proof/signature
contents: decoding must preserve these bytes, not authorize them. Malformed-field,
profile, flags, balance and resource tests were mutation-checked; bypasses yielded
successful decoding of invalid inputs. Clearing ciphertext bytes failed the
preservation assertion. These mutations were restored. Limits on allocation in
this function do not bound the caller's earlier wire parsing or the entire process.
The TOS Cell schema, profile-tag mapping, contextual flags policy,
hybrid ciphertext envelope and external authorization digest remain separate work.

When the public spend-enable flag is false, both the decoder and typed verifier
require `Anchor::empty_tree()`. A generated output-only bundle using field zero
as its anchor passes the underlying proof, spend signatures and binding signature,
but is explicitly rejected by this UNO rule. Bypassing either entry point's
check independently makes its negative test accept the bundle; both were restored.
With spends enabled this rule does not authenticate an anchor against host state
or distinguish real from dummy inputs. Transaction-kind flags and host anchor
membership remain required, separate checks.

## Context-bound verification

`FixedVerifier::verify_in_context` reads valueBalance and permissions from the
same typed bundle it cryptographically verifies. Logical `PublicContext` variants
express Transfer fee, Unshield amount plus fee, and the four output-only amounts.
All amounts are u128 nanotomi; addition is checked before symmetric i64 narrowing.
The typed variants cannot carry an unrelated Transfer principal or settlement fee.
Their equations match the existing C++ `uno/core/bundle-context.h` prototype;
an initial [shared 26-case corpus](../testdata/README.md) now checks both implementations
against the same acceptance oracle. This is not exhaustive equivalence or FFI
integration. These Rust variants are not wire discriminants.

The six-context permission/value matrix and wide arithmetic boundaries pass.
Real generated bundles pass matching contexts and reject a changed public amount;
a damaged proof still fails through the combined entry point. Seven mutations
independently bypassed arithmetic bounds, value/permission checks, or either half
of combined verification; each accepted an invalid fixture and failed its test.
All were restored. `verify_bundle` remains a lower-level cryptographic API, not
an admission API. Neither entry point authenticates a claimed deposit, genesis
allocation, refund record, fee source, destination or caller-supplied digest.

## Source review, 2026-09-05

- [Pinned bundle version implementation](https://github.com/zcash/orchard/blob/29d1d55db62153dcaeef8ef631c8991c53ed1248/src/bundle.rs)
  distinguishes historical, fixed and later profiles. Version selection changes
  flag interpretation and canonical-proof-size enforcement.
- [Pinned circuit implementation](https://github.com/zcash/orchard/blob/29d1d55db62153dcaeef8ef631c8991c53ed1248/src/circuit.rs)
  exposes explicit circuit variants and key construction; the corrected and
  historical keys are not interchangeable.
- [Pinned batch verifier](https://github.com/zcash/orchard/blob/29d1d55db62153dcaeef8ef631c8991c53ed1248/src/bundle/batch.rs)
  accepts a caller-supplied 32-byte signature digest and checks proofs plus spend
  and binding signatures. Its empty-batch success must not authorize an empty
  user transaction in a future adapter.
- [Release security disclosures](https://github.com/zcash/zcash/releases)
  and [identity-point advisory](https://github.com/ZcashFoundation/zebra/security/advisories/GHSA-452v-w3gx-72wg)
  are review inputs, not evidence of completed dependency auditing.

Before production use: inspect all applicable advisories and licenses across the
lock, record transitive source revisions/features, construct and fingerprint the
allowed VK, enforce canonical lengths and full point/field decoding, integrate
the TOS authorization digest, expand authoritative/differential and adversarial
vectors beyond the generated fixture, and validate hybrid encryption separately.
The caller's digest and limits must eventually come from frozen TOS core encoding
and authenticated configuration. Contextual public-value equations are checked
by the combined API, but authenticated context derivation, anchor/nullifier state,
output-only authorization and host integration remain unimplemented.
No encryption or production activation is shipped.

An initial [read-only C ABI](ABI.md) now exports the combined decoder/verifier
through a static library. Generated positive/negative fixtures exercise the export
from Rust; separate C++ programs test argument/decoding failures and real exported
proof/signature fixtures across the linked ABI. This is not yet production host linking or complete cross-language ABI
acceptance; ownership, panic limits, remaining tests and reproduction are in ABI.md.

The root CMake build now offers `TOS_UNO_CRYPTO_PROTOTYPE_TESTS=ON` (default OFF)
for the Rust suite and both C++ callers through CTest. This is test-only linking,
not node/engine registration. See [ABI.md](ABI.md#opt-in-cmakectest-integration).

## Optional proving measurements

The real-bundle test can reuse its proving key to generate fresh randomized
proofs repeatedly for its output-only and real-spend fixtures:

```sh
UNO_PROVING_SAMPLES=100 cargo test --locked --offline --release -j48 \
  --lib real_bundle_requires_proof_and_signatures -- --nocapture
```

Use the same `CARGO_TARGET_DIR` as CMake when sharing that build. The opt-in count
must be 3 through 1000; an absent variable disables repetitions. The test prints
proving-key construction time separately, each raw proving sample, median and
maximum. Nearest-rank p95/p99 are printed only with at least 100 samples. The
ordinary fixture proof warms the prover before these repetitions. Each sample
times only `create_proof`: cloning the unsigned bundle, builder/encryption work,
signing and subsequent complete verification are outside the interval.

Every generated bundle must verify, and consecutive proofs must differ; returning
a cached valid proof cannot masquerade as near-zero proving time. Require a zero
test exit before using any partial stdout. Samples reuse the same witnesses and
key with fresh proof randomness; they are not independent wallet workloads, cold
starts, maximum-action bundles or memory measurements. The fixtures do not use
the planned hybrid encryption. Record hardware, source revision, dependency lock
and runtime thread configuration. Client proving occurs before submission, so
these numbers inform wallet/expiry budgeting, not a serial block-slot deadline.

## Note-tree frontier prototype

`tree::NoteTree` reuses the pinned depth-32 Sinsemilla tree implementation and
canonical node encoding. Ordered `append_batch` stages a private frontier, checks
remaining capacity including caller-supplied refund reservations, and rejects
noncanonical nodes without modifying the source. `snapshot`/`restore` preserve
the last leaf, its position and at most 32 prior subtree roots. This is a Rust
in-memory representation, not a frozen wire or Cell StateV2 encoding.

The real-spend fixture now builds its anchor from the complete two-Action output
tree, including the padded output, and checks its witness root against the
restored frontier before generating a valid spend proof. Both subsequent spend
outputs are then appended. Full-layer reduction tests independently check the
frontier's carry logic through 65 leaves; synthetic near-capacity snapshots test
the final leaf, reserved space and exhaustion without allocating billions of
leaves. These synthetic snapshots do not authenticate historical commitments.

The caller must authenticate the snapshot and reservation count, enforce the
eventual cmx duplicate policy, and retain full output/ciphertext history for
wallet scanning and witnesses. A frontier is insufficient for that history.
The [tree C ABI prototype](ABI.md#tree-transition-abi-prototype) now exposes this
transition to linked C++ callers. A bounded C++ frontier Cell codec is now tested
through BoC restoration and continued append; authenticated StateV2 storage,
anchor-window integration and production engine registration remain absent. The existing locked incrementalmerkletree
0.8.2 dependency moved from test-only to runtime; no dependency revision changed.
