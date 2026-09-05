# UNO crypto prototype

Not registered in the node, not a production verifier, and not an activation
manifest. This isolated crate starts M2 dependency/API validation without adding
the upstream transaction, consensus or wallet backend to the host.

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
and authenticated configuration. Contextual public-value checks, anchor/nullifier
state, output-only authorization, host integration and FFI are not implemented
by this verifier. No encryption or production activation is shipped.
