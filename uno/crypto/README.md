# UNO crypto prototype

Not registered in the node, not a production verifier, and not an activation
manifest. This isolated crate starts M2 dependency/API validation without adding
the upstream transaction, consensus or wallet backend to the host.

## Reproduction

From this directory, run `cargo test --locked -j48`. Rust 1.97.1 is selected by
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
the actual key-version assertion failed. This is not a VK fingerprint, bundle
verification or proof of ownership.

`validate_proof_shape` is a separate allocation-free precheck for the pinned
profile. It requires nonzero configured action/byte limits and an exact proof
length of `2720 + 2272 * actions`, computed with checked arithmetic. Tests compare
against the pinned dependency for 1–32 actions and reject short/padded proofs,
empty bundles and resource/overflow boundaries. This checks lengths, not proof
contents, and must follow profile selection before expensive verification.

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
the TOS authorization digest, run real positive/negative proof and signature
vectors, and validate hybrid encryption separately. No proof/signature
verification, proving-key construction, encryption or FFI entry point is shipped
by this prototype yet.
