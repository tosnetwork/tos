# Fixed VK diagnostic freeze

`fixed-vk-debug.blake2b512` freezes the actual constructed `FixedVerifier` key
under the committed Rust toolchain, dependency revisions, features and lockfile.
The preimage is the UTF-8 bytes of `format!("{:?}", verifier.key)`, with **no
trailing newline**. Hash: unkeyed BLAKE2b-512, no personalization, hexadecimal
lowercase output. The initial preimage is 907512 bytes on the recorded Linux
x86_64 build. It includes the actual commitment parameters, fixed commitments,
permutation key and constraint-system data exposed by the derived Debug chain,
not merely the circuit selector.

This is a test-only diagnostic representation, **not canonical VK serialization**,
a TOS scheme identifier, or a production activation manifest. Formatting and
derived/cache fields can change the digest without changing cryptographic
semantics. Such changes intentionally fail the regression test and require
review, not silent acceptance. The fixed dependency does not expose the internal
VK through a serialization accessor; its `verifier-fingerprint` feature captures
a verification run's MSM and does not solve key serialization.

Reproduce with `cargo test --locked --offline --release -j48 vk_snapshot`.
For independent inspection, create a dedicated temporary directory and run:

```sh
UNO_VK_DEBUG_OUT=/absolute/temporary/path/fixed-vk.debug cargo test --locked --offline --release -j48 export_constructed_vk_debug_snapshot -- --ignored
```

The ignored export test checks the frozen digest before writing and never updates
the constant. An independent Node/OpenSSL-backed BLAKE2b-512 hash of the exported
bytes matched the committed constant when first recorded.

Do not regenerate this constant to make a dependency-update test pass. Treat it
as frozen from this commit onward. Any change must document the old/new dependency
graph, exact changed key/representation fields and circuit security rationale,
then revalidate affected vectors. Once vectors bind this artifact, a key change
invalidates that binding and requires a new versioned vector/manifest review.
Production still needs an explicit, reviewed canonical export covering verifier
parameters and actual VK commitments; do not promote this Debug digest to that role.
