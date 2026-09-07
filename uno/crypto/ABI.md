# Borrowed verification ABI v1

This is a native process interface, not a TL-B constructor, network proof
profile or M0 freeze. Version 0 is retired; the static library does not export
`uno_crypto_verify_v0` or the old Note-tree function.

The existing boundary discipline is retained: every exported entry contains
the entire call in catch_unwind, no AssertUnwindSafe, no pointer retention or
ownership transfer, and checked bounded_span before nonempty slice creation.
Both Cargo profiles require unwind; cfg(panic = "abort") is a compile error.
OOM abort, process termination and invalid caller allocations are not
recoverable panics. No mutable verifier cache or partially initialized key is
retained. Generator construction is currently per call.

The caller supplies initialized immutable allocations valid until return.
Null is permitted for an empty receipt-ID array only; numeric checks do not
establish allocation validity. Arrays contain canonical 32-byte compressed
Ristretto points or canonical little-endian scalar encodings as specified by
the field, never native Rust objects. Padding and pointer layout are a C ABI,
not serialized network bytes.

## Request

`UnoCryptoLimits`: u64 max_balance and max_value in nanotomi, plus size_t
max_collect, max_context_bytes and max_proof_bytes. All are mandatory and
nonzero; 0 < max_value <= max_balance. No defaults are installed.
Policy is trusted caller input, not attacker-provided limits. A future host
must resolve and admit it from authenticated configuration; this library is
not that admission layer. K=8 is exercised, not hardcoded as the only limit.

The request has a version, relation discriminator, limits, and borrowed
(context, points, receipt_ids, commitments, responses, proof) arrays.
On the supported 64-bit Linux target limits occupy 40 bytes, request 144 bytes,
context offset 48. Rust and C++ assert these sizes.

SEND points, in order:
`P_A,P_B,C_old,D_old,C_new,D_new,C_transfer,D_transfer_A,D_transfer_B,J`.
There are no receipt IDs, eight Sigma commitments, six shared responses.

COLLECT points:
`P,C_old,D_old,C_new,D_new,J0`, followed by k triples `C_i,D_i,J_i`.
The k receipt IDs must be strictly increasing and distinct; there are 2k+5
Sigma commitments and 2k+4 shared responses. A response belongs to a witness,
never an equation. The arrays contain no caller-supplied range commitments.

The range encoding is the fixed upstream encoding: four points, three
canonical scalars, log2(64m) interleaved L/R pairs, final a/b scalars.
Its exact byte length is 32*(9+2*log2(64m)), where m is the padded range count.
The parser rejects other lengths before constructing expensive generators.
Public keys and new encryption handles must be nonidentity; valid zero
commitments, including padding, are not indiscriminately rejected.
COLLECT also rejects each identity receipt handle independently of the SEND
producer's checks; incoming representation is not trusted by construction.

The current COLLECT implementation materializes a dense (2k+5) by (2k+4)
point matrix and performs that many scalar/point terms across its Sigma checks:
its matrix storage and this work are O(k squared), not a linear K budget.
Generator derivation adds O(64m) work per request. The exercised K=8 is not
evidence for large configured K. A future policy must admit worst-case allocation
and work before enabling it; this kernel installs no unapproved internal ceiling.

## Results and caller obligations

| Code | Meaning |
|---|---|
| 0 OK | Mathematical relation accepted; not AdmittedInput or authority to commit |
| 1 ARGUMENTS | Local caller ABI/policy contract violation; do not vote candidate-invalid |
| 2 DECODE | Malformed or disallowed candidate representation |
| 3 VERIFY | Cryptographic relation failed |
| 4 KEY | Reserved legacy local-construction category, not emitted by this kernel |
| 5 PANIC | Contained local unwind; never treat as an invalid proof |

This preserves invalid-input versus local-failure semantics. The full host's
AdmittedInput/CandidateInvalid/LocalUnavailable classification is not replaced
by a new status enum and is not wired here.

The context byte string is mandatory and length-bounded. It must encode the
authenticated network/instance, account identities, keys/epochs, old state and
nonce, policy identity, recipient eligibility, fees/expiry and operation IDs.
The kernel binds all supplied bytes but cannot determine their provenance or
whether an application omitted a field. No production context codec has been
selected, and these fixtures must not be deployed as a transaction format.

## Header discipline

`build.rs` generates the header with cbindgen and compares it byte for byte
with the committed header before exporting any copy. After an intentional ABI
change, inspect the generated OUT_DIR header, update the committed artifact
and run the header guard. Never bypass the comparison to make a build pass.
