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

The unsafe raw-pointer borrows have caller-chosen lifetimes. Allocation lifetime
and absence of retention are caller-contract and reviewed call-site obligations,
not a type-system proof that arbitrary raw pointers are valid. All current borrows
are consumed synchronously before return; the helper does not authenticate memory.

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
and work before enabling it. The kernel rejects `max_collect > 64` with ARGUMENTS
before reading candidate slices or allocating the matrix, independently of what
the host permits. This is an implementation capability ceiling, not production K.
A candidate exceeding a supported policy still returns DECODE, not ARGUMENTS.
At K=64 the dense matrix has 17,556 points (about 2.8 MB on the measured backend);
the ceiling is not a whole-call memory/WCET guarantee. If large K becomes necessary,
sparse rows can make the Sigma storage and group-operation term count linear.

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

## Deterministic public system ciphertexts

The additive `uno_crypto_system_encrypt_v1` and
`uno_crypto_system_verify_v1` entries implement the system-encryption mechanism,
not deposit admission, account updates or public fee deductions in SEND/COLLECT.
The existing verification request layout and symbols are unchanged.

`UnoCryptoSystemEncryptionRequest` contains ABI version (u32), domain (80 bytes),
deposit ID (32 bytes), recipient P (32 bytes), and amount (u64).
On the supported 64-bit Linux ABI its size is 160 bytes and
amount offset is 152. `UnoCryptoSystemCiphertext` is 64 bytes: commitment then
decryption handle, both canonical compressed Ristretto encodings. These sizes
are asserted on both sides. Native struct layout is not transaction wire.

The fixed domain byte string has this layout. Unsigned integers and signed
two's-complement integers use little endian; hashes are literal bytes.

| Byte offsets | Field |
|---|---|
| 0..1 / 2..3 / 4..5 / 6..7 | engine / relation / wire / proof version, each u16 |
| 8..11 | network/global_id, a single i32 |
| 12..43 | genesis hash |
| 44..47 | workchain, i32 |
| 48..79 | instance ID |

The kernel absorbs the full 80 bytes. It does not authenticate them or select
network version values; the host must encode the actual resolved domain.
There are no optional fields or implicit defaults. The transcript is:

1. `Transcript::new(b"uno-v2/system-encryption")`.
2. `append_message(b"protocol-domain", domain)`.
3. `append_message(b"deposit-id", deposit_id)`.
4. `append_message(b"recipient-P", recipient)`.
5. `append_message(b"amount", amount.to_le_bytes())`.
6. `challenge_bytes(b"r", 64 bytes)`, followed by wide scalar reduction.

Reject zero r, zero amount, or a malformed/identity recipient with DECODE.
The primitive accepts every positive u64 amount; it imposes no Deposit policy.
The host MUST check V_min <= x <= V_max from the same authenticated policy
slice: every pending item must later satisfy the COLLECT range relation.
Ordinary over-limit deposits must follow the specified bounce path without
creating obligations. Late returns use checked subtraction of the pending slot
fee before the same upper-bound check; failed admission goes to the unexpected
bucket, never a second bounce. These host paths are not implemented here.
No retry, counter or resampling changes the derived r. A nonidentity P and
nonzero r in a prime-order group ensure a nonidentity rP; there is no redundant
second check whose removal would be masked by that invariant. The computed
ciphertext is `(xG+rH, rP)` using the same fixed Pedersen generators as the
balance kernel. Neither r nor any secret key is returned or retained.

Wide reduction has negligible statistical bias, not exact uniformity; domain
separation prevents transcript reuse, not mathematically all hash collisions.
All derivation inputs are public. This mechanism does not conceal a deposit's
amount and must only produce pending entries, never replace available balances.

The construction call requires disjoint readable request and writable output
allocations, and writes the output only after success. Verification borrows both
inputs without writing; it recomputes and compares both complete canonical
encodings. Any ciphertext mismatch returns VERIFY, including a noncanonical
supplied encoding; no malformed encoding can equal the canonical output.
PANIC is local unwind, never a proof failure. For an authenticated Native
inbox the enclosing host must retain the source of DECODE/VERIFY rather than
mechanically labeling the original queued message an invalid user candidate.
All entries contain the entire operation in the existing unwind boundary.

The fixed vector in Rust and C++ uses domain versions 2/3/4/5,
network/global_id -7, genesis bytes 08, workchain 2, instance bytes 09, deposit-ID bytes
0a and amount 123. Its recipient is generated from test secret
11. It is a regression artifact, not an independent cryptographic audit. The
separate decryption equation and per-public-byte mutation checks constrain its
meaning; the C++ consumer runs both real entries under the entropy trap and
four-thread test. Source, normal dependency graph and reachable-symbol gates
cover the new module and entries. Runtime samples and lexical gates are not
complete call-graph proofs.

## Header discipline

`build.rs` generates the header with cbindgen and compares it byte for byte
with the committed header before exporting any copy. After an intentional ABI
change, inspect the generated OUT_DIR header, update the committed artifact
and run the header guard. Never bypass the comparison to make a build pass.
