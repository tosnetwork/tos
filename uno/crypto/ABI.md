# Borrowed balance verification ABI v2 and independent possession v2 entries

## D64 construction work in progress (2026-09-11)

`withdrawal_statement` is a read-only Rust construction and verification API;
it exposes no C ABI and has no node-host caller. It specializes the unchanged
SEND matrix with P_B=P_A and locally derived C_t/D_tA/D_tB. Its explicit
Withdrawal context binds the two IDs and the separate principal, outward fee,
return reserve and operation fee; the enclosing authenticated host context is
still a caller obligation. This is not a completed Native wire/context contract
or a Withdrawal execution path. No new relation number is allocated.

Before adding any host caller, provide the admitted metering entry and the
canonical authenticated Native context interface. No unmetered ABI is to be
connected temporarily. Profile 4 coverage is not expanded by this Rust-only
construction step.

D34 scope: M5 does not expand the relation family, but adds critical verifier
checks. C_t reconstruction and the no-pending host branch prevent under-debit
or double issuance. Under the existing proof system's soundness assumption,
the public-opening algebra adds no computational assumption; one handle is
redundant when P_B=P_A. All remain review subjects.
This is not a claim of no new unreviewed cryptographic surface. The host
no-pending branch is not implemented or evidenced by these kernel tests.

## Possession transcript upgrade (2026-09-10)

The two independent M3 entries are now `uno_crypto_verify_key_possession_v2`
and `uno_crypto_verify_closure_possession_v2`, with request `abi_version=2`.
Their v1 symbols are rejection-only stubs (`UNO_CRYPTO_ARGUMENTS`), and a v2
request bearing version 1 is rejected before verification. There is no legacy
verification fallback. The equations and 64/96-byte proof formats are unchanged.

Both challenges use their `/v2` literal domain, then absorb `context[426]`,
then the previously listed statement fields and commitments. These are precisely
the bytes returned by `encode_workchain_replay_context`: operation constructor
tag, context, subject, address, protocol, rules and profiles, all fixed-width.
The host constructs them from authenticated policy and the relevant account;
the candidate's context is compared separately and is never passed to the ABI.
The wallet consumes the same canonical encoding, not a parallel layout.

Carrying context in a block proves that the block commits it; absorbing context
in Fiat-Shamir proves that the prover authorized it. Neither substitutes for
the other. Tests submit an X proof with wire context Y and authenticated Y:
the host comparison passes and each cryptographic verifier rejects the proof.

There remain **two** independent entries outside D34 relation-family review,
but their transcript/ABI content has changed to v2. Correspondence tests still
do not constitute a reliability argument. The account nonce/revision, Native
key-origin limitation and independent host state checks remain unchanged.

## Profile 4 possession coverage

M4 extends the same profile to system ciphertext generation and reconstruction,
before adding Deposit execution callers. Each reserves 7 existing v4 units:
3 scalar multiplications, 1 generated blinding base, 1 decoded point, and 2
encoded points. Reconstruction runs the same generation algorithm and then
compares bytes. Fixed transcript fields do not count as variable context bytes,
consistent with the existing profile; these units are not CPU time or fees.
Both entries share precharge, no refund, and sticky failure with proof verification.
Only a reconstruction mismatch is candidate-invalid; failure to reconstruct the
host's authenticated request is local-unavailable. Deposit admission must precede
request construction and is not implied by cryptographic success.

Profile 4 now covers registration and closure verification through the same
`WorkchainProofVerifier` precharge and sticky failure path as SEND/COLLECT.
The SEND/COLLECT counting rules are unchanged. Possession counts are fixed:
their context is exactly 426 bytes and their equations do not scale with a
candidate-selected collection size. They reserve the full path even if a
malformed proof exits early; failure does not refund work.

| Existing v4 component | Registration | Closure |
| --- | ---: | ---: |
| Scalar multiplications | 2 | 4 |
| Generated points | 1 | 2 |
| Decoded points | 2 | 5 |
| Encoded points | 0 | 1 |
| Sigma equations | 1 | 2 |
| Sigma witnesses | 1 | 1 |
| Context bytes | 426 | 426 |
| MSM terms / range rounds | 0 / 0 | 0 / 0 |
| Total | 433 | 441 |

These counts follow `key_possession.rs` and `closure_possession.rs`: closure
constructs H for the challenge and again for its first equation, and compresses
the challenge's H once. Fixed transcript fields use the existing v4 convention;
no new hash, fee, or time unit is introduced. These are algorithm-boundary
counts, not measured CPU instructions or a production preflight bound.

## Historical registration key possession v1 (superseded; rejected)

`uno_crypto_verify_key_possession_v1` accepts a fixed-field
`UnoCryptoKeyPossessionRequestV1`, not a new balance relation. The 64-byte
proof is canonical Ristretto `R[32] || z[32]` (canonical little-endian scalar).
It verifies `zP = R + cH`, with nonidentity P/R and the existing Pedersen
blinding generator H. The challenge is SHA-512 reduced modulo the scalar
order over `TOS/UNO/REGISTER/KEY-POSSESSION/v1` followed by global_id,
genesis_hash, workchain_id, account, incarnation, asset, custody, policy,
schema_version, relation_profile, proof_profile, key_epoch, public_key, R.
All integers are fixed-width big-endian; ABI padding is never hashed.
The host must independently check address/configuration bindings. Knowledge
of s does not prove its origin or independence from Native signing secrets;
independent key generation is wallet discipline, not a chain-verifiable claim.
This entry has not undergone D34 relation-family review. Correspondence tests
are not a reliability argument. Rotation is not authorized by this entry.

## Historical closure possession v1 (superseded; rejected)

`uno_crypto_verify_closure_possession_v1` is the second independent M3 entry
outside D34 relation-family review. Its 96-byte proof is R1 || R2 || z.
It checks zP=R1+cH and zD=R2+cC; P and D must be nonidentity. Randomized zero
(rH,rP) is accepted, not replaced by an all-identity encoding requirement.
The SHA-512 challenge reduces the digest over the literal
`TOS/UNO/CLOSE/KEY-POSSESSION/v1`, domain[80], the registration context fields
through key_epoch in their order above, auth_nonce, available_revision, P,H,D,C,
R1,R2. Integers are fixed-width big-endian, points canonical compressed bytes;
z is canonical little-endian. H is the fixed Pedersen blinding generator.
This proves possession and zero plaintext under the admitted v<l bound, not
empty pending or absence of obligations. Those remain authenticated host checks.
The host must supply the current revision/ciphertext, not a caller's old copy.

This is a native process interface, not a TL-B constructor, network proof
profile or M0 freeze. Balance versions 0 and 1 are retired; the library exports
`uno_crypto_verify_v2`, not the previous fee-less balance verification entries
or the old Note-tree function. The system-encryption entries remain version 1.

The existing boundary discipline is retained: every active verifier entry contains
the entire call in catch_unwind, no AssertUnwindSafe, no pointer retention or
ownership transfer, and checked bounded_span before nonempty slice creation.
Both Cargo profiles require unwind; cfg(panic = "abort") is a compile error.
Retired possession v1 stubs only return an error constant: no dereference,
allocation, cryptographic operation or unwinding code runs in them.
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

`UnoCryptoVerifyRequestV2` has ABI version 2, relation discriminator, limits,
an 80-byte protocol domain, public u64 fee in nanotomi, and borrowed
(context, points, receipt_ids, commitments, responses, proof) arrays.
On the supported 64-bit Linux target limits occupy 40 bytes, request 232 bytes,
domain offset 48, fee offset 128, context offset 136. Rust and C++ assert the
layout. The protocol domain uses the exact system-encryption layout below.
It has no default; the host must supply authenticated configuration values.

SEND proves `a = a' + v + fee`; its old ciphertext and auxiliary commitment
targets each subtract the public group element `fee*G`. COLLECT proves
`a + sum(v_i) = b + fee`; its new ciphertext target adds `fee*G`.
These are exact group operations, not unchecked integer balance arithmetic.
The existing ranges still bound the actual old and new balances and values.
With at most 64 receipts and u64-bounded integers, the corresponding integer
relations cannot wrap the scalar modulus. There is no additional fee witness.
The primitive allows fee zero; the host, not a local kernel default, enforces
the authenticated fee schedule and performs checked account settlement.

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
not deposit admission or account updates. Their version-1 request layout and
symbols remain unchanged by the version-2 balance interface.

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
M4 reuses these entries without adding a proof relation. The test suite also
constructs canonical ciphertexts under a different transcript domain and checks
that the reconstruction ABI returns VERIFY, rather than a parsing error.
The authenticated pending codec retains the original Native Message CellRepr
hash and checked sequence to recompute DepositID; neither is authenticated by
this ABI. System receipts occupy separate per-account capacity in the shared
Add-only receipt dictionary and never overwrite available balance.

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

### D69 versioned system origins

The additive `uno_crypto_system_encrypt_v2` / `uno_crypto_system_verify_v2`
use `UnoCryptoSystemEncryptionRequestV2`, with `abi_version=2`, the same
80-byte domain, 32-byte receipt ID, 32-byte recipient, u64 amount, then a
115-byte origin buffer and u32 `origin_bytes`. The used length is exactly
41 (Deposit or settlement) or 115 (sweep); unused tail bytes must be zero.
The v1 symbols, request layout and Deposit transcript remain unchanged.

The host's `encode_workchain_system_origin_transcript` is the canonical
encoder: root data bits followed by attribution data bits, with zero low-bit
padding after the trailing Bool. Integers in these TL-B data bits are big
endian, unlike the domain's explicitly defined little-endian integers.
Kinds 0/1 use one tag byte, 32 identity bytes and a nonzero u64 sequence.
Kind 2 uses one tag byte, a nonzero u64 sequence, then the tagged type-2
attribution (source workchain/address, account ID, uint256 value, return_failed).
The sequence remains the host's shared authenticated `deposit_sequence`.

Kind 0 delegates to the exact original D33 transcript above. Kinds 1 and 2
use `uno-v2/system-encryption/withdrawal-settlement` and
`uno-v2/system-encryption/bucket-sweep`, respectively. Append order is
`protocol-domain`, `receipt-id`, `origin`, `recipient-P`, `amount` (LE u64),
then the same 64-byte `r` challenge and existing wide reduction/zero rejection.
There is no new proof relation. Transcript byte differences are domain
separation, not a claim that finite hashes or scalars cannot collide.

The ABI checks kind, payload length, nonzero sequence and padding. It does not
parse/authenticate the attribution's TL-B fields or recompute CellRepr IDs:
the dedicated host codec performs that reconstruction, and the caller must
compare it to authenticated state. A successful primitive call does not prove
counter consumption, pending uniqueness, eligibility for type-2 sweep, or
atomic installation. New node callers require A's metering entry and ABI
inventory registration before connection; none is installed by this patch.

The new account codec exposes schema 3 through
`decode_workchain_withdrawal_account(root, authenticated_limit)` and its paired
encoder. The wrapper contains common account fields, the authenticated control
envelope and new-origin receipts. Legacy and new-origin system receipt views
share a total capacity of four in the same Add-only dictionary; user capacity
remains sixteen. Decoding an old account through this API is an error, not an
implicit migration. The old account decoder likewise rejects the new root.
