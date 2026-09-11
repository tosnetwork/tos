# TIP-0002 P0: what this repository does today

TIP-0002 (*Post-Quantum Validator Signatures and Cryptographic Agility*) asks
for a delivery milestone it calls **P0**: before mainnet, freeze and implement
algorithm-neutral validator key, signature, certificate, signing-context,
signer-service and policy interfaces, with only Ed25519 enabled. The TIP is a
specification; it supplies no implementation, and it places the implementation
work here.

**P0 is not implemented.** This document is the inventory the TIP requires
before that work starts — what signs a consensus decision today, what shape it
has, and which of the TIP's requirements each boundary does not yet meet. It is
written from the source, not from the TIP's summary of it, and every claim below
cites a file and line that can be checked.

Pinned TIP revision: `231570f4ae4511b5e42c6b8ce0fdb5576b2663d9`
(`tosnetwork/TIP` PR #1). The conformance corpus in
`test/validator-auth-policy/` records the same revision.

## 1. Signature inventory

TIP-0002 §1: *"The first enforcing release MUST inventory every signature that
can affect a consensus transition, committee selection, or authenticated key
replacement."* This is that inventory for the consensus-authorization paths.

| What is authorized | Produced at | Verified at | Shape today |
| --- | --- | --- | --- |
| Block proposal (candidate broadcast) | `validator/consensus/block-producer.cpp:210` | `validator/consensus/types.cpp:209` | Ed25519 over `dataToSign(session_id, candidate_id)` |
| Notarize / Finalize / Skip vote | `validator/consensus/simplex/pool.cpp:814` | `validator/consensus/simplex/votes.cpp:89` | Ed25519 over `dataToSign(session_id, unsigned_vote)` |
| Vote certificate (quorum of votes) | assembled from the above | `validator/consensus/simplex/certificate.cpp:46` | one Ed25519 signature per signer |
| Block signature set (persisted proof) | `crypto/block/signature-set.cpp:121` | `crypto/block/signature-set.cpp:377` | `ed25519_signature#5`, exactly 64 bytes |
| Block proof / signatures, client side | `tosctl/src/block/src/signature.rs` | same | `CryptoSignature([u8; ED25519_SIGNATURE_LENGTH])`, `SigPubKey([u8; ED25519_PUBLIC_KEY_LENGTH])` |

The signing context is a single TL constructor, shared by every entry above:

```
consensus.dataToSign session_id:int256 data:bytes = consensus.DataToSign;
```
(`tl/generate/scheme/tos_api.tl:1204`)

Verification resolves the validator's key from the session's validator set and
calls the Ed25519 encryptor directly (`validator/consensus/types.cpp:27-37`).

Quorum accounting is already separated from the signature layer and is shared.
`tos/quorum.h` provides `has_quorum`, `quorum_threshold` and
`checked_add_validator_weight`. The certificate path uses the latter two
(`validator/consensus/simplex/certificate.cpp:35` and `:40`); the persisted
block signature set uses `has_quorum` (`crypto/block/signature-set.cpp:90`).

Out of scope for TIP-0002 and not inventoried here: ADNL/overlay/transport
keys, external message authentication, and wallet or agent-account
authentication. The replaceable authentication added for Wallet V5 and the
Agent Account is application-level; TIP-0002 §Backwards Compatibility states
explicitly that it neither satisfies nor depends on the validator transition.

## 2. Gaps against the TIP's P0 requirements

These are consequences of the inventory above, not defects in the current
design. Ed25519-only consensus does not need any of them; a later algorithm
does.

**Fixed outer widths.** The C++ serializer writes a 4-bit `ed25519_signature#5`
tag and requires exactly 64 bytes (`crypto/block/signature-set.cpp:121-123`,
`377-384`). The Rust codec fixes the same widths in the type system
(`CryptoSignature([u8; ED25519_SIGNATURE_LENGTH])`,
`SigPubKey([u8; ED25519_PUBLIC_KEY_LENGTH])`). TIP-0002 §2.0 requires a
bounded *variable-length* component collection before mainnet; an `alg_id`
added to one struct while another consumer still expects 64 bytes does not
satisfy it.

**One signing context for every role.** Proposals and all three vote types are
signed through the same `dataToSign(session_id, payload)` wrapper with the same
key. Domain separation rests entirely on the TL constructor tag inside
`data`. TIP-0002 §4 requires proposal signing, consensus votes and
administrative key changes to have separate roles and domains — a requirement
that becomes load-bearing if a stateful scheme is ever selected, because role
aliasing there means reusing one-time signing capacity (§8.1).

**The signed statement binds less than §5 requires.** Today it binds the
session identifier and the payload. TIP-0002 §5 additionally requires the
network/genesis commitment, the policy commitment, a commitment to the complete
validator set, and an explicit validator identity and key-epoch binding. The
existing short validator-set hash is called out by name in §3 as insufficient
for that purpose.

**No key epoch, suite identifier or policy state exists.** A validator is a
public key plus a weight (`validator/consensus/types.h:75-79`). There is no
registration, rotation, retirement, suite selection or activation state to
extend, so C1/C2/C3 as described cannot be reached by enabling dormant fields;
those fields do not exist yet.

## 3. What landed with this document

The one artifact TIP-0002 designates for this repository that can be made real
today is its policy model, so it is here as a test rather than an illustration:

- `test/validator-auth-policy/policy-cases.json` — 25 cases, vendored from the
  TIP at the pinned revision, provenance recorded in the file.
- `test/validator-auth-policy/check_policy.py` — the TIP's model, unchanged in
  substance.
- `test/test-validator-auth-policy.cpp` — an independent evaluation of the same
  corpus that delegates every weight decision to `tos/quorum.h`.

The second implementation is the point. A model that only agrees with itself
proves nothing; this one fails if the production quorum predicate changes.
Verified by deletion:

| Change | Result |
| --- | --- |
| `has_quorum` uses strict `>` | `classical_two_of_three: expected accept, got reject_quorum` |
| `checked_add_validator_weight` admits zero weight | `zero_weight_rejected: expected reject_registry, got accept` |
| hybrid rule relaxed from AND to OR | `hybrid_classical_only_is_not_a_fallback: expected reject_authentication, got accept` |

What the corpus pins is the set of rules a future implementation must not get
wrong: hybrid authorization is AND and never OR, a shadow verification result
carries no consensus authority, a validator that did not vote does not shrink
the denominator, and a duplicate or unknown signer contributes nothing.

**What it is not.** `ed_valid` and `pq_valid` are supplied outcomes, not
signatures. Nothing here verifies a signature, and no phase beyond the
classical one exists in this codebase. Passing this test is not evidence of P0
readiness, of a post-quantum implementation, or of measured overhead.

## 4. What P0 needs next, and what has to happen first

Per TIP-0002 §12.1, the launch gate needs a frozen outer wire/API profile
(constructor tags, suite-ID allocation, component cardinality and order, signer
errors, resource limits), end-to-end consumers in C++ and Rust plus RPC/SDK,
proof and light-client paths, byte-exact golden and negative vectors, proof
that C0 accepts only Ed25519, and a testnet rehearsal with measured overhead.

The wire profile comes first and is not this repository's to invent: §Normative
language requires *"a revision or companion Core TIP"* to freeze it before the
initial public mainnet. Assigning constructor tags and field widths here, ahead
of that review, would have to be redone. The useful work that does not depend
on the frozen profile is the audit in §2 above — finding every remaining fixed
Ed25519 assumption outside the algorithm-specific provider and the historical
codecs, which §12.1(2) requires regardless of what the profile ends up saying.
