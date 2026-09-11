# D34 external cryptographic review scope input (draft)

Specification read for this assignment: memo 271b2d86, SHA256
d309dc6a5158f3fe3fb5c6229bc808ed3a79a0163ed2c1b802f6ebf0fb709c6d. Implementation reference snapshots: encoding ed1cb0f60 and
host 293fc152ac32e9a464a3e426534a69b881ddcf78. These are separate committed
snapshots, not a claim that a final M5 integrated tree exists. Before contracting
the review, freeze the actual integrated commit, dependency lockfiles, generated
ABI/schema artifacts and build profile together. Exclude uncommitted host work.
This document is a scope proposal, not an external review or approval.

Governance status must not be inferred from this request: current D34 (line
1410), the activation table (1250) and D44 (1422) still describe no further
external audit, while line 67 recommends budgeting one before real value.
This draft fulfills the coordinator's new scope-writing request; it does not
resolve those texts or silently revoke D34. Commissioning and the effect on
milestone/activation status need an explicit owner decision.

## Mandatory distinct entrypoints and their composition

| Surface | Starting source / entrypoint | Questions the reviewer must answer |
| --- | --- | --- |
| SEND and COLLECT relations (§6) | `uno/crypto/src/relation.rs`, `statement.rs`, `lib.rs`, `ffi.rs::uno_crypto_verify_v2` | Reconstruct every equation, shared witness index, range object and challenge binding; verify amounts, fees, old/new balances, receipt ordering/distinctness, arity and limits. Check that accepted proofs imply the intended relation under precisely stated assumptions. Include system/user mixed COLLECT and V_max/B_max boundaries. |
| M3 registration Schnorr | `key_possession.rs`, `uno_crypto_verify_key_possession_v2`; `workchain-registration-proof.cpp` and registration host callers | Separate authorization relation and transcript, key encoding/nonidentity, canonical responses and challenge, operation/domain identity, authentication and persistence. This is NOT included automatically by reviewing SEND/COLLECT. |
| M3 closure DLEQ | `closure_possession.rs`, `uno_crypto_verify_closure_possession_v2`; `workchain-account-closure.h`, `workchain-closure-settlement.h` | Establish possession/equality statement, authenticated binding and zero-balance closure semantics; trace the statement actually verified to the account actually closed. This is another independent kernel entrypoint outside §6. Host obligations must be reviewed separately from proof validity. |
| M5 public-opening specialization | `withdrawal_statement.rs`, `workchain-withdrawal-codec.h`, eventual Native prepare caller | Check checked x+q+b before scalar conversion, unchanged SEND witness sharing/equations/ranges, authenticated owner P, P_B=P_A, derived C_t and handles, and f remaining the separate operation fee. Compare the exact externally paid x/q and locked b to those used in derivation, not two copies of the same untrusted value. |
| M5 prepare must not install pending | eventual Native prepare state publisher/validator; full account/control/pending codecs | Compare the complete authenticated account-to-pending cut, user/system entries and both counts, across prepare. A valid proof alone does not prohibit a host from also creating a receipt. Settlement Paid/Failed legitimately creates backed pending: this prohibition applies only to prepare/statement. |
| D33/D69 deterministic system issuance | `system_encryption.rs`, `uno_crypto_system_encrypt_v1/v2`, `uno_crypto_system_verify_v1/v2`; `workchain-system-origin.h` and actual issuance callers | Verify authenticated amount/key/domain/origin, fixed member encoding and ID derivation, wide reduction, zero rejection without resampling, and actual independent point recomputation before credit installation. No proof is required, but omitted amount/ciphertext checking can install unbacked claims. Test each member and actual caller, not only primitive success. |

## Required D64 distinction

In the presence of a valid shared witness and at least one correctly derived
handle, prime-order nonidentity P forces r=r0; the correctly derived C_t then
forces v=T within the bounded integer range. The correct statement is:

> Under the soundness assumptions of the existing proof system, this public-
> opening algebra introduces no additional computational assumption.

It must not be shortened to "accepted withdrawals are unconditionally sound."
The step from proof acceptance to an appropriate satisfying/extractable witness
is itself a proof-system premise to examine.

Classify modifications separately:

* Accepting a prover-selected C_t can allow a commitment to a debit smaller than
  the host payout total, without breaking a cryptographic assumption. The
  amount-to-derived-commitment link is independently critical.
* P_B=P_A makes the two handle equations redundant for this deduction. Dropping
  only one derived-handle constraint is not independently a minting result.
* Letting both handles be selected loses the direct algebraic pinning of r;
  the residual amount binding relies on Pedersen binding. Do not describe that
  change as the same unconditional minting case as accepting arbitrary C_t.
* Installing pending during prepare while also paying externally violates the
  host value linkage even if the proof and all derived points are valid.

Include both changed-point tests against a fixed proof and derivation mutations
with a newly matching proof. They answer different questions; failure of the
former does not establish the latter's protection. Preserve all eight equations
and six SEND range objects rather than silently simplifying the relation.

## Cross-cutting review inputs

1. Supply exact transcript order, labels, endianness, lengths, domain versions,
   network/genesis/workchain/instance bindings, incarnation/epoch, operation and
   Attempt identities, nonce/sequence provenance and limits. Distinguish bytes
   carried from bytes cryptographically bound, and bound from authenticated.
2. Review curve/scalar canonical decoding and nonidentity checks on every
   reachable ABI path, including FFI framing and scalar zero handling. Supply
   the generated header and its producer, not just hand-transcribed types.
3. Include `uno/prover` construction and witness ordering as review inputs;
   node verification remains the consensus acceptance boundary, and prover
   success is not evidence that the verifier enforced a constraint. Include
   aggregation, generator derivation, Fiat-Shamir composition and deterministic
   verification/no-RNG assumptions explicitly.
   Include the vendored curve, Bulletproofs and transcript dependencies and
   their modifications/lockfiles in the selected dependency scope. Inventory
   matching and checksums do not mean dependencies were audited. Shared forks
   are not independent implementations for differential evidence.
4. Preserve Deposit v1 derivation and existing vectors byte-for-byte. New D69
   origins use separate domains. Sequence provides stateful issuance ordering,
   not collision-free hashes/scalars; authenticated duplicate-ID rejection
   across both pending kinds remains necessary. Trace actual staged counter
   installs, including multiple issuers, failed/no-receipt and overflow cases.
5. Trace ABI return values through host error handling and state publication.
   Verify no unchecked alternative caller installs claims after a failed point
   check. Include metered wrappers and their format-before-charge boundary as
   integration inputs, without mistaking work units for billing units.
6. Supply negative controls and their isolation/restore logs. Each must identify
   the assertion and layer reached. Every behavioral result must name its
   observation slice and executed paths. The callee file-write probe is NOT
   evidence of changing a Native authenticated account root; missing Native
   prepare integration remains a delivery gap until that path is tested.

## Deliverables and exclusions

Request an explicit reviewed-entrypoint matrix, assumptions and threat model,
findings with reproductions, affected build/profile/commit, and re-review of fixes.
Ask the reviewer to list unreviewed dependencies, host adapters and alternate ABI
paths rather than treating this draft's file list as exhaustive. New callers or
relations added after the frozen snapshot require a scope delta.

This cryptographic scope is not a full audit of consensus, networking, queue
liveness, economic tariffs, governance, storage capacity, Native VM execution,
wallet UI, key custody or deployment. Their authentication/value-flow interfaces
above ARE in scope where a cryptographic claim depends on them. Full side-channel,
compiler/toolchain and platform audits require separately agreed coverage; do
not silently imply them from functional verification. This document neither
commissions a reviewer nor transmits source externally.

A favorable review would not prove bug absence, authorize activation of unfrozen
parameters, establish delivery within a finite bound, prove recipient credit
from Paid, certify all dependencies, or cover later commits automatically.
M5's use of existing relations does not remove the new host/public-derivation
checks from D34. Engineering tests and this scope draft do not discharge the
unreviewed cryptographic assurance gap.
