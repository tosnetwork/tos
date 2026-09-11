# Independent prepare review and public-component anchors

B, 2026-09-11. Read-only review of A's `65b8196398c0724e971342f7f717956c108d5247`
and test follow-up `7f23ceb790438c7edfc75087a8f380ff4cc7cce2`.
Specification at the start of the follow-up: memo `17a7af4e`, SHA256 prefix
`21bc8334ac1213b6`. The anchor table also records the subsequently communicated
D76 decision and reserve-policy supplement: memo `8b96aa66`, prefix
`24291053f8c289fe`; it does not claim that
D76 code is present in either reviewed commit.

This is independent **post-implementation review**, not a frozen prediction.
B read A's code and tests. B independently executed isolated shadow builds and
redecoded/decrypted an archived accepted state from A's run. A's worktree and
production files were not edited. No new live collation/validation run was made.

## Findings by requested check

| Check | Finding and evidence |
|---|---|
| Component perturbations | A's accepted state independently yields R=999999506, N=999999483, P=137, W=160. Re-encoded account-root mutations: record x+1 passes the pairing oracle because P and W both increase; record q+1 also passes because neither reads q; reserve b+1 fails the second equation. These are post-acceptance artifact mutations, not candidate-acceptance experiments. |
| Oracle control | Keeping the same reserve mutation but disabling the copied actual `check_m4_backing` predicate makes the control fail at `check.is_error() == (component == 2)`, exit 1. The oracle is not empty. |
| D75, both directions | Normal q=99 and q=101 reach the specific -7200 exact-fee equality error. Removing only the equality block, retaining the expanded pricing ceiling and actual Native construction, makes both tests fail at `result.is_error()`, exit 1. The check carries enforcement; earlier pricing rejection does not explain the green. |
| Expanded pricing ceiling | No caller Account publication found before equality. The allowance enters a private pricing scratch; the final equality precedes returning the pair, and overlay commit is later. The independent publication mutation/control below corroborates this at the Native pair boundary. |
| Legacy optional absent | Four canonical BOCs compared byte for byte, all identical: the two Native transaction roots and two resulting Account roots. One legacy fixture, principal 137, actual fee 100, ceiling 500, absent exact-q. This is not universal legacy equivalence or a full regression claim. |

Evidence is under [measurements/uno-m5-prepare-independent-review](measurements/uno-m5-prepare-independent-review/),
including the actual artifact oracle, frozen accepted state/block, control logs,
minimal publication mutation patch, and SHA256 manifest.

### What the equations observe

Pinned `test/m4-live-deposit.h:295–305` reconstructs R_book from authorized
operation f, x and q; `:328` compares it with the custody balance. `:337–342`
reads **both** P's x and W's x from the same stored Withdrawal record, and only
W additionally reads `original_reserve`. The second comparison is `:351`.
Thus the equation cannot independently authenticate the record's principal,
or its historical `outward_fee_paid`. Changing only that historical q also
leaves the first equation's inputs unchanged; this last statement follows from
the inspected data dependencies, not a new live first-equation mutation run.

Pinned `test/test-m3-live.cpp:325` separately compares record principal with
operation principal, and `:340` compares actual payout value with operation
principal. Those are **test assertions**. They must not be presented as D76's
new consensus-side CandidateInvalid check.

The artifact experiment changed one economic component at a time. For b it
also changed `refundable_reserve` by the same unit, preserving the independent
codec invariant `consumed + refundable == original`; otherwise rejection would
occur at the codec, before the equation under review. All three mutated roots
successfully encoded and decoded. Decoding ceiling 100 is an inspection bound,
not an authenticated policy value or a proposed K_withdrawal default.

The input state is from A's `/tmp/uno-m3-live-grcv32yz` accepted run, not a new B
live execution. Its SHA256 is
`e002041ede75ff7d92c2adb484b17a4f7f96aa3ca04ea5ade9083542f7d1ea03`.
N was independently recovered with the existing test keys and ciphertext
helper; no production decryption/privacy claim follows. R_book's complete
historical replay was inspected, not independently rerun in this artifact test.

## D76: which public components have independent anchors?

Subsequent evidence: the f matching-proof admission and removal control has now
been executed; see [the follow-up](uno-m5-fee-admission-independent-review.md).
The table below preserves the status at the original review, rather than silently
claiming those later tests had already run.

All implementation locations below refer to `65b819639` (unchanged in the
relevant paths by `7f23ceb79`). Decision, implementation, and mutation evidence
are separate columns deliberately.

| Component/link | Required independent anchor | Implemented evidence | Remaining boundary |
|---|---|---|---|
| x: authorized principal to actual outbound value | D76: published message value == authorized x, mismatch CandidateInvalid | Live test compares record to operation (`test/test-m3-live.cpp:325`) and payout to operation (`:340`). Pricing checks sent payment against its request (`transaction.cpp:4599–4603`). | Those checks do not establish the new serialized publication-boundary D76 consensus check. D76 is newer than reviewed code; x±1 controls at that new assertion are pending. Do not substitute principal cancellation in P/W for this anchor. |
| q: authorized outward fee to actual fee spent | D75: decoded custody debit minus actual payout value == q | `transaction.cpp:4717–4735`; before-payout balance is captured after entry/D32 allocation. Both q directions reject at equality; removal controls fail. | This anchors actual q spending, not every historical copy of q. It is opt-in for exact-q callers. |
| q: authorized fee to W record's `outward_fee_paid` | Stored historical cost must retain the authorized value | Engine copies it from the operation at `crypto/test/workchain-m3-node-engine.h:289–293`. | No independent field equality assertion found in the inspected live oracle. Re-encoding q=101 instead of 100 leaves pairing green. Correct copying in current code is not mutation evidence against a shared reconstruction error. This does not demonstrate acceptance of a forged candidate. |
| b: authorized reserve to W and refundable balance | `record.original_reserve == authorized b`; initially consumed=0 and refundable=b, W=x+b | Same engine construction `:289–293` copies b into both original and refundable fields. Proof request receives the same b at `crypto/test/workchain-m5-debit.h:73–74`; context binds encoded operation data at `:49–58`. Codec checks consumed+refundable=original at `workchain-withdrawal-codec.h:184–185`. | No separate record-b versus operation-b assertion found. The codec is an internal reconciliation, not an authorization comparison. The single-record reserve perturbation is caught by the second equation, but a common mistake on both sides is outside that control. No native reexecution mutation proving this independent link was run. |
| b: authorized reserve to required authenticated reserve policy | D76 supplement: stored b must equal authenticated max_bounce_cost; mismatch CandidateInvalid; no local default | Prepare parameters at `workchain-m3-business-config.h:15–18` contain state_fee, withdrawal_limit and settlement_blocks, not max_bounce_cost. The inspected debit path checks the sum and proof, but has no authenticated required-reserve comparison. | **Not found in this test prepare profile.** Distinct from the proof binding the b it was given. No default value is proposed here. |
| f: authorized operation fee to authenticated floor | f >= state_fee + base × SEND's one billing unit; sender remainder is tip | **Now wired:** node engine `:246–248` requires explicit prepare/tariff and calls `derive_workchain_withdrawal_fee_amounts`. `workchain-operation-fees.h:35–39` checks arithmetic and rejects below floor with -7200. This occurs before proof verification. | The earlier statement “no host fee check exists” is stale for this commit. FEE-ADMISSION readiness still requires the independent pair of matching proofs (both first verified separately by the kernel) and the targeted admission/removal evidence. That evidence was not produced in this review. |
| f: authorized fee to confidential debit and D32 destinations | Same f reaches proof and independently reconstructed S/C/T; no x/q/b inside F | Proof request gets operation_fee (`workchain-m5-debit.h:74,87`); engine materializes derived fees at `:300–302`; helper fields state/compute/tip/total are distinct (`workchain-operation-fees.h:14–15,40,74–77`). | Static chain verified. No new mutation of the complete physical S/C/T settlement was executed here; no full prepare acceptance claimed. |

The registered engine is explicitly test-only/D59-permitted. These facts do not
establish a production-wide Withdrawal admission profile. In particular, a
pending handoff test is not proof that its check is absent, and a present helper
is not proof that all handoff requirements have been met.

## Publication mutation and nonempty oracle

`7f23ceb79:crypto/test/test-workchain-block.cpp:8023–8058` snapshots the actual
caller-owned custody/coordinator Account BOCs **before** calling the real Native
builder. It then reads those same Accounts' `transactions`, decodes each
Transaction's committed `out_msgs`, checks count and emptiness, and inspects any
returned pair. It does not inspect only the builder's private scratch.

B recreated the advertised mutation independently in the exact-q mismatch
branch, with braces preserving that branch:

```
const_cast<Account&>(custody).push_transaction(pair[0]->root, pair[0]->start_lt);
return td::Status::Error(-7200, "Native payout fee differs from authenticated exact q");
```

No price, fee, payment, equality condition or status changed. The sole added
operation publishes the already serialized transaction to the caller Account.
The attached patch records this minimal difference. This independently verifies
the advertised mutation shape; it cannot attest to unretained historical edits
in A's temporary worktree.

- Original: exit 0, no published Account/transaction/pair residue.
- Mutation: exit 1 at `out_msgs.is_empty()` (shadow test line 8040), before the
  later error-code assertions. Account BOC alone would not catch this specific
  transaction-list publication, demonstrating why the larger slice matters.
- Same mutation, only `if (check_nonpublication)` changed to
  `if (false && check_nonpublication)`: exit 0, original -7200 retained.
- A separate driver requiring that mutation's out_msgs rejection actually
  exits 1: `EXPECTED_PUBLICATION_REJECTION_MISSING`.

A's second advertised `commit(custody)` mutation is supported by A's supplied
log, not independently rerun here. B's direct evidence is the transaction-list
variant above. Neither variant is a live collator queue test or an authenticated
candidate-acceptance test.

## Pricing boundary and legacy comparison details

`transaction.cpp:4357–4418` stages messages into local `ActionPhase` state;
`:4570–4605` constructs a private `Transaction scratch` with a virtual allowance.
The actual funded/debited Native pair remains private until the final return
at `:4737`. `workchain-payout-overlay.h:133` propagates builder errors before
moving the pair into overlay transactions or committing them. No pre-equality
caller Account write was found along this inspected path. This is a source-path
review plus the Native boundary experiment, not an exhaustive claim about all
indirect runtime side effects or live queue publication.

For the legacy comparison, the shadow-before variant restored the old
`fee_budget` pricing expression and removed the new exact-q block; the optional
signature remained to compile the common translation unit. A dedicated caller
passed no exact value. Both variants executed real Native construction and
serialized all four roots; full BOC bytes, not just hashes, matched. This is a
comparison of the changed behavior with that behavior restored, not a claim to
have rebuilt the entire historical repository.

## Execution/provenance limits

Shadow compilation used pinned exported crypto headers/sources and explicit
replacement transaction/test objects, linked against A's existing native build
libraries. It was not a hermetic rebuild of every dependency. No A WIP source
was used as the reviewed implementation identity. Observed live artifacts came
from A; B's artifact decryption and shadow-control runs were direct observations.

Initial harness failures were not business findings: a missing shadow test
include was fixed; invalid UTF-8 in a fatal log required replacement decoding;
a broad legacy selector also ran an exact-q=100/zero-ceiling case and failed
before reaching the legacy call, so it was replaced with an absent-optional-only
selector. An initial mutation draft lacked braces and was discarded before
accepting results. Only the brace-preserving patch and final control logs count.

No guard was retired. No frozen prediction was rewritten. No complete M5,
WITHDRAWAL-PREPARE, native D76, reserve-policy or Failed-path acceptance is claimed.
