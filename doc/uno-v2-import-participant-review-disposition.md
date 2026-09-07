# Restricted import participant: boundary review disposition

Scope: the importing participant factory, its declaration, and the importing
pair in `NativeCoordinatorEntry`, based on `caf75291e`. The verbatim review is
`~/memo/reviews/uno-v2-import-participant-review.txt`. This is an inactive M1
primitive, not authenticated Deposit/return handling or live scope acceptance.

## Disposition

| Finding | Disposition | Reason or repair |
| --- | --- | --- |
| F1: wrapper validation has no negative witnesses | Fixed; rebuilt controls fail | Twelve import-wrapper cases cover both binding hashes, ordinal, data, workchain, generation time, host LT, old account hash, missing/extra declared write, transfer cap and currency-validation budget. Each is run against an unsafe inline implementation that retains valid credit/allocation but drops full entry validation and caller bounds. This is a composite delegation-contract control, not proof that each inherited guard is independently indispensable. |
| F2: a new importing tag/amount field is required | Disputed | Authenticated full input already contains each envelope and its destination; effects contain the allocation graph and payout request. Alongside resolved roles and old state these determine expected credit, allocation and payout without consulting a proposer-selected factory or a claimed balance rule. A no-credit allocation record against a nonempty own inbox has the wrong expected balance/state update and fails reconstruction as well as independent value flow. The serialized transactions are not indistinguishable: their account-state hashes differ. No new tag or claimed credit field is needed. |
| F3: unbounded importing-participant multiplicity | Accepted cost prerequisite; disputed new owner decision | The protocol's two receiving roles are coordinator and custody, not every changed account. Production materialization must enforce that exact role set, with at most two full-context credit traversals. Storage-only participants retain their cheaper plan-based path. Admission must account for both traversals, Native envelope validation, access lookups and allocation currency work; a helper's per-call bound is not sufficient evidence for the complete host. No production cost limit is frozen by this unit. |
| F4: missing direct `in_msg` assertion | Fixed; rebuilt controls fail | Assert the actual serialized transaction has no direct `in_msg`. Also set a direct message after preparation and require cached serialization to reject. Removing that serializer guard exposes the new negative witness; merely removing the preparation guard, as proposed in the review, would still be masked by serialization. |
| F5: no perturbed import-flow rows | Fixed; rebuilt controls fail | Zero either account's imported amount and swap the two amounts; all three must reject. The positive rows are decoded from actual Native account/transaction artifacts and credited by actual InMsg augmentation. |
| F6: construct descriptor before delegated preparation | Disputed change; document invariant | The full entry has already successfully constructed a descriptor containing the same binding plus input/effects. The smaller binding-only descriptor cannot newly exceed depth, bits or refs. Constructing it before validation changes malformed/null-binding failure ordering. All objects remain private and must be discarded on an exception; no publication occurs. Allocation failure remains a local exception, not proof of invalid candidate data. |
| F7: unique full entry obligation moved out of scan comment | Fixed | Restore an explicit note that the enclosing host must publish exactly one full tag-12 entry. The factory alone never proves this obligation. |
| F8: opaque legacy decoder status | Deferred production prerequisite; classification explanation corrected | Existing VM-to-Status conversion remains unfinished source-aware wiring. Exception class alone cannot classify every VmError as candidate-invalid: authenticated state corruption or locally unavailable data is not a candidate fault. Failure propagation short-circuits rather than emitting one status per receiving role. No string matching or new error class is added here. |

## Reconstruction is not a factory selector

A shared descriptor identifies one restricted participant in a logical batch.
It does not authorize arbitrary choice among helper functions. The enclosing
validator must independently derive the exact authenticated inbox, roles,
effects, wrappers and Native evidence, reconstruct the expected transaction,
then compare all required hashes. Actual InMsg evidence supplies a second,
independent conservation check; it is not a switch selecting whether a caller
wants its own message credited. A claimed credited-amount field would still
require reconstruction and cannot substitute for it.

The test supplies one canonical envelope vector to input construction and
Native evidence construction. This does not establish network authentication
or complete inbox reconstruction. Its transfer values are encoded from the
same fixture and decoded in preparation; no claim is made that this test alone
provides independent effects authorization. Those scope limits do not justify
weakening the required full host reconstruction.

## Arithmetic and exceptions

The wrapper adds no amount arithmetic. Native credit uses checked addition and
wire encoding; allocation uses checked addition/subtraction per currency.
Subtraction succeeds only when each remainder is nonnegative. The wrapper
retains the delegated failure classification and does not add a catch-all.
The descriptor is private metadata, not a public post-seal mutation API.

The review's binary timestamp comparison and passing test support its observed
test run, but timestamps alone are not build provenance. Recorded source and
binary hashes plus successful rebuilds are used for the removal controls.

## Evidence status

The original stub failed and the implemented fixture passed. After review
repairs, all seventeen removal controls rebuilt successfully and failed:
twelve isolated wrapper-contract cases, wrong descriptor tag, cached direct
input, and three perturbed import-flow rows. The exactly restored source passes
all five regression targets and standalone transaction-header compilation.
Raw outputs, exact substitutions, and source/binary hashes are recorded in
`measurements/uno-v2-import-participant-evidence.json`. This is not M1 acceptance
or exhaustive independent-guard coverage. These manual controls are not recurring
mutation CI. No production activation,
retirement rule, new wire field or cost-policy value is installed by this unit.
