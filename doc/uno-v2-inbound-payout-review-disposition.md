# Inbound payout boundary review disposition

Scope: the post-admission pair and private payout overlay, based on
`ff4626e8c`. The complete runner still rejects nonempty inboxes. This is not
M1 completion or production admission evidence. The verbatim review is in
`~/memo/reviews/uno-v2-inbound-payout-review.txt`.

## Accepted test work

The review correctly asks for the outgoing allocation funding boundary, an
unsupported *written* recipient witness, and independent mutation of the
Native import credit. A recipient absent from the write set would also fail
the processing-record check and would not isolate the receiving-role rule.

The pair has a matched boundary fixture: old custody 1000, import 100,
payment 137, outgoing allocation 963 succeeds with custody zero; allocation
964 fails. Coordinator ends at 1963 in the successful case, after its own
100 import and the 100 forwarding fee. No allowance is borrowed from the
other role. The targeted composite control and its result are recorded in the
evidence artifact; the additional helper conservation check must be removed
with the insufficient-principal check to expose the negative fixture.

One rebuilt control now zeros only the overlay's independent imported credit.
The valid importing overlay fails with a per-account Native value-flow
mismatch (exit 1). Restored five-target build and regression pass. The raw
control, exact substitution and source/binary hashes are in
`measurements/uno-v2-inbound-payout-evidence.json`.

The unsupported-recipient fixture now includes the destination in the real
read/write set and carries zero principal. Its otherwise identical coordinator
message succeeds. Broadening the receiving set to all written accounts turns
the unsupported-recipient assertion red; neither missing processing evidence
nor a lost nonzero credit hides this predicate.

Five individual replay comparisons and inbound LT planning have rebuilt red
controls. The count experiment also records a **survivor**: removing only the
early planner count limit stays green because final-import construction repeats
the limit. Removing both checks turns the over-count assertion red. This proves
the composite limit, not independently that rejection preceded old-state reads.
Early count ordering is supported by source inspection and the direct planner
tests; this unit does not claim a new zero-state-load overlay witness.

## A: pair-level admission obligation (retained; live admission incomplete)

The pair has no independent inbox count or complete-recipient acceptance
check; its full-context preparations select each role's own messages. The
outer overlay enforces both roles and the explicit count before state reads.
This is a real caller-contract dependency, not a live silent-drop fix. Retain
the pair as a private materialization primitive and enforce complete-recipient
acceptance in the enclosing overlay. It is not a complete block consumer or a
queue-removal authority. The final admitted-input boundary must enforce the
same complete-input obligation before publication. Repeating planning inside
each primitive would not establish source authentication or aggregate work
admission. No owner policy or new numeric limit is needed to retain this
separation, and no direct pair caller may claim it consumed the complete inbox.

## B: block-level Native import fees (accepted, incomplete)

Actual InMsg augmentation and replay bind imported value and collected import
fees. Returning them is not consuming them in a complete block ValueFlow.
That integration remains open. This is distinct from the aggregate outgoing
operation-fee payment, which is also open; the two must not be conflated.

## C: downstream LT checks (retained)

The overlay scheduler makes the import helper's LT guards unreachable along
this correctly planned path. Direct helper tests already exercise those
guards. Keep them as the helper's own contract; do not claim that an overlay
failure independently witnesses each duplicated guard.

## Source attribution and work admission (still open)

The shared inbox decoder collapses VM failures into an ordinary Status. The
live boundary must distinguish malformed candidate material from unavailable
or corrupt authenticated state by source, not by exception class alone.
Builder, write and allocation exceptions still propagate from these private
helpers. Two complete receiving-role traversals and closure-validation work
must be included in admission. Count bounds alone do not establish a CPU or
memory envelope, and this change freezes no production numeric bound.

The review ran the existing filters without rebuilding. Embedded diagnostic
strings are not exact build provenance; the implementation evidence records
successful builds and source/binary hashes separately. Manual mutation logs
are not recurring CI gates.
