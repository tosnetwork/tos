# Mixed allocation and payout boundary review

The read-only review is in `~/memo/reviews/uno-v2-mixed-payout-review.txt`.
This extends the inactive M1 private overlay: internal Native allocation edges
and one priced payout can share a batch. It does not activate the record tags,
authenticate withdrawal obligations, handle nonempty inboxes, or implement the
separate aggregate operation-fee output. Native balance arithmetic alone never
authorizes a transfer of custody principal.

## Review disposition

| Item | Disposition |
|---|---|
| B1: old custody envelope | Added an incoming allocation making custody sufficient for a payout above its old balance. The independent old-balance check must still reject. No error-text-only assertion is used as mutation evidence. |
| B2: mixed replay | Added a three-account mixed replay at the exact engine-edge limit, plus altered account root, AccountBlock root, message and end LT. |
| B3: third-account wiring | Both incoming and outgoing amounts now have nonzero witnesses; a third-account overdraft is rejected. |
| B4: map lookup | Disputed as a present exception defect. The planner inserts every update key, and the exact update/write scan proves equality before any participant is built. The lookup therefore cannot miss on an admitted execution. Documented that invariant rather than adding an unreachable fallback guard. Weakening the exact-set check is not an allowed future refactor. |
| B5: partial pair contract | The public declaration now requires every effects update to be materialized and independently included in full-set Native value flow. Added direct pair balance assertions. The pair alone does not conserve a graph touching a third account. |
| B6: host fee slot | Mixed replay and construction now use exactly one engine edge with a limit of one. The independently priced fee edge needs its own checked extra slot. |
| B7: diagnostics | Count overflow now reports payout transfer count overflow, not a logical-time error. The checked arithmetic is unchanged. |
| B8: third-record tag | Explicitly check settlement tag 11 on third accounts, including zero-allocation full-entry batches. Legacy explicitly null-context primitives still use storage tag 10 for third accounts. Live scope acceptance remains closed. |
| B9: rejected boundaries | Added exactly-one engine invocation checks to both one-unit-short cases. Neighboring exact-bound positives and rebuilt-source mutations are the evidence; error wording is not the property. |

## Arithmetic and evidence boundary

Allocation sums are applied before the payout and actual forwarding-fee debits.
Each sum has a checked 256-bit bound; each subtraction checks sufficient funds
for every currency. Incoming allocations cannot enlarge the old custody payout
envelope, while outgoing allocations can leave insufficient funds to honor it.

The independent check reads actual serialized Native balances, messages and
fees. Its edges are the decoded effects graph plus one actual priced fee-funding
edge. A fee edge may share endpoints with an engine edge: both values must be
counted, not deduplicated. The graph's count limit is unchanged; checked host
overhead reserves one additional verification edge before state reads.

No new catch or error category is introduced. VM, virtualization, builder and
allocation exceptions still propagate to a source-aware caller. These helpers
are not wired to production. At wiring, invalid authenticated configuration,
candidate data, missing local state and engine faults must retain their distinct
origins; merely naming a caller collator or validator is not sufficient to
classify every failure. No owner policy default is introduced here.

The review's inability to run tests is not our execution evidence: its syntax
checks used a sibling worktree's generated headers, and its description of the
local build as absent is not accurate for the running build used here. Our
evidence must come from this checkout's successfully rebuilt targets.

Nonblocking follow-ups remain open: typed resource parameter grouping, closer
alignment of payout/allocation artifact rereads, and eliminating redundant
entry graph scans without weakening standalone entry validation. The pair scans
the graph twice, entry preparation once, and the overlay planner once; this is
a constant number of graph passes, not one pass in total.

Fifteen successful rebuilds each produced a failing control. The old-principal
control specifically made the prohibited payout succeed; the count-overflow
control changed observed state loads from zero to two. Both are independent of
rejection wording. The four replay comparisons and the composite zero-allocation
tag control each fail their explicit assertion. After exact source restoration,
all five regression targets and standalone header compilation pass.

Raw outputs, substitutions, build/test exit codes and source/binary hashes are
in [the manual evidence](measurements/uno-v2-mixed-payout-evidence.json). A failed
patch application was not counted as a red test. Manual red controls must not
be described as a recurring CI mutation gate.
