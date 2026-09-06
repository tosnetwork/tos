# Reservation root closures and terminal capacity

This extends the owner-history comparison with **deduplicated Cell closure**
measurements. Separate BoC byte sums cannot answer the Native Cell-count limit.
No production schema, ConfigParam 43 value, admission policy or host changed.
External review remains pending at the milestone.

## Counting and scope

The existing checked Cell walker now accepts multiple roots. It counts each
Cell hash once, checks ordinary fixture Cells and adds payload bits with the
checked counter. Each experimental page is measured with all of its used,
reserved and owner/manifest roots. A separate union covers all pages. Per-page
maxima and cross-page deduplication are distinct metrics: a global shared Cell
does not make an individual account's reachable closure disappear.

`reservation_cells` reports `max_page_cells`, `max_page_bits`,
`max_root_depth`, `union_cells`, `union_bits` and `roots_fit_65536`, for pending
and refunded cuts. Maxima of different fields need not occur on the same page.
Scans are outside codec timers, after restored-root verification; they add work
and affect process HWM and later cache state. Depth excludes outer wrappers.

The boolean tests the fixed experimental control 65536, not a resolved consensus
policy. Out-of-bound controls intentionally complete and emit false so the
failure boundary remains visible in the dataset. The self-test separately
requires exact-bound success and one-cell-over failure. There is no production
preflight connection or claim that the instrument limits execution cost.

Co-locating these three roots is the comparison assumption, not an approved
partition schema. Their union is a lower bound on an account containing them:
it omits the data wrapper, code/library, notes, anchors, coordinator and future
settlement space. A false control rules out even this payload at that bound;
a true value does not establish deployable capacity. Type-isolating the roots
into different accounts would need a different complete layout comparison.

## Tests and provenance

A literal DAG has three distinct Cells and five payload bits, with a leaf
shared by both parents and supplied again as a root. It must still count 3/5.
A refunded fixture must count more than its used root alone, and agrees with
Native CellStorageStat accounting across the same roots. Exact/one-cell-over
controls use 3/2 against the three-Cell fixture.

Three independent mutations fail the registered self-test (CTest exit 8):
disable deduplication, omit the owner root, and always report the limit satisfied.
Restoration passes. No assertion relies only on diagnostic wording. The archive
contains precise patches, failure diagnostics, restored build/CTest and data.
Existing exception handling and checked output flushing remain unchanged.

Measured source: `cb2e70791` plus `reservation-capacity-final-source.patch` in
`doc/measurements/uno-reservation-capacity-pilot.tar.gz`. Use the twenty-invocation
matrix in `uno-owner-history-pilot.md`, then add:

```sh
for history in 13105 13106; do
  build/measure-uno-partition-state single owner-refund "$history" 3 45
done
```

All 22 invocations completed: 1122 phase rows and 132 closure records. Each cut
has three identical structural measurements. Release clang++-21, `-O3 -DNDEBUG`,
seed 45 on the same Xeon Platinum 8455C host; environment observations are in
the archive. This does not establish host isolation or controlled cold caches.

## Observed boundary

Single page, one refunded single-key owner per historical key, plus the current
two-key event:

| Historical keys | Pending Cells | Refunded Cells | Pending control | Refunded control |
| --- | --- | --- | --- | --- |
| 8192 | 40966 | 40967 | fits | fits |
| 13105 | 65531 | 65532 | fits | fits |
| 13106 | 65536 | 65537 | fits exactly | exceeds by one |
| 65536 | 327686 | 327687 | exceeds | exceeds |

At 13106, pending/refunded payload bits are 10181507 / 10180968, with maximum
root depth 19. The terminal cut gains a Cell while losing bits: byte or bit
headroom alone does not establish Cell headroom. Even before adding wrappers,
accepting the pending cut without future capacity would leave this primitive's
refund beyond the control. This is not a claim that the real host has admitted
such a candidate or that this synthetic single-key history is a valid sequence
of complete proof-bearing transactions.

At 65536 historical keys, the uniform 16-page owner-history experiment has a
maximum page closure of 21188 Cells / 3271846 bits / depth 19 at both cuts;
the global union changes from 327656 to 327658 Cells. The corresponding
spent-only control has maximum 8475 Cells / 1065912 bits / depth 17, with unions
131062 and 131064. Positive page controls omit all other production components
and do not establish capacity under concentration or a future split policy.

## Remaining gates

The terminal reservation must be evaluated against the entire chosen state
layout, not only the used-set or present pending state. These data do not pick
that layout or its reservation policy. Large manifests, mixed pending/Paid
history, concentration, persistent account wrappers, note reservations,
authenticated obligations, coordinator/participant atomicity and successor
cutover peaks remain unmeasured together. No production count limit, WCET or
deadline margin follows; Y-1/D-3 remain open.
