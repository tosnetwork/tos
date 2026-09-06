# Storage comparison: evidence and remaining decision inputs

Snapshot: `31813e9cc`, 2026-09-06. This is the consolidated data-delivery ledger
for the partition comparison, not approval of a production schema or completion
of Y-1/D-3. It separates real component evidence from the missing joint host
experiment. External milestone review remains pending.

## Keep the resource units separate

| Resource | Measured scope | Do not substitute |
| --- | --- | --- |
| Native per-account Cell limit | Reachable code/data/library closure; host wrappers stored inside data count here | Entire ShardAccounts/AccountBlock size or simultaneous old/new database versions |
| Candidate/block evidence | Versioned input, inbox, witnesses, effects and physical records | Engine-defined wire_bytes or a state BoC alone |
| Logical persisted Cell bytes | Merged Cell hash-key/value records at specified retention cuts | BoC size, compressed SST size, WAL or device writes |
| Physical/memory peak | Live buffers, arenas, database versions, directory and migration staging | Final state size or a per-account protocol limit |
| Depth | Actual reference paths including their wrappers | Total Cells or a standalone anchor capacity |

The Native limit distinction is visible in `crypto/block/transaction.cpp`:
`storage_stat.replace_roots({new_code, new_data, new_library}, ...)`, followed
by comparison of total Cells with the applicable account limit. Other wrappers
still need their own budgets; excluding them from that particular limit does
not make their cost disappear.

## Decision-relevant observations

Each row retains its own source, fixture and measurement boundary. These are
not samples of one common pipeline and must not be summed into a latency bound.

| Evidence | Observation | What it establishes | What it does not establish |
| --- | --- | --- | --- |
| `23a83d6ba`, [Native envelopes](uno-native-envelope-pilot.md) | At 65536 history plus two keys: maximum data closure 131075 Cells single; 8475 uniform 16 pages; 131075 concentrated 16 pages | Fixed-prefix partitioning helps this uniform distribution, not concentration | Adaptive splitting, coordinator or admitted complete accounts |
| `0c9b9d6c2`, [incremental persistence](uno-incremental-partition-pilot.md) | Uniform 65536 history: two-key update adds 39/41 records and 4159/4405 logical bytes, single/16 pages | Real retained-root and reopen behavior; more pages need not reduce local writes | Physical I/O, full execution or multi-record host atomicity |
| `8eee1613f`, [bulk repartition](uno-persisted-bulk-split-pilot.md) | Uniform 16→32 at 65536 history: two-root retention is 11728041 logical bytes, versus baseline 11710804 | Actual same-database sharing and old-root release with spent retention | Independent-database copy, authenticated migration or successor peak |
| `cb2e70791`, [owner history](uno-owner-history-pilot.md) | Single-page owner/manifest BoCs reach 5368183 bytes at 65536 historical owners | Owner history is a growing component, not the constant 93-byte current-event fixture | Full account or deduplicated physical bytes |
| `9ff62cfd1`, [three-root closure](uno-reservation-capacity-pilot.md) | Single-page 13106 owner history: pending 65536 Cells, refunded 65537 | Future settlement can cross a Cell limit even as bits decrease | A production history limit or complete proof-bearing event sequence |
| `31813e9cc`, [existing component wrappers](uno-note-component-envelope-pilot.md) | Same 13106 history with window 100: pending/refunded 65648/65650 Cells | Existing frontier/anchor/component wrappers already invalidate the raw-root fit | Full engine, Native account, note archive, fees or coordinator capacity |

The latest component archive (96 rows), incremental archive (96 record rows),
bulk-split archive (48 footprint rows), root-capacity archive (132 structural
rows) and owner-history archive (120 byte rows) were read directly when preparing
this ledger. Selected table values were checked against all three archived
repetitions, rather than taken solely from report prose. This is an archive
consistency check, not a rerun at the snapshot HEAD or automatic mutation CI.

## Required scenario coverage

The user-requested comparison is broader than the available pilots:

| Required scenario | Existing evidence | Joint acceptance still missing |
| --- | --- | --- |
| Empty block | Idle dictionary/anchor primitives and functional NoteState idle tests | Bounded complete block with system-message/checkpoint progress and real deadline |
| Private transfer | Real isolated crypto ABI corpora; separate dictionary and NoteState effects | One authenticated candidate through admission, inbox, proof, effects and persistent host replay |
| Cross-partition duplicate | Canonical-route/late-duplicate primitive failures; dropped/wrong-route persistence mutations | Exact read/write/participant coverage and I13a-I13e in the versioned host |
| Concentrated growth | Fixed 16/32 prefixes remain concentrated | Bounded adaptive routing, directory growth and deterministic split exhaustion |
| Bulk split | Real same-database 16→32 retained-root experiment | Account identities, directory/evidence size, reserved work and restricted physical records |
| Prepare/refund | All-root codecs, permanent-owner history, paired frontier/reservation component tests | Authenticated obligations, large/mixed manifests, Native principal/fee isolation and atomic settlement |
| Long anchor rolling | Isolated rolling instrument; mature windows 3/100 in components | Whole-state persistent rolling with realistic ingress/settlement and history retention |
| Large history, tiny current event | Spent/owner closure, real local update and restore measurements | Complete typed state, bounded authenticated hot access, cold import, GC and catch-up together |

M1 real Simplex block-consensus evidence is distinct from these payload and
storage gates. A constant Counter candidate source does not supply the missing
private-candidate/availability pipeline. Conversely, raw dictionary capacity
failures do not negate the real persistence and restart evidence.

## Next comparison experiment, without production schema expansion

The next useful step is a test-only adaptive partition/directory comparison,
not another uniform fixed-prefix success run. It must:

1. Specify canonical ownership and non-membership for all keys, including
   empty ranges; candidates must not choose a page by assertion. Compare
   concentration and long common prefixes without silently dropping keys or
   assuming pseudorandom distribution. Finite key-space exhaustion must be an
   explicit experimental boundary, not an unbounded generation/split loop.
2. Budget leaf data, directory nodes, bounded coordinator metadata and split
   staging separately. Any experimental control values remain test parameters,
   not ConfigParam 84 defaults. Count complete closures, depth and newly
   persistent records; do not threshold on key count alone.
3. Preserve historical spent and terminal-owner evidence. Pending manifests
   crossing a split need an explicit comparison model, not deletion, a reset
   owner ID or unmeasured duplication. A spent-only prototype must label that
   limitation rather than claim settlement coverage.
4. Keep complete page data out of the coordinator's ordinary Cell reference
   closure. Hash binding alone is not availability: identify which experimental
   evidence would carry the accessed data and count that representation.
5. Preserve a staged all-or-nothing model and independently check old/new
   routing and complete key coverage. Include mutations for omitted directory
   changes, wrong ownership, lost old evidence and partial publication. Do not
   call those tests production I13 acceptance before physical-record replay
   exists.
6. Produce the same scenario/configuration/seed/sample/retention-cut metadata
   as the current pilots. Cold database reopening and cold OS storage are
   different conditions; neither may be claimed from a fresh in-memory arena.

This contract does not assign account addresses, TL-B constructors, production
split thresholds, fees or a migration state machine. Those remain M0 decisions.
No positive fixed-prefix sample is a substitute for this comparison.

## Gates that stay open

The three production input limits require the versioned policy/admission work
and the whole validation envelope, including semantic/proof admission and
deadline margin. Independent component medians and their maxima do not supply
that envelope, and the synchronous work cannot be bounded by citing a 60-second
alarm alone. No numerical limit or slot recommendation is made here.

Claim-only feasibility still requires a compatible accepted storage design,
unique inherited obligations and deduplication identities, full backing and an
authenticated old/new cutover without double consumption. Same-database sharing
does not establish that feasibility. The unused balance is not confiscated,
and copying a full instance is not a capacity solution.
