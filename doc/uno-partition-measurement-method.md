# Isolated used-set partition comparison

`measure-uno-partition-state` is a test-only instrument, not a proposed
production storage schema. The two modes use the same `UsedNullifiers` and
Native dictionary/Cell implementations and identical deterministic key seeds:

- `single`: one dictionary root.
- `pages16`: a C++ vector of 16 dictionary roots, routed by the first four key
  bits. No coordinator Cell references that vector or its roots. There are no
  Native partition transactions, participant records or block commitments here.
  The additional storage-only envelope phases project the roots into Native
  Account/ShardAccounts structures, without making this vector a host schema.

The executable accepts `mode scenario history_entries samples seed`. Suggested
comparison matrix: both modes; history 0, 1024, 8192, 32768, 65536; three samples;
seed 45; scenarios `idle`, `insert`, `prefix`, `split`, `duplicate`, `refund`.
Run separate invocations serially on the same hardware/build, with no competing
benchmark or compilation. The empty/idle combination is an empty used-set
operation, **not** a complete UNO empty block. All input counts are experiment
controls, not production recommendations.

The current update has two fresh keys. `prefix` zeros their and the history's
first 128 bits: all fall in one page, explicitly exposing skew rather than
assuming uniform distribution. `split` rebuilds the same key set in 32 pages
for the paged mode; the single mode fully rebuilds one root as a control. This
is a bulk repartition primitive, not an incremental production split protocol.
`duplicate` claims the same key twice, on different pages in paged mode; the
canonical route check must reject before any source-root publication. `refund`
uses the actual per-page `NullifierState` reservation/refund primitives with an
owner ID, but does not authenticate a prepare/terminal receipt, lock funds,
reserve note-tree leaves, charge fees or implement the Native Reserve machine.
The original serialization rows measure used sets only. Additional
`serialize_pending_roots` / `serialize_refunded_roots` and corresponding
`decode_validate_*` rows include used, reservation and owner/manifest roots as
three independent BoCs per page. This is not a production account encoding:
framing and shared contents may be repeated between those BoCs. Neither set of
rows includes note-tree reservations, authenticated receipts, funds or full
settlement serialization. See `uno-reservation-roots-pilot.md` for the measured
scope and permanent-owner roundtrip checks.

## Timing and counters

stdout is CSV; stderr contains per-sample structural metrics. Capture both.
`load_full` revalidates all used dictionaries already resident in memory;
`lookup_history` looks up two old keys (no lookup when history is empty);
`incremental_absence` checks two fresh keys against validated state. Neither
incremental row traverses full historical state. Updates start from the same
baseline for every sample; they do not accumulate growth between samples.

`serialize_all_pages` includes all nonempty dictionaries; `serialize_changed_pages`
only serializes pages whose root changed. A touched-page BoC still includes the
entire reachable page, not just newly created cells. `deserialize_new_arena`
constructs new Cells from the in-memory BoCs and `new_arena_full_validate`
validates them again. This is cold **arena** restoration, not cold OS caches,
disk acquisition, network synchronization or database reopening.

The structural metrics count the union of reachable Cell hashes, payload bits,
sum of per-page BoC byte lengths, and hashes introduced relative to the old
state. Per-page BoC lengths include each serialization's framing and may repeat
shared contents; they are not a canonical multi-account state encoding. New
hash count is not a claim about bytes actually written to CellDb. Counters use
checked arithmetic. `max_depth` excludes any future wrapper or account layer.

The RSS column is Linux `getrusage(RUSAGE_SELF).ru_maxrss`, the process high-water
mark in KiB when sampled after each phase. It includes key generation, metric
sets, simultaneously retained old/new arenas and earlier samples. It is **not**
a phase-local peak or an isolated validator memory requirement. Timed regions
exclude input generation and invariant assertions unless stated by their
phase name; metadata scans have their own row. Preparation of per-page refund
state is outside reserve/refund primitive timers.

## Instrument failures and limits

`--self-test` asserts exact-entry-limit success, one-entry-over rejection,
cross-page duplicate rejection, failure atomicity of immutable source roots,
old-key retention and checked-counter overflow. Its required mutations are:
remove the entry guard; remove canonical routing; publish updates into the
source instead of the staged copy; remove the checked-add overflow guard.
Each must make the self-test nonzero. Exit status and state/count properties,
not error strings, are the evidence. Mutation outcomes are recorded separately
from performance results after they have actually run.

The experiment's command-line input cap prevents accidental huge allocations;
it is not ConfigParam 43 enforcement. In particular, 32768/65536-key single-root
rows may exceed the already demonstrated Native account capacity. Their
successful dictionary operations do not overturn that boundary.

Not measured here: full wrapper/candidate/effects depth, anchor/note frontier,
proof parsing or verification, participant TL-B, authenticated witnesses,
AccountBlock or shard updates, Native value-flow, fee isolation, CellDb atomic
commit, GC, migration obligations, complete cold synchronization, or safety
margin to a real validation deadline. These gaps cannot be filled by treating
the root vector as already implemented multi-account host state. In particular,
this tool alone cannot support selection of a production schema or three input
limits. Actual observed maxima are not WCET proofs.

## Recorded run: 703935250

Code: `7039352500a7c025818b812d437b5303b5702db6`; raw directory:
`build/uno-wave4-run-703935250/partition-*.csv` and matching `.metrics`.
The complete archived raw run is maintained by the fourth-wave report.
Release build, Clang 21, `-O3 -DNDEBUG`; Intel Xeon Platinum 8455C,
192 logical CPUs. Both modes used seed 45 and the matrix above. There are
60 invocations, three samples each, and 1,620 phase rows. The table values below
are sample medians, **not** p95/p99 or WCET estimates. Runs were serialized but
the raw metadata does not establish CPU pinning or host isolation; recorded one-minute system load
was 0.49 at run start and 4.70 at end. Relative timings must not be attributed
solely to the partition representation from this three-sample, fixed-order run.

### Two fresh keys against historical spent state

`load_full` checks the entire resident history; `absence` is the two-key
incremental lookup. Changed-page serialization is still whole-page BoC
serialization, not a persistent CellDb write.

| History | Mode | Full load ms | Absence µs | Update µs | Changed-page serialization ms | Changed BoC bytes | New unique Cells |
|---:|---|---:|---:|---:|---:|---:|---:|
| 0 | single | 0.000092 | 0.073 | 1.929 | 0.000818 | 88 | 3 |
| 0 | pages16 | 0.000361 | 0.099 | 0.746 | 0.001138 | 94 | 2 |
| 1,024 | single | 0.215 | 2.328 | 9.090 | 0.318 | 42,231 | 22 |
| 1,024 | pages16 | 0.213 | 1.555 | 6.361 | 0.040 | 4,994 | 17 |
| 8,192 | single | 2.031 | 3.129 | 13.020 | 3.426 | 335,703 | 31 |
| 8,192 | pages16 | 3.392 | 4.381 | 18.222 | 0.538 | 41,729 | 24 |
| 32,768 | single | 8.402 | 3.837 | 15.237 | 12.366 | 1,402,744 | 32 |
| 32,768 | pages16 | 13.984 | 5.442 | 22.448 | 2.166 | 164,558 | 27 |
| 65,536 | single | 17.377 | 4.849 | 21.779 | 27.645 | 2,793,889 | 38 |
| 65,536 | pages16 | 29.339 | 6.644 | 26.920 | 4.623 | 331,386 | 31 |

Observed: at the two largest levels, full resident validation is milliseconds
while the two-key absence lookup is microseconds. That supports separating
incremental hot work from required full restore validation; it does not justify
omitting old spent-nullifier queries. The paged representation reduced bytes
and time for serializing only the touched pages in this uniform-key sample,
but did not reduce the measured full-load or two-key update times at those
levels. Serialization of **all** pages had medians 14.106/17.603 ms at 32,768
and 30.771/38.130 ms at 65,536 (single/pages16).

| History | Mode | New-arena decode ms | New-arena full validation ms | Process peak RSS KiB | Used-set depth | Total used-set Cells after two inserts |
|---:|---|---:|---:|---:|---:|---:|
| 32,768 | single | 11.137 | 7.004 | 37,284 | 19 | 65,539 |
| 32,768 | pages16 | 21.154 | 13.222 | 30,720 | 15 | 65,524 |
| 65,536 | single | 23.439 | 14.064 | 77,608 | 21 | 131,075 |
| 65,536 | pages16 | 38.074 | 14.701 | 58,092 | 17 | 131,060 |

RSS is the maximum high-water observation across that invocation, including
old/new arenas and instrumentation; it is not a stage-local memory saving
claim. The single-root counts already cross the shared Native account cell
limit; these rows are deliberately primitive-only results, not deployable
host capacities. The page totals omit every account and coordinator wrapper.

### Skew, split and failure/settlement primitives

| History | Scenario/phase | single median µs | pages16 median µs |
|---:|---|---:|---:|
| 32,768 | prefix: changed-page serialization | 14,517.4 | 23,975.9 |
| 65,536 | prefix: changed-page serialization | 29,949.7 | 30,141.1 |
| 32,768 | split: full rebuild control / 16→32 repartition | 180,664 | 192,386 |
| 65,536 | split: full rebuild control / 16→32 repartition | 393,250 | 265,542 |
| 32,768 | duplicate rejection | 14.978 | 16.256 |
| 65,536 | duplicate rejection | 24.131 | 15.445 |
| 32,768 | reserve primitive | 10.929 | 9.307 |
| 32,768 | refund primitive | 20.112 | 20.057 |
| 65,536 | reserve primitive | 10.441 | 13.499 |
| 65,536 | refund primitive | 20.783 | 29.876 |

The concentrated-prefix case put all history and new keys on one experimental
page. Both modes had exactly the same changed BoC bytes (872,434 at 32,768;
1,729,348 at 65,536), used-set Cell counts, depths, and introduced Cell counts
(32 and 35 respectively). Partitioning by a fixed prefix did **not** improve
that structural limit; any production skew/split policy is still unchosen.

The split control rebuilds an identical single root, hence zero changed bytes
and zero new hashes after the costly rebuild. The experimental 16→32 split
introduced 32 unique Cell hashes and serialized 1,337,432 / 2,663,073 changed bytes at
the two levels; its depths were 14 / 16. This is not an atomic Native account
split or bounded migration protocol. Across all measured partition phases,
the largest observed time was the single 65,536-key rebuild: **399.279 ms**;
the paged maximum was **268.100 ms** for the same scenario. These maxima omit
proof verification, complete transaction construction and persistent commit,
and therefore cannot be compared as end-to-end validation bounds to an alarm.

## Native account envelope extension

`native_account_envelopes` builds a structurally valid Native Account for each
experimental page at addresses 0 through page-count minus one in workchain 2,
and a real augmented ShardAccounts dictionary. An empty page has one empty data
Cell. Accounts have no code/library, zero balance and placeholder zero storage
usage metadata. These addresses and payloads are experiment controls, not a
proposed partition-addressing or account schema. There are no participant
transactions, last_trans updates, coordinator, candidates/effects, authenticated
read/write witnesses, fee calculation or settlement reservations.

The phase includes a full per-page data-closure scan and TL-B Account structural
validation; it is not an incremental hot-path cost. `native_account_dictionary_boc`
serializes the whole account dictionary, not only changed accounts or persistent
CellDb deltas. Additional stderr rows report per-account maxima of data Cells,
bits and depth, account count, union dictionary Cells/bits/depth and BoC bytes.
Account metadata remains a simplified lower-bound fixture, not a deployable
state with correctly computed storage charges.

`data_fits_65536` compares the maximum page data closure with the fixed experiment
control 65536. The Native size check in `transaction.cpp` counts code/data/library
roots, not the whole Account/ShardAccounts envelope; these two metrics must stay
separate. A false result rules out even this minimal data payload at that control.
A true result does not validate a complete UNO account or prove production
headroom. No shared ConfigParam 43 value is changed.

The instrument's self-test is now a dependency of `all-tests` and registered as
`test-uno-partition-measurement-self`. It unpacks each Native account and compares
its data hash with the assigned page, checks exact/one-cell-over bounds and a
BoC roundtrip. Removing the data-cell comparison or replacing stored page data
with an empty Cell independently makes it fail. Performance matrices remain
manual. See `uno-native-envelope-pilot.md` for the new measured rows; the earlier
703935250 tables above retain their original primitive-only scope.

## Historical run completion notes (703935250)

All duplicate cases rejected without publishing source changes and had zero
introduced hashes/changed bytes. Refund samples checked actual reservation
then used-state transitions in `NullifierState`; their used-set metrics matched
the two-key insert cases. They do not measure authenticated Deposit/Withdrawal,
note-tree reservation, principal or Native fees. No assertion failure was
reported in the 60 completed runs. Each phase had all three sample rows; all
timings were finite and nonnegative, all RSS samples positive, and all structural
metrics identical across the three repetitions of each scenario. Timing spread
remains visible: for example single 65,536-key full load was 17.377 ms median
but 28.277 ms maximum, and the split run's full serialization reached 76.381 ms.
Do not discard those samples or infer stable tail percentiles from three runs.

The deliberate instrument-failure runs preceded this data run: removing each
entry-budget, route, staged-copy and checked-add guard produced a nonzero
self-test, and the restored instrument passed. Their detailed logs are named
`build/wave4-partition-{budget,routing,atomic,overflow}-mutation.log`.
