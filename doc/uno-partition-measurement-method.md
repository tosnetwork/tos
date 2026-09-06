# Isolated used-set partition comparison

`measure-uno-partition-state` is a test-only instrument, not a proposed
production storage schema. The two modes use the same `UsedNullifiers` and
Native dictionary/Cell implementations and identical deterministic key seeds:

- `single`: one dictionary root.
- `pages16`: a C++ vector of 16 dictionary roots, routed by the first four key
  bits. No coordinator Cell references that vector or its roots. There are no
  Native partition accounts, participant records or block commitments here.

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
Its serialization rows measure used sets only, excluding reservation/owner
tombstone roots. Do not interpret them as full settlement serialization costs.

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
