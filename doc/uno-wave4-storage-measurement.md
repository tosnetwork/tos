# Wave 4: bounded existing-state storage measurements

Status: test-only measurement, not production partition-schema approval or a
complete synchronization/consensus benchmark. Source baseline
`33895e3537ebbf3b44ec7cc63ea6aeef34ddb685` plus the measurement changes committed
with this report. Date: 2026-09-06. Raw rows are in `doc/measurements/`.

## Fixture and procedure

Build: existing CMake Release tree, clang++-21, `-O3 -DNDEBUG`, Ninja, crypto
prototype tests ON. Hardware: shared build host, Intel Xeon Platinum 8455C,
192 logical CPUs. No global cache dropping, CPU isolation or disk-cache control.
Measured runs must not overlap another planned build or benchmark. Background
machine activity is not fully controlled.

Each sample runs `test-uno-storage-measurement --filter SnapshotStages` in a new
process with `TOS_UNO_STORAGE_KEYS` equal to 1000, 8000 or 32000. Each uses a fresh
temporary RocksDB/CellDb V2 directory, then destroys that actor/scheduler and opens
the same database again **inside the same process**. Seed 91, `std::mt19937`, one
byte per generator output, gives identical prefix-related key sets across sizes.
There are no deletes and no garbage-collected spent-nullifier evidence.

The payload is the real persistent `UsedNullifiers` dictionary inside a valid
single-account shard wrapper. Before sampling storage it passes the actual
`Transaction::prepare_workchain_batch` and serialization with a Counter fixture,
default 65536 account-cell limit and full batch witness/effects wrapper. It is
not a full UNO Note/anchor/reservation/accounting state or an authenticated network
checkpoint. The snapshot carries the initial executor wrapper rather than the
larger synthetic batch wrapper; these counts must not be conflated. The reported
batch data closure is `tx.new_data`, whereas the serialized account closure is
`tx.new_total_state`. The actual Native limit applies to code/data/library roots
inside `check_state_limits`, not to the serialized account header itself.

The source DAG and serialized BoC remain resident during import. The file was
just written and may be in the OS page cache. Thus this is **fresh-database import**
and **same-process reopen**, not cold-node synchronization or cold-device I/O.
CellDb is non-memory mode, V2 enabled, configured cache/min-cache 64 MiB; importer
resident frontier budget 16 MiB. Other production importer/spool defaults remain
unchanged. Synthetic block ID `(wc=2, shard=all, seqno=1)` registers the imported
root for the existing ownership/GC-lease protocol, not consensus finality.

## Columns and timing boundaries

`STORAGE_CSV` columns:

1. keys, seed, snapshot BoC cells, BoC bytes, synthetic batch data-closure cells,
   serialized account-closure cells;
2. generation ms (keys, used-set and initial shard); Native host admission plus
   batch serialization and the two closure censuses ms;
   BoC serialization ms (not file write/fsync);
3. import-request ms: actor startup/DB opening through successful import callback,
   including bounded parse, spool and CellDb commit, not separate measurements of
   those internals;
4. first full lookup ms: root validation/extraction and membership lookup of every
   supplied key on the imported lazy root;
5. root-store ms: request to successful synthetic block/root registration callback;
6. reopen-root ms: fresh actor/DB opening to root load callback;
7. reopen-validate-and-append ms: full lookup, `UsedNullifiers::from_root` full
   validation, duplicate rejection and staging one fresh key against restored state;
8. whole import / whole reopen actor-lifecycle ms, including additional assertions,
   traversal and teardown, so they overlap rather than add to preceding columns;
9. Linux `getrusage(RUSAGE_SELF).ru_maxrss` KiB at process baseline, after generation
   plus Native admission, after serialization, after import lifecycle, after reopen;
10. exact snapshot root hash.

RSS is the cumulative process high-water mark including source objects, runtime
and allocator retention; it is not incremental memory charged to one phase, and
it is not an upper bound on future production process RSS. No commitment/inbox,
Halo2 proof, engine execution, partition split or Reserve settlement stage is
hidden inside these reported labels.

## Instrument and limits

`CapacityGateInstrumentSelfCheck` constructs the same real payload with 32768
keys and requires the Native account-limit failure, then requires 32000 keys to
pass. This deliberately crosses the default limit and checks the structured
limit code rather than an error string. This test is not a new maximum-capacity
search; the prior 32765/32766 fixture boundary remains separately documented.
The larger sample is never imported and never counted as a valid measured state.

The capacity self-check was demonstrated red by lifting the measured Native
limit to 100000: the over-limit input then succeeds, violating the required
rejection. `SnapshotStages` was independently demonstrated red by bypassing import
and falsely marking its phase complete: the subsequent real database reopen
cannot load the required root and fails. Neither check depends on error text or
on a timer being nonzero. Both mutations were restored before sampling.

All temporary databases/files are removed only after successful measurements;
failures print and retain their paths. Formal limits, production schema and
worst-case execution time remain undecided. Pure transfers, cross-partition double
spends, concentrated-prefix growth, batch splitting, prepare/refund and long anchor
rolling are not exercised by this storage fixture.

## Results

Pending sequential timed runs; do not infer numbers from fixture size or other
cryptographic measurements. Observed maxima will be sample maxima, not WCET.
