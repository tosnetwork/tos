# Wave 4: bounded existing-state storage measurements

Status: test-only measurement, not production partition-schema approval or a
complete synchronization/consensus benchmark. Measured instrument commit:
`7039352500a7c025818b812d437b5303b5702db6` (based on
`33895e3537ebbf3b44ec7cc63ea6aeef34ddb685`). Date:
2026-09-06. The serial matrix ran 09:50:14–09:52:07 UTC; these timestamps cover
the entire joint matrix, not just its final storage section. Raw storage rows are
in [measurements/uno-wave4-storage.csv](measurements/uno-wave4-storage.csv).

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
unchanged: maximum 50,000,000 cells, one root, 512 MiB scaffolding, 16 GiB total
cell bytes; 48 GiB per-import and 96 GiB shared spool caps, 300% minimum file-size
reservation ratio plus the checked encoding/rollback bound. The scheduler has
two threads; Native fixture global version is 15. Synthetic block ID
`(wc=2, shard=all, seqno=1)` registers the imported
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

Nine successful samples: exactly three independent process launches per size,
always seed 91. For each size all three root hashes, serialized byte counts and
cell counts agree. Each sample verified every key before and after root adoption,
reopened the database, verified the registered root hash, fully decoded the used
set, rejected a known duplicate and staged a fresh insertion. The fresh insertion
is not a committed UNO transaction. Every sample retained the source DAG in RAM.
Within each size, the three committed CSV rows retain sample order 1–3 from
`build/uno-wave4-run-703935250/storage-<keys>-<sample>.csv`.

| Keys | BoC cells / bytes | Batch data cells | Serialized account cells | Max process HWM, KiB |
|---:|---:|---:|---:|---:|
| 1,000 | 2,006 / 41,348 | 2,006 | 2,007 | 29,184 |
| 8,000 | 16,006 / 327,895 | 16,006 | 16,007 | 39,776 |
| 32,000 | 64,006 / 1,306,019 | 64,006 | 64,007 | 93,020 |

The equality of BoC-cell and batch-data-cell counts here is coincidental: they
describe different roots. The full serialized account includes its own header.
The Native account admission check passed all measured cases with its limit
unchanged at 65536; the self-check's 32768-key case was rejected and not imported.
This does not certify a full UNO state at 32000 entries or establish a production
capacity value. Process baseline HWM was 10752 KiB in all nine launches.

All following times are milliseconds. Values are **median / observed maximum**
among the three processes, not p95/p99 estimates or worst-case bounds.

| Keys | Generate | Native admission + census | BoC serialize | Import request | First full lookup |
|---:|---:|---:|---:|---:|---:|
| 1,000 | 7.176 / 7.195 | 2.748 / 2.798 | 0.534 / 0.543 | 39.239 / 40.629 | 8.073 / 9.328 |
| 8,000 | 70.916 / 71.611 | 14.712 / 15.573 | 4.641 / 4.705 | 161.336 / 161.565 | 74.265 / 74.725 |
| 32,000 | 278.194 / 327.893 | 42.861 / 63.041 | 14.116 / 19.331 | 603.887 / 781.021 | 328.073 / 330.037 |

| Keys | Root adoption | Reopen root | Reopen validation + staged append | Whole import lifecycle | Whole reopen lifecycle |
|---:|---:|---:|---:|---:|---:|
| 1,000 | 6.369 / 6.779 | 12.764 / 13.433 | 12.777 / 13.279 | 63.913 / 64.652 | 28.073 / 28.299 |
| 8,000 | 6.386 / 6.752 | 31.739 / 31.775 | 86.917 / 89.145 | 294.670 / 296.970 | 124.711 / 125.179 |
| 32,000 | 6.871 / 10.244 | 102.017 / 106.445 | 397.545 / 398.950 | 1172.860 / 1355.510 | 521.709 / 524.504 |

The largest measured import-request sample was 781.021 ms; the whole import
lifecycle reached 1355.510 ms. These are storage recovery operations, **not** a
per-block validity pipeline or a lower bound for UNO's slot. They cannot be
added to proof timings from another process to claim end-to-end deadline margin.
Likewise, a 16 MiB importer frontier budget is not a process RSS bound: the
measured process also owns source cells, account-stat dictionaries, database caches
and allocator state. The 93020 KiB observed HWM is not a safe production maximum.

No failed timed sample occurred in this nine-run set. Failure evidence is the
separate explicit over-limit self-check and its demonstrated-red mutation, plus
the independent import-bypass mutation described above. No inference is made
about absent partition, proof, inbox or settlement stages, larger states, slow
devices, OS-cold reads, concurrent workloads, or full production synchronization.
