# Incremental Cell record accounting

The test-only counter compares actual Cell key/value records before a commit
and after reopening the database. It is attached to the existing
`GrowingStateRetainsSharedCellsAfterRootRelease` test: seed 91, twelve epochs,
64 fresh keys per epoch, at most three retained roots, using the real v2
DynamicBagOfCellsDb and RocksDB write-batch/merge implementation. The test still
checks all retained roots, reachability versus stored Cells, old spent keys,
duplicate rejection and removal of obsolete roots. No production API changed.

The generic v2 `get_stats_diff()` returns an empty result. The older backend's
`cells_total_size` counts serialized Cell size, not these database record bytes.
Neither is used as a proxy for this measurement.

## Definitions

The database in this test is owned solely by CellStorer. As in its existing
reachability check, 32-byte keys identify Cell hash records; other metadata is
excluded. Full scans collect their merged logical values. Each transition
classifies:

- added: a hash key absent before, present afterward;
- removed: a hash key present before, absent afterward;
- changed: the same hash key remains but its value differs (for example refcount
  changes). The reported byte count is the complete **after** key/value length,
  not the byte-length difference and not a write-operation count.

Added and removed bytes are the respective key plus value lengths. Every sum
is checked; overflow leaves the helper's output unchanged. Counts satisfy
`before_count + added = after_count + removed` using checked addition, without
subtracting unsigned counters. Snapshot maps and scans add memory and read work;
no latency or importer RSS claim is made from this test.

These are logical persisted record sizes, not BoC bytes, SST/compressed allocation,
WAL/device traffic or write amplification. Counts are per transition, not unique
identities across all history. Releasing an obsolete root can remove path copies
without deleting any spent evidence reachable from the retained current root.

## Recorded control

Base `3da5bf292` plus archived `cell-record-final.patch`. Restored twelve rows
matched the initial run exactly. Across transitions, 3673 added records account
for 354042 key/value bytes; 1652 removed records account for 166511 bytes; 1895
per-transition changed records account for 172724 post-change key/value bytes.
Do not subtract or combine the latter as if it were net growth.

| Epoch | Added records | Added bytes | Removed records | Removed bytes | Changed records | Changed after-bytes |
|---:|---:|---:|---:|---:|---:|---:|
| 0 | 134 | 12090 | 0 | 0 | 0 | 0 |
| 3 | 268 | 25445 | 83 | 8056 | 91 | 8045 |
| 11 | 374 | 36795 | 250 | 25403 | 274 | 25046 |

`CELL_RECORD_DELTA` rows contain epoch then the six columns above. Teardown
subsequently releases all remaining test roots and checks that no Cell records
remain; this teardown is not a proposed retirement or production GC policy.

The independent literal-map unit expects 35/33/41 bytes for added/removed/changed
records. Removing overflow detection, omitting changed-record accounting and
omitting key bytes each made that unit exit 1. The byte mutation produced 3
instead of 35, so this does not merely assert diagnostic wording. After restoring
all changes, the complete `test-uno-state-snapshot` CTest and a separate twelve-
epoch growth run passed. Raw evidence and patches are in
`measurements/uno-cell-record-deltas.tar.gz`; mutation experiments are manual,
not automated CI. The new unit runs in the existing default snapshot test binary.
External review remains pending the milestone.

This establishes a counter against real incremental commits for the small
single-account retention control. Applying it to comparable multi-account
updates, larger history, reservations and splits remains work. It does not
implement participant records, atomic logical-batch acceptance, a production
schema or the full D-3/Y-1 measurement requirements.
