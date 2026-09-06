# Incremental partition persistence pilot

## Scope and source

Source: base `562ae6543` plus the final source patch in
`doc/measurements/uno-incremental-partition-pilot.tar.gz`. This adds only a
storage measurement test and a registered CTest smoke. External review remains
pending at the milestone under AGENTS.md; no consensus judgement or error
classification changed.

The test uses structurally encoded Native Account/ShardAccounts envelopes with
raw UsedNullifiers data, zero balances and placeholder storage metadata and
transaction fields. They are not production UNO accounts or authorized
participant records. In particular the large single-account controls are not
admitted under ConfigParam 43. No shared limit is raised or bypassed in production.

## Reproduction and measurement boundary

Build `test-uno-storage-measurement` with `-j48`, then run:

```sh
ctest --test-dir build -R 'test-uno-(incremental|partition)-storage-smoke' --output-on-failure
for count in 1000 8000 32000 65536; do
  for pages in 1 16; do
    for shape in uniform prefix; do
      for sample in 1 2 3; do
        env TOS_UNO_STORAGE_KEYS="$count" TOS_UNO_STORAGE_PAGES="$pages" \
          TOS_UNO_STORAGE_SHAPE="$shape" build/test-uno-storage-measurement \
          --filter PartitionIncrementalRecords || exit 1
      done
    done
  done
done
```

Seed 91 supplies historical keys. Prefix mode zeros their first 16 bytes.
Sixteen-page routing uses the first nibble; uniform updates touch pages 0 and
15, prefix updates both touch page 0. Each process imports a baseline through
DynamicBagOfCellsDb v2/RocksDB, closes and reopens it, adds two fresh keys to
the touched accounts, retains both roots, closes and reopens, releases the old
root, and closes and reopens again. All historical keys remain readable and
both new keys reject a repeated spend. Untouched account data hashes remain
unchanged. Lazy Cell references must be released before closing database handles.

Actual merged Cell key/value deltas use the definitions in
`uno-cell-record-delta-method.md`. Checked sums account for key and value bytes.
Three separately timed stages are prepare_commit, staging the RocksDB batch,
and commit_write_batch. The last is not a claim of fsync or power-loss durability.
Full record scans occur outside those timers and warm the cache. Timers exclude
state construction, dictionary decoding/update, full verification and scans.
Peak RSS is the process high-water mark, including fixture construction and
record maps, not isolated commit memory. Reopening handles is not a cold OS cache.

CSV fields after `INCREMENTAL_RECORDS_CSV` are history count, seed, pages, shape,
phase, added records/bytes, removed records/bytes, changed records/after-bytes,
prepare ms, staging ms, write-batch ms and process HWM KiB.

## Recorded results

Run on 2026-09-06 at approximately 13:22 UTC: Xeon Platinum 8455C, 192 logical
CPUs, Release clang++-21, `-O3 -DNDEBUG`, v2 extra_threads=0. The 48 serial
processes passed and produced 96 rows. Each of 32 scenario/phase groups has
three samples with identical record counts and bytes. Other host work was not
excluded; observed load during the run was 2.75/2.15/2.32 and disk free space
was about 72 GiB. This is not a controlled cold/warm acceptance experiment.

At 65,536 historical keys, adding two keys while retaining the old root:

| Pages | Shape | Added records / bytes | Changed records / after-bytes | Median prepare / stage / write ms |
| --- | --- | --- | --- | --- |
| 1 | uniform | 39 / 4159 | 30 / 3077 | 0.091785 / 0.015859 / 1.229280 |
| 16 | uniform | 41 / 4405 | 30 / 3093 | 0.075260 / 0.013112 / 1.367320 |
| 1 | prefix | 26 / 2706 | 19 / 1790 | 0.073113 / 0.011735 / 1.325840 |
| 16 | prefix | 30 / 3146 | 23 / 2235 | 0.072619 / 0.012059 / 1.575040 |

No records are removed during retention. Releasing the old root adds none and
removes respectively 35/3803, 37/4049, 22/2409 and 26/2849 records/bytes in the
table order. Maximum individual timed stages across this run were 0.416748,
0.024369 and 5.101390 ms. These separate maxima must not be presented as a
measured end-to-end sample. Maximum process HWM was 184632 KiB.

## Negative evidence and limits

Removing `database->inc(next)` makes the new-root lookup fail after reopening;
the restored test passes. The archive includes the exact mutant and final
source patches and diagnostic logs. An earlier fixture lifetime failure is
also retained: stale lazy readers held the RocksDB lock. It is diagnosis, not
a passing sample or a deliberately reproduced mutation (its exact source was
not archived). The registered smoke and the earlier partition import smoke
both pass; the zero-test regex prevents an empty match from passing CTest.
The matrix is manual and the mutation is archived, not an automatic CI mutation.

This closes an incremental storage measurement gap, not Y-1 or D-3. It does not
measure bounded coordinator state, participant transaction construction,
I13a-I13e host atomicity, split/migration peaks, prepare/refund obligations,
authenticated network acquisition, production admission or a full validation
deadline. Existing full-scan `from_root` work remains outside commit timers.
No production schema, input limit, cost coefficient or WCET follows from these
results. Claim-only feasibility still depends on an accepted storage design.
