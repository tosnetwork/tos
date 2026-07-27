# Node3 Anonymous-Memory Growth: RocksDB MemTable Root Cause and Fix (2026-07-27)

## Conclusion

The residual node3 growth previously measured at approximately 3.8 MiB/min
was not an unbounded network, QUIC, Simplex, CellDB V2, or allocator leak. It
was the aggregate allocation rate of multiple independent RocksDB MemTables,
including flushed MemTables retained as optimistic-transaction conflict
history.

The important distinction is:

- the observed 3.8 MiB/min was a **warm-up rate**, not one container growing
  forever;
- before this change there was no process-wide budget, so each RocksDB
  instance could independently warm up to its own mutable and retained
  MemTable limits;
- several databases that never start a RocksDB transaction were nevertheless
  opened as `OptimisticTransactionDB`, causing them to retain history that
  could never be used.

TOS now shares one `rocksdb::WriteBufferManager` across all RocksDB instances,
allows the mutable and transaction-history targets to be configured, and
opens CellDB, StateDB, and WalletIndexDb as ordinary RocksDB databases without
transaction history.

## Direct evidence

The one-minute monitor correlated process RSS with the sum of
`rocksdb.size-all-mem-tables` across the live databases. During the residual
growth window, MemTable reserved bytes rose at the same rate and explained
most or all positive RSS movement. RSS fell when a non-transactional MemTable
was flushed, while a transactional database retained approximately one
configured history window after its first flush.

A jemalloc differential profile from 08:15:57 to 08:25:27 UTC on the fixed
node3 binary recorded 38,495,385 bytes of net live allocation. Of that:

| Allocation chain | Net live bytes | Share |
|---|---:|---:|
| `rocksdb::MemTable::Add` → `SkipListRep::Allocate` → `ConcurrentArena` | 37,814,132 | 98.2% |
| All other positive and negative changes combined | 681,253 | 1.8% |

This profile identifies the final retaining container. The same interval's
RocksDB diagnostics showed the shared MemTable total rising by roughly the
same amount. The allocations were still below the new aggregate limit because
the retained transaction histories were completing their first warm-up.

The source-level reason is deterministic:

1. `td::RocksDb::open()` historically opened every database as
   `OptimisticTransactionDB` unless `no_transactions` was set.
2. RocksDB changes an unspecified
   `max_write_buffer_size_to_maintain == 0` to `-1` when opening an
   `OptimisticTransactionDB`.
3. RocksDB then sanitizes `-1` to
   `max_write_buffer_number * write_buffer_size`. With the inherited defaults,
   this is 2 × 64 MiB, or a 128 MiB history target, per database.
4. A validator owns several databases with different write rates. Their
   independent warm-up therefore appears as a smooth process-wide RSS slope.

The upstream `~/ton-c` RocksDB wrapper has the same default
`OptimisticTransactionDB` behavior. The bug exposed here is the absence of an
aggregate validator-process memory policy, combined with retaining transaction
history in TOS call sites that only use atomic `WriteBatch` commits.

## Code changes

### Process-wide bounds

`td::RocksDbOptions` now accepts:

- `write_buffer_size`;
- `max_write_buffer_size_to_maintain`;
- a shared `rocksdb::WriteBufferManager`.

`td::RocksDb::open()` also recognizes:

```text
TOS_ROCKSDB_WRITE_BUFFER_SIZE
TOS_ROCKSDB_TRANSACTION_HISTORY_SIZE
TOS_ROCKSDB_GLOBAL_WRITE_BUFFER_SIZE
TOS_ROCKSDB_GLOBAL_WRITE_BUFFER_ALLOW_STALL
```

One static `WriteBufferManager` is constructed for the process and passed to
every subsequently opened RocksDB instance. With `ALLOW_STALL=1`, RocksDB
flushes earlier as the mutable working set approaches the target and applies
write back-pressure if total tracked MemTable memory reaches the limit.

The memory diagnostic line now reports:

```text
write_buffer_manager_bytes
write_buffer_manager_mutable_bytes
write_buffer_manager_limit_bytes
```

These values are process-wide and therefore repeat on each per-database
diagnostic line.

### Removing unused transaction history

The following databases now set `no_transactions=true`:

- CellDB, including its read-only in-memory-mode handle;
- StateDB;
- WalletIndexDb.

All three use atomic RocksDB `WriteBatch` commits and have no
`begin_transaction()` call. `WriteBatch` atomicity and WAL durability are
unchanged; only unused optimistic-transaction conflict tracking is removed.
Databases used through `KeyValueAsync` or explicit
`begin_transaction()`/`commit_transaction()` remain transactional.

## Test coverage

`test-tddb` contains a targeted `RocksDbMemoryBounds` regression test. It
exercises:

- a non-transactional database under a small shared write-buffer manager;
- flush and release without retained transaction history;
- the exported shared-manager diagnostic values;
- an optimistic-transaction database with an explicit bounded history.

Validation completed before deployment:

- `ninja -C build -j64 test-tddb validator-engine test-consensus`;
- all 10 `test-tddb` cases passed;
- all 14 `test-consensus-simplex2-*` CTest scenarios passed;
- the same suites passed with aggressive 4 MiB per-DB buffers/history and a
  64 MiB global manager limit.

## Node3 live configuration

Node3 was restarted at 08:01:12 UTC with:

```text
TOS_ROCKSDB_WRITE_BUFFER_SIZE=16777216
TOS_ROCKSDB_TRANSACTION_HISTORY_SIZE=16777216
TOS_ROCKSDB_GLOBAL_WRITE_BUFFER_SIZE=268435456
TOS_ROCKSDB_GLOBAL_WRITE_BUFFER_ALLOW_STALL=1
```

The deployed executable hash matched the newly built executable. Consensus
finalization resumed, the process did not restart, and the journal contained
no transaction-conflict, write-stall, corruption, OOM, or fatal errors during
the initial observation window.

Early live diagnostics also confirmed the intended semantic split:

- CellDB, StateDB, and WalletIndexDb had
  `active_memtable_bytes == all_memtable_reserved_bytes`, including after
  flushes: no history was retained;
- the active consensus database retained one approximately 16 MiB history
  after its first flush;
- the shared manager accounted for the aggregate MemTable allocation and
  exposed the configured 256 MiB limit.

### Extended live validation

The first ten-minute differential, taken while the transactional databases
were still establishing their initial 16 MiB histories, intentionally
reproduced the old slope: 38.5 MB net, 98.2% in `MemTable::Add`. This proved
that the new counter and the heap profiler identified the same storage.

The important post-warm-up check compared endpoints immediately after
successive CellDB V2 cache drops, so both the Cell-object cache and the
RocksDB fill/flush cycle were at comparable phases:

| Interval (UTC) | Duration | jemalloc net live growth | Rate | Dominant persistent chain |
|---|---:|---:|---:|---|
| 08:45:42 → 08:52:24 | 6.7 min | 3.64 MB | ~0.52 MiB/min | none |
| 08:52:24 → 08:59:04 | 6.7 min | 7.53 MB | ~1.08 MiB/min | none |

The two residual profiles were phase-sensitive mixtures of ordinary
MemTable turnover, table-reader/compaction work, buffer ingress/egress, and
overlay traffic. Their positive and negative stacks changed between rounds;
no container reproduced the former linear 3.8 MiB/min retention. At the same
time:

- `BufferAllocator` stayed around 339-341 MiB;
- QUIC and generic network tracked current bytes stayed at or near zero;
- Simplex state/candidate caches stayed at their configured 1,024/4,096
  entry ceilings while eviction counters advanced;
- BlockData and Plumtree tracked bytes stayed flat or decreased;
- the shared RocksDB manager oscillated with flushes and remained far below
  its 256 MiB back-pressure threshold;
- node3 continued finalizing blocks with zero service restarts and no OOM,
  transaction-conflict, corruption, fatal, or write-stall event.

Short, unmatched RSS windows can still report a positive slope while several
16 MiB MemTables are filling, and a negative slope immediately after they
flush. Full-cycle and phase-matched measurements show that the former
3.8 MiB/min retention is gone. The remaining sub-MiB-to-about-1 MiB/min
sampled variation has no repeatable retaining container and is bounded by the
separate MemTable and cache ceilings.

After collecting the two phase-matched profiles, the temporary profiling
`LD_PRELOAD` was disabled to stop producing heap-dump files. Node3 was
restarted on the same executable hash with the RocksDB limits and lightweight
`TOS_MEMORY_DIAGNOSTICS=1` counters still enabled, and resumed obtaining
finalization certificates. The existing heap dumps were retained as the raw
evidence for this report.

## Operational interpretation

RSS is not expected to be numerically flat each minute. Mutable MemTables grow
between flushes, flushed files and cache readers turn over, and jemalloc may
retain clean pages briefly. The correctness condition is that:

1. MemTable allocation is attributed by the shared-manager counters;
2. non-transactional databases do not accumulate conflict history;
3. total MemTable memory approaches a configured ceiling instead of warming
   independently toward a per-database ceiling;
4. peak-to-peak RSS becomes bounded after the initial history/cache warm-up;
5. consensus progress and disk latency remain healthy under back-pressure.

The 16/16/256 MiB values are a low-memory test profile, not a universal
production recommendation. A production value must be chosen from measured
write throughput and storage latency. Reducing the values too far trades
memory for more frequent flushes, compactions, and possible write stalls.
