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
- a shared `rocksdb::WriteBufferManager`;
- `critical_write_path`, which selects the isolated critical manager when it
  is configured.

`td::RocksDb::open()` also recognizes:

```text
TOS_ROCKSDB_WRITE_BUFFER_SIZE
TOS_ROCKSDB_TRANSACTION_HISTORY_SIZE
TOS_ROCKSDB_GLOBAL_WRITE_BUFFER_SIZE
TOS_ROCKSDB_GLOBAL_WRITE_BUFFER_ALLOW_STALL
TOS_ROCKSDB_CRITICAL_WRITE_BUFFER_SIZE
TOS_ROCKSDB_CRITICAL_WRITE_BUFFER_ALLOW_STALL
```

The global manager covers every `td::RocksDb` instance in the process. The
critical manager is an independent optional domain used only by CellDB,
StateDB, Simplex, and Catchain. When both are configured, critical databases
use the critical domain and archive, DHT, ADNL/overlay, wallet-index, and other
databases use the global domain. This prevents a background flush storm from
consuming the consensus write-buffer budget or initiating its write stall.

Up to two static `WriteBufferManager` instances are constructed for the
process: the optional consensus-critical domain and the optional global
background domain. Each subsequently opened RocksDB instance is assigned to
at most one of them. With `ALLOW_STALL=1`, RocksDB flushes earlier as the
mutable working set approaches the target and applies
write back-pressure if total tracked MemTable memory reaches the limit.

The memory diagnostic line now reports:

```text
write_buffer_manager_bytes
write_buffer_manager_mutable_bytes
write_buffer_manager_limit_bytes
write_buffer_manager_domain
memtable_flush_pending
running_flushes
pending_compaction_bytes
actual_delayed_write_rate
write_stopped
```

These values are process-wide and therefore repeat on each per-database
diagnostic line when that database belongs to a manager domain. The flush,
compaction, delayed-write, and stopped-write values are per database.

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

`test-tddb` contains targeted `RocksDbMemoryBounds` and
`RocksDbCriticalMemoryDomain` regression tests. They exercise:

- a non-transactional database under a small shared write-buffer manager;
- flush and release without retained transaction history;
- the exported shared-manager diagnostic values;
- an optimistic-transaction database with an explicit bounded history;
- simultaneous critical and global managers, including correct database
  assignment, independent limits, and diagnostic domain names.

Validation completed before deployment:

- `ninja -C build -j64 test-tddb validator-engine test-consensus`;
- all 10 `test-tddb` cases passed;
- all 15 `test-consensus-simplex2-*` CTest scenarios passed, including the
  deterministic CandidateResolver finalization/network/persistence
  interleaving test;
- the same suites passed with aggressive 4 MiB per-DB buffers/history and a
  64 MiB global manager limit.

`test-wallet-index` also passes with the WAL-only marker path. This is
correctness coverage, not a controlled before/after throughput benchmark.
Node3 supplies a useful live canary because it continuously indexes applied
workchain blocks, but a numerical WalletIndex latency or throughput claim
still requires a dedicated sustained-load comparison.

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

### PR review follow-up: isolated critical-domain canary

The merge review correctly noted that static analysis could not establish the
live RSS effect or the write-stall coupling of one global manager. The
follow-up implementation therefore added an independent critical domain and
deployed this critical-only profile to node3:

```text
TOS_ROCKSDB_WRITE_BUFFER_SIZE=16777216
TOS_ROCKSDB_TRANSACTION_HISTORY_SIZE=16777216
TOS_ROCKSDB_CRITICAL_WRITE_BUFFER_SIZE=268435456
TOS_ROCKSDB_CRITICAL_WRITE_BUFFER_ALLOW_STALL=1
```

The final executable started at `2026-07-27 10:54:03 UTC`. Its SHA-256 matched
the file mapped by the running process:

```text
8b7c9fcfba42912caac40e5e8cbf0fe181369e67b06002753e522bfe88a744b9
```

The executable linked Ubuntu's `libjemalloc.so.2` version 5.2.1. The actual
target process repeatedly returned `result=ok` from
`mallctl("arena.4096.purge")`. Two examples from the post-catch-up steady
period were:

| Cache drop (UTC) | Cache entries | RSS before | RSS after | Immediate release |
|---|---:|---:|---:|---:|
| 11:06:02 | 41,700 | 2,513 MiB | 2,505 MiB | about 8.3 MiB |
| 11:12:50 | 41,293 | 2,518 MiB | 2,509 MiB | about 9.0 MiB |

Those drops are separated by 408 seconds and have the same TTL-triggered cache
phase. Their before-drop endpoints differ by about 5 MiB
(approximately 0.73 MiB/min), while their after-purge endpoints differ by
about 4 MiB (approximately 0.59 MiB/min). This is materially lower than the
old approximately 3.8 MiB/min residual slope.

The formal monitor window from `10:55:53` through `11:12:57 UTC` contained 17
samples from one PID. It included the normal restart warm-up, during which the
1,024-entry CandidateResolver and StateResolver caches filled from empty and
then began evicting. Consequently, the raw start-to-end RSS delta is not a
steady-state comparison. By the last sample, the monitor's ten-minute RSS
rate had fallen to 2.06 MiB/min, of which 1.57 MiB/min was concurrent bounded
MemTable turnover; the phase-matched cache-drop comparison above removes that
sawtooth.

Operational safety results for the same window:

- the critical manager peaked at about 42 MiB total and 40 MiB mutable against
  its 256 MiB limit;
- every sample reported zero flush-pending databases, running flushes,
  pending compaction bytes, delayed-write databases, and write-stopped
  databases;
- CellDB, StateDB, and both active Simplex databases reported
  `write_buffer_manager_domain=critical`; archive, overlay, and WalletIndexDb
  reported no manager domain;
- node1, node2, and node3 reported the same finalized masterchain slot
  (`127496`) at `11:13:15 UTC`;
- node3 remained on one PID with `NRestarts=0`, and no error-priority or
  WalletIndex failure appeared after the observation baseline.

This is a successful single-node canary, not a production multi-region load
test. It demonstrates working domain assignment, no observed write-stall or
finalized-height coupling, and a functioning jemalloc purge on the deployed
binary. It does not provide a controlled before/after WalletIndex throughput
number or prove behavior under production storage saturation.

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
