# Addendum: wallet index handoff when ApplyBlock lacks block data

This addendum qualifies the claim in
[`wc0-index-apply-latency.json`](wc0-index-apply-latency.json). That file is
kept unchanged as the record of its own run. Read the two together.

## Claim

Block application does not wait for the wallet index on any path, including
an apply that does not hold the block's data. ApplyBlock hands the index hook
the block id and whatever it already holds (block data, state) and flushes
the block handle at once. It makes no read for the index. When the data is
absent, the indexing worker reads it itself, off the block-application path.

This replaces the earlier behaviour, recorded in
[`wc0-index-apply-readback-b8a3f5350.json`](wc0-index-apply-readback-b8a3f5350.json),
in which ApplyBlock read the block back from the database before the hook and
the flush, so apply completion grew one-for-one with that read (p50 1.1 ms,
10.7 ms and 51.0 ms for reads answered after 1, 10 and 50 ms). That file is
kept as the record of its own run at `b8a3f5350`.

## How a block without data reaches the index now

- The hook is a bounded, non-waiting enqueue. It takes only a producer lock
  and, to keep the block in the archive until its marker exists, a lock
  around an in-memory set of generation times; nothing holds either across
  I/O or a wait. It does not log, mark, or sync.
- The recorder thread durably marks every handed-over block id before the
  worker may index it. A block the worker never finishes stays marked, and
  startup recovery re-indexes it.
- The worker asks a fetcher for the missing data. The validator engine's
  fetcher is an actor that reads the block handle, block data and, when
  needed, the state from the validator databases. The worker gives up after
  60 s or at shutdown; the block then stays marked.
- When the worker is 256 blocks behind, a new block is not queued; its id is
  still recorded, so it is marked and recovered later.
- The indexing-run marker is written and WAL-synced before any producer is
  accepted. The exit flush closes the queue to producers, waits until every
  handed-over block is marked, and only then clears the run marker. A block
  handed over after the queue closed is only recorded and keeps the run
  unfinished; one handed over after the marker was cleared makes the recorder
  record the run as active again before marking it.
- **Crash safety after the run marker is cleared rests on genuine producer
  quiescence.** The validator engine clears the marker only from its final
  exit path, after the actor scheduler has stopped and the hook is removed, so
  no block can be applied any more (`Wc0IndexProducers::Quiesced`). The
  asynchronous re-recording after an unexpected late block is a defence, not
  a replacement for that requirement: a crash between such a block's apply
  and the recorder's write would leave no trace of it. A scheduled shutdown,
  which exits while blocks may still be applied, never clears the marker.

## Measurement

- **Tool:** `test/validator/apply-block-readback-latency.cpp` (target
  `test-apply-block-readback-latency`).
- **Source commit:** `968992c50`, Release build with clang 21.1.8.
- **Host:** Intel Xeon Platinum 8455C, Linux 6.8.
- **Command:** `build/test-apply-block-readback-latency <existing parent dir> 2000 1 10 50`
- **Exit status:** 0.
- **Raw output:**
  [`wc0-index-apply-readback-968992c50.json`](wc0-index-apply-readback-968992c50.json),
  914 bytes, SHA-256
  `6bacdb0560930840c7dc171ab10b0cf818436ce0ae9af46da41d2507875965ed`.
  This is the tool's complete output, so it is committed whole.

Apply completion is the time from starting the apply query to its promise,
which resolves after the handle flush. n = 2000 for each mode. Times are in
microseconds. "Worker read delay" is how long each of the worker's own reads
takes.

| mode | reads by ApplyBlock | reads by the worker | p50 | p99 | max |
| --- | --- | --- | --- | --- | --- |
| index off (no hook) | 0 | 0 | 20.2 | 37.9 | 2222.0 |
| index on, worker read answered at once | 0 | 1978 | 24.2 | 32.7 | 144.1 |
| index on, worker read takes 1 ms | 0 | 62 | 21.0 | 28.5 | 44.9 |
| index on, worker read takes 10 ms | 0 | 7 | 21.1 | 28.7 | 44.0 |
| index on, worker read takes 50 ms | 0 | 2 | 21.1 | 27.4 | 78.9 |

Apply completion no longer depends on the read's duration. The worker read
counts are low in the slow modes because applies arrive far faster than a
slow worker reads: once it is 256 blocks behind, further blocks are only
marked for recovery, which is the designed overflow behaviour, and the exit
flush still reported every block marked (`index_flushed_cleanly: true`).

## Scope

- **What it establishes:** apply completion does not wait for the index's
  block-data read. It does not measure production archive-read latency.
- **Real pieces:** the real ApplyBlock actor, the real index hook, worker and
  recorder, queueing into a real wallet index database.
- **Stand-ins:** every manager request ApplyBlock makes is answered by a
  stand-in; the handle flush is simulated. The worker's fetcher is the tool's
  own: it sleeps for the configured delay on the worker thread and then fails
  the read, so the block stays marked.
- **Read counting (an automatic check):** the run fails unless no sample made
  a block-data read through the manager. With the old read-back restored in
  `ApplyBlock::applied_set` (checked by hand on top of `968992c50`, 200
  samples per mode), every hook sample read once (`apply_read_backs: 200`),
  `no_apply_read_backs` was false, and the tool exited 1.

## Gates

The latency tool is a measurement, not a gate. The gate is
`test-wallet-index-apply` (`test/validator/wallet-index-apply-test.cpp`,
CTest label `security-findings`): it drives the real ApplyBlock actor against
a manager whose block-data read never answers, and requires every apply to
complete while the worker's read is blocked, while the recorder's WAL write
is stalled, and while the worker's queue is full. Restoring the read-back in
ApplyBlock makes all three fail.
