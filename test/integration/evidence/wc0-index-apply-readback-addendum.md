# Addendum: wallet index handoff on the block-data read-back path

This addendum qualifies the claim in
[`wc0-index-apply-latency.json`](wc0-index-apply-latency.json). That file is
kept unchanged as the record of its own run. Read the two together.

## Claim

Index processing and its WAL writes run asynchronously. When ApplyBlock lacks
block data, index handoff currently requires one block-data read before apply
completion. The earlier integration measurement did not establish latency on
this path.

Any wording that indexing never delays block application is withdrawn: on
this path, apply completion waits for the block-data read.

## Why the path exists

When ApplyBlock runs without block data in hand, it reads the block back from
the database. It then hands the block to the index hook, and only after that
flushes the block handle. If the read fails, the block id alone is handed
over. The hook comes before the flush so that a block whose apply is durable
has always reached the index, and a clean exit can account for every applied
block. The earlier integration run measured hook duration and apply duration
on a live chain, but it did not show whether, or how often, its blocks took
this path.

## Measurement

- **Tool:** `test/validator/apply-block-readback-latency.cpp` (target
  `test-apply-block-readback-latency`).
- **Source commit:** `b8a3f5350`, built with clang-21 and
  `-DTOS_WERROR_BUILD=On` (Release).
- **Host:** Intel Xeon Platinum 8455C, Linux 6.8.
- **Command:** `build/test-apply-block-readback-latency <existing parent dir> 2000 1 10 50`
- **Exit status:** 0.
- **Raw output:**
  [`wc0-index-apply-readback-b8a3f5350.json`](wc0-index-apply-readback-b8a3f5350.json),
  772 bytes, SHA-256
  `88ecbf2da296264f531c5abb4c03b3b9db975d6748863b49b7053b9c735561e3`.
  This is the tool's complete output, so it is committed whole. A scratch copy
  on the measuring host is not retained beyond the review that requested it.

Apply completion is the time from starting the apply query to its promise,
which resolves after the handle flush. n = 2000 for each mode. Times are in
microseconds.

| mode | block-data reads | p50 | p99 | max |
| --- | --- | --- | --- | --- |
| index off (no hook) | 0 | 8.7 | 15.6 | 3242.8 |
| index on, read answered at once | 2000 | 12.9 | 19.1 | 76.6 |
| index on, read answered after 1 ms | 2000 | 1116.0 | 1157.0 | 1285.4 |
| index on, read answered after 10 ms | 2000 | 10682.0 | 10911.7 | 11057.4 |
| index on, read answered after 50 ms | 2000 | 50992.0 | 51250.2 | 63950.2 |

On this path, apply completion grows one-for-one with the time the
block-data read takes.

## Scope

- **What it establishes:** apply completion depends on the read-back. It does
  not measure production archive-read latency.
- **Real pieces:** the real ApplyBlock actor and the real index hook, queueing
  into a real wallet index database.
- **Stand-in manager:** every other manager request is answered by a
  stand-in. The block-data read always fails, after the chosen delay, so the
  hook receives only the block id. The handle flush is simulated: the
  stand-in marks the handle written and does no database write.
- **Read counting (an automatic check):** a run fails unless every sample with
  the hook read its block back exactly once and no sample without the hook
  read at all. With the hook disabled inside ApplyBlock (checked at
  `d6b77f983`), the run read nothing and exited 1.
- **Sensitivity (shown by timings only):** when the old ordering is restored
  (flush without waiting for the read), apply completion with 1 ms and 10 ms
  reads drops to a p50 of about 11 µs, against 1.1 ms and 10.8 ms here. That
  control was run by hand at `d6b77f983` with 200 samples per mode. It is not
  an assertion the tool makes.

## Possible future work

A bounded asynchronous fetch by the indexing worker would take the read off
the apply path: ApplyBlock would hand over only the block id, and the worker
would read the data itself. Before that could replace the current ordering,
it would need:

- durable coverage of every handed-over block id before the indexing-run
  marker is cleared;
- recovery marks that stay in place whenever the fetch fails;
- tests for shutdown while fetches are pending, and for queue overflow.
