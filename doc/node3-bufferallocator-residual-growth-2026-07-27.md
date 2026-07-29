# td::BufferAllocator and the Post-Bug-A Residual Growth (2026-07-27)

## Status

**Current status (2026-07-29): resolved as an upstream-retention symptom, not
a `BufferAllocator` leak.**
The diagnostic proposed in this report was subsequently wired into node3's
periodic memory telemetry. On current `main` after PR #15, PR #16, and
`1c137fa44`, `BufferAllocator` `live_bytes` stayed between 590.6 and 591.2 MB
over the 00:38-00:47 UTC window instead of following the former residual
slope. A 00:26-00:47 UTC differential heap profile attributed the remaining
37.2 MB net delta entirely to ordinary RocksDB write paths, not retained
BufferRaw objects.

The best-supported attribution for the old net BufferAllocator growth is live
backlog retained by the workchain-0 state-resolution/standstill retry storm:
the slope disappeared when that liveness bug was fixed, and the buffers now
drain normally. No allocator pooling or `BufferAllocator` ownership change is
required.

Historical context follows. This report was a follow-up to
[node3-residual-leak-archive-memtable-2026-07-26.md](node3-residual-leak-archive-memtable-2026-07-26.md).
After the Bug A / Bug B fixes landed and were re-profiled live, total residual
growth per comparable window dropped ~55% (625-680 MB → 284-332 MB per
~15-16 min), with the forced-memtable-construction chain eliminated and the
archive-read chain confirmed as a downstream effect of it. What's left is no
longer dominated by wallet-index code at all.

An independent reviewer reproduced this on a fresh 20-minute window: 398.3 MiB
net growth (19.9 MiB/min), of which 314.8 MiB (79%) lands in
`td::BufferAllocator::create_reader`, and ~69.1 MiB (17.3%) in the current
RocksDB memtable (expected — see the parent doc, this is now just ordinary
`MemTable::Add` growth, not the eliminated forced-reconstruction chain). The
`create_reader` share's upper callers are Plumtree broadcast, QUIC send/recv,
and TL parse/serialize — i.e. it's a shared low-level allocator used by many
otherwise-unrelated modules, not evidence any one of them is uniquely at
fault. This document records what was investigated in `BufferAllocator`
itself: whether these allocations are actually freed, and whether the
allocator can be made to prefer recycled memory. At that point this was an
analysis with one proposed diagnostic step; the current result is recorded
above.

## Is the memory `create_reader` allocates ever freed?

Yes — confirmed by reading `BufferAllocator::dec_ref_cnt`
(`tdutils/td/utils/buffer.cpp:96-104`):

```cpp
void BufferAllocator::dec_ref_cnt(BufferRaw *ptr) {
  int left = ptr->ref_cnt_.fetch_sub(1, std::memory_order_acq_rel);
  if (left == 1) {
    auto buf_size = max(sizeof(BufferRaw), TD_OFFSETOF(BufferRaw, data_) + ptr->data_size_);
    buffer_mem -= buf_size;
    ptr->~BufferRaw();
    delete[] ptr;
  }
}
```

`WriterPtr`/`ReaderPtr` (`buffer.h:69-70`) are `std::unique_ptr` with custom
deleters (`DeleteWriterPtr`/`DeleteReaderPtr`, `buffer.h:55-67`) that both
route here — standard RAII. Every `BufferRaw` gets a real `delete[]` once its
refcount reaches zero. There is no leaked-reference path inside
`BufferAllocator` itself: no path stores a `BufferRaw*` outside the
ref-counted `WriterPtr`/`ReaderPtr` wrappers.

**This means the jeprof `--base` diff result is not evidence of a forgotten
free.** A `--base` diff shows *net retained* bytes at the second snapshot
relative to the first — i.e. more `BufferRaw`s were still *live* (referenced)
at t2 than at t1. That is consistent with two very different underlying
situations, indistinguishable from the diff alone:

1. **A genuine reference leak upstream** — some caller in the Plumtree/QUIC/TL
   code paths holds a `BufferSlice` (or a raw `WriterPtr`/`ReaderPtr`, or a
   copy of a `BufferSlice`, which bumps the same refcount via
   `create_reader(const ReaderPtr&)`/`create_reader(const WriterPtr&)`,
   `buffer.cpp:85-94`) longer than it should — e.g. stashed in a container
   that's never drained, or captured by a callback that never fires.
2. **A queueing/backpressure backlog, not a leak** — outbound messages
   (broadcast fan-out, QUIC send queue) produced faster than drained during
   the diff window, so more are transiently in-flight. This would self-drain
   under lighter load and isn't a bug.

The fix is entirely different depending on which one this is (find-the-leaked-
reference vs. add-backpressure/queue-limits), and neither fix lives in
`BufferAllocator`.

### Diagnostic proposed then, now completed

`BufferAllocator::get_buffer_mem()` (`buffer.h:82`, backed by the atomic
`buffer_mem` counter maintained in `create_buffer_raw`/`dec_ref_cnt`) already
tracks *live* buffer bytes process-wide, updated on every allocation and
every free. It's not a diagnostic added for this investigation — it already
exists and is already trusted as a leak-invariant check elsewhere in this
codebase: `test/test-download-state-budget.cpp` asserts it does *not* grow
across various parse/download operations (e.g. lines 718, 762, 786, 2221,
2237).

At the time of the original report it was not wired into node3's periodic
`mem-stat` log. It was subsequently exposed through
`BufferAllocator::get_memory_stats().live_bytes` (the same underlying
process-wide counter) and observed over live windows. Watching it together
with `stats.allocated` directly
distinguish the two cases above:

- Flat/oscillating, not tracking `stats.allocated`'s slope ⇒ backlog
  (case 2) — self-resolving, no code fix needed here.
- Climbing in lockstep with `stats.allocated` ⇒ real reference leak
  (case 1) — and the specific call-stack-filtered `jeprof --focus=` breakdown
  (Plumtree vs. QUIC vs. TL) becomes the map of where to look for the
  retaining reference.

**Result:** the live counter is flat/oscillating after the workchain-0
liveness fixes and does not track an unbounded `stats.allocated` slope. This
rules out a `BufferAllocator` reference leak in the measured deployment.

## Can `create_reader` be optimized to prefer already-freed memory?

Short answer: it already effectively does, one layer down, and adding a
custom pool on top is not recommended without first knowing which case
(leak vs. backlog) above applies — pooling helps neither.

Looking at the two allocation paths in `create_reader`
(`buffer.cpp:61-83`):

- **<512B**: `create_reader_fast` batches many small allocations into a
  16 KB thread-local slab (`buffer_raw_tls`), only falling back to a fresh
  16 KB block (`create_buffer_raw(4096 * 4)`) once the current one is
  exhausted. This is already a form of pooling, scoped per-thread.
- **≥512B**: `create_writer_exact(size)` → `create_buffer_raw(size)` is a
  plain `new char[buf_size]` per call (`buffer.cpp:50-52,106-116`) — no
  pooling inside `BufferAllocator` for this size range.

In both cases, "prefer recently-freed memory of the same size" is already
the job of **jemalloc's per-thread tcache** underneath `new[]`/`delete[]` —
that's the specific purpose of a thread-caching allocator: same-size-class
alloc/free cycling is served from already-freed, already-warm memory without
touching the global arena or the OS. A hand-rolled pool inside
`BufferAllocator` would largely duplicate this, while introducing a real
correctness concern jemalloc already handles: these buffers are frequently
allocated on one actor worker thread and freed on another after an async
callback (very plausible in this actor-based codebase) — jemalloc's arenas
are safely multi-threaded; a naive custom free-list would need its own
synchronization to avoid becoming *its own* new bug.

More fundamentally: **allocator-level pooling doesn't address either
possible root cause above.** If case 1 (reference leak) is true, the memory
is still reachable — nothing is ever returned to any pool to reuse,
allocator-side or not. If case 2 (backlog) is true, the fix is
backpressure/queue-limiting at the message-producing layer, not a change in
how the allocator serves requests.

## Recommendation

Don't change `BufferAllocator`. Keep the existing live-byte telemetry and
alert on a sustained slope only when it correlates with a growing owning
container or in-flight queue. The completed observation identifies the old
slope as retry backlog and requires no allocator-level fix.
