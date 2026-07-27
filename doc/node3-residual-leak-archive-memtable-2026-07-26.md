# Node3 Residual Growth: Two Candidate Sources Found via Heap Profiling, Not Yet Root-Caused (2026-07-26)

## Status

This is a follow-up to
[state-resolver-cache-leak-2026-07-26.md](state-resolver-cache-leak-2026-07-26.md),
which bounded `StateResolverImpl`'s two maps and live-validated them on node3,
but left a residual ~34 MiB/min `stats.allocated` growth ("not fully fixed")
unattributed.

Two `jeprof --base` differential heap profiles, taken ~16-20 minutes apart on
a fresh node3 run, **confirm the StateResolver fix holds** (`state_cache_`/
`finalized_blocks_` show ~0% or slightly negative net growth in both diffs)
and identify **two other, consistent, dominant contributors** to the residual
growth. Neither has been root-caused yet — this document records what the
profiling shows and what source-level investigation has ruled in/out so far,
so the next session doesn't have to repeat the setup work.

**2026-07-27, later update: Bug A and Bug B are now implemented (built, not
yet deployed or re-profiled).** Node3's profiling `LD_PRELOAD`/systemd
drop-in has been removed and it's back on the normal production binary; the
~15,000-file dump directory was left in place (not cleaned up) as the raw
data behind rounds 1-3. Code changes:

- **Bug A**: `tddb/td/db/RocksDb.{h,cpp}` gained `flush_wal(bool sync)`
  (wraps `rocksdb::DB::FlushWAL`). `WalletIndexDb::put_incomplete_block()`
  now calls `flush_wal(true)` instead of the heavy `flush()`.
  `WalletIndexDb::commit_batch()`'s trailing `flush()` call was deleted
  outright (proven redundant — `commit_write_batch()` already writes with
  `sync=true`, which combined with `manual_wal_flush=true` already syncs the
  WAL).
- **Bug B**: `WalletIndexDb::for_each_incomplete_block()` added (enumerates
  `0x1E` markers). `ValidatorEngine::recover_wc0_index()` added in
  `validator-engine.cpp`, fired once right after `validator_manager_` is
  created in `start_validator()`.

Both changes built cleanly at the time, but **the first Bug B
implementation had two real correctness bugs**, caught by a second
independent review pass — see the correction immediately below before
reading the rest of this section as current.

**2026-07-27, second correction (same day): Bug B's first cut was wrong,
now fixed for real.**

Two issues found by re-reading the code and re-running the build:

1. **The marker was keyed by seqno alone, which is not unique.** wc=0 can
   shard-split/merge, so a different shard can reuse the same seqno — a
   seqno-only marker can't tell which block it meant, and
   `get_block_by_seqno_from_db(AccountIdPrefixFull{0, shardIdAll}, seqno, ...)`
   (an account/shard-*prefix* search) has no guarantee of resolving back to
   the exact original shard's block. **Fixed**: the marker is now keyed by
   the full block position — `0x1E + workchain_be(4) + shard_be(8) + seqno_be(4)
   -> root_hash(32) + file_hash(32)` — and recovery does an exact lookup via
   `ValidatorManagerInterface::get_block_handle(BlockIdExt, force=false, ...)`
   instead. This required threading the full `BlockIdExt` through the whole
   call chain, not just workchain+seqno: `g_wc0_block_index_hook`'s signature
   (`validator/wc0-block-hook.h`), both call sites in
   `validator/apply-block.cpp:applied_set()`, and `wc0_index_block()`'s
   signature (`validator-engine/wallet-index-writer.h`/`.cpp`) all now carry
   the full block id.
2. **A failed state fetch during recovery still called `wc0_index_block()`**,
   which indexes events-only and then deletes the marker on that partial
   "success" — permanently losing the chance to backfill jetton/NFT data for
   that block, since nothing would ever retry it again. **Fixed**: if
   `get_shard_state_from_db` errors or returns null during recovery, the
   marker is left in place and `wc0_index_block()` is not called at all, so
   a later restart can retry once state is available.

Also addressed along the way (raised in the same review, lower severity but
cheap to fix immediately):

- Recovery now processes markers **one at a time** (a self-chaining
  `step()` continuation), not all fired concurrently — avoids many actor
  workers piling up on `WalletIndexDb`'s single `write_mutex_` at once if a
  crash ever leaves behind a large batch of markers.
- `for_each_incomplete_block()`'s scan status is now logged on error instead
  of silently `.ignore()`d.

**Deliberately not changed then, revisited in the third pass below**: the
two-WAL-syncs-per-block structure is required, not incidental — the marker
must be durably synced *before* the risky indexing work starts (so a
mid-index crash still leaves a recoverable trace), a different durability
point in time from the batch commit that happens *after* indexing succeeds.
Collapsing them would break the crash-recovery guarantee the marker exists
for; this stays as designed. But the `.ignore()` on the marker write itself
turned out to matter — see item 3 in the next update.

**2026-07-27, third correction pass: three more issues found by a second
independent review of the corrected Bug B.**

1. **Reference cycle in the recovery continuation.** The sequential-processing
   fix (previous update) used `auto step = std::make_shared<std::function<void()>>();
   *step = [..., step]() {...};` — the closure stored *inside* `step` captured
   a strong copy of `step` itself. That's a genuine cycle: nothing ever drops
   the refcount to zero, so `step` (and everything it captured — the marker
   list, the index) leaks for the life of the process after every recovery
   run. **Fixed** by dropping the shared_ptr-closure approach entirely:
   `wc0_recovery_markers_`/`wc0_recovery_index_` are now `ValidatorEngine`
   members, and `recover_wc0_index_step()` re-invokes itself by sending a
   message to its own `actor_id(this)` through the actor scheduler instead of
   calling a captured continuation. This has no cycle (members aren't
   self-referential) and is also safer if `ValidatorEngine` were ever torn
   down mid-recovery — the actor framework just drops in-flight messages to a
   dead actor, rather than needing manual lifetime bookkeeping.
2. **The marker still wasn't a full `BlockIdExt`.** The previous fix put
   `root_hash`/`file_hash` in the marker's *value*, keyed only by
   workchain+shard+seqno. If the same position could ever legitimately be
   re-applied with a different hash (a reorg/hardfork path — not confirmed
   impossible), a new marker write would silently overwrite the old one's
   hash rather than being distinguishable from it. **Fixed**: the full
   `BlockIdExt` (including both hashes) is now the key
   (`0x1E + workchain_be(4) + shard_be(8) + seqno_be(4) + root_hash(32) +
   file_hash(32)`, 81 bytes); the value is now just a 1-byte sentinel.
3. **A failed marker write was silently ignored and indexing proceeded
   anyway.** `db->put_incomplete_block(block_id).ignore()` meant that if the
   write (or its `flush_wal(true)`) failed, the code indexed the block
   regardless — with no durable marker to protect a mid-index crash, exactly
   defeating the crash-recovery guarantee the marker exists for. **Fixed**:
   the status is now checked; on failure, indexing this pass is skipped
   entirely (logged at ERROR) rather than proceeding without a safety net.

**Also fixed, lower severity**: old binaries (every version before this
change, including production binaries that may already be running, not just
this session's first Bug-B cut) used a 9-byte seqno-only marker key. The new
scanner would have silently and permanently discarded any real legacy
marker as generic "malformed". `for_each_incomplete_block()` now recognizes
the legacy 9-byte length distinctly and logs it at ERROR with the decoded
seqno instead — it still can't be auto-recovered (no shard/hash to
disambiguate), but it's now visible rather than silently dropped. **Before
deploying to any node, check its startup log for this message** — if
present, that node has a real historical indexing failure that needs manual
investigation, not just a restart.

**2026-07-27, fourth pass: comment/doc accuracy cleanup, no code-behavior
changes.** A third review round confirmed all three fixes above are
implemented correctly and found no further lifecycle or concurrency issues,
but flagged three places where comments had gone stale across the earlier
rounds of edits:

- `wallet-index.h`'s marker doc-comment still described the second-round
  layout (hashes in the *value*) after the third round moved them into the
  *key* — updated to match the actual 81-byte-key/1-byte-value layout.
- `wallet-index-writer.cpp` and `wallet-index.h` both still said "one WAL
  flush per block" / "single fsync per block" from before Bug A's fix — it's
  two necessary syncs (marker, then commit), not one; comments corrected to
  say so explicitly. Also fixed in `doc/tos-wc0-wallet-index.md`, which had
  the same stale claim in the original design writeup.
- The marker-write-failure comment said the block "stays un-indexed until
  some future event re-triggers this hook" — inaccurate: the hook fires
  exactly once per block, so a marker-write failure leaves that block's
  index entries **permanently** missing, not pending-retry. Corrected to say
  so plainly, and noted that a stronger guarantee (vs. today's log-and-skip)
  would need an in-memory retry queue or a full-index-rebuild path, neither
  of which exists.

Confirmed still correct as originally implemented: legacy-marker handling
(log loudly, don't auto-recover, expect a manual pre-deployment log check)
was already accurate and needed no change.

All of this builds cleanly (`validator-engine` and `validator-engine-console`
targets). **None of it has been live-tested, re-profiled, or exercised under
an actual injected failure yet** — see Next steps. Node3 has not been
redeployed with any of these changes.

**2026-07-27 update:** an independent review verified this document against
the code and against a third differential round. Bug A's diagnosis and fix
are confirmed precise (see below — the second `flush()` is now *proven*
redundant, not just suspected). One conclusion in the original write-up was
wrong and has been corrected in place: the claim that both growth chains
"nest under a common caller" was an artifact of reading a flat,
`--cum`-sorted `jeprof --text` listing as if it were an indented call tree —
it isn't one, and re-checking the raw diffs shows the archive-read chain's
call stack does *not* actually contain `ApplyBlock`/`wc0_index_block`. See
"Correction: the two chains are not confirmed to share a caller" below.

## Method: getting a working differential heap profile

Ubuntu's packaged `libjemalloc2` is **not** built with `--enable-prof`, so
`MALLOC_CONF=prof:true` on the production binary is silently a no-op. Getting
a working profile required:

1. **Build jemalloc 5.3.0 from source** with `--enable-prof --enable-stats`
   (see `/tmp/.../scratchpad/jemalloc-prof/` from this session — not
   committed anywhere permanent). `prof-libgcc` (the default backtrace
   method, no `libunwind` dependency) builds fine and works for `cum%`-based
   analysis, see point 3 below.
2. **`LD_PRELOAD` the custom `libjemalloc.so.2` via a temporary systemd
   drop-in**, `/etc/systemd/system/tos-validator@3.service.d/heap-profile.conf`
   (not committed, matches the approach used in the original investigation
   referenced in `celldb-v2-node3-rss-growth-2026-07-26.md`).
   - **Gotcha:** the base unit has `PrivateTmp=true`, so a custom
     `.so`/dump-directory placed under `/tmp` is invisible to the service and
     `LD_PRELOAD` fails *silently* (`ld.so: ... cannot be preloaded: ignored`,
     easy to miss in the journal) while the process quietly falls back to
     the system (non-profiling) jemalloc. Fix: put the built library and the
     dump directory under the repo, e.g.
     `/home/tomi/tos/.node3-heap-profile/{lib,dumps}/` — a path the
     service's private-tmp namespace doesn't affect.
3. **Triggering dumps:** the standard technique of attaching `gdb -p <pid>`
   and calling `mallctl("prof.dump", ...)` via inferior function-call
   injection **does not work in this sandbox** — `Couldn't write extended
   state status: Bad address` (the ptrace `XSTATE` regset needed to safely
   call a function in the target is blocked). Worked around this by setting
   `lg_prof_interval:28` (auto-dump every 256 MiB cumulative allocated) in
   `MALLOC_CONF` instead of triggering dumps on demand. This produces *many*
   more dumps than needed (the dump/backtrace machinery's own allocations
   count toward the interval, which can mildly self-perpetuate) — just pick
   any two dumps at the wall-clock times you want and diff those.
   **Correction:** this was originally described as "harmless" — it is not,
   for extended runs. By 2026-07-27 the dump directory had produced ~12,500
   files (~1.9 GB) at roughly 1/sec sustained. Three rounds of diffs is
   enough data; this should be throttled (raise `lg_prof_interval` a lot, or
   stop profiling) rather than left running indefinitely.
4. **Reading the diff output:** in `jeprof --text --lines` output, "self"
   for a jemalloc profile will **always** show 100% at
   `prof_backtrace_impl` (jemalloc's own capture wrapper is definitionally
   the innermost frame of every sampled stack) — this is expected, not a
   bug, and is *not* evidence the profile is broken. The actual signal is in
   the **`cum%`** column further up the stack. (This was misdiagnosed as a
   broken backtrace during this investigation, leading to an unnecessary
   rebuild with `--enable-prof-libunwind` — that rebuild works too, but
   wasn't the fix; needed `libunwind-dev` installed via `apt`, and needed
   dynamic linking against `libunwind.so` since the static `.a` had an LTO
   bytecode version mismatch against this system's `gcc`.)

Final working `MALLOC_CONF`:
```
background_thread:true,dirty_decay_ms:10000,muzzy_decay_ms:10000,prof:true,prof_active:true,lg_prof_sample:19,lg_prof_interval:28,prof_prefix:/home/tomi/tos/.node3-heap-profile/dumps/jeprof
```

Node3 stayed healthy throughout (no crash/OOM/restart), consensus
certificates continued flowing on both groups, consistent with the
production-binary live validation already documented.

## Findings

Three independent `jeprof --base` diffs, each ~16-20 minutes, on continuous
node3 runs (round 3 taken 2026-07-27 after further uptime, same methodology):

| Call chain (cum%) | Round 1 (625.4 MB net) | Round 2 (680.7 MB net) | Round 3 (645.1 MB net) |
|---|---|---|---|
| `RootDb::get_block_data` → `ArchiveSlice::get_file` → `PackageReader::start_up` → `td::BufferAllocator::create_reader` | 291.2 MB (46.6%) | 247.5–343.8 MB (36.4–50.5%) | 237.1 MB (36.8%) |
| `DBImpl::SwitchMemtable` → `ConstructNewMemtable` → `MemTable::MemTable` → `ConcurrentArena` (forced memtable flush) | 189.8 MB (30.3%) | 240.2 MB (35.3%) | 239.7 MB (37.2%) |
| `StateResolverImpl::{state_cache_,finalized_blocks_}` (for comparison) | ~0% / slightly negative | ~0% / slightly negative | ~0% |

Three rounds in, both chains are consistently the two dominant contributors,
each in the 35-50% range, with `StateResolverImpl` staying flat at ~0% —
the earlier fix continues to hold. Everything else in all three diffs is
scattered 2-6% entries across networking/overlay/quic code with no single
dominant chain — consistent with ordinary in-flight traffic, not a leak.

### Correction: the two chains are not confirmed to share a caller

The original version of this document claimed both dominant chains "nest
under a common caller" (`ApplyBlock::applied_set` → `wc0_index_block`),
based on both entries appearing near each other in round 2's `jeprof --text
--cum` output. **That was a misreading.** `jeprof --text` prints a *flat*
list of functions/lines sorted by cumulative weight — it has no indentation
and does not represent a call tree; two entries with similar `cum%` are not
thereby parent/child. Re-checking all three saved diffs directly against the
raw call stacks:

- The **memtable/flush chain** genuinely is rooted at `ApplyBlock::applied_set`
  → `wc0_index_block` in all three rounds — this part of the original claim
  holds.
- The **archive-read chain**'s own stack terminates at `PackageReader` →
  `RootDb`'s promise callback and does **not** contain `ApplyBlock` or
  `wc0_index_block` anywhere in it, in any of the three rounds.

So these are two separately-rooted chains, not one chain feeding into the
other as previously written. They may still be *indirectly* related — e.g.
a forced flush blocking an actor-scheduler worker thread could cause
archive-read `BufferSlice`s returned around the same time to queue up
un-freed for longer, inflating the archive chain's apparent net growth as a
side effect of Bug A rather than a bug of its own — but **the profile data
does not establish this causal link**; it's a hypothesis to test (see Next
steps), not a finding.

## Source-level investigation so far

**Ruled out** (RAII-safe / no retention found):

- `PackageReader::start_up` (`validator/db/archive-slice.cpp:201-227`, and
  the near-identical variant in `validator/db/archive-db.cpp:21-35`): calls
  `Package::read()`, sets the promise result, drops its `Package` shared_ptr,
  and calls `stop()` on itself. The actor is created via
  `td::actor::create_actor<PackageReader>(...).release()`
  (`archive-slice.cpp:528-530`) — the returned `ActorId` is discarded
  immediately, no map/vector/member anywhere holds a long-term reference.
  Genuinely fire-and-forget, self-terminating.
- `Package::read` (`validator/db/package.cpp:76-109`): three plain `pread()`
  syscalls into a freshly-allocated `td::BufferSlice` per call — no mmap, no
  application-level cache of previously-read content.
- `td::BufferAllocator::create_reader` (`tdutils/td/utils/buffer.cpp:61-93`):
  for reads <512B, pulls from a thread-local 16 KB slab arena
  (`create_reader_fast`); for ≥512B (the common case for block payloads),
  a plain sized heap allocation via `create_writer_exact`. Both paths are
  refcounted `BufferSlice`s, not a source of retention on their own.
- `ArchiveSlice::before_query` / `begin_async_query` / `end_async_query`
  (`archive-slice.cpp:709-801`, `900-925`): the `active_queries_` counter is
  reliably decremented on every path checked, including error paths and
  early destruction — the wrapped `Promise<T>`'s `LambdaPromise` destructor
  fires a "Lost promise" error if never explicitly resolved, which still
  triggers the decrement; other direct callers use `SCOPE_EXIT`. Not the
  leak.

**Investigated — Bug A found, explains chain (a) (memtable/arena churn)**:

`WalletIndexDb::flush()` (`validator-engine/wallet-index.cpp`) calls
`td::RocksDb::flush()` (`tddb/td/db/RocksDb.cpp:389-391`), which is
`db_->Flush(FlushOptions{})` — RocksDB's **synchronous forced memtable
flush** (`wait=true` by default), not a cheap WAL sync. This is called
**twice per applied wc=0 block, unconditionally**, on the happy path:

- `WalletIndexDb::put_incomplete_block()` (`wallet-index.cpp:246-255`) —
  writes a durability marker, then calls `flush()`.
- `WalletIndexDb::commit_batch()` (`wallet-index.cpp:286-297`) — commits the
  batch, then calls `flush()` again, with a comment citing "`td::RocksDb`
  opens with manual WAL flush and its destructor does not flush" as the
  justification.
- Both are called unconditionally from `wc0_index_block()`
  (`validator-engine/wallet-index-writer.cpp:416` and `:463`) on essentially
  every applied wc=0 block.

Each forced `Flush()` goes through `DBImpl::SwitchMemtable → ConstructNewMemtable
→ MemTable::MemTable → ConcurrentArena` — exactly the chain in the profile —
regardless of how little data (often just a handful of keys) has accumulated
since the last flush. `td::RocksDb` never exposes RocksDB's actual
WAL-only-sync API (`FlushWAL()`); `flush()` is the only durability primitive
available, and it's the wrong (heavy) one for this use case. For comparison,
the only other RocksDB-backed component in the repo, `TosDbImpl`
(`crypto/vm/db/TosDb.cpp:287`), calls `flush()` exactly once, in its
destructor at shutdown — `WalletIndexDb` is the only caller flushing on
every write.

RocksDB options are otherwise unremarkable: `WalletIndexDb::open()`
(`wallet-index.cpp:66-78`) opens a separate `td::RocksDb` at
`${db_root}/wc0-index` with default-constructed `RocksDbOptions{}` (no
custom `write_buffer_size`, single default column family) — so this is not
a config-driven small-buffer issue, it's the explicit `Flush()` call sites.

**Not yet fixed. Precise fix, confirmed by reading `RocksDb.cpp` directly**:

- `RocksDb::commit_write_batch()` (`tddb/td/db/RocksDb.cpp:363-369`) already
  sets `WriteOptions.sync = true` before calling `db_->Write(...)`. Combined
  with `manual_wal_flush = true` (set once in `RocksDb::open`,
  `RocksDb.cpp:108`), RocksDB itself auto-flushes-and-syncs the WAL for any
  write issued with `sync=true` — that is exactly what `commit_batch()`'s
  call to `commit_write_batch()` already does. So the second `flush()` at
  the end of `commit_batch()` (`wallet-index.cpp:296`) is not merely
  "possibly redundant" — it is **provably redundant**, confirmed by both the
  RocksDB-documented semantics of `sync=true` + `manual_wal_flush=true` and
  by the code already present in this repo. It should simply be deleted.
- The other call site, `put_incomplete_block()` (`wallet-index.cpp:246-255`),
  writes the marker via a plain (non-sync) `db_->set()`, so it *does* need
  an explicit durability step — but a WAL-only sync suffices for a marker
  record, not a full memtable flush. Fix: add a `FlushWAL(bool sync)`
  wrapper to `td::RocksDb` (there is currently none — `RocksDb.h`/`.cpp`
  only expose the heavy `flush()`), wrapping `rocksdb::DB::FlushWAL(true)`,
  and call that instead of `flush()` at `wallet-index.cpp:254`.

Net effect: one `FlushWAL(true)` per block (cheap), zero `DB::Flush()` calls
on the normal per-block path — down from two heavy forced flushes today.

**Investigated — explains chain (b) nesting (archive re-fetch), not a leak**:

`wc0_index_block()` itself never fetches historical/older block data — it
only operates on the single block passed in. But its caller,
`ApplyBlock::applied_set()` (`validator/apply-block.cpp:277-309`), re-fetches
**the same block currently being applied** via
`ValidatorManager::get_block_data_from_db` → `RootDb::get_block_data` →
`ArchiveSlice::get_file` whenever `ApplyBlock`'s `block_` member is empty —
which happens on the recursive-parent-application path during catch-up
(`apply-block.cpp:252,254`, `run_apply_block_query(..., td::Ref<BlockData>{}, ...)`).
This is real, avoidable per-block I/O specific to the wc0-index hook (a
normal `ApplyBlock` without the hook wouldn't need this fetch at
`applied_set` time), and explains why the archive-read chain shows up nested
under `wc0_index_block` in round 2 (likely more empty-`block_` applies
during that window, e.g. catch-up). No container was found caching the
re-fetched `BlockData`/`BufferSlice` beyond the callback's scope — this is
**overhead, not a memory leak**. Still worth fixing (skip the re-fetch when
possible), but it's a separate issue from Bug A and from the residual RSS
growth investigation.

**Provenance check against upstream TON (`~/ton-c`)**: neither bug is
inherited. `wallet-index.cpp`/`wallet-index-writer.cpp`/`WalletIndexDb` don't
exist in `~/ton-c` at all — the whole subsystem is a TOS-only addition.
`RocksDb::flush()` itself (`db_->Flush({})`, no WAL-only-sync alternative
exposed) is byte-identical between the two trees, so the heavy primitive is
inherited from TON unchanged — but ton-c's only caller
(`crypto/vm/db/TonDb.cpp:286`) uses it exactly like TOS's `TosDbImpl`: once,
in the destructor, at shutdown. Every upstream caller respects the primitive
being heavy; Bug A is TOS's new per-block caller misusing it, introduced
when `wallet-index` was added, not a carried-over upstream issue.

**Separately found — Bug B, disk-resident correctness bug (not the RSS leak)**:

In `wc0_index_block()` (`validator-engine/wallet-index-writer.cpp:401-471`),
`delete_incomplete_block()` (the marker erase, `:462`) is only called on the
success path. On failure (`index_block_walk` throws `vm::VmError` or hits
unparseable TLB data), `abort_batch()` runs instead (`:469`) and the
durability marker written earlier by `put_incomplete_block()` (`:416`) is
**never removed** — and `has_incomplete_block()` has zero callers anywhere
in the repo, so there's no startup/crash-recovery reaper either. This leaks
on-disk RocksDB keys (not in-process memory), should be rare in practice
(blocks reaching `applied_set` are already consensus-validated, so TLB
parsing failures should be exceptional), and is not believed to be the
driver of the RSS growth this document is chasing.

**Correction on the fix**: don't just call `delete_incomplete_block()` from
the `catch` blocks. `has_incomplete_block()` having zero callers means the
crash-recovery mechanism this marker exists for was never actually wired up
— silently deleting the marker on failure would make the problem
*invisible* (the block's index entries would simply stay missing forever,
with no record that indexing failed) rather than fixing the recovery gap.
Correct fix: at startup, scan for `0x1E` markers, re-fetch and re-index each
flagged block from the archive, and only then delete its marker atomically
on success — i.e. actually build the crash-recovery path the marker was
designed for, not just clean up after the fact.

**Investigated — `ArchiveLru::on_query` ruled out**:

`ArchiveLru::on_query` (`validator/db/archive-slice.cpp:1488-1501`) updates
`slices_[to_tuple(id)]` (a small `SliceInfo` per `PackageId`: an `ActorId`,
a file count, an LRU index) and calls `enforce_limit()`, which bounds
`lru_` by open-file count. `slices_` itself is never erased for historical
`PackageId`s, so there is a slow metadata leak here — but each entry is tiny
(an actor id + a couple of integers, not a buffer), package files cover many
blocks each so new entries are created rarely, and this implementation is
essentially identical to `~/ton-c`'s. It cannot plausibly account for
~237 MB of `BufferAllocator` growth every 20 minutes. Not the leak.

**Still open**:

1. Whether Bug A's fix (once implemented) actually shrinks chain (a)
   proportionally, and whether it has any effect on chain (b) given the
   unconfirmed indirect-causation hypothesis above (worker-thread blocking
   → BufferSlice backlog). Both need to be checked empirically by re-running
   this same diff methodology after the fix, not assumed.
2. What's actually driving the archive-read chain if it turns out to be
   independent of Bug A — no in-process retention was found anywhere on
   that path (`PackageReader`, `Package::read`, `BufferAllocator::create_reader`,
   `ArchiveSlice::before_query`/`begin_async_query` are all ruled out above),
   so if it doesn't fade after the Bug A fix, the next place to look is
   whatever *calls* `get_file` on the non-wc0-index paths, and the
   actor-scheduler/worker-queue behavior itself (is something queuing more
   read requests than it retires?).
3. `jemalloc`'s `dirty_decay_ms:10000`/`muzzy_decay_ms:10000` do **not**
   explain sustained `stats.allocated` growth — dirty/muzzy page retention
   inflates `active`/`resident`/RSS (pages the allocator holds but hasn't
   returned to the OS), but `stats.allocated` only counts bytes actually
   requested by *live* (unfreed) allocations. Since `stats.allocated` itself
   has been climbing continuously throughout this investigation, that is
   direct evidence of live retained allocations or a growing processing
   backlog — not just the allocator being slow to hand pages back to the OS.

## Context: node1/node2 status (unrelated to this investigation)

At the time of this session, `tos-validator@1` and `@2` were still running
the **pre-fix** binary (up since 2026-07-26 04:39:10 UTC, ~15h), each at
~29 GiB RSS and climbing (~29-30 MiB/min measured live, `VmHWM == VmRSS` i.e.
never plateaued) — the same already-diagnosed unbounded `state_cache_`/
`finalized_blocks_` growth this whole investigation started from, just not
yet remediated on those two nodes. Per explicit instruction, they were left
running and not restarted during this session; this is purely a note of
current state, not a new finding.

## 2026-07-27: live restart-recovery test on node3 — passed

The Bug B recovery path was exercised end-to-end on node3 with the actual
`ValidatorManagerInterface` actor, not a mock — the thing the earlier unit
test explicitly couldn't cover.

**Method**: a temporary, env-var-gated fault-injection knob was added to
`wc0_index_block()` (`TOS_WC0_INDEX_TEST_FAIL_SEQNO=<seqno>`, forces
`index_block_walk`'s result to `false` for exactly one target seqno) so a
real failure could be produced through the real code path deterministically,
instead of racing a real crash's timing. Removed again after the test — not
meant to ship.

**Finding along the way**: the "block id" visible in `pool.cpp`'s
`FinalizeVote`/`NotarizeVote` log lines is a Simplex **consensus slot/
candidate counter**, not the underlying wc=0 shard-chain block seqno — they
are different, unrelated counters (consensus slot was ~42,000 at the time;
the real wc=0 seqno being applied was ~528,000+, from many hours of
accumulated chain history across this session's restarts). Don't target a
seqno for anything block-id-related off the consensus slot number visible in
those logs — read the actual applied block id from `apply-block.cpp`/
`wallet-index-writer.cpp` logging instead.

**Result**:
1. Deployed the Bug A + Bug B binary to node3, set the fault-injection env
   var to a wc=0 seqno slightly ahead of the live catch-up position.
2. Confirmed via log (`wc0-index: TEST-ONLY fault injection forcing failure
   for seqno=528400`) that indexing was forced to fail for that exact block,
   and the node continued processing subsequent blocks normally afterward —
   no crash, no cascading failure (`NRestarts=0` throughout).
3. Restarted node3 **without** the fault-injection env var. Startup log:
   `wc0-index: recovering 1 block(s) left incomplete by a previous crash/
   parse-failure`, immediately followed by a fresh `wc0_index_block` call
   for seqno 528400 — confirming `recover_wc0_index()` correctly scanned the
   marker, resolved it via the exact `get_block_handle()` lookup (not the
   old ambiguous seqno search), fetched `BlockData`/`ShardState`, and
   re-drove indexing. No errors on the re-index.
4. Restarted a third time: no "recovering" message at all — confirming the
   marker was durably deleted after the successful re-index, not just
   deleted in memory.
5. Throughout, the three pre-existing **legacy** 9-byte markers already on
   node3's disk (seqno 286866, 348949, 527209 — real historical failures
   from before today, not test artifacts) were correctly logged at ERROR on
   every startup and correctly *not* auto-recovered or double-counted in the
   "recovering N block(s)" figure, exactly as designed.

This is now considered validated, live, against the real actor runtime —
not just unit-tested at the storage layer. The still-missing pieces from the
original test list (missing-state-during-recovery specifically, and a
same-seqno-different-shard collision through the real `get_block_handle()`
path rather than storage alone) remain open but are lower priority given
this result; see remaining items below.

Node3 is currently running the clean (no diagnostics, no fault-injection
knob) Bug A + Bug B binary, PID current as of this test. It has **not** been
re-profiled yet for Bug A's effect on the memtable/flush chain — that's
still open, see below.

## 2026-07-27: post-fix re-profiling — Bug A's effect confirmed, two rounds

Node3 redeployed with the Bug A + Bug B binary and the profiling
`LD_PRELOAD`/systemd drop-in (interval raised to `lg_prof_interval:30`,
1 GiB, to avoid the earlier dump-storm — this run produced ~500 dumps over
36 min instead of ~15,000 over ~40 min). Old dumps from before the fix were
cleared first (already fully captured in the tables above).

| Metric | Before (rounds 1-3, pre-fix) | After (round 4, 02:08→02:24) | After (round 5, 02:24→02:39) |
|---|---|---|---|
| Net growth, ~15-16 min window | 625.4 / 680.7 / 645.1 MB | 332.3 MB | 284.3 MB |
| `ConstructNewMemtable`/`SwitchMemtable`/`ConcurrentArena::ConcurrentArena` | 30.3% / 35.3% / 37.2% | **0 occurrences** | **0 occurrences** |
| Memtable chain now (`MemTable::Add`, no reconstruction) | — | 54.7 MB (16.5%) | 52.4 MB (18.4%) |
| Archive re-fetch (`PackageReader::start_up` / `RootDb::get_block_data`) | 291.2 / ~295 / 237.1 MB (36.8-50.5%) | 32.6 MB (9.8%) | 1.0 MB (0.4%) |
| `StateResolverImpl` | ~0% (both maps) | ~0% | ~0% |

Both open questions from the original investigation are now answered:

1. **Bug A's fix works, cleanly.** Not just smaller — the forced
   `DB::Flush()` → `SwitchMemtable` → `ConstructNewMemtable` →
   `ConcurrentArena` construction chain that dominated all three original
   rounds is **completely absent** from both post-fix rounds. What remains
   under `rocksdb::` is ordinary `MemTable::Add` growth into the
   *existing* memtable — expected, healthy per-write cost, not a bug.
2. **The archive-read chain was a downstream effect of Bug A, not an
   independent leak** — confirming the hypothesis noted after the second
   correction pass. It dropped from the single largest contributor
   (36-50%) to a minor one (9.8%) to essentially zero (0.4%) across the two
   post-fix rounds, tracking Bug A's fix rather than persisting
   independently. No separate root-cause work needed here.

Net effect: total residual growth per comparable window is now roughly
**55% lower** (284-332 MB vs 625-680 MB). What's left is spread across
ordinary-looking network/consensus traffic (QUIC message buffers via
`BufferAllocator::create_reader`, overlay broadcast forwarding, TL object
serialization) with no single dominant chain — consistent with normal
operational churn, not an obvious remaining bug. Whether this residual
~19-22 MiB/min is fully "healthy churn that nets to zero over a long
enough window" or has a smaller, still-unidentified component is not yet
determined — see Next steps.

Node3 is currently running with profiling still active
(`lg_prof_interval:30`); dumps continue to accumulate in
`.node3-heap-profile/dumps/` (~500 so far, well short of the earlier
storm). Should be reverted to the plain production binary once this
investigation is considered closed.

## Next steps

1. ~~Implement the Bug A fix~~ **Done** (see 2026-07-27 update above) —
   `flush_wal()` added, `commit_batch()`'s redundant `flush()` removed.
2. ~~Fix Bug B properly (startup scan + re-index + atomic marker delete)~~
   **Done, after a second correction pass** (see the two 2026-07-27 updates
   above) — full-`BlockIdExt` markers, exact `get_block_handle()` lookup,
   sequential recovery, and leave-marker-on-missing-state.
3. ~~Deploy and re-profile~~ **Done** (see "2026-07-27: post-fix
   re-profiling" above) — memtable/flush chain confirmed eliminated, archive
   chain confirmed as a downstream effect (dropped to ~0), both across two
   consistent rounds. Total residual growth per window down ~55%.
3b. **New, smaller open item**: the remaining ~19-22 MiB/min residual isn't
   yet confirmed as fully benign — it's spread across ordinary-looking
   network/consensus traffic with no dominant chain, which is consistent
   with healthy churn but not proven to net to zero over a longer window.
   A longer-duration diff (an hour or more, comparable to the original
   multi-hour observation that first motivated this whole investigation)
   would clarify whether it's genuinely flat/oscillating or has a small
   residual slope worth chasing further.
4. Bug B had **no test coverage at all** — only built, never run. Progress:
   - ~~Unit-test the marker key/value encoding round-trip~~ **Done**:
     `test/test-wallet-index.cpp` (registered as ctest target
     `test-wallet-index`, `tos_test(test-wallet-index)` in the top-level
     `CMakeLists.txt`, links `wallet-index.cpp` directly since it isn't part
     of any existing static library). Four cases, all passing:
     `IncompleteBlockMarkerRoundTrip` (put → has → scan → delete → confirm
     gone), `IncompleteBlockMarkerDistinguishesSameSeqnoDifferentShard` and
     `...SamePositionDifferentHash` (regression tests for the two marker
     bugs fixed above — two markers at the same seqno/position but different
     shard/hash must both survive as distinct entries, not overwrite each
     other), and `LegacySeqnoOnlyMarkerNotSurfaced` (hand-writes a raw
     9-byte legacy key via a separate `td::RocksDb` handle, confirms the
     scanner doesn't crash, excludes it from the callback, and — verified by
     checking actual log output, not just the return value — does emit the
     expected ERROR line with the decoded seqno).
   - ~~Force an indexing failure ... confirm marker left behind, restart,
     confirm recover_wc0_index() finds it, re-indexes, deletes it~~ **Done
     live on node3** — see "2026-07-27: live restart-recovery test on
     node3" above. This is the big one: real `ValidatorManagerInterface`
     actor, real `get_block_handle()` exact lookup, real restart, three
     restarts total to confirm both the recovery and the durable delete.
   - Test the missing-state path specifically: confirm a failed/null
     `get_shard_state_from_db` during recovery leaves the marker in place
     rather than deleting it. (Not covered by the unit test above — that's
     storage-level only; this needs the actual `recover_wc0_index_step()`
     path with a mocked/failing `get_shard_state_from_db`.)
   - ~~If wc=0 shard-splitting is actually reachable in this deployment,
     test that two different shards reusing the same seqno don't
     collide~~ **Storage-level regression covered** by
     `IncompleteBlockMarkerDistinguishesSameSeqnoDifferentShard` above.
     Still open: an end-to-end version through `recover_wc0_index_step()`'s
     actual `get_block_handle()` call, if shard-splitting is reachable in
     this deployment at all — worth confirming either way.
   - Confirm `recover_wc0_index_step()`'s recursion via `actor_id(this)`
     doesn't leak either — run a recovery pass with several markers under a
     leak-checking build/profiler and confirm memory returns to baseline
     after the batch completes (the direct motivation for the shared_ptr
     rewrite was catching a real cycle by inspection; worth confirming
     empirically too, not just by code review).
   - Confirm the legacy 9-byte marker detection path: seed one under an old
     binary (or hand-craft one), start the new binary, confirm it logs the
     ERROR with the decoded seqno instead of silently vanishing.
5. Once re-profiling confirms (or rules out) the hypothesis in item 3,
   live-validate on node3 the same way the StateResolver fix was validated
   (sustained run, watch `stats.allocated` slope, confirm no crash/
   oscillation) before considering this closed.
6. Clean up `.node3-heap-profile/`'s accumulated dumps once no longer needed
   as reference data.
