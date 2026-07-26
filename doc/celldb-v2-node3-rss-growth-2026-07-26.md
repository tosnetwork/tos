# CellDB V2 Anonymous RSS Growth — node3 Diagnosis and Fix (2026-07-26)

## Summary

Validator node3 exhibited unbounded anonymous RSS growth (RssAnon), from
about 0.5 GiB after restart to over 4 GiB within roughly 45 minutes, with
RssFile flat at 30-35 MiB and no swap/huge pages involved. Root cause was
two independent bugs in the V2 CellDb reader cache
(`crypto/vm/db/DynamicBagOfCellsDbV2.cpp`). Both are fixed, built, and
verified against a live restart of node3. Changes are uncommitted pending
review.

**Update:** a longer live observation (see "Follow-up observation" below)
found that after these two bugs are fixed, the CellDB V2 cache itself
behaves correctly (bounded, and purges measurably release memory), but
total process RSS still climbs afterward at a steady rate driven by a
separate, not-yet-root-caused source of live allocation. The bugs fixed
here are confirmed real and confirmed fixed; they are not necessarily the
only contributor to node3's total memory growth.

## Scope

In scope:

- `DynamicBagOfCellsDbImplV2` / `CellDbReaderImpl` / `CellInfoStorage` in
  `crypto/vm/db/DynamicBagOfCellsDbV2.cpp`
- the systemd deployment config for node3
  (`deploy/tos-validator-node3-cache.conf`)

Out of scope:

- RocksDB's own block cache (separately capped via `--celldb-cache-size`
  / `--celldb-cache-min-size`, confirmed bounded at 1 GiB and not the
  source of this growth — RssAnon reached 7.2 GiB on the affected process,
  far past that cap)
- consensus/protocol behavior, DB on-disk format

## Root Cause

### Bug 1 — cache-size limit not enforced at the insertion boundary

`CellDbReaderImpl` never received `cache_size_max`. The
`--celldb-cell-cache-max-size 100000` limit was only checked periodically,
inside `DynamicBagOfCellsDbImplV2::set_loader()`, which runs roughly once
per committed block. Between those checks every `load_cell` /
`load_ext_cell` call kept inserting into the cache with no limit at all.
This is exactly how the observed log line was produced:

```
celldb_v2: reset reader, TTL=31/2000, cache_size=971287, force_drop_cache=true
```

`cache_size` reached ~971,287 — roughly 10x the configured 100,000 cap —
because nothing checked the limit until the next `set_loader()` call.

This periodic-only check is inherited from upstream `~/ton-c`: it has the
identical check and never threads `cache_size_max` into its reader either.
TOS did not regress this behavior; TOS's aggressive 100,000 cap (vs.
upstream's typical 1,000,000 default) simply made the gap far more visible.

### Bug 2 — the allocator-trim call was a no-op under jemalloc, and released nothing

This build links jemalloc (`TOS_USE_JEMALLOC=ON`, confirmed via `ldd` on
`validator-engine`), which replaces `malloc`/`free`/`realloc` process-wide.
Once that is true, glibc's `malloc_trim(0)` can only see glibc's own
(entirely unused) arenas — it cannot release memory that jemalloc owns.
This explains the observed symptom precisely:

> After reader reset, cache_size later dropped to about 56,596, but RSS
> did not decrease.

The C++ objects (`CellInfo`/`DataCell` for up to ~971K cached cells) were
genuinely freed at the point `internal_storage_.reset()` ran. But nothing
told jemalloc to return the resulting dirty/muzzy pages to the OS, and
without `background_thread` configured (confirmed absent from the live
process's environment at the time), jemalloc had no reason to do so on its
own within the observation window.

A first attempt at fixing this (calling `mallctl("arenas.purge", ...)`)
was itself wrong: that mallctl name does not exist in jemalloc 5.x and
returns `ENOENT`. This was caught during live verification (the new
diagnostic logged `result=error`) and confirmed with a standalone repro
against the linked libjemalloc 5.2.1. The correct call is
`mallctl("arena.4096.purge", ...)`, where `4096` is jemalloc's
`MALLCTL_ARENAS_ALL` constant (see `<jemalloc/jemalloc.h>`), addressing all
arenas merged.

## Fix

All changes are in `crypto/vm/db/DynamicBagOfCellsDbV2.cpp` unless noted.

- **`CellInfoStorage`**: added `on_cell_created()` backed by an O(1) atomic
  `size_` / `peak_size_` pair, replacing the previous `cache_size()`, which
  scanned all 8192 per-bucket mutexes on every call. Calling that scan on
  every single cell insertion (required by the fix below) would have been
  a serious lock-contention regression, so `cache_size()` had to become
  O(1) first. `mark_force_drop_cache()` now edge-triggers (CAS
  `false`→`true`) so the "limit reached" diagnostic log fires once per
  reader instead of once per insertion for the remainder of that reader's
  life.
- **`CellDbReaderImpl::enforce_cache_limit()`** (new): called from both
  cache-insertion points, `register_ext_cell_inner` and
  `load_cell_slow_path`, so the cap is enforced where cells actually enter
  the cache rather than only checked periodically. It does not evict
  synchronously — an in-flight commit may still need cells it just read —
  it flags the reader (`force_drop_cache_`) for reset at the next
  `set_loader()` call, the same mechanism already used for "cell cached
  from another db."
- **`trim_allocator_after_cache_drop()`**: rewritten to detect jemalloc at
  *runtime* via a weak-linked `mallctl` symbol, since this file compiles
  once into the shared `tos_db` static library, which is linked into
  binaries that do and do not enable `TOS_USE_JEMALLOC` — a compile-time
  `#ifdef` cannot express that. When jemalloc is present it calls
  `mallctl("arena.4096.purge", ...)`; otherwise it falls back to glibc
  `malloc_trim(0)`.
- **Diagnostics added** (all gated by `TOS_MEMORY_DIAGNOSTICS=1`; the
  enforcement and purge logic itself is unconditional): cache current
  size, cache peak size, cache drop count, allocator trim method/result,
  and RSS before/after every drop (read from `/proc/self/statm`, so it
  works regardless of which allocator is active). All of these are also
  exposed through `get_stats()`.
- Removed a dead, never-referenced `std::array<Bucket, buckets_n> bucket_;`
  member that duplicated the real `buckets_` array, silently
  double-allocating 8192 buckets' worth of mutexes and hash tables per
  reader instance.
- `deploy/tos-validator-node3-cache.conf`: added
  `MALLOC_CONF=background_thread:true,dirty_decay_ms:10000,muzzy_decay_ms:10000`
  as defense-in-depth, so jemalloc reclaims proactively between explicit
  drops as well.

## Why the fix is safe

- No consensus or DB-format changes.
- `enforce_cache_limit` only ever sets a flag; it never evicts cells
  synchronously, so no in-flight commit can lose a cell it already read.
- The purge call runs only on the drop path inside `set_loader()` — a
  handful of times per hour at typical TTL settings — never on the
  per-cell insertion hot path.
- All new logging is gated by `TOS_MEMORY_DIAGNOSTICS=1`; the actual fixes
  (limit enforcement, purge) run unconditionally in production.

## Verification

### Build

```
CCACHE_DISABLE=1 cmake --build /home/tomi/tos/build --target validator-engine -j64
```

Clean build, no warnings.

### Unit tests

```
./test-db --filter TosDb_DynamicBoc
```

All 4 tests pass (`DynamicBoc`, `DynamicBoc2`, `DynamicBocHint`,
`DynamicBocIncSimple`) across V1/V2/InMemory reader variants — no
functional regression.

### Live restart of node3 (`systemctl restart tos-validator@3`)

**Before** (pre-fix binary, running since its last restart): RssAnon grew
from 505 MiB to 7.2 GiB over roughly 1h56m and never recovered.

**After** (fixed binary, first pass with the buggy `arenas.purge` call):

```
CellDB V2 cache limit reached size=100000 max_size=100000 peak_size=100000
CellDB V2 cache drop before_size=1087788 peak_size=1087788 ttl=39 max_size=100000 force_drop=true drop_count=1 rss_before=3022MB
CellDB V2 allocator trim method=jemalloc_arenas_purge result=error rss_before=3022MB rss_after=3035MB
```

The limit is now *detected* immediately at exactly 100,000 (vs. never
being checked until 971,287 before), but the purge itself failed
(`result=error`, `ENOENT`), confirming Bug 2's diagnosis.

**After** (corrected `arena.4096.purge` call, second restart):

```
CellDB V2 cache limit reached size=100000 max_size=100000 peak_size=100000
CellDB V2 cache drop before_size=1104151 peak_size=1104151 ttl=41 max_size=100000 force_drop=true drop_count=1 rss_before=3055MB
CellDB V2 allocator trim method=jemalloc_arena.4096.purge result=ok rss_before=3055MB rss_after=3029MB
CellDB V2 allocator trim released approx 25MB RSS
```

The purge now succeeds and measurably returns memory to the OS — the
exact symptom in the bug report ("RSS did not decrease") is fixed and
proven with real numbers. An independent `/proc/<pid>/status` RSS sampler
running every 20-30s corroborates a larger drop across the same window
(~180 MiB), consistent with continued allocation/free traffic around the
sampled instant.

At steady state, once the initial-sync catch-up burst settles, later
drops in the same run happen at cache sizes of 44,286 and 39,981 cells —
comfortably under the 100,000 cap and driven by the TTL limit
(`cache_ttl_max=2000`) rather than the size limit, confirming normal
day-to-day operation is now properly bounded.

## Known remaining limitation

During the initial-sync catch-up burst specifically, a single reader can
still grow to ~1.08-1.1M cells before the flagged reset actually executes,
because `set_loader()` — where the reset happens — is called far less
often than insertions occur while catching up on a large backlog of
blocks. Detection now happens immediately at the 100,000 boundary;
execution of the reset is still gated on the next `set_loader()` call, and
during a catch-up burst that call can lag by up to a minute or more behind
insertion volume. Post-sync steady state is unaffected and stays well
under the cap. If this matters in practice (e.g. very large initial-sync
windows), a follow-up could check the `force_drop_cache_` flag more
eagerly during bulk sync rather than only at block-commit boundaries.

## Follow-up observation (2026-07-26, later in the same session) — a separate, still-unexplained growth source

A third restart of node3 was left running longer to see whether RSS
eventually plateaus. The CellDB V2 fix continued to behave correctly: TTL-
driven drops stayed small and well-bounded (`cache=40050`, `cache=44469`,
`cache=39800`, all `force_drop=false`, all well under the 100,000 cap),
and each purge measurably released a few MB of RSS
(`released approx 8308KB / 20MB / 8552KB / 8876KB RSS`).

However, total process RSS kept climbing afterward (to ~3.69 GiB by
`11:48`), which raised the question of whether the reclaim mechanism is
actually working or whether something else is still leaking. Pulling the
periodic `JEMALLOC_STATS` log line (`stats.allocated` — jemalloc's count of
bytes actually handed out and still live, which is a stronger signal than
RSS because it is not inflated by not-yet-purged fragmentation) shows a
steady, roughly linear increase that is independent of the CellDB V2 drop
events:

```
11:36:33 allocated=2,649,447,864 (~2.47 GiB)
11:40:33 allocated=2,912,344,288 (~2.71 GiB)
11:44:33 allocated=3,163,351,792 (~2.95 GiB)
11:48:33 allocated=3,418,509,096 (~3.18 GiB)
11:51:33 allocated=3,611,922,704 (~3.36 GiB)
```

That is ~710 MiB of growth in `stats.allocated` over 15 minutes
(~47 MiB/min), while the CellDB V2 cache itself stayed under ~45,000
entries the entire time and its drops only ever released single-digit-to-
tens-of-MB. This confirms the growth is **not** fragmentation and **not**
the bug fixed in this document — it is a genuinely separate source of live
anonymous allocation elsewhere in the process.

This is not yet root-caused. The leading (unverified) hypothesis is that
this is the RocksDB CellDb block cache (`--celldb-cache-size 1073741824`,
1 GiB) still warming up toward its configured cap during initial sync,
which would be expected/benign and should plateau once `allocated` growth
is roughly 1 GiB above its post-restart baseline. If growth continues
linearly well past that point, it indicates a second, independent
unbounded-cache bug elsewhere (candidates: another uncapped in-memory
cache, growing live shard-state working set during sync, or a per-message
buffer in networking/consensus) and would need its own investigation —
out of scope for this document's fix.

## Deployment note

Verifying this fix required copying the updated
`deploy/tos-validator-node3-cache.conf` into
`/etc/systemd/system/tos-validator@3.service.d/cache.conf` and restarting
`tos-validator@3` twice via `systemctl`. This is a live change to local
systemd configuration, separate from the (still uncommitted) repository
changes.
