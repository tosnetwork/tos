# StateResolver Maps Bounded and Live-Validated; Residual Growth Open (2026-07-26)

## Status

**The two unbounded StateResolver maps are fixed and their eviction behavior
has been validated on node3. The validator's total live-allocation growth is
not fully fixed.** During a 33-minute live observation, both caches reached
their configured limits and continued evicting without a restart, crash, or
the 17–36 GiB oscillation caused by the earlier bad fix. However,
`stats.allocated` still increased by about 34 MiB/min after both state caches
were bounded. That residual growth is outside these two bounded maps and
remains open for attribution.

Related: this is the "separate, not-yet-root-caused source" flagged in
[celldb-v2-node3-rss-growth-2026-07-26.md](celldb-v2-node3-rss-growth-2026-07-26.md),
which covers the (already fixed and deployed) CellDB V2 cache-overshoot bug.
That fix is unrelated to this one and should not be touched.

## Symptom

After the CellDB V2 fix, node3's memory still grows steadily at roughly
**60 MiB/minute**, confirmed via jemalloc's `stats.allocated` (the actual
live-allocation count, not RSS/fragmentation), independent of CellDB V2
cache activity (which stays correctly bounded under ~45,000 entries at
steady state) and independent of the RocksDB block cache (confirmed via a
`rocksdb.block-cache-usage`/`-pinned-usage` diagnostic in
`validator/db/celldb.cpp`'s `flush_db_stats()` to be healthy and sitting
almost exactly at its configured 1 GiB capacity, with negligible — 96 B —
pinned usage).

Isolating the growth required a `jeprof --base` diff between two jemalloc
heap-profile dumps taken ~10 minutes apart (canceling out anything already
stable, like the full block cache). Of the ~750 MB net growth in that
window, the dominant call chain rooted in
`tos::validator::consensus::simplex::StateResolverImpl` resolving
historical chain state, reading through archived blocks
(`RootDb::get_block_data` → `ArchiveSlice::get_file` → `PackageReader`).
The growth rate tracks the consensus finalization/candidate-processing
rate, consistent with "one permanently-retained entry per resolved
candidate."

## Code location and root cause

`validator/consensus/simplex/state-resolver.cpp`, class `StateResolverImpl`:

- `std::map<ParentId, CachedState> state_cache_;` (~line 118) — caches a
  resolved historical state per parent candidate (`ParentId`).
- `std::map<CandidateId, FinalizedBlock> finalized_blocks_;` (~line 189) —
  tracks which candidates have been finalized.

Both maps are only ever erased on the **failure** path inside
`resolve_state()` (~lines 120–141) and `finalize_blocks()` (~lines 191–215).
On success — the normal case — `resolve_state()` sets
`entry.result = result.move_as_ok();` and `finalize_blocks()` sets
`state.done = true;`, but neither erases the entry. Entries accumulate for
the entire process lifetime.

`start_up()` (~lines 34–71) makes this worse on every restart: it bulk-loads
**the entire historical set** of previously-finalized blocks from the
persistent DB into `finalized_blocks_` (all marked `done = true`), so
`finalized_blocks_`'s size on a fresh restart already equals the full
lifetime count of finalized blocks the chain has ever produced.

## Attempted fix and why it was rolled back

A fix mirroring the existing finalization-frontier pruning pattern already
used by `PoolImpl::received_candidates_` in `pool.cpp` (~lines 1025–1031:
`received_candidates_.erase(begin, lower_bound(CandidateId{
first_nonfinalized_slot_, {}}))`) was implemented: on each
`FinalizationObserved` event, erase all `state_cache_`/`finalized_blocks_`
entries that are both (a) *completed* (`result.has_value()` / `done ==
true` — never an in-flight entry, since both `resolve_state()` and
`finalize_blocks()` hold a live reference into their map across a
`co_await` suspension point, and erasing an in-flight entry would leave
that suspended coroutine holding a dangling reference) and (b) strictly
before `event->id.slot + 1`.

This built cleanly, passed all 11 `test-consensus-simplex2-*` ctest
scenarios (including restart/gremlin, partition, and byzantine scenarios)
plus a manual stress run producing 100+ finalized blocks. It was deployed
to node3 (`systemctl restart tos-validator@3`).

**On live deployment it triggered a severe, previously-unseen oscillating
memory pattern**: RSS spiked to 33–36 GiB within ~10 minutes of restart
(the prior worst case, across the whole investigation, was 7.2 GiB over
~2 hours), fell back to ~7.7 GiB, then spiked again to ~17–22 GiB and
stayed there — jemalloc's own `allocated` metric (not just resident/
fragmentation) swung by double-digit GiB within single one-minute sampling
intervals. No CellDB V2 cache-drop events correlated with the worst of it
(ruling that mechanism out), and thread count stayed flat at 19 throughout
(ruling out a thread explosion). The pattern did not settle within ~15
minutes of observation.

The fix was reverted (`git restore
validator/consensus/simplex/state-resolver.cpp`, rebuild, redeploy). On the
reverted binary, node3 immediately returned to the smooth, predictable
~60 MiB/min growth pattern with no oscillation, confirmed over a 12+ minute
window — strong evidence the fix, not a coincidental heavy catch-up burst,
caused the regression.

**Leading theory**: pruning `finalized_blocks_` right up to the latest
finalized slot removes entries that `resolve_state_inner()`'s
`is_finalized(*id)` fast path (~line 168: skip straight to
`ChainState::from_manager` using just the finalized block id) depends on.
Once evicted too eagerly, resolution falls back to the slow recursive path
(`resolve_state(candidate->parent_id)`, ~line 175), which is far more
expensive — and during any catch-up/replay burst (many candidates
resolved in a short window), this can amplify into the kind of runaway,
oscillating cost observed. This theory is plausible and consistent with
the evidence but has not been independently confirmed with its own
profiling pass.

## Implemented fix

The final implementation bounds both in-memory structures without weakening
the exact finalized-candidate check:

1. `state_cache_` keeps at most 1,024 completed entries by default.
   `finalized_blocks_` keeps at most 4,096 completed entries by default.
   Both use a completed-entry LRU; in-flight entries are never added to the
   eviction index.
2. Historical finalized IDs are no longer bulk-loaded into memory during
   startup. `Db::get_latest()` performs an asynchronous exact point lookup
   through the same `KeyValueAsync` actor used for writes, so it sees both
   data present at startup and successful writes from the current process.
   This preserves `resolve_state_inner()`'s finalized fast path after an ID
   has left the in-memory LRU.
3. The original snapshot semantics of `Db::get()` and `get_by_prefix()` are
   unchanged. The live lookup is a separate API, avoiding a behavior change
   in the vote, pool-state, and candidate recovery paths.
4. The limits can be overridden for diagnostics and stress tests with
   `TOS_SIMPLEX_STATE_CACHE_MAX_ENTRIES` and
   `TOS_SIMPLEX_FINALIZED_CACHE_MAX_ENTRIES`. Invalid or zero values are
   ignored.
5. With `TOS_MEMORY_DIAGNOSTICS=1`, the resolver reports bounded cache sizes,
   eviction counts, and finalized live-DB hit/miss/skip counts at WARNING
   level, so the diagnostics remain visible on the production `-v2` setting.
6. Once a `FinalizationObserved` frontier is known, first-time resolution of
   a candidate newer than that frontier skips the historical finalized DB
   lookup. Startup/replay stays conservative until the first frontier is
   observed, and block finalization always performs the exact live lookup.

The exact DB fallback is the key difference from the rolled-back fix. An
evicted finalized ID remains exactly recognizable, so state resolution still
jumps directly to `ChainState::from_manager` instead of recursively rebuilding
the full historical parent chain.

## Correctness requirements

1. **Never erase a map element referenced by an in-flight resolver
   coroutine.** Both `resolve_state()` and `finalize_blocks()` hold a
   reference into their respective map across a `co_await` suspension
   point. `std::map` guarantees references to elements that are *not*
   erased stay valid across other insertions/erasures, but erasing an
   in-flight entry itself is undefined behavior. Any eviction must be
   gated on completion (`result.has_value()` / `done == true`).
2. **Do not infer exact finalized membership from a slot frontier.** The
   rolled-back fix lost this information and forced recursive historical
   reconstruction. The implemented fix uses an exact live DB point lookup
   after an ID leaves the bounded in-memory LRU.
3. **Keep state eviction independent of the finalization frontier.**
   Completed state entries use LRU capacity eviction, so replay timing and
   delayed `FinalizationObserved` delivery cannot erase a still-running map
   element.
4. **Must not break observer or restart-recovery behavior.**
   `should_be_spawned()` (~line 30) shows validators and observers run the
   identical `StateResolverImpl` code against the same maps, so any fix
   must not introduce an asymmetry. `start_up()`'s bulk DB reload into
   `finalized_blocks_` on every restart must be handled gracefully by
   whatever eviction policy is chosen — including the possibility of a
   large sudden reload followed immediately by heavy catch-up traffic,
   which is exactly the scenario that broke the previous attempt.
5. **Stress-test heavy catch-up, not just steady-state consensus.** This is
   now covered by `test-consensus-simplex2-state-resolver-catch-up`: cache
   limits are forced to eight entries, one validator is stopped while the
   quorum advances, and the validator must catch up after restart. The test
   also requires at least one successful live-DB recovery of an evicted
   finalized ID, rather than checking height alone.

## Validation

- `test-consensus-simplex2-state-resolver-cache-unit` covers LRU ordering,
  capacity enforcement, hits, eviction, and explicit failure removal.
- The forced-small-cache catch-up scenario finalized roughly 95 blocks on
  every node and observed four successful historical finalized-ID live-DB
  lookups in the measured run.
- The complete `test-consensus-simplex2-*` matrix passes: 13/13 tests,
  including loss, restart, partition, malicious observer, relay loop,
  adaptive Byzantine, manager-ingress adversarial, cache unit, and catch-up.
- `validator-engine` and `test-consensus` build successfully with `-j64`.

## Node3 live validation

The rebuilt binary (`sha256
1360c820fe70d9f36244a2b4dba8fc6a3ec2f99492ac0bcd010f8d03ee8128ac`)
was deployed to `tos-validator@3.service` at 14:17:36 UTC. It was observed
continuously through 14:50:51 UTC:

- PID remained `3210537`, `NRestarts=0`, service state remained
  `active/running`, thread count remained 19, and swap remained zero.
- Both state caches reached `1024/1024`. Later diagnostics showed 3,063 and
  3,065 completed-entry evictions while capacity remained exactly 1,024.
- Both finalized caches reached `4096/4096` and began evicting. The first
  live diagnostics showed 9 and 7 evictions; a later masterchain sample
  showed 520 finalized evictions while capacity remained exactly 4,096.
- The new WARNING diagnostics were visible under the node's production
  `-v2` setting.
- The recent-slot optimization was exercised (`finalized_db_skips` reached
  1,022 on the basechain resolver), while exact DB hits remained available
  for historical finalized IDs.
- CellDB V2 performed its expected initial forced drop and later TTL drops;
  every jemalloc purge reported success.
- Both consensus groups continued producing finalization certificates
  throughout the observation window.
- There was no StateResolver-related crash, assertion, OOM, restart, sharp
  multi-GiB spike, or oscillating allocation pattern.

The process as a whole did **not** reach a memory plateau. From 14:28:36 to
14:50:36, after state-cache eviction was active, jemalloc
`stats.allocated` rose from 3,159,452,216 to 3,949,135,504 bytes: about
34.2 MiB/min. RSS showed a similar smooth residual slope of roughly
38.7 MiB/min. This is materially below the pre-deployment observation of
roughly 60 MiB/min, but it is not zero and must not be attributed to the now
bounded StateResolver maps without a new differential heap profile.

## Reference

Full investigation history, raw data (jeprof diffs, RSS/jemalloc time
series, before/after the rollback) is in
[celldb-v2-node3-rss-growth-2026-07-26.md](celldb-v2-node3-rss-growth-2026-07-26.md),
section "Second leak root-caused, fix attempted and then ROLLED BACK after
a live regression."
