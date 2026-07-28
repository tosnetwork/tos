# Read-Only Review: "Bound finalized Simplex history" (535c8fd13, 2026-07-27)

## Scope

Commit `535c8fd13` replaces two unbounded-growth containers in Simplex
consensus with slot-aware, finalization-pruned equivalents:

- `SimplexDb`'s historical vote/certificate hash set
  (`validator/consensus/simplex/db.cpp`), now backed by a new
  `FinalizedSlotDedup<Value>` template
  (`validator/consensus/simplex/finalized-slot-dedup.h`).
- `SimplexPool`'s `seen_broadcasts_` set
  (`validator/consensus/simplex/pool.cpp:1027`), pruned on finalization via
  `erase(begin, upper_bound(finalized_slot))`.

This review covered the full diff, the call chains into `db.cpp`/`pool.cpp`,
the `Bus`/`Db` event and interface definitions, `votes.h`, `certificate.h/.cpp`,
and the new/updated tests. It compared behavior against the equivalent
Simplex implementation in `/home/tomi/ton-c`. Verification was strictly
read-only: existing tests were rebuilt and executed, but no code was modified,
committed, deployed, or restarted in production.

## Conclusion

**Safe to merge.** No confirmed Critical or High correctness or
consensus-safety issue was found. This conclusion is based on tracing the
actual invariants the fix depends on — not merely on the fact that the new
and existing tests pass.

## Verified-safe reasoning (not just "tests pass")

1. **Any DB scan order (hash-ordered, not slot-ordered) is safe.** Proven
   algebraically that `FinalizedSlotDedup`'s final state depends only on the
   final `finalized_through_` value and the set of distinct values ever
   inserted, not on insertion/prune interleaving order, because `insert()`
   rejects strictly by `slot <= finalized_through_` and `prune_through()`
   only removes entries with `slot <= finalized_through_`. Confirmed
   empirically: `test/validator/consensus/test-consensus.cpp`'s
   `TestDbImpl::get_by_prefix` returns entries in raw-key (hash) byte order
   via `std::map<BufferSlice, ...>` — exactly the non-slot-ordered case in
   question — and `test-consensus-simplex2-restart` (gremlin-driven restart)
   passes against it.
2. **A non-quorum "prospective" certificate cannot prematurely advance the
   high-water mark.** `handle_prospective_certificate` (pool.cpp:936)
   publishes `SaveCertificate` before this node's own tally is finalized, so
   a naive reading suggests `db.cpp`'s `init_votes()`-triggered
   `prune_through()` on a `FinalizeVote`-bearing cert could fire on an
   unverified certificate. Ruled out: `Certificate<T>::from_tl`
   (`certificate.cpp:40`) hard-rejects any signature set below
   `quorum_threshold`, so a `Certificate<Vote>` object cannot exist —
   whether received live or reconstructed during DB replay — unless it
   already met quorum.
3. **No race between in-flight persistence and finalization pruning.**
   `saved_vote_hashes_.insert()` runs synchronously to completion before the
   first `co_await` in both `process(BroadcastVote)` and
   `process(SaveCertificate)` (db.cpp:80, 102), so the dedup decision is
   atomic with respect to actor reentrancy. For the self-generated
   finalization path, `SaveCertificate` is `co_await`ed (pool.cpp:937)
   strictly before the corresponding `FinalizationObserved` publish
   (pool.cpp:1017) in the same call chain.
4. **No dangling-iterator risk in `pool.cpp`.** Neither
   `handle_typed_saved_certificate` (the `seen_broadcasts_.erase` call site,
   pool.cpp:1005-1034) nor `process(PrecheckCandidateBroadcast)`
   (pool.cpp:618-638, the only other reader/writer of `seen_broadcasts_`)
   contains a `co_await` spanning the container's iterator lifetime; the
   latter is already gated by `slot < first_nonfinalized_slot_` regardless of
   the new erase.
5. **No wire/schema change.** Only in-memory containers changed; RocksDB key
   and value formats are untouched, so old and new binaries remain
   compatible and rollback-safe.
6. **Bootstrap replay cannot lose data from dedup bookkeeping.** In
   `init_votes()`, both `our_votes` and `certs` are populated unconditionally
   regardless of `insert()`/`prune_through()` outcome (db.cpp:218, 236) — the
   dedup state only gates the anti-duplicate/anti-resubmission check, never
   the actual vote/cert data used for recovery.

## Findings

### Critical / High
None confirmed.

### Medium (potential risk, not confirmed)
1. **Finality-stall retention has no independent hard cap** —
   `finalized-slot-dedup.h:23-30`. This is not an unbounded burst within one
   slot: the records admitted for a slot are protocol-bounded. `BroadcastVote`
   stores only this node's guarded vote choices, `CertificateBundle` keeps at
   most one certificate of each vote kind, and quorum intersection prevents
   conflicting certificates under the Byzantine safety assumption. The
   remaining risk is accumulation across an increasing number of
   unfinalized slots if finality stops progressing. That is not a regression
   — the old `saved_votes` retained the same entries forever — and normal
   finalization prunes the accumulated slots.
2. **RocksDB rows are retained for the validator-group lifetime.** This
   change prunes only the in-memory `saved_vote_hashes_` and
   `seen_broadcasts_`; it does not delete individual `db_key_vote` rows.
   Those rows are not permanent, however. `Bridge::destroy_inner()`
   (`validator/consensus/bridge.cpp:516-525`) destroys the per-group RocksDB
   and removes its directory when the validator group is retired. Disk use
   can therefore grow throughout one group and reaches its operational peak
   just before rotation, but it does not accumulate indefinitely across
   normally completed group rotations. On the current local test network,
   whose group lifetime is 100,000 seconds, that still allows approximately
   27.8 hours of per-group accumulation.
3. **Test-coverage gap.** The only new test
   (`test_simplex_db_finalized_slot_dedup`, test-consensus.cpp) exercises the
   bare `FinalizedSlotDedup<int>` container in isolation, not `DbImpl`.
   Missing, specifically:
   - An assertion-bearing test that a hash-ordered DB scan recovers the
     correct `finalized_through_` (`test-consensus-simplex2-restart`
     incidentally exercises this path but only asserts finalization
     progress, not the dedup/high-water-mark invariant).
   - Duplicate/out-of-order `FinalizationObserved` delivered through the
     actual actor bus (only container-level idempotency is unit-tested).
   - Validator-group rotation / catch-up interaction with a fresh `DbImpl`
     instance's dedup state.
   - Finalize-vs-network-message interleaving within one actor tick (item 3
     above is a logical proof, not an executed test).

### Low
1. **`insert()` return-value ambiguity** (db.cpp:80-82, 102-104). `false`
   means either "duplicate" or "slot already finalized," and both call sites
   unconditionally log an "already casted"/"already saved" message even when
   the real cause is finalization. Functionally harmless — `BroadcastVote`
   publishes are `.start().detach()`'d and `SaveCertificate`'s result is
   `co_await`ed but never inspected (pool.cpp:937) — but misleading in logs.
   A tri-state (`Inserted` / `Duplicate` / `AlreadyFinalized`) would remove
   the ambiguity.
2. **`saved_vote_hash_evictions_` conflates two different counters** —
   `prune_through()`'s actual-erase count, and `init_votes()`'s
   "`insert()` returned false during replay" count (which also includes
   ordinary same-scan duplicates, not just finalized-and-pruned entries).
   Makes the periodic `MEMORY_DIAGNOSTICS ... evictions=` log line ambiguous.
3. **No `td::uint32` slot wraparound handling** in
   `finalized-slot-dedup.h`. Not realistic at current slot rates; no action
   needed beyond awareness.

## Upstream comparison (`/home/tomi/ton-c`)

Diffed both `db.cpp` and `pool.cpp` directly against ton-c's equivalents.
Upstream's `db.cpp` still uses a flat, never-pruned `std::set<Bits256>
saved_votes`, and its `pool.cpp` has no finalization-triggered erase on
`seen_broadcasts_` at all. Both unbounded-growth issues this commit fixes are
present identically upstream and are TOS-specific improvements, not
inherited-and-ignored upstream behavior. The invariants the fix depends on
(quorum check in `Certificate::from_tl`, cumulative `first_nonfinalized_slot_`
semantics) are identical between the two trees, so the safety argument above
would apply equally to upstream's unfixed code.

## Empirical validation performed

- Rebuilt `test-consensus` (`ninja test-consensus -j 128`); confirmed the
  binary (12:27:56) postdates both `db.cpp` (12:27:24) and
  `finalized-slot-dedup.h` (12:27:03), so the executed binary reflects this
  commit.
- Ran `ctest -R "simplex2" --output-on-failure -j 8`: all 16 tests passed in
  9.21s, including `test-consensus-simplex2-restart` (gremlin-driven restart
  against the hash-ordered `TestDbImpl`).
- Ran the standalone `--simplex-db-finalized-slot-dedup-unit-test` directly:
  exit code 0.

Per review instructions, none of the above test passes were treated as
sufficient proof of correctness on their own — each was paired with a
file/line-level trace of the invariant it was meant to exercise.

## Recommended follow-ups (non-blocking)

1. Add a `DbImpl`-level integration test asserting `finalized_through_`/
   `saved_vote_hashes_` state after a restart with a hash-ordered mock DB
   (not just finalization progress).
2. Add a test for duplicate/out-of-order `FinalizationObserved` delivered via
   the actor bus, not just the container directly.
3. Consider a tri-state return from `FinalizedSlotDedup::insert()` to remove
   the log ambiguity in db.cpp.
4. Consider splitting `saved_vote_hash_evictions_` into separate
   replay-rejected and prune-erased counters.
