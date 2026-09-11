# Consensus-DB Cleanup Queue (P2 / F4 follow-up)

## Problem

When a validator group is retired, its per-group consensus RocksDB directory
(`${db_root}/consensus/consensus.<wc>.<shard>.<cc>.<session_hex>...`) must be
deleted. PR #72 added a startup sweep (`sweep_destroyed_consensus_dbs`,
`manager.cpp:2349`) that, before any group starts, walks the consensus dir and
deletes directories whose parsed session id is in `destroyed_validator_sessions_`
(`manager.cpp:2371`). That closes the simple crash case.

But there is still an orphan window, because the sweep's gate set —
`destroyed_validator_sessions_` — is the **same** set used for a different
purpose with a different lifetime, and it is pruned too early:

- `destroyed_validator_sessions_` is a "do not recreate this session's group"
  set, checked at `manager.cpp:2779/2824/2889`. It is correctly pruned in
  `updated_init_block` (`manager.cpp:3064-3075`) once the init block rotates past
  those sessions — they can never be referenced again.
- The #72 sweep reuses that same set as its "which directories are orphaned"
  source. But a directory can outlive the set entry:

In the all-shards rotation path (`manager.cpp:3001-3011`), the ids destroyed
this round are added to `destroyed_validator_sessions_` in memory
(`:2956/:2992`), then:

```
update_init_masterchain_block (persist init block)
  -> P fires:
       updated_init_block(...)   // erases those ids from the set AND persists
                                 // the pruned set (:3068, :3072)
       destroy_sessions()        // async: each group deletes its dir
```

So the durable `destroyed_validator_sessions_` is written **without** the
just-destroyed ids before their directories are deleted. A crash after that
persist but before the directory deletion completes (or a crash inside
`destroy_inner`'s `RocksDb::destroy` + `rmrf`, `bridge.cpp:509-510`) leaves the
directory on disk while its id is absent from `destroyed_validator_sessions_`.
On restart the sweep does not recognize it, nothing ever recreates that group,
and the directory is a permanent orphan. (This is the window the audit called
out and PR #72 explicitly deferred.)

Root cause: **one set, two lifetimes.** "Do not recreate" must be pruned at
init-block rotation; "directory still needs deleting" must survive until the
directory is confirmed gone. They must be separate.

## Proposed fix — a separate, durable `pending_consensus_db_cleanup` queue

Add a second persisted set whose *only* job is "these session directories still
need physical deletion," with a lifetime tied to the directory, not to init
block rotation. `destroyed_validator_sessions_` and its pruning are left
unchanged.

### Durable storage (mirror `destroyedSessions`)

`destroyed_validator_sessions_` persists through
`db.state.destroyedSessions` / `db.state.key.destroyedSessions`
(`tl/generate/scheme/tos_api.tl:587,598`; `StateDb::{update,get}_destroyed_validator_sessions`,
`statedb.cpp:121-149`; `RootDb` + `Db` interface `interfaces/db.h:131-133`).

Add a parallel TL type and Db methods:

```
db.state.pendingConsensusDbCleanup sessions:(vector int256) = db.state.PendingConsensusDbCleanup;
db.state.key.pendingConsensusDbCleanup = db.state.Key;
```

- Regenerate `auto/tl` from the scheme (and the mirrored copies under
  `tosctl/.../tos_api.tl` and `test/tostester/.../tos_api.tl` if they must stay
  in lockstep — to confirm in review).
- `Db`: `update_pending_consensus_db_cleanup(vector<ValidatorSessionId>, promise)`
  and `get_pending_consensus_db_cleanup(promise)`; `RootDb` forwards to `StateDb`;
  `StateDb` implements them exactly like the destroyedSessions pair.

### Manager

- Member `std::set<ValidatorSessionId> pending_consensus_db_cleanup_;`.
- **Add-before-destroy (durable):** where a group is retired
  (`manager.cpp:2956` and `:2992`), also insert the id into
  `pending_consensus_db_cleanup_`, and **persist it before any directory is
  deleted**, in both the rotated-all-shards and the non-rotated branch. The
  persist must be ordered before `destroy_sessions()` so a crash always leaves a
  durable record for the sweep. (In the rotated path the natural place is
  alongside the existing `update_init_masterchain_block`/`updated_init_block`
  sequence; the pending-set persist does not depend on the init block and can be
  issued up front.)
- **Remove-after-confirmed-deletion:**
  - Startup: load `pending_consensus_db_cleanup_` (parallel to
    `destroyed_validator_sessions_` at `manager.cpp:2335`), then run the sweep.
  - `sweep_destroyed_consensus_dbs`: gate on `pending_consensus_db_cleanup_`
    (not `destroyed_validator_sessions_`); after a directory is **confirmed gone**
    (the existing `stat`==ENOENT check), remove that id from the set and persist.
    Also **reconcile**: any id in the set whose directory is already absent at
    startup (deleted before a crash lost the removal) is dropped and the set
    re-persisted — so the queue cannot leak across restarts.
  - New manager method `consensus_db_cleanup_done(ValidatorSessionId)`: remove
    the id from `pending_consensus_db_cleanup_` and persist. Called by the group
    once it has actually deleted its directory, so the queue is pruned during
    normal uptime too (not only at restart).

### Bridge

`BridgeImpl::destroy_inner` (`bridge.cpp:501-519`) already deletes the directory
(`RocksDb::destroy` + `rmrf`). After a successful deletion, notify the manager:
`send_closure(params_.manager, &ValidatorManagerInterface::consensus_db_cleanup_done, params_.session_id)`
(the group holds `params_.manager` and `params_.session_id`; a new method on the
manager interface). On deletion failure it does **not** notify, so the id stays
queued and the next startup sweep retries — fail-closed for cleanup.

## Why not reuse `destroyed_validator_sessions_`

Rejected: the two purposes have different, conflicting lifetimes (see root
cause). Keeping destroyed ids around until their dir is gone would either bloat
the "do not recreate" set or, if pruned at rotation, reintroduce the orphan
window. A separate queue is the reviewer-prescribed and correct separation.

## Consensus safety

The consensus DB directory and this queue are **off the consensus state tree**
(never hashed); losing or delaying a deletion only wastes disk, never changes
validation. The change adds a persist ordered before an already-async directory
deletion and a callback after it; it does not gate consensus progress on
cleanup. The add-before-destroy persist must not block the rotation critical
path longer than the existing `update_destroyed_validator_sessions` persist
already does.

## Test (fault-injection recovery)

A falsifiable test that reproduces the window: seed a `consensus/<dir>` for a
session id, record that id in the pending queue durably, do **not** delete the
directory (simulating a crash between persist and deletion), then run the
startup path and assert the directory is reclaimed and the id removed from the
queue. Reverting the sweep's gate change (back to `destroyed_validator_sessions_`)
or the add-before-destroy persist must turn it red. Also cover: reconciliation
drops an id whose dir is already gone; a deletion failure keeps the id queued.

## Codex review outcome (2026-09-10) — corrected design (v2)

Codex confirmed the problem AUTHENTIC and the approach SOUND-WITH-CHANGES, and
found two consensus-safety blockers plus several required changes. The design
below supersedes the sketch above.

1. **Retirement proof must be durable atomically with (or before) the cleanup
   record — never after.** Persisting a pending-cleanup record *before* durable
   proof the session is retired allows: persist pending `S` → crash before the
   new init checkpoint / destroyed tombstone → restart from the *old* init block
   → sweep deletes `S`'s dir (pending) → group creation *recreates* `S` (creation
   checks `destroyed_validator_sessions_`, not pending, `manager.cpp:2824`).
   Deleting a live session's consensus DB (its own votes / leader recovery,
   `simplex/db.cpp:75/114/153`) is a **safety** issue. Fix: in **one StateDb
   write batch**, persist the destroyed-session set (with the newly retired ids)
   **and** the pending-cleanup dirs, and only run `destroy_sessions()` after that
   batch is acknowledged — in **both** branches. Recreation is then barred by the
   durable destroyed set even after a restart from the old init block.
2. **One session id is not one directory.** Dir names carry a suffix
   (`db-path.h:39`): validators empty, observers `.observer.<identity>`, and a
   session can have several observer dirs (`manager.cpp:2919`), destroyed on a
   path (`manager.cpp:2944`) that bypasses the id-insertion sites. Fix: the queue
   holds **exact directory names**, not session ids; each retired group (active,
   tentative, observer) contributes its own dir name; removal is per directory,
   after that directory is confirmed gone.
3. **Reconciliation needs a complete successful inventory.** The sweep walk
   swallows its overall error (`manager.cpp:2412`); "not seen" ≠ "absent". Only
   reconcile (drop a queue entry whose dir is absent) after a fully successful
   walk. Storing dir names (not bare ids) lets reconciliation and deletion act on
   an exact path.
4. **Confirmed-absence on the live path too.** `destroy_inner` ignores `rmrf`'s
   result (`bridge.cpp:509-510`); the cleanup-done callback must `stat`-probe for
   absence (like the sweep, `manager.cpp:2389`) before dequeuing, and carry the
   exact dir name.
5. **Migration.** A fresh (empty) pending key would silently drop #72's recovery.
   On first startup after upgrade, import into the pending queue every existing
   `consensus/` directory whose parsed session id is in the loaded
   `destroyed_validator_sessions_` (and keep the destroyed-set gate as a legacy
   fallback in the sweep). Acknowledge that a dir whose id was already pruned pre
   upgrade cannot be recovered from either set.
6. **Load ordering.** Load both `destroyed_validator_sessions_` and the pending
   queue before the sweep and before `finish_start_up` (chain the two `get`s).
7. **Consensus safety wording.** The record is local StateDb metadata (off the
   state tree), but the change still touches consensus-DB deletion and startup
   latency; deletion stays async, startup sweep stays bounded.
8. **Test.** Drive the *real* retirement path (both branches) with a simulated
   crash between the atomic persist and the deletion, asserting recovery; plus
   multi-directory (validator + observer) completion, migration import, a walk
   that fails enumeration (no reconciliation), and a false-success deletion
   (rmrf ok but dir remains → stays queued). Each corresponding code mutation
   must turn its test red.

TL declarations are at `tos_api.tl:601` / `:614`; the `tosctl`/`tostester` `.tl`
copies do **not** need lockstep for C++ codegen (Rust/Python read their own).

## Implementation review outcome (2026-09-10) — scope decision

Codex reviewed the implementation and confirmed the core is sound: the manager
computes directory names that match `bridge` exactly (validator `""`, observer
`.observer.<adnl pubkey_hash>`, tentative `""`), both retire branches delete only
after the atomic `{destroyed + pending}` batch is durable, there is no
stale-snapshot overwrite race (single-threaded actor), and the raw StateDb
key/value round-trips. It also found three items; this PR is deliberately scoped
to close the orphan window it set out to fix, and documents the rest:

- **Finding 1 (P1) — full recreation invariant needs checkpoint-relative
  pruning (deferred, pre-existing).** The safety guarantee relies on the
  destroyed-session tombstone barring recreation until the directory is gone.
  But `updated_init_block` prunes the tombstone set *coarsely* (the whole set),
  and replaying an old rotation checkpoint at startup re-runs that pruning, so a
  session retired *after* the durable checkpoint can have its tombstone pruned
  during replay and then be recreated with its just-swept DB. This is a
  **pre-existing** weakness (present since the #72 sweep; not introduced here —
  #72 deletes the same directory in the same scenario), and the obvious contained
  fix (prune only this rotation's ids) breaks the set's growth bound because
  non-rotated-branch retirements are only ever pruned by the coarse whole-set
  sweep. A correct fix tracks each id's retirement block and prunes only those the
  persisted checkpoint has passed — a delicate change to consensus rotation
  logic, out of this PR's F4 orphan-window scope. **Tracked as a follow-up.** This
  PR does not make it worse than #72.
- **Finding 2 (P2) — observer premature-deletion → recreation is a harmless
  re-sync.** Observer consensus DBs hold no votes/own-state, so deleting one and
  re-syncing loses nothing consensus-relevant (Codex agrees this is not vote
  loss). The queue still tracks observer directories to prevent disk leaks;
  premature deletion under the same crash/replay window only forces a re-sync.
- **Finding 3 (P2) — legacy migration completeness depends on a successful
  enumeration.** A pre-upgrade directory recorded only by session id is migrated
  (deleted) when the startup walk reaches it; if the walk fails before reaching
  it, it is retried on a later startup as long as its tombstone survives — which
  is bounded by the same coarse-pruning caveat as Finding 1. The sweep already
  skips reconciliation on a failed/partial walk so it never drops a still-needed
  queue entry.

Net: the PR closes the intended orphan window (a crash between the durable
retirement record and the directory deletion) and is safe relative to #72; it
does not claim the full no-recreation invariant, which requires the deferred
checkpoint-relative pruning rework.

## Final design (2026-09-10) — observers-only queue (supersedes the above)

A second implementation review found the earlier "safe relative to #72" claim
too strong: a *validator* directory placed in the cleanup queue can, across a
failed-first-sweep plus the Finding-1 coarse-pruning replay plus another restart,
be deleted after its tombstone is gone but while its session is again
recreatable — deleting a live validator's consensus DB. #72 would skip that
directory (its gate required the now-absent tombstone). Because the queue's whole
benefit (surviving tombstone pruning) is also this risk, closing the *validator*
orphan window safely genuinely requires the deferred checkpoint-relative pruning
rework — it cannot be done in this PR's scope.

The PR is therefore narrowed to **observer directories only**:

- **Observers** are queued (exact directory names), persisted before the observer
  actors are destroyed, and swept/reconciled at startup. An observer consensus DB
  carries no votes or leader state, so deleting one and re-syncing loses nothing
  consensus-relevant — the queue's premature-deletion risk is harmless here. An
  observer-only session's directory is **not** covered by
  `destroyed_validator_sessions_` (only validator/tentative retirement adds a
  tombstone), so #72 cleaned it only incidentally — when the same session id also
  belonged to a destroyed validator group — and otherwise left it to leak; the
  queue closes that leak with no safety cost. On a failed sweep deletion, only an
  already-queued (observer) directory stays queued; a directory reached only via
  the legacy destroyed-session gate (a validator) is never added to the queue, so
  validator cleanup can never gain queue-based deletion authority that outlives
  its tombstone.
- **Validator / tentative** directory cleanup is left **exactly as #72**: gated on
  `destroyed_validator_sessions_`, never on the queue. This change does not alter
  their retirement/persist/delete path, so it introduces no validator-safety
  regression. Their orphan-on-tombstone-pruning window (Finding 1) is unchanged
  and remains a tracked follow-up requiring checkpoint-relative pruning.

The sweep helper (`sweep_orphaned_consensus_dbs`) still deletes a directory whose
name is queued **or** whose parsed session id is in the destroyed set; with the
manager only ever queuing observers, the queued path affects observers and the
legacy destroyed-set path reproduces #72 for validators. `retire_consensus_sessions`
(the atomic destroyed+pending batch) is removed: observers need no ordering
against the destroyed set.

## Open questions for review

1. Is a new persisted TL field the right mechanism, or should the pending queue
   piggyback on an existing structure? (I believe a separate field is correct.)
2. Must the `tosctl` and `tostester` copies of `tos_api.tl` stay in lockstep, or
   is `tl/generate/scheme/tos_api.tl` the sole source for the C++ `auto/tl`?
3. Is the `consensus_db_cleanup_done` manager-interface callback worth the extra
   surface, or is startup sweep + startup reconciliation sufficient (accepting
   that the queue is only pruned at restart during a long uptime)?
4. Any ordering hazard in issuing the pending-set persist up front in the
   rotated-all-shards branch relative to `update_init_masterchain_block`.

## Full lifecycle (v4, requested) — checkpoint-relative pruning + validator queue

The observers-only scope (v3) was chosen because queuing *validator* directories
was unsafe: the destroyed-session tombstone (which bars recreation) is pruned
*coarsely* by `updated_init_block` (it erases the whole captured set), and
replaying an old rotation checkpoint re-runs that pruning, so a validator
retired *after* the durable checkpoint could lose its tombstone during replay and
be recreated with a swept DB. This v4 fixes that root cause so the queue can
safely cover validators too, giving one complete cleanup lifecycle.

### Core fix: checkpoint-relative destroyed-session pruning

- `destroyed_validator_sessions_` changes from `std::set<ValidatorSessionId>` to
  `std::map<ValidatorSessionId, BlockSeqno>`, where the value is the **masterchain
  seqno at which the session was retired** (`last_masterchain_block_id_.seqno()`
  at the retire site, `manager.cpp:2981/3017`). Recreation checks
  (`manager.cpp:2791/2836/2901`) become key lookups — unchanged behavior.
- `updated_init_block(last_rotate_block_id)` no longer erases a captured set.
  Instead it sets `last_rotate_block_id_` and prunes exactly the ids with
  `retire_seqno <= last_rotate_block_id.seqno()`. Rationale: on restart the
  manager replays from the init block, so an id retired at or before that
  checkpoint is already absent from the replayed config and can never be
  recreated — safe to forget. An id retired *after* the checkpoint keeps its
  tombstone, so replaying an old checkpoint no longer prunes it prematurely.
  (The rotated retire branch stops passing `old_destroyed_validator_sessions`.)
- Non-rotated-branch retirements accumulate with their own `retire_seqno` and are
  pruned at the next rotation whose checkpoint seqno reaches them — the same
  bound the coarse sweep gave, but per-id and replay-safe.

### Why this makes queuing validators safe

With the tombstone lifetime now correct, a queued validator directory is only
ever deleted while EITHER its tombstone is still present (recreation barred) OR
the checkpoint has advanced past its retirement (session permanently
unreferenceable). Both are safe, so validator + tentative directories can be
added back to `pending_consensus_db_cleanup_` alongside observers, and the sweep
deletes on (queued OR legacy-tombstone) as before. The load-time observer-only
filter is removed.

### Persistence + migration

The destroyed-session record must now carry a seqno per id. To avoid a TL
schema/codegen change (as with the pending queue), store it as a raw StateDb
key/value: a list of `id_hex:seqno` lines under a new key, via new Db methods
`update/get_destroyed_validator_sessions_v2` (map form). On load: read v2 if
present; otherwise migrate the legacy `db.state.destroyedSessions` (ids only) by
assigning each `retire_seqno = last_rotate_block_id_.seqno()` loaded from the
init block (they were retired at or before the current checkpoint, so this is the
conservative safe value — they prune at the next rotation, never earlier). The
`{destroyed-with-seqnos + pending}` write is atomic again (re-add
`retire_consensus_sessions`), so a crash cannot queue a directory without the
durable tombstone that bars its recreation.

### Fault-injection recovery test (hard acceptance)

1. Retire a validator session at seqno R (atomic persist of tombstone{R} +
   queued dir), simulate a crash before deletion, restart: assert the sweep
   reclaims the directory and, because the durable checkpoint is < R, the
   tombstone is still present (recreation barred) throughout.
2. Replay an old rotation checkpoint C < R and assert `updated_init_block(C)`
   does NOT prune the tombstone for a session retired at R > C (the premature
   pruning that v3 could not prevent).
3. A rotation checkpoint that advances past R prunes the tombstone, and a queued
   dir deleted after that is safe (session unreferenceable).
Plus the existing sweep-helper cases (observer + validator), migration, failed
enumeration, false-success deletion.

### Open questions for Codex

1. Is `retire_seqno = last_masterchain_block_id_.seqno()` the correct retirement
   point, and is `prune iff retire_seqno <= last_rotate_block_id.seqno()` the
   correct, replay-safe condition — especially for retirements in non-rotated
   blocks whose seqno exceeds the last rotation checkpoint?
2. Does `last_rotate_block_id_` (the all-shards rotation checkpoint) advance such
   that "replay starts at/after it" holds on every restart path
   (`manager-init.cpp`), or must the reference be the last *applied* masterchain
   block instead?
3. Migration seqno assignment for legacy ids — is `last_rotate_block_id_.seqno()`
   safe (never prematurely prunes a legacy id that a replay could still
   reference), or should it be higher/lower?
4. Any fork/liveness risk from changing the destroyed-set model or the pruning
   timing; and is re-including validators in the queue now genuinely safe under
   the same multi-restart history that broke v3?

### Codex review outcome (v4) — DEFERRED, not safe as designed

A read-only Codex review of the v4 design against the current source returned
**"sound to implement: yes-with-changes"**, but the required changes are two
genuine safety holes, not refinements. v4 is therefore **deferred**: the shipped
scope stays observers-only (v3), and validator reclamation waits for a v5 design
that resolves the durability-ordering proof below.

**P1 — the prune reference is not a durable lower bound on replay.** Rotation
persists the init-block id and calls `updated_init_block()` on the *StateDb write
ack* (`manager.cpp:3059`, `statedb.cpp:31`), which covers only the checkpoint
write — not that the block was durably *applied* (`apply-block.cpp:263/275/309`).
After a crash, startup can fall back *below* checkpoint `C`
(`manager-init.cpp:359`), while a prune-through-`C` may already be durable. So
"a session retired at `R <= C` is permanently unreferenceable" is unproven: an
over-prune plus a queued deletion can destroy a validator DB that a later replay
recreates. A correct design must prune only against a checkpoint whose *usable
applied state* is durable before the prune becomes durable; reading `is_applied()`
in memory is not enough.

**P1 — legacy migration `retire_seqno = last_rotate_block_id_.seqno()` is wrong.**
Non-rotated retirements persist tombstones *without* advancing the init
checkpoint (`manager.cpp:3070`), so real histories have a session retired at
`R > C`. Stamping every legacy id with `C` makes it prunable at the first
checkpoint replay, before replay reaches its true retirement `R` — reintroducing
exactly the coarse-pruning failure v4 set out to fix. Legacy ids need an explicit
*unknown-retirement* treatment with a defensible upper bound, absent from v4.

**Supporting defects.** `last_rotate_block_id_` is not loaded into the manager at
startup — it is only assigned by `updated_init_block()` (`manager.hpp:293`,
`manager.cpp:2303`), so it is empty at sweep time. Deliberate rollback / hardfork
truncation can move the init checkpoint *backward* (`manager-init.cpp:400/423`,
`statedb.cpp:505`); numeric-seqno pruning does not preserve the session-expiry
invariant across a rollback or a different chain history, so a recovery policy is
required. The `CHECK(!destroyed_validator_sessions_.contains(id))` at
`manager.cpp:2791` has a real exception via the unsafe-recovery rewritten-id path
(`manager.cpp:2840/2859`) that longer tombstone retention can expose.

**Decision (2026-09-10, one week before genesis).** Ship observers-only (this
PR): it closes the observer orphan leak (the common case) and never regresses
validator safety. Full validator reclamation is deferred post-genesis to a v5
design that (a) prunes only against a checkpoint whose applied state is proven
durable, (b) gives legacy ids a bounded unknown-retirement treatment, (c) loads
the prune reference at startup, and (d) defines rollback/hardfork recovery — with
the fault-injection recovery test above (extended to the crash-before-applied and
rollback histories) as hard acceptance.
