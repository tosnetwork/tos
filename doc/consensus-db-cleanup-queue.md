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
