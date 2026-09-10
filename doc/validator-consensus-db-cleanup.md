# Validator-group consensus-DB cleanup (Finding 1) — checkpoint-relative design

## Status

Design / plan. Tracks **Finding 1**: the validator-group consensus-DB crash
orphan that the observer-only cleanup queue (PR #90) deliberately did **not**
touch. This is a separate PR track from #90.

Scoreboard this design closes:

| Item | Status |
|---|---|
| Observer consensus-DB crash orphan | fixed by #90 |
| Validator-group consensus-DB crash orphan | this design (Finding 1) |

## Why the observer queue must not simply be widened to validators

The observer queue authorizes deletion by a single fact: *this exact directory
name is in the durable pending set*. For observers that is safe — an observer DB
holds no votes, so a premature deletion is at worst a harmless re-sync. For a
validator it is a safety hazard, because a validator DB holds own-votes and
leader-window recovery state. Widening the observer queue to validators
reintroduces the danger Codex caught:

```
old validator session retired
  -> DB delete fails
  -> dir name stays permanently in the queue
  -> session later legitimately reappears (recreatable)
  -> queue still authorizes deletion
  -> a live-again validator's consensus DB is destroyed
```

The root defect is not the delete itself. It is that the **durable record of
delete authority outlives the proof that the session can never be live again.**
So the fix is not "another queue"; it is to split two concerns that
`destroyed_validator_sessions_` currently conflates:

- **session lifecycle fence** — "do not recreate this session" (short-lived).
- **disk-deletion authority** — "this directory may be reclaimed" (durable, and
  must be *checkpoint-bound*, not queue-bound).

## Target state model

For a validator group, persist three kinds of information instead of today's
single `destroyed_validator_sessions_` set:

1. **retired_validator_sessions**: `session_id -> retirement_checkpoint`
   — the short-lived "do not recreate" fence.
2. **pending_validator_db_cleanup**: `session_id -> { retirement_checkpoint,
   dir_name }` — the durable cleanup *intent*.
3. **current/recreatable session knowledge** — derived from the current
   init/masterchain checkpoint at startup, not persisted separately.

The central invariant:

> Cleanup authority is not "this session was once destroyed". It is "this
> session was definitively retired at checkpoint C, **and** the node's durable
> state has advanced to a checkpoint past which it can never legally be
> recreated." Deletion authority is bound to a checkpoint.

## Deletion eligibility

A cleanup record authorizes deletion only when **both** hold:

```
record.retirement_checkpoint <= durable_safe_cleanup_checkpoint
AND
session_id is not currently live/recreatable
```

The first is the real, durable safety basis. The second is defense-in-depth
(the group map may not be fully reconstructed yet at startup, so it cannot be
the primary basis).

```cpp
can_delete_validator_db(record) =
    record.retirement_checkpoint <= cleanup_safe_checkpoint
    && !current_validator_sessions.contains(record.session_id);
```

## Persistence: structured per-record, checkpoint as BlockIdExt

Do not reuse the newline-joined string queue for validators. Use a structured
record keyed per session so deletion, recovery, and reconciliation are atomic
and need no whole-table rewrite:

```cpp
struct PendingValidatorConsensusDbCleanup {
    ValidatorSessionId session_id;
    BlockIdExt         retirement_checkpoint;  // NOT just a seqno
    std::string        dir_name;
};
```

The checkpoint is a full `BlockIdExt`, not a bare seqno: a seqno cannot
distinguish a fork / hardfork / alternate block identity (same reasoning as the
incomplete-block marker). Per-record key:

```
key:   tos.state.pending_validator_consensus_db_cleanup | session_id
value: retirement_checkpoint (BlockIdExt) | exact_dir_name
```

Persisted via the existing StateDb WAL-synced WriteBatch path.

## Retirement flow — four phases (persist intent before destroy)

Today `update_shards()` does `destroyed_validator_sessions_.insert(id)` and the
eventual `updated_init_block()` erases it, then the actor is destroyed and the
DB removed — the authority record can vanish before the delete completes.

New flow:

**Phase A — determine retirement.** When `update_shards()` decides a validator
group is no longer needed, build the record:

```cpp
PendingValidatorConsensusDbCleanup record{
    .session_id            = id,
    .retirement_checkpoint = last_masterchain_block_id_,
    .dir_name              = exact_consensus_dir,  // via consensus_db_dir_name(...)
};
```

Do **not** delete the DB yet.

**Phase B — persist cleanup intent first.** One atomic StateDb write of
{retirement state + pending cleanup record + checkpoint relation}. Only after
that write's fsync success may the actor be destroyed:

```
persist cleanup intent -> fsync success -> destroy validator actor -> delete consensus DB
```

Crash after persist => restart still has the record => delete authority is
re-derivable => no orphan.

**Phase C — become eligible.** A record becomes `DELETE_ELIGIBLE` when
`durable_safe_cleanup_checkpoint >= record.retirement_checkpoint` and the
session is not live (see eligibility above).

**Phase D — confirmed delete + dequeue.** `RocksDb::destroy` + `rmrf`, then the
record is removed **only** after the directory is confirmed gone by `stat`
(`ENOENT` on POSIX; `ERROR_FILE_NOT_FOUND`/`ERROR_PATH_NOT_FOUND` on Windows)
and the dequeue is persisted.

## durable_safe_cleanup_checkpoint

Meaning: the node has durably advanced to this checkpoint, and any old validator
session whose `retirement_checkpoint <= it` can never again be legally created.

```
retirement_checkpoint = MC block N
when the durable init/masterchain checkpoint has advanced to N
and session selection based on N has stably completed
  -> the cleanup record becomes eligible
```

This is the property the fix must actually *prove* — it is the same ordering
gap Codex flagged against v4: a checkpoint write ack is not proof the block was
durably applied, so the safe checkpoint must be derived from state that is
durable before any prune becomes durable. The safe checkpoint must be
**monotonic** (it must not regress when an older init block is loaded), mirroring
the wc0 watermark approach.

## Decoupled pruning (the core of checkpoint-relative cleanup)

`updated_init_block()` today erases the whole captured old destroyed set. It
must become a checkpoint-relative prune of the **session fence only**:

```cpp
for (sid : old_destroyed) {
    if (validator_session_retirement_is_checkpoint_safe(sid, new_init_block)) {
        destroyed_validator_sessions_.erase(sid);   // fence may be pruned
    }
}
```

But the corresponding **cleanup record must NOT be removed because the tombstone
was pruned.** A cleanup record is removed only after the filesystem confirms the
directory is gone and the dequeue is persisted.

> Tombstone (fence) pruning and cleanup-authority pruning are decoupled. Pruning
> the fence must never also drop the delete authority.

## Per-record lifecycle

```
ACTIVE
  | session retired at checkpoint C
  v
RETIREMENT_PENDING
  | durable persist: session_id + dir + C
  v
CLEANUP_PENDING
  | safe_cleanup_checkpoint >= C  AND  session not live
  v
DELETE_ELIGIBLE
  | destroy RocksDB + rmrf
  v
DELETE_ATTEMPTED
  |-- stat == ENOENT -> CLEANUP_DONE -> persist dequeue -> removed
  |-- exists / EACCES / EIO -> stay CLEANUP_PENDING -> retry next startup/sweep
```

Session lifecycle and filesystem cleanup lifecycle are no longer the same set.

## Startup ordering (strict)

```
1. load current init/masterchain checkpoint
2. load destroyed/retired session metadata
3. load pending validator cleanup records
4. reconstruct sessions that may legally be live
5. compute durable_safe_cleanup_checkpoint
6. only then sweep validator DBs
7. start/create validator groups
```

Never: load queue -> see dir -> delete. Steps 4 and 5 must complete before any
validator sweep. Sweep should precede group creation but must not precede the
eligibility computation.

## Pre-delete exact-directory re-validation (stricter than observers)

Even though the record stores `dir_name`, the sweep re-parses and requires:

```
parsed = consensus_db_parse(dir_name)
parsed.session_id == record.session_id
parsed has NO ".observer." suffix
dir_name == consensus_db_dir_name(parsed.shard, parsed.cc_seqno, record.session_id, expected_suffix)
dir is a direct child of consensus_db_root   // bad metadata cannot become arbitrary-path deletion
```

## Recreated-session safety (runtime defense)

Before deleting, also check the live group maps:

```cpp
if (validator_groups_.contains(record.session_id) ||
    next_validator_groups_.contains(record.session_id)) {
    LOG(ERROR) << "refusing cleanup of live/recreatable validator session";
    keep record; continue;
}
```

This is runtime defense only; the durable safety basis remains
`record.retirement_checkpoint <= safe_checkpoint`, because at restart the group
maps may not yet be fully built.

## `destroyed_validator_sessions_` migration (staged, not removed at once)

Keep `destroyed_validator_sessions_` as the short-term "do not recreate" fence;
introduce `pending_validator_cleanup_` as the durable delete intent. Only change
`updated_init_block()` to prune the fence checkpoint-relatively (above), and
never drop a cleanup record merely because its fence was pruned.

## Two-PR split

**PR A — persistent state machine only, deletion authority NOT widened.**
`PendingValidatorConsensusDbCleanup` record + checkpoint fields, persistence
APIs, startup loading, `durable_safe_cleanup_checkpoint` computation, and tests.
Validator sweep still behaves exactly as #72 (no new deletions). This proves the
checkpoint state machine does not perturb validator creation/rotation.

**PR B — enable validator cleanup.** Enqueue-before-destroy retirement, startup
eligible sweep, runtime confirmed dequeue, and the full fault-injection matrix.

This avoids changing `update_shards` + `updated_init_block` + startup + StateDb +
bridge destroy + sweep all at once.

## Fault-injection test matrix (hard acceptance — not helper-only)

| Case | Crash point | Expected |
|---|---|---|
| 1 | retirement determined, CRASH before queue persist | old group not yet destroyed; DB safe |
| 2 | cleanup record persisted, CRASH before actor destroy | restart sees record; if session may be live, no misdelete |
| 3 | actor destroyed, CRASH before rmrf | restart -> eligible -> delete |
| 4 | rmrf partially fails, CRASH | record remains -> retry |
| 5 | directory removed, CRASH before dequeue persist | restart -> stat ENOENT -> reconcile entry away |
| 6 | first delete fails -> tombstone later pruned -> restart -> session recreatable/live | cleanup record does NOT authorize delete unless checkpoint safety proves the session can never be live |

Case 6 is the core red/green test — the exact history Codex caught against the
queue-widening approach.

Two additional danger tests:

- **Recreated-session safety**: pending cleanup {sid=X, checkpoint=old} while
  current/recreatable has sid=X -> `deleter_called == false`.
- **Checkpoint monotonicity**: record C=100, safe checkpoint=99 -> cannot delete;
  safe checkpoint=100 -> may delete; loading an older init block must not regress
  the safe checkpoint 100 -> 98.

## Five merge blockers (hard conditions for PR B)

1. Cleanup authority must be checkpoint-bound, not directory-queue-bound.
2. The queue record must be durable before the actor is destroyed.
3. Tombstone (fence) prune and cleanup-record prune must be decoupled.
4. No live/recreatable session may ever be deleted through the queue.
5. There must be crash-boundary fault-injection tests — above all the
   "delete fail -> tombstone prune -> restart -> session recreated" history.

## One-line summary

Split `destroyed_validator_sessions_` from a mixed lifecycle+GC-authority set
into a short-term session fence; add a durable validator cleanup record carrying
a `retirement_checkpoint`; permit DB deletion only once the checkpoint proves the
session is permanently retired; and remove the record only after `ENOENT`
confirms the physical delete — so the validator-group orphan is genuinely closed
without ever trading "may leave a stale directory" for "may occasionally delete a
live validator DB".
