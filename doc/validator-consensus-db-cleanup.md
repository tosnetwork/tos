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
record.retirement_checkpoint is the safe checkpoint, OR a VERIFIED ANCESTOR of
    it on the accepted masterchain
AND
session_id is not currently live/recreatable
```

The first is the real, durable safety basis. The second is defense-in-depth
(the group map may not be fully reconstructed yet at startup, so it cannot be
the primary basis).

**The comparison is ancestry, not `<=`.** `BlockIdExt::operator<` is a
structural/lexicographic ordering that includes hashes (`tos/tos-types.h:280`),
not chain ancestry. Using `<=` on it is wrong. Eligibility must mean
`retirement == safe` or `retirement` is a verified ancestor of `safe` on the
accepted masterchain; **unknown ancestry or a different branch must fail
closed** (retain, do not delete).

```cpp
can_delete_validator_db(record) =
    is_ancestor_or_equal(record.retirement_checkpoint, cleanup_safe_checkpoint)
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
`record.retirement_checkpoint` is a verified ancestor of (or equal to)
`durable_safe_cleanup_checkpoint` and the session is not live (see the
ancestry-based eligibility above — not a `<=` on `BlockIdExt`).

**Phase D — confirmed delete + dequeue.** `RocksDb::destroy` + `rmrf`, then the
record is removed **only** after the directory is confirmed gone by `stat`
(`ENOENT` on POSIX; `ERROR_FILE_NOT_FOUND`/`ERROR_PATH_NOT_FOUND` on Windows)
and the dequeue is persisted.

## durable_safe_cleanup_checkpoint

Meaning: the node has durably advanced to this checkpoint, and any old validator
session whose `retirement_checkpoint` is an ancestor of (or equal to) it can
never again be legally created. See amendment 1 below for the concrete durable
signal and the application-durability-vs-replay-floor distinction.

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

**PR A — persistent state machine only, strictly observational (shadow state).**
`PendingValidatorConsensusDbCleanup` record + checkpoint fields, persistence
APIs, startup loading, `durable_safe_cleanup_checkpoint` computation, and tests.
The split is only real if PR A changes **nothing** that validator behavior
depends on: **no change to fence (`destroyed_validator_sessions_`) contents or
pruning, to session selection, to destroy scheduling, or to sweep inputs.** The
fence is consulted at group creation (`manager.cpp:2824/2889`) and is itself the
deletion authority in the existing sweep (`manager.cpp:2370`), so the fence-prune
change (below) is **deferred to PR B**, not PR A. The new records/checkpoint are
shadow state that baseline code never reads. Baseline validator decisions are
left unchanged (this preserves baseline behavior; it does not by itself prove the
baseline is fully safe — and "byte-for-byte" is not claimed, since PR A adds real
persistence and asynchronous work).

**PR B — enable validator cleanup.** Enqueue-before-destroy retirement, startup
eligible sweep, runtime confirmed dequeue, and the full fault-injection matrix.

This avoids changing `update_shards` + `updated_init_block` + startup + StateDb +
bridge destroy + sweep all at once.

### Delivered / remaining (status)

**PR A delivered (observational, not merged pre-genesis):**

- *Increment 1 — safety core* (`validator/consensus/validator-cleanup.h`): the
  record type; a versioned, architecture-independent codec that fails closed on
  malformed/observer/non-canonical/session-mismatch/non-masterchain input; the
  pure ancestry-based `can_delete_validator_db` predicate; and the monotonic
  `should_adopt_safe_checkpoint` guard. Falsifiable unit tests, guards
  mutation-verified.
- *Increment 2 — persistence + shadow load* (`validator-cleanup-store.h`,
  StateDb/RootDb/`Db`, `ValidatorManager`): per-session durable records with a
  bracketed prefix-scan and decode-skip; a fire-and-forget startup load into the
  shadow `pending_validator_db_cleanup_` that no retirement/sweep/selection/
  destroy/deletion path consults. Real-RocksDb round-trip tests over the same
  production store/erase/load functions, bounds and write/erase mutation-verified.

**Deferred to PR B (post-genesis):** the `durable_safe_cleanup_checkpoint`
derivation (amendment 1: post-`set_applied` handle-flush signal + replay anchor +
rollback-floor policy), the concrete ancestry oracle wired to real chain state
(amendment 2), and the **side-effect-free selection-only pass** computing the
current+next recreatable session set (amendment 4). These were originally sketched
as PR A items, but each is consumed only by deletion and requires the same deep
consensus-selection / chain-ancestry integration as PR B; building them as inert
shadow state pre-genesis would risk a subtle divergence from the live selection
logic for no current behavioral benefit. They move to PR B, where their output is
actually used and can be exercised by the fault-injection matrix.

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

## PR B integration boundaries (from the PR A review — not reusable as-is)

These note where PR A's base components cannot simply be wired together when PR B
activates deletion:

1. **The store helper cannot nest inside a combined retirement transaction.**
   `store_validator_cleanup_record` runs its own `begin_write_batch` /
   `commit_write_batch`, and `RocksDb::begin_write_batch` creates a fresh batch
   without protecting one already open. So PR B must NOT do
   `outer begin -> write fence -> store_validator_cleanup_record() -> outer commit`
   (that can reset the outer batch). Provide a single StateDb retirement operation
   that writes {fence + cleanup record + checkpoint relation} in one batch, or
   split "add to an existing batch" from "standalone synced write" as two explicit
   APIs. (No current nesting exists; StateDb calls the helper standalone, so this
   is not a PR A regression.)

2. **Full-load is not a bounded-queue proof.** The loader reads all valid records
   into a vector and the manager holds them in a resident map, so startup memory
   grows with the backlog. There are no production enqueue callers yet, so this is
   not a live leak. When PR B enables enqueue, cover a long-running
   delete-failure backlog and consider chunked scanning, a per-record size bound,
   and queue metrics — but memory must NOT be bounded by dropping cleanup records
   (that turns a backlog back into unrecoverable orphan directories).

## One-line summary

Split `destroyed_validator_sessions_` from a mixed lifecycle+GC-authority set
into a short-term session fence; add a durable validator cleanup record carrying
a `retirement_checkpoint`; permit DB deletion only once the checkpoint proves the
session is permanently retired; and remove the record only after `ENOENT`
confirms the physical delete — so the validator-group orphan is genuinely closed
without ever trading "may leave a stale directory" for "may occasionally delete a
live validator DB".

## Codex directional review outcome (v5) — binding amendments before PR A

A read-only Codex review against source returned **"sound to implement:
yes-with-changes"**. The split architecture is correct; the following six
amendments are binding and must be reflected in the code (and tests) before PR A
is considered done. Inline sections above already carry the two most load-bearing
corrections (ancestry comparison; PR A = shadow state).

**1. `durable_safe_cleanup_checkpoint` needs a concrete durable protocol, not a
property statement.** The usable durable signal is the **post-`set_applied()`
handle flush that persists `dbf_applied` for the exact masterchain block id**
(`apply-block.cpp:309`); the archive serializes the handle and acknowledges after
a `sync=true` transaction commit (`archive-slice.cpp:343`, `RocksDb.cpp:549`).
`is_applied()` on an in-memory handle is **not** sufficient, and `applied_stored()`
is not a separately persisted flag (`block-handle.cpp:34`, `archive-slice.cpp:469`).
But application durability is **not** the same as "where startup resumes":
startup loads the persisted init pointer and walks backward across unapplied
handles (`manager-init.cpp:334/359`). So the protocol must be: (a) durable
application of checkpoint C, (b) a durable replay anchor at C or a proven
descendant, (c) rollback enforcement below the authorized floor. Do **not** await
application inside a path that withholds `new_block`'s acknowledgement (that would
wait on application which itself needs that acknowledgement).

**2. Fork/rollback: ancestry + an enforceable rollback floor.** Eligibility is
ancestry (amendment above), failing closed on unknown/foreign branches. Startup
can truncate for a hardfork or explicit request (`manager-init.cpp:400/423`) and
StateDb rewrites the init pointer backward (`statedb.cpp:448`). A monotonic
watermark alone cannot restore a DB already deleted at safe=100 if startup then
resumes at 98. Pick one policy: (a) an enforced durable cleanup/replay floor that
**rejects incompatible rollback before validation resumes**; or (b) a
conservative existing boundary — the **persisted GC checkpoint** — with
durable-applied + ancestry validation (hardfork startup requires its predecessor
at/above GC, `manager-init.cpp:411`; StateDb truncation checks GC is not above the
target, `statedb.cpp:430`). Policy (b) sacrifices cleanup latency but reuses a
proven boundary; it is **not** equivalent to taking the max init checkpoint.

**3. Separate stop/close from delete (PR B).** The manager already releases actor
ownership into a retained list and sends `destroy` only from persistence
callbacks (`manager.cpp:2951/2995`; synced batch ack `statedb.cpp:121`,
`RocksDb.cpp:558`), so persist-before-destroy is achievable without blocking
`update_shards()`. **But `destroy()` unconditionally stops the bus, closes the DB,
waits for actors, and then removes the directory** with no eligibility check or
completion ack (`bridge.cpp:334/501`). Literal `persist -> destroy -> delete`
would therefore delete before Phase C whenever the safe checkpoint lags
retirement. Required: a **stop/close-without-delete** operation, then
eligibility-controlled deletion with a confirmed-completion ack back to the
manager. Track retiring/stopping actors as owners until closure completes —
**absence from `validator_groups_`/`next_validator_groups_` does not prove the DB
is closed** (entries disappear before the async stop completes). The rotated
callback sends `updated_init_block` and actor-destroy to different actors and
awaits neither (`manager.cpp:3003`); the protocol must not infer cross-actor
completion from those sends.

**4. Startup needs a side-effect-free selection-only pass.** Groups do not
precede the current sweep — order is recovered-state -> tombstones -> sweep ->
`finish_start_up` -> `new_masterchain_block` -> `update_shards`
(`manager.cpp:2303/2343/2421`). But creation and selection are interleaved inside
`update_shards()` (`manager.cpp:2784` create, `2865` start), so populated group
maps cannot supply the "live/recreatable" set at sweep time. Extract a
**side-effect-free computation of potentially recreatable current AND next
session ids** and await metadata/eligibility before the sweep. Do **not** treat
sessions omitted by the tombstone filter as proven non-recreatable, and an empty
map from validation gating or unavailable local keys is **not** permanent
retirement proof (`manager.cpp:2806/2880/3521`).

**5. PR A must be strictly observational.** (Captured inline in the two-PR split
section.) No change to fence contents/pruning, selection, destroy scheduling, or
sweep inputs; the fence-prune rewrite moves to PR B. The fence is read at creation
(`manager.cpp:2824/2889`) and is the deletion authority in the existing sweep
(`manager.cpp:2370`), and current pruning erases the captured set
(`manager.cpp:3064`); retaining fences longer would both suppress recreation and
widen what the unchanged sweep deletes — so none of that may move in PR A.

**6. Non-rotated retention + record-driven reconciliation.** The non-rotated path
persists tombstones without advancing init (`manager.cpp:3012`), so for retirement
R>C with the floor stuck at C the record must stay **ineligible** (conditional
liveness: retain until a verified replay/rollback floor passes R; retry when it
advances). Do **not** assign retirement=C, and do **not** promote safe to the
latest applied R while startup still selects C — either substitutes premature
deletion for retention. Reconcile by **iterating records**, not only existing
directories: a crash after removal but before dequeue leaves an absent-directory
record that a directory walk (`manager.cpp:2362`) would never discover.

### Acceptance split (PR A delivered vs PR B required)

The amendments above were written when the selection-only pass and checkpoint
derivation were still scoped into PR A; they have since moved to PR B (see
"Delivered / remaining" under the two-PR split). To avoid any misreading that
PR A delivers the full state machine, the acceptance is split here:

**PR A (delivered, observational):** the ancestry-based fail-closed predicate and
the monotonic safe-checkpoint guard as pure functions; the masterchain/full
checkpoint requirement; the canonical-directory codec; durable per-session
persistence and the shadow startup load; the key/value session-id binding on
load. All new state observational — no change to fence contents/pruning,
selection, destroy scheduling, or sweep inputs. Covered by falsifiable unit and
real-RocksDb tests.

**PR B (required before deletion is enabled):** name the post-applied
handle-flush acknowledgement as the durable-applied signal and build the
`durable_safe_cleanup_checkpoint` derivation; supply the concrete ancestry oracle
wired to real chain state; **choose and implement the enforceable rollback-floor
policy (2a or 2b) — an unrevertable boundary, not merely a monotonic variable**;
implement the side-effect-free current+next recreatable-session reconstruction
without using tombstones as proof; define non-rotated retention/progress and
record-driven (not directory-driven) reconciliation; and the persist-before-
destroy + stop/close-without-delete flow. Tests must exercise backward init,
alternate branches, application-flush crashes, and delayed actor shutdown — the
crash fault-injection matrix above — not merely helper predicates.

---

# PR B — enabling validator cleanup (finalized design)

PR B turns the observational PR A state into a real, safe deletion state machine.
It is **not** one big `manager.cpp` change; it lands around four components and is
itself split into **B1 (lifecycle plumbing, no delete)** and **B2 (eligibility +
deletion)**. The chosen safety floor is the **persisted GC checkpoint**, reused as
the rollback/cleanup boundary rather than a new "never-regress watermark".

## Safety rule (all four required to delete)

```
A. cleanup record is durably persisted
B. retirement_checkpoint is an ancestor of (or equal to) the safe checkpoint
C. session is NOT in the current/next recreatable set
D. the owning actor has stopped and its DB is closed
```

Any condition unknown => DO NOT DELETE. The bias is explicit: **when in doubt,
leak a directory; never risk deleting live validator consensus state.**

## Safe checkpoint = persisted GC checkpoint

Not `latest_applied_masterchain_block` ("applied" does not prove startup can
never fall back before it). The danger is: delete at 100 -> restart rolls back to
98 -> the session at 98 can legally reappear -> its DB is gone. So the cleanup
floor must be bound to a boundary the node will never go back before. The existing
`gc_masterchain_block` is exactly that boundary (hardfork startup requires its
predecessor at/above GC, `manager-init.cpp:411`; StateDb truncation refuses to go
above... i.e. cannot truncate below GC, `statedb.cpp:430`). Definition:

```
durable_safe_cleanup_checkpoint_ = gc_masterchain_block_id   // once durable
can_delete = ancestor_or_equal(retirement_checkpoint, gc_checkpoint)
          && !recreatable_sessions.contains(session_id)
          && db_is_closed
```

Slower reclamation (a few epochs) is acceptable; one mis-delete is not.

## Retirement flow (B1)

```
validator session should retire
  -> build cleanup record
  -> ONE atomic durable retirement write {fence + cleanup record}
  -> fsync ok
  -> stop/close actor, but DO NOT delete the DB
  -> enter pending cleanup
  (B2:) -> wait for safe floor -> eligible -> filesystem delete
        -> ENOENT confirmed -> erase cleanup record
```

i.e. `persist -> close -> (wait until eligible) -> delete`, never
`persist -> destroy() -> destroy() auto-deletes`.

## Component 1 — atomic retirement persist (B1)

New StateDb API writing the fence and the cleanup record in ONE synced batch, so
"actor may begin retiring" implies "cleanup intent is already durable":

```cpp
void persist_validator_retirement(std::vector<ValidatorSessionId> destroyed_sessions,
                                  consensus::PendingValidatorConsensusDbCleanup record,
                                  td::Promise<td::Unit> promise);
// begin_write_batch(); set destroyed_sessions; set validator_cleanup_record; commit(sync)
```

This replaces the two-independent-commit sequence and avoids PR A's single-record
helper being nested inside an outer batch (see "PR B integration boundaries").

## Component 2 — split BridgeImpl::destroy() (B1)

`destroy()` currently stops the bus, waits actors, closes the DB, AND `rmrf`s the
dir. Split into:

- **close_for_retirement()** (a.k.a. retire-without-delete): stop bus -> wait
  child actors -> close DbImpl -> `manager` callback
  `consensus_db_closed(session_id, dir_name)` -> actor may exit. **No delete.**
- **physical delete lives in the manager / a cleanup helper, not the old actor:**
  `delete_validator_consensus_db(record)` => `RocksDb::destroy(dir/db)` + `rmrf`
  + `stat`, success only on ENOENT / ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND.

Validator actor lifetime and filesystem cleanup become fully independent.

## Component 3 — manager state (B1 introduces, B2 consumes)

```cpp
std::map<ValidatorSessionId, PendingValidatorConsensusDbCleanup> pending_validator_db_cleanup_; // PR A
std::set<ValidatorSessionId> recreatable_validator_sessions_;        // current+next that may be created
std::set<ValidatorSessionId> closed_retiring_validator_sessions_;    // actor closed, no longer holds DB
```

Delete only when: `pending && !recreatable && (closed || startup-no-owner) &&
checkpoint_safe(record)`.

## Component 4 — recreatable set computed independently (B2)

Must NOT be `validator_groups_.contains(sid) || next_validator_groups_.contains(sid)`
(those maps may be empty at startup sweep time). Extract a **pure selection
helper** from `update_shards()`:

```cpp
RecreatableValidatorSessions compute_recreatable_sessions(
    masterchain_state, current_validator_set, next_validator_set,
    local_validator_keys, consensus_config);   // no actor create / no mutation / no messages
```

`update_shards()` then reuses the same helper, so startup safety logic cannot
drift from production selection. A tombstone-filtered-out session is NOT proven
non-recreatable; an empty map from gating/missing keys is NOT retirement proof.

## Tombstone vs cleanup record (decoupled)

`destroyed_validator_sessions_` stays as the short-term do-not-recreate fence and
may be pruned checkpoint-relatively, but the cleanup record is erased ONLY after
the filesystem is confirmed gone — never because the fence was pruned.

## Startup order (B2)

```
recovered MC state -> persisted GC checkpoint -> destroyed-session fences
-> validator cleanup records -> compute recreatable current+next IDs
-> validate every cleanup record -> eligibility from GC ancestry
-> sweep eligible validator dirs -> reconcile ENOENT records
-> finish_start_up -> update_shards creates groups
```

A startup dir with no actor owner may be treated as closed, but only after the
recreatable-set and checkpoint-eligibility checks.

## Ancestry oracle (B2)

Async, not seqno-based; reuse any existing manager-init/block-handle traversal:

```
equal -> Ancestor-equal
ancestor.seqno > descendant.seqno -> NotAncestor
walk prev-masterchain from descendant to ancestor.seqno:
    exact BlockIdExt match -> Ancestor ; mismatch -> NotAncestor
handle unavailable / DB error -> Unknown (FAIL CLOSED)
```

## Pre-delete exact-directory re-validation (B2)

Re-check before deleting even though decode already validated: canonical name for
the session, no `.observer.`, no `/`, no NUL, a direct child of the consensus
root. Always build the path as `consensus_db_root(db_root_) + record.dir_name`,
never trust a persisted absolute path.

## Runtime cleanup triggers (B2)

Not startup-only: (1) startup, (2) GC checkpoint advances, (3) validator actor
close completes. One entry point `try_cleanup_pending_validator_dbs()`, bounded
work per turn (e.g. 16-64 records) to avoid heavy manager turns on a big backlog
— but the budget limits WORK, it must never drop a queue record.

## Record-centric reconciliation (B2)

Iterate records, not filesystem dirs (a crash after delete but before record
erase is only visible by iterating records):

```
for each pending cleanup record:
  if not eligible: continue
  stat(exact path)
  ENOENT          -> erase durable record
  exists          -> try delete; if confirmed ENOENT -> erase record
  EACCES/EIO/...   -> keep (retry later)
```

## Deterministic fault injection (B2 test infra)

Injectable coordinator / failpoints (not random kills):

```
AfterRetirementDecision, AfterRetirementPersist, AfterActorClosed,
BeforeFilesystemDelete, AfterFilesystemDelete, BeforeRecordErase
```

covering crash before/after persist, after close, before/after delete, before
dequeue.

## Case 6 end-to-end (B2 hard acceptance)

Not a pure-predicate assert (PR A already has that). Drive the real manager
cleanup orchestration:

```
session X retired at checkpoint 100 -> cleanup record durable -> first delete
fails -> tombstone later pruned -> restart on a state where X is recreatable
-> pending record still exists -> deleter MUST NOT be called
```

It must prove the system actually feeds `recreatable = true` through the full
state assembly, not just that the predicate is correct in isolation.

## B1 / B2 split

- **B1 — lifecycle plumbing (no delete):** atomic retirement persist,
  close-without-delete, cleanup records actually produced, closed callback. DB may
  linger temporarily; nothing is ever deleted, so no mis-delete is possible.
- **B2 — eligibility + deletion:** GC floor, ancestry oracle, recreatable
  selection-only pass, startup/runtime sweep, record reconciliation, fault
  injection matrix.

## PR B acceptance (hard blockers)

| Item | Required |
|---|---|
| record durable before actor close | yes |
| retirement fence + cleanup intent atomically committed | yes |
| stop/close separated from delete | yes |
| safe floor bound to persisted GC/rollback boundary | yes |
| ancestry check is not a seqno comparison | yes |
| current+next recreatable set computed independently | yes |
| live/recreatable session never deleted | yes |
| Unknown ancestry fails closed | yes |
| cleanup record erased only after file confirmed gone | yes |
| tombstone pruning does not erase cleanup record | yes |
| Case 6 end-to-end red/green | yes |
| crash-after-delete-before-dequeue recoverable | yes |

Chosen route: **GC checkpoint as conservative cleanup floor + B1/B2 two-phase.**
Slowest to reclaim, easiest to prove safe, least likely to disturb consensus
recovery.
