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

## Codex design review corrections (PR B) — binding

A read-only Codex review of the PR B design returned **needs-changes**: keep GC as
the floor and implement B1 first, with the following binding corrections.

**1. Eligibility needs an ON-CHAIN obsolescence proof, not just GC ancestry.**
`retirement_checkpoint ancestor-or-equal GC` proves the block cannot be rolled
away; it does NOT prove the session is permanently obsolete. Current retirement
(`manager.cpp:2997`) retires every active group absent from the new selection,
without distinguishing an on-chain rotation from a LOCAL change (temporary key
removed — `manager.hpp:347`, `manager.cpp:3599` — or validation/config gating).
Counterexample: X's actor retires at R because its local key was removed; GC
passes R while X is still an on-chain current session at GC; the head moves to a
later session so X is absent from current+next; A–D would permit deletion, yet a
permitted truncation back to GC plus key restoration recreates X. So condition B
becomes:

```
B. retirement_checkpoint proves X is off the ON-CHAIN current+next validator
   schedule (independent of local keys, gating, and tombstones)
   AND retirement_checkpoint is ancestor-or-equal of the GC checkpoint
```

A cleanup record may therefore be produced with delete authority ONLY for a
session proven off the on-chain schedule. A purely local-key/gating retirement
must NOT yield a delete-authorizing record (record it as unknown-obsolescence, or
do not record it). Also validate full-ID ancestry from GC to the recovered chain,
not height alone.

**2. B1 must disable legacy validator deletion in the startup sweep.** Replacing
the retirement `destroy()` call is not enough: startup still calls
`sweep_destroyed_consensus_dbs()` with the fences, and the helper authorizes
deletion on a legacy destroyed-session match (`manager.cpp:2378/2408`,
`db-path.h:129`). **B1 must remove validator deletion authority from that sweep**
(observer cleanup continues); validator directories then linger until B2. Only
with this + close-without-delete routing is B1 genuinely "no validator deletion".

**3. Atomic retirement persist must preserve rotated/non-rotated semantics and
multi-group retirement.** The rotated branch persists the init block then schedules
`updated_init_block()` (which advances `last_rotate_block_id_`, prunes captured
fences, persists the remaining set, and is a prerequisite GC depends on —
`manager.cpp:3079/3142`); the non-rotated branch persists the destroyed-session
set. The new batch must write the fence snapshot + ALL newly-retiring records
(one update can retire several groups) in one synced batch, and must NOT replace
`updated_init_block()` nor close the whole captured actor vector on a single
record's ack. Encode and write record keys directly in the batch — do not call the
single-record helper (it starts/commits its own batch, `validator-cleanup-store.h:34`).

**4. Close-without-delete shutdown order.** Preserve the existing sequence
(`StopRequested -> await writer close -> release bus ref -> await bus destruction
-> [was: delete]`, `bridge.cpp:504`). The bus destructor destroys `db` BEFORE
satisfying `stop_promise` (`bus.h:189`), so send the manager's
`consensus_db_closed(session_id, dir_name)` callback AFTER that waiter completes;
the bridge then exits without keeping the directory alive (manager holds copied
identity/path). "No owner => closed" is sound only for a fresh process before
group creation — NOT at runtime, where retirement releases actors from the maps
before async shutdown completes (`manager.cpp:3000`).

**5. Selection helper inputs (B2) are more than listed.** A side-effect-free
candidate/session-id computation needs: MC shard topology + split/merge state; an
explicit clock (future-shard uses `fsm_utime < now + 60`); per-shard current+next
validator sets; consensus options/hash + last-key-block seq; max vertical seq and
the unsafe catchain-rotation policy INCLUDING its session-id rewrite; and temporary-
key membership (`manager.cpp:2741/2800/2860/3156`). `next_validator_groups_` also
has historical ownership (tentative groups retained until superseded,
`manager.cpp:3010`). Correction: share the deterministic candidate/session-id
computation; cleanup uses a CONSERVATIVE candidate set or an explicit Unknown;
keep active/tentative/retiring ownership checks separate; missing keys/config must
not yield an authoritative empty set; and selection at today's head must not
substitute for the permanent-retirement proof in (1).

**6. Fence/record decoupling needs reopen/stale-callback protection.** When a
retired session reopens, invalidate its previous closed acknowledgement, register
the new owner, and reject stale eligibility/close/delete completions — else
`closed_retiring_validator_sessions_` can describe an earlier incarnation. Keep
observer persistence/callbacks separate (the queue is observer-filtered at
startup, `manager.cpp:2368`).

**7. Triggers + reconciliation need concurrency/retry rules.** Trigger after the
durable GC ack and after confirmed bus/DB teardown; startup must AWAIT record
loading (today the load gates nothing, `manager.cpp:2342`). Before a filesystem
job: revalidate record version, owner/closed state, and selection snapshot, and
serialize deletion against reopening that exact directory. The three triggers
alone don't guarantee retry after a transient FS failure — add bounded scheduled
retry, a fair continuation cursor, and bounded outstanding work; FS work must not
block the manager's consensus processing (a 16-record turn cap doesn't bound
recursive deletion time).

**B2 tests must add:** the key-removal/rollback counterexample (1), stale-close-
after-reopen (6), multi-session retirement persistence (3), and B1-restart-through-
the-legacy-sweep (2) — each demonstrably failing when its guard is removed.

---

# PR B / B2 — implementation increment plan

B2 enables the actual checkpoint-bound deletion. It is sequenced so deletion is
the LAST thing turned on: every increment before the final one is inert or
gated, and each is Codex-reviewed. The pure decision core (`can_delete_validator_db`,
ancestry fail-closed, monotonic safe checkpoint) already exists and is tested
(B1-1). B2 supplies the concrete inputs, the orchestration, and the enablement.

**B2-1 — manager-owned physical delete helper (inert, testable).** A free/helper
function `delete_validator_consensus_db(db_root, dir_name) -> bool` that does
`RocksDb::destroy(dir/db)` + `rmrf` + `stat`, returning true only on confirmed
ENOENT (POSIX) / FILE_NOT_FOUND (Windows) -- the same confirmation the bridge's
destroy_inner uses and the sweep deleter uses. Plus exact-path re-validation:
build the path only as `consensus_db_root(db_root) + dir_name`, require
`is_canonical_validator_dir_name`, reject anything else. Inert: no caller. Tested
against real temp dirs (deletes a real dir, confirms gone; refuses a non-canonical
name; returns false when the dir persists).

**B2-2 — durable GC safe-checkpoint tracking (inert).** Track
`durable_safe_cleanup_checkpoint_` = the persisted GC masterchain block id,
adopted monotonically via `should_adopt_safe_checkpoint` as GC advances
(`advance_gc`/`got_next_gc_masterchain_state`) and loaded at startup
(`get_gc_masterchain_block`). Shadow: consulted by nothing yet. Testability is
limited (manager state); rely on the pure monotonic guard test + Codex review.

**B2-3 — async full-ID ancestry oracle (inert, testable where possible).**
`check_masterchain_ancestry(ancestor, descendant) -> Task<CleanupAncestry>`:
equal -> ancestor-equal; `ancestor.seqno > descendant.seqno` -> NotAncestor;
else walk prev-masterchain handles from descendant to ancestor.seqno, exact
BlockIdExt match -> Ancestor else NotAncestor; any handle/DB unavailability ->
Unknown (FAIL CLOSED). Reuse an existing manager-init/block-handle traversal if
one exists rather than a new walk. Inert: not wired to deletion.

**B2-4 — on-chain recreatable-session set (the obsolescence proof).** Extract a
side-effect-free `compute_recreatable_sessions(...)` from `update_shards()`
(shard topology, clock fsm_utime<now+60, current+next validator sets,
consensus options/hash, last-key-block seq, max vertical seq, unsafe-rotation
session-id rewrite, temp-key membership; honor tentative historical ownership).
It yields the set of session ids that could still be legally created at the
current head, or an explicit Unknown when inputs are missing (never an
authoritative empty set). `update_shards()` reuses the same helper so startup
safety cannot drift from live selection. Unit-test the pure extraction.

**B2-5 — generation / reopen protection (inert).** Give each retiring session a
generation/incarnation marker so a `consensus_db_closed` callback, an eligibility
check, or a delete completion for an OLD incarnation is rejected once the session
reopens. Track `closed_retiring_validator_sessions_` with its generation; a
reopen invalidates the prior closed-ack.

**B2-6 — the cleanup orchestrator (still gated OFF).** `try_cleanup_pending_
validator_dbs()`: iterate RECORDS (not dirs), for each: skip if not eligible
(`can_delete_validator_db(record, durable_safe_cleanup_checkpoint_, is_live,
ancestry_oracle)` with is_live from the recreatable set AND the ownership/closed
checks); stat the exact path; ENOENT -> erase record; exists -> delete (B2-1) ->
confirm ENOENT -> erase; EACCES/EIO -> keep. Bounded work per turn (a cursor),
FS work off the consensus path, fair scheduled retry. Behind a compile/runtime
gate so it is a NO-OP until B2-7.

**B2-7 — deterministic fault-injection harness + Case 6 + ENABLE.** An injectable
coordinator with failpoints (AfterRetirementDecision, AfterRetirementPersist,
AfterActorClosed, BeforeFilesystemDelete, AfterFilesystemDelete, BeforeRecordErase).
Tests: Case 6 end-to-end (delete fail -> tombstone prune -> restart -> session
recreatable -> deleter MUST NOT run); key-removal/rollback; stale-close-after-
reopen; multi-session retirement; crash-after-delete-before-dequeue. Each must
fail red when its guard is removed. Only when all pass is the orchestrator gate
turned ON (triggers: startup, GC advance, close). This is the one increment that
changes deletion behavior, under the five merge blockers.

Ordering rationale: B2-1..B2-6 add inputs, state, and gated machinery without ever
deleting a validator DB; B2-7 supplies the end-to-end safety evidence and is the
sole enablement. If B2 cannot be finished with that evidence, B1's safe
no-deletion state stands.

## B2 plan review — binding refinements (before B2-4 / B2-6)

A Codex review of the B2 plan surfaced two binding refinements:

**B2-4 obsolescence proof must be anchored on-chain, not "absent from today's
head".** A session's absence from the current recreatable set does NOT prove it
was off the on-chain validator schedule at its retirement checkpoint (the
key-removal counterexample: local actor retired while the session was still
scheduled on-chain). Condition C must therefore be derived from the on-chain
validator schedule relative to the GC floor -- e.g. the session is not in the
current+next validator schedule determined by the masterchain state at/after GC,
verified against the actual validator sets (`ancestor_is_valid`,
`get_old_mc_block_id`), not merely the live recreatable set at the head. The exact
condition is being settled in a focused design query before B2-4 is coded.

**Delete must be serialized against reopen (B2-5/B2-6), not only post-hoc
rejected.** A per-session generation marker must prevent an IN-FLIGHT delete from
racing a reopen of the same session/directory -- rejecting a stale `consensus_db_
closed`/eligibility/delete callback after the fact is insufficient. The
orchestrator must not begin (or must abort) a filesystem delete for a session that
has reopened, and must hold a guard for the exact directory across the async
delete.

**Reusable primitives (ancestry oracle, B2-3):** use
`MasterchainState::get_old_mc_block_id(seqno, blkid)` and `ancestor_is_valid(
BlockIdExt)` (`validator/impl/shard.hpp`), and `BlockHandle::one_prev(true)` for
prev-masterchain traversal -- do not hand-roll a new chain walk.

**B2-1 (physical delete helper) is independent of the above** and proceeds first.

### B2 plan review — additional points (completed verdict)

- **Temp-key membership must NOT exclude candidates from the on-chain proof.** A
  known local key set that happens to exclude X does not prove X obsolete;
  obsolescence is an on-chain-schedule fact, independent of which keys this node
  holds. "Unknown when inputs missing" vetoes deletion; a key-set exclusion must
  not be read as proof.
- **Record-version check on erase.** An old/stale erase must not remove a
  replacement cleanup record written after a reopen. Bind erase (and close/delete
  callbacks) to the owner generation AND the record version.
- **Condition assembly (B2-6/7) must establish all four explicitly:** B =
  checkpoint-specific on-chain obsolescence AND retirement->GC ancestry AND
  GC->recovered-chain validation; C = known conservative non-membership (unknown
  selection vetoes); D = confirmed closure for the relevant ownership generation,
  with active/tentative/retiring owners each independently vetoing.
- **Order ancestry before adopting a completed GC**, and **separate the
  fault-injection harness + tests from the final enablement change** (split the
  old B2-7 into B2-7 harness/tests and B2-8 enablement).
- **B2-1 signature:** the physical-delete primitive does ONLY path revalidation +
  filesystem delete + confirmed-gone; eligibility stays entirely in the
  orchestrator (B2-6), never in this helper.

## B2 implementation — structural updates (from reading the source)

- **B2-2 folds into B2-6.** The manager already tracks the durable GC block via
  `gc_masterchain_handle_` (persisted by `update_gc_block_handle` before
  `advance_gc` installs it, loaded at startup, monotonic by construction, kept a
  non-regression floor by the existing startup/truncation checks). The safe
  cleanup checkpoint is simply `gc_masterchain_handle_->id()`; no separate tracked
  member is needed (adding an unused one would also trip -Werror). B2-6 reads it
  directly.
- **B2-3 needs no custom async chain walk.** `MasterchainState::ancestor_is_valid`
  == `check_old_mc_block_id(blkid, strict)` (full-ID ancestor check against the
  state's prev-blocks dict). So condition B is
  `gc_masterchain_state_->check_old_mc_block_id(retirement, /*strict=*/true)` (or
  retirement == GC id), synchronous, using validated chain data. Depth-limited:
  a retirement older than the dict returns false -> we keep (leak) conservatively,
  never a false "is ancestor".
- **B2-4 obsolescence** is under a focused design query: the candidate predicate
  is condition B AND a per-shard catchain-seqno obsolescence check against the GC
  state (`get_shard_cc_seqno(shard)` past the record's cc_seqno by the current+next
  margin), binding the whole decision to the GC rollback floor. The exact form
  (margin, shard split/merge monotonicity) is being settled before coding.

## B2-4 obsolescence predicate — settled (Codex design verdict)

From one durable GC snapshot (state `S`, `G = gc_masterchain_handle_->id()`), the
on-chain obsolescence portion is true ONLY when:
- `S.get_block_id() == G` (use the GC block's own state);
- the record's directory is canonical for its session id (yielding shard + `r`);
- `retirement == G` OR `S.check_old_mc_block_id(retirement, /*strict=*/true)`
  (full-ID ancestor-of-GC; `prev_blocks_dict` keeps full history, so no false
  ancestor; missing/unreadable -> keep);
- `g = S.get_shard_cc_seqno(shard)` is known (reject the `UINT32_MAX` unknown
  sentinel -> keep);
- **`r < g`** (strict; `g` is the current set's counter and `g+1` the next set's,
  so `r < g` excludes both; per-shard catchain seqno does not decrease on the
  accepted chain -- splits copy, merges take max+1 -- so it cannot recur from GC
  forward). No `+2` margin.

Residual release-gate caveat: `CatchainSeqno` is uint32 and the chain's
transition checks do not reject wrap; a no-wrap/no-reuse invariant (~4e9 catchain
rotations away, not practically reachable) underpins the permanent "never recurs"
claim and must be noted at enablement. This predicate is the obsolescence portion
only; deletion additionally requires C-runtime (session not a live/pending group)
and D (actor closed), and the delete-vs-reopen serialization.

Implemented as the pure, injected-oracle `validator_session_is_onchain_obsolete`
(B2-3's ancestor check and B2-4's cc check combined), plus
`parse_canonical_validator_dir_name` exposing shard + cc. Falsifiable tests pin
the strict `r < g` boundary, the ancestor/equality gate, the unknown-sentinel
veto, invalid-GC, and non-canonical rejection.

## B2-8 adapter invariant checklist (Codex) + enablement gating

The pure coordinator (B2-1..B2-7) is safe within its injected-oracle contract.
Codex confirmed it is ready for the B2-8 adapter but **NOT for production
enablement** until the adapter satisfies these invariants AND has its own red/green
tests. To get that evidence without a full manager harness, the stateful adapter
is extracted into a testable component (`ValidatorCleanupManager`, B2-8a); the
`ValidatorManagerImpl` is a thin forwarder (B2-8b); the flip-on is B2-8c.

Adapter invariants (all required before enablement):
1. **Durable, current record authority.** Only committed records; one current
   record per session; bind ops to record version + ownership generation; reject
   stale snapshots. (Shadow-map membership alone is insufficient — retirement
   updates the map before persistence completes.)
2. **Complete current liveness.** `is_live` = in `validator_groups_` OR
   `next_validator_groups_` OR any pending/in-progress creation/reopen; no false
   "not live" interval across container transitions; unknown ownership vetoes.
3. **Fence the entire async deletion.** Atomically establish eligibility and
   RESERVE the exact session/dir before dispatching FS work; every reopen path
   honors the reservation until the worker finishes; overlapping sweeps honor it.
   A before/after re-check is NOT enough (an after-check can't restore deleted
   votes).
4. **Generation-scoped closure.** Accept close acks only for the retiring
   incarnation; reopen invalidates prior closure; a bare session-id set with
   unconditional insert is insufficient. After restart, establish closure from
   completed recovery + exclusive ownership (no owner yet in the fresh process
   before group creation), not an invented ack.
5. **One coherent durable GC snapshot.** Match GC state's full block id to the
   durable GC handle; use `check_old_mc_block_id(retirement, true)`; map
   `UINT32_MAX` -> nullopt; fail closed on missing state/topology; preserve the
   no-wrap/no-reuse premise under `r < g`.
6. **Completion, not dispatch, is confirmed deletion.** The async adapter must not
   translate "job queued" into a true deleter result; only a fenced, confirmed
   absence counts.
7. **Durable erase without re-add race.** Bind erase to the captured
   record/generation; update the shadow entry only after durable success; a stale
   completion must never remove a replacement record.
Plus: bounded aggregate in-flight FS work + fair retry rotation; and adapter
acceptance tests (reopen during FS work, stale close/delete/erase, replacement-
record preservation, restart reconciliation) demonstrably red/green BEFORE the
flip. Enablement (B2-8c) also remains post-genesis per the overall plan.

## B2-8b done (gated OFF); B2-8c remaining checklist (Codex-refined)

B2-8b wired ValidatorCleanupManager into ValidatorManagerImpl with
kValidatorConsensusCleanupEnabled=false. Codex review: safe as-is, no
consensus-safety regression; with the gate off no validator directory can be
deleted (every delete is downstream of the gate check), and the only runtime
change is adapter bookkeeping + the generation flowing through the close
callback. Before flipping the gate (B2-8c, post-genesis), the following remain:

1. **Fence creation before constructing the actor.** get_or_make_next_group must
   check is_delete_in_flight and DEFER creation (with a retry path) before
   building the actor, so an async delete cannot have its directory reopened mid
   worker. (No-op while gated; required once async deletion exists.)
2. **Async worker + separate durable-erase completion.** Move the filesystem
   delete off the manager actor thread; call on_delete_completed only from the
   worker's completion, and clear the reservation / drop the entry only after the
   durable erase is ACKed (not merely queued). Preserve incarnation identity
   through completion; demonstrate replacement-record protection.
3. **Bound aggregate work + fair retry rotation.** The per-pass budget (16) bounds
   attempts per pass, not total concurrent work or scan fairness; persistently
   failing early entries can starve later ones. Add a continuation cursor / fair
   rotation and an outstanding-work bound.
4. **Startup ordering / exclusive ownership barrier.** Validator-record loading is
   a separate async startup request; establish (or add an explicit barrier for)
   the ordering before relying on the generation-0 closed=true startup load.
5. **Falsifiable integration acceptance before the flip:** gate-off directory
   preservation; delayed persistence/closure; stale generations; reopen during
   deletion; overlapping passes; failed deletion/erase; restart reconciliation;
   real GC-oracle boundaries. Keep the catchain no-wrap/no-reuse premise and the
   post-genesis enablement gate.

## Honest current-state (branch fix/validator-consensus-db-cleanup-prb, gated)

Correcting two over-claims:

1. **"Only the flip remains" is wrong.** Safely enabling deletion (B2-8c) needs
   real code, not just changing the constant: the async worker + durable-erase-ACK
   completion (release the reservation / drop the entry only after the durable
   erase is acknowledged, not merely dispatched); a delete/erase completion that
   carries an operation token (session + incarnation + record revision + delete-op
   id) so a late completion cannot act on a replacement entry (the current
   on_delete_completed interface has no such binding -- safe only because the
   synchronous caller cannot produce a stale completion); the startup
   ordering/exclusive-ownership barrier (the generation-0 closed=true load must be
   proven to precede any group creation/retirement, and must not overwrite a newer
   entry); fence-before-create (defer group creation while is_delete_in_flight);
   and bounded/fair retry (a continuation cursor, not just a per-pass attempt
   budget). Finding 1 is NOT "fixed pending a flip".

2. **The gated branch is not resource-neutral.** Relative to current main it
   changes normal validator retirement from "close + delete" to "close only" and
   removes the startup sweep's validator deletion, while deletion stays gated off.
   So even with no crash or FS failure, normally-retired validator DBs now
   ACCUMULATE and their pending metadata grows. This is a deliberate
   deletion-safe STAGING state, suitable for a dev/acceptance environment with a
   test window and disk monitoring -- NOT a long-term production version that has
   closed the disk-growth finding. "Safe to not delete" and "safe to complete
   reclamation" are different acceptance goals; only the former is met so far.

Accurate progress: retirement persistence, the close-without-delete flow, the
cleanup decision components, and the manager wiring are implemented; production
deletion is not enabled, and the concurrency, completion-acknowledgement,
startup-ordering, and resource-reclamation work required to enable it safely is
not yet done.

## B2-8c progress — safety-logic prerequisites DONE; enablement bundle remains

The B2-8c **safety-logic** prerequisites are implemented and unit-tested (gate
still off):

- **Durable-erase-ack + operation-token completion** (B2-8c-1): Pending/Deleting/
  Erasing state machine; begin_eligible_deletes returns the incarnation generation
  as an op token; on_delete_completed and on_erase_acknowledged reject a
  wrong-generation or wrong-state completion; the record is dropped and the
  reservation released ONLY on the acknowledged durable erase.
- **Fair round-robin retry cursor** (B2-8c-2): a failing prefix can no longer
  starve later records.
- **Fence-before-create** (B2-8c-3): get_or_make_next_group defers creation while
  is_delete_in_flight(session).
- **Startup barrier** (B2-8c-3): validator records load before finish_start_up, so
  on_loaded_at_startup precedes any group creation.

Each has a falsifiable test (mutation-verified): durable-ack held until erase ack,
token rejection, round-robin fairness, generation reclamation, the four-condition
gate, and Case 6.

**Remaining before the flip (the enablement bundle, post-genesis):**

1. **Async delete worker.** Move the blocking RocksDb::destroy + rmrf off the
   manager actor thread (a dedicated IO worker / executor), calling
   on_delete_completed from the worker's completion, never inline. This is actor
   infrastructure, not a safety-logic gap -- the completion state machine already
   handles an async completion -- and it affects timing/liveness, so it is
   validated together with the enablement soak. The current synchronous call is
   behind the gate and documented in try_validator_consensus_db_cleanup.
2. **Falsifiable INTEGRATION acceptance** (needs a manager harness and/or the async
   worker): reopen during an in-flight delete, stale close/delete/erase callbacks
   end-to-end, replacement-record preservation, restart reconciliation, and real
   GC-oracle boundaries. The component-level equivalents exist; the end-to-end
   manager-level proofs are the enablement gate.
3. **The flip** (kValidatorConsensusCleanupEnabled -> true), only after 1 + 2 and a
   disk/RSS soak, post-genesis.

Finding 1 remains open until that bundle is done; the branch stays a deletion-safe
staging state (no validator DB deleted anywhere).

## B2-8c review round 2 — three gaps closed (gate still off)

The three gaps from the second manager-wiring review are fixed and
mutation-verified:

1. **Startup-load no longer overwrites a runtime incarnation.** on_loaded_at_startup
   is insert-if-absent: a session already known from runtime (live or pending) is
   not clobbered with generation-0/closed=true. This makes correctness independent
   of whether block application reaches update_shards before the startup load's
   callback returns (the load is not the only path to group creation), rather than
   relying on the finish_start_up ordering alone.
2. **Per-attempt operation token.** A process-wide attempt_id distinguishes delete
   attempts of the SAME incarnation; on_delete_completed / on_erase_acknowledged
   require both generation and attempt_id to match, so a stale/duplicate completion
   from an earlier attempt cannot release a later attempt's reservation. A timeout
   must NOT be reported as a completion (the fence is held until the real attempt
   finishes or is cancelled) -- documented as the worker contract.
3. **Scan and outstanding budgets.** begin_eligible_deletes bounds entries examined
   per pass (scan_budget; the round-robin cursor still covers all records) and the
   total concurrent Deleting+Erasing reservations across passes (max_outstanding),
   not just reservations per pass.

Still remaining before the flip (async-worker enablement bundle): move the blocking
FS delete off the manager actor with the worker honoring the per-attempt token and
the no-speculative-completion-on-timeout rule; manager-level integration acceptance
(reopen during delete, stale callbacks end-to-end, restart reconciliation, real GC
oracle); then the flip after a disk/RSS soak, post-genesis. Finding 1 stays open;
the branch remains a deletion-safe staging state.

## Async delete worker — wired (gate still off)

Enablement bundle item 1 is now implemented as a separate actor,
`ValidatorConsensusCleanupWorker` (`validator/consensus/validator-cleanup-worker.h`),
and wired into the manager:

- The blocking delete (`delete_validator_consensus_db` = RocksDb::destroy + rmrf +
  confirmed-absent stat) runs on the worker actor, OUTSIDE the manager's own message
  handling, instead of inline on the manager between its other messages.
  `try_validator_consensus_db_cleanup` now dispatches each reserved delete to the
  worker via `send_closure(..., run_delete, db_root, session, dir_name, promise)` and
  returns; the worker is created lazily only after the gate check, so a gated-off node
  never allocates the worker actor or its mailbox.
- **Completion is reported exactly once, only on real completion.** The worker has no
  timer and never reports a speculative/timeout completion; the `td::Promise<bool>`
  continuation carries the confirmed-gone result plus the `(session, generation,
  attempt_id)` token back to `validator_cleanup_delete_done`, which feeds
  `on_delete_completed` (a stale/duplicate token is rejected there). The ownership
  fence and the reservation stay held until this real completion; the durable record
  is erased (sync) only after a confirmed delete, and the reservation released only on
  the erase-ack. The worker re-validates the canonical directory name for the session
  inside `delete_validator_consensus_db`, so a corrupt request cannot target an
  arbitrary path.
- **Threading caveat (honest):** the worker is a separate actor context, NOT a
  dedicated OS thread. Both actors draw from the shared scheduler thread pool, so this
  guarantees the blocking call is not a manager message, not full CPU isolation from
  every manager message. Recorded in the worker header comment so the enablement soak
  can decide whether a dedicated executor is warranted.
- **Retry pacing (review P2 fix).** A completed delete attempt does NOT re-trigger the
  cleanup pass: a delete that reports not-gone returns its entry to Pending, and an
  unconditional re-trigger would spin a backoff-free retry loop against an undeletable
  directory (e.g. a parent denying removal). Failed attempts instead wait for the next
  GC-paced pass (`advance_gc`) -- that external cadence is the rate limit. Only an
  acknowledged durable erase (`validator_cleanup_erase_acked`) re-triggers draining,
  where re-triggers are paid for by a completed removal, so the backlog is
  monotonically decreasing and cannot loop.

Falsifiable coverage added: `test/test-validator-cleanup-worker.cpp` drives the worker
through a real actor Scheduler -- a canonical dir is removed and reported gone
(mutation-verified red against both a constant-`true` and a constant-`false` worker
body), and a non-canonical dir name is refused and left on disk.

**Still remaining (manager-level integration acceptance, post-genesis):** the
retry-pacing property above (no hot loop on persistent failure; bounded re-trigger on
progress) is structural in the manager glue and needs a manager/worker harness to
exercise end-to-end -- it is NOT covered by the worker unit test and is added here as
an explicit integration-acceptance item, alongside reopen-during-delete, stale
callbacks end-to-end, restart reconciliation, and real GC-oracle boundaries. Then the
flip after a disk/RSS soak. Finding 1 stays open; the branch remains a deletion-safe
staging state.
