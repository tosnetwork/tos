# Private publication and recovery implementation notes

This work is separately authorized after the D47(a) construction-isolation unit.
The earlier D47 split and its measurements are not retroactively relabeled as
storage/recovery evidence. No live collator, validator, activation or consensus
judgment is connected by this work. No implementation or acceptance is claimed
by this inventory.

## Approved uncertain outcome

The publication attempt has three outcomes: Committed, NotCommitted and
Undetermined. Undetermined describes the writer's knowledge, not a third allowed
persistent generation. A complete recovered generation or its absence must decide
whether the atomic operation took effect. A write error does not decide this.

After Undetermined, stop the publication path. Close and reopen the actual store,
then read back the batch identity. Do not reconstruct from writer state, cached
snapshots or a returned Status. If reopening or reading fails, remain
LocalUnavailable; do not execute, release, retry or reject the candidate. Recovery
that observes a committed identity returns the existing commit without execution
or another logical publication. Only recovery that establishes NotCommitted
permits another execution attempt.

Tests must cross an actual process boundary and reconstruct from disk. Injected
errors cover before writing, during writing, the commit point with an ambiguous
writer result, and process termination after commit. The commit-point case must
resolve through disk observation. Returning an injected code before entering
storage cannot establish this property. Independent execution/side-effect
observations must survive the restart; equal result bytes do not prove that
execution did not repeat.

## Existing mechanisms inspected before implementation

The source locations below refer to the committed tree at `6c4b7993a`.

| Existing operation | Behavior and reuse boundary |
|---|---|
| `td::RocksDb::commit_write_batch`, `tddb/td/db/RocksDb.cpp:545` | Moves the write batch, writes with `sync=true`, propagates the backend Status. It does not classify a failed write as absent. |
| Backend WAL writer, `third-party/rocksdb/db/db_impl/db_impl_write.cc:1734` | Writes the WAL before synchronizing it; a subsequent sync error is propagated. Do not translate that error into NotCommitted. |
| CellDb startup, `validator/db/celldb.cpp:404` and `:422` | Opens the actual store, processes rollback/adoption recovery before normal loading/metadata validation, and refreshes the reader snapshot after recovery. Reuse the open/recover/fresh-read ordering. |
| Permanent CellDb write, `validator/db/celldb.cpp:777` and `:805` | Stages cells and block metadata in a write batch. Commit error terminates through `ensure`; the inspected path does not report that nothing was written. |
| Registered-root reader, `validator/db/celldb.cpp:528` | Reads metadata by block identity and returns its registered root. This is a real keyed read, but not a wc=2 batch-generation index. |
| Streaming-import recovery, `validator/db/celldb.cpp:2493` | Enumerates persistent rollback/adoption/committed markers before metadata validation. These markers belong to streamed state import; they are not reusable wc=2 commit receipts. This is a targeted inspection, not a full audit of every recovery error path. |
| Archive reopen, `validator/db/archive-slice.cpp:709` | Opens RocksDB and reads persisted status/slice metadata. |
| Archive handle reader, `validator/db/archive-slice.cpp:455` | Reads a persisted block-info key and reconstructs a handle from those bytes. |
| Archive commit, `validator/db/archive-slice.cpp:956` | Calls `commit_transaction().ensure()` before completing waiters. The inspected failure behavior stops the path rather than asserting absence. |

Existing persistent-key reads and backend batch writes can be reused. Neither
CellDb's block key nor archive's handle key currently binds the entire private
wc=2 generation, its submitted count, pending messages and retry identity.
The earlier P1–P5/N1–N3 inventory remains applicable to existing live paths;
wrapping them in one C++ call would not make them one transaction.

## Providers and remaining contract boundary

The provider table in `workchain-candidate-construction.md` remains binding.
Batch identity and count are externally supplied values; the publication entry
must not calculate or normalize the count. I13a independently recounts the
block. Account coverage includes blind replacement of entries, independently
of read observations.

A private batch commit does not grant consensus finality or permission to send.
The coordinator requires release outside the transaction, driven solely by a
persistent read that establishes Committed. Normal completion and restart use
one readback/release implementation. Undetermined never permits release.

The initial release surface is passive: installing one immutable whole-generation
view for real readers. It sends no notifications and invokes no component that
could perform a non-idempotent action. Releasing an already installed generation
must preserve its view identity and contents. Reopening before first release
must install the committed generation through that same code. A later integration
requiring a non-idempotent external side effect needs a separate coordinator
contract; a persistent "released" marker alone cannot close that protocol.

Planned ownership is new publication entry/reader/record files and dedicated
private tests. No existing settlement/overlay edits are currently proposed.
Existing CellDb/archive files were inspected read-only; no edits to A's engine,
resource policy, wrapper, validator or shared block test are part of this work.
