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

## Persistent contents and release timing (D50)

Section 9.3 requires the persistent message deliverability record, candidate
contents and externally supplied committed-batch count to occupy the same
WriteBatch. D50 requires passive readers to receive the immutable snapshot only
after a real reopened-store read resolves the generation as committed. These
are different obligations: common persistent contents and delayed observation.
Release inside a transaction would satisfy neither obligation by itself; a
rollback cannot revoke an observation already made.

The private implementation uses one `read_and_release` path for normal success
and recovery. There is no separate normal-path notification, recovery-only
notification, or persistent released flag. Its consumer API returns immutable
snapshots. Repeated release of the same bytes preserves the installed pointer.
A private batch commit does not grant consensus finality or permission to send.

### Providers and bounds

The host supplies all ten canonical component byte strings (accounts,
AccountBlocks, incoming/outgoing descriptors, outgoing/dispatch queues, shard
state/update, value flow and processing metadata), pending message payloads and
queue metadata, admitted input identity, batch identity, revision, and batch
count. The publisher does not manufacture missing roots or recompute count.
The existing construction provider fixture supplies them in these private tests;
no live collator provider is wired. A deliberately supplied count of 19 must
survive unchanged: its validity is I13a's independent responsibility.

This storage adapter serializes complete supplied bytes, not a CellDb delta.
Its byte limit bounds codec output and decoded strings, with framing included.
The caller has already allocated the supplied strings before that check; their
construction, peak simultaneous copies, reopen cost, retained history and disk
growth are not bounded by an authenticated D31 admission here. The 16 MiB test
limit is a fixture parameter, not evidence of D31 integration. Cross-component
semantic consistency remains the provider/admission obligation.

The private directory uses the existing RocksDb backend with an explicit store
identity marker and mandatory existing-store reopen. It is not a new consensus
authority and does not unify the live P1–P5 transitions. Bootstrap initialization
is explicit and is outside the operational batch failure matrix. Runtime fault
controls target the isolated directory's WAL and recovery reads, not every
possible filesystem failure or power-loss behavior. Read observation is not a
coverage oracle: complete persisted component/message bytes are compared with
fresh frozen provider outputs, including entries writable without loading old
bodies.

### Local errors before durable writing

Outcome and availability are independent. A failed encoding or either failed
RocksDb `set` before `commit_write_batch` returns NotCommitted together with
LocalUnavailable. The operation can prove non-commit because only the pending
in-memory batch was touched; it cannot call the failed local operation Ready.
The recovery flag prevents continued publication until a real reopen succeeds.
A successful absent-record lookup remains NotCommitted with Ready.

The private executable's linker wrapper calls the real concrete RocksDb `set`
first, then injects a distinct error status for the record or head key. These
are API-boundary status propagation tests, not physical disk-failure evidence.
The two paths must retain the injected numerical error identity, abort their
staged writes, expose no new messages, and resolve absence from reopened disk.
WAL write and sync failures use separate runtime I/O controls.

The partial-WAL scenario resolves absence twice through actual reopen before
a permitted new execution. Its durable entry count must become exactly two
(one failed attempt, one allowed new attempt); subsequent committed retries
must not increase it or the write/release counts. Thus D49's resolved-absence
retry is distinct from re-executing an already committed identity.

### Private measurement matrix and limits

| Case | First attempt / fault | Observation from real reopened storage |
| --- | --- | --- |
| 0 | Ordinary synced write | Committed; one read observation before the subsequent retry probes |
| 1 | Cancellation before writing | NotCommitted; complete old state and messages remain |
| 2 | Actual partial WAL write followed by EIO | NotCommitted twice across reopen; only then a new execution may commit |
| 3 | Real successful WAL sync followed by reported EIO | Undetermined writer result resolves to Committed |
| 4 | WAL write fails before transferring bytes | The same Undetermined writer classification resolves to NotCommitted |
| 5 | SIGKILL after commit, before first read/release | Fresh process/store recovery installs the first new released view |
| 6 | Sync ambiguity, then actual recovery read errors | Stays LocalUnavailable; later readable recovery resolves commitment |
| 7 | Host supplies count 19 | Count remains 19; this is not an I13a-validity assertion |
| 8 | Existing store directory is moved away | Open fails and does not create a replacement recovery store |
| 9 | Wrong external store identity | Open fails on the persisted binding |
| 10 | Record-key Put status replaced after actual Put | NotCommitted / LocalUnavailable; staged contents disappear on abort |
| 11 | Head-key Put status replaced after actual Put | NotCommitted / LocalUnavailable; neither staged key survives |

The execution trace is fsynced independently of the candidate store and counts
entry into the actual Native builder callback. Fixture/oracle preparation is not
counted as a publisher execution. Committed retries are tested with the current
predecessor, so the independent predecessor check cannot mask a missing duplicate
check. Separate mutations re-execute identical work, rewrite identical bytes, or
reinstall an identical view; their failure identities are 205, 219 and 206.

Read-observation identity 220 checks that exactly one `PersistentRead` event has
occurred at the normal-return boundary. It is a count assertion, not a complete
event-order assertion. Removing the actual normal readback while retaining the
correct bundle and release event targets that pre-existing assertion. A mutant
that also forges a read event is outside this observation's exclusion claim;
static inspection places that event after actual snapshot reads. The unreadable
recovery case separately exercises real file reads. These facts do not constitute
a proof of arbitrary implementation path equivalence.

Premature view installation targets identity 202, which compares the actual
passive view, including message bytes, with the predecessor. This comparison is
made after the publication call returns or its prewrite cancellation unwinds.
The cold-crash case terminates before that post-call assertion and is not an
independent early-installation control. It instead checks SIGKILL before any new
release event, and a first release from reopened storage in the surviving reader.

Log archives preserve complete output, including empty stderr members. The
artifact manifest identifies every member, its uncompressed byte count and its
SHA-256. Historical runs retain their source commit and are not evidence for a
later test version. This is private mechanism evidence, not live I13e acceptance.

The present dynamic check for D50's common path is observation count 220. It
detects the normal readback omission measured here, does not check order, and
cannot rule out a forged `PersistentRead` event. A green 220 alone must not be
read as proof that disk readback occurred.

### Independent persistent-content calibration

The separate manual calibration in `workchain-publication-provenance.py` does
not count read observations. Its dedicated executable captures the real RocksDb
set boundary through a test-only linker wrapper. At the existing
`AfterCommitBeforeRead` callback it commits a replacement account-root BOC into
the actual record. Batch identity, admitted input, scalar fields and every other
component remain unchanged. No production code/header or observer assertion was
added or changed for this calibration.

The substitution occurs after the durable decision but before the first release
of that identity. This timing is essential: changing an already released
same-identity record would correctly trigger the existing immutable-view check,
rather than release new bytes. The replacement is a valid canonical fixture BOC;
this deliberately altered record is not claimed to be a semantically valid whole
candidate. The calibration never grants finality or permission to send.

Baseline and restored implementations release the replacement bytes. A single
shadow-source mutation skips normal readback, installs the original bundle and
forges both read/release observations. It fails only the final content-origin
assertion, identity 230. Before that assertion, all bindings, other fields, one
builder execution and one substitution have been checked. After closing the
publisher, an independent real RocksDb reopen reads the same substituted record
in all three runs. Their stored-record hashes are identical; their released
component hashes distinguish the mutant from the two genuine-read runs.

This is one independent content-origin calibration in addition to count 220. It
excludes the measured no-read/forged-event substitution, not every conceivable
implementation or all read paths. It is manual calibration evidence, not another
CI mutation driver and not live I13e acceptance.
