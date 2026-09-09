# I13e atomic publication contract proposal

**Pending coordinator decision. Not an implementation or acceptance result.**
The [current-boundary inventory](workchain-i13e-boundary.md) identifies the
missing operation. This proposal supplies its intended obligations and strict,
currently unwired assertions. No production header or activation gate changes.

## Meaning of visibility

The proposed entry owns one identifiable batch and one publication generation.
Private engine work, root construction and referenced-cell persistence precede
one atomic decision that installs the entire generation. A returned private root
is not that decision. Unreferenced persisted cells may remain after an abort;
no authoritative reader or publisher may discover them through a committed root.

| Observer | Required meaning of visible |
|---|---|
| Subsequent processing in the same block | Reading the authoritative committed batch context, including accounts, imports, queues and processing metadata. It sees the complete old generation until the decision, then the complete new generation. Private candidate builders are not authoritative readers. |
| Recovery reader | Reopening the real commit store and reconstructing the same authoritative generation, including message eligibility. No reconstruction from an adapter cache. |
| Other shards / external consumers | Logical handoff at the actual downstream publication boundary. Eligibility is bound to the owning committed generation AND existing enclosing block acceptance/finality rules. A private batch commit does not grant consensus finality or permission to send. |

The last row requires a private recording transport at the real handoff boundary.
It records **every attempt**, including an orphan attempt, without filtering by
commit status or deduplicating observations. It sends no live traffic. Existing
receipts remain visible. Logical handoff is distinguished from subsequent wire
retransmission: this contract does not promise exactly-once network delivery.
The test drives the existing eligibility policy in an isolated fixture; it must
not enable a workchain or bypass production activation/finality checks.

Publication is therefore an atomic commitment of state **and message release
eligibility**, followed by release under the enclosing policy. A fallible direct
send followed by a state commit cannot implement this contract. This proposed
interpretation of "publication and commit cannot split" requires ratification;
it is not a decision to implement a particular database or outbox design.

## Bundle and outcomes

One generation binds all of the following, including references between them:

- ShardAccounts root and all participant changes;
- AccountBlocks and their transactions;
- inbound descriptors and consumed-input accounting;
- outbound descriptors, outgoing queue and deferred dispatch queue;
- shard state root and shard update;
- value-flow result;
- processing metadata affecting subsequent execution: logical-time bounds,
  counters and resource/budget totals, and any other authoritative cached value;
- batch identity, committed-batch count and message identities/payload bindings.

The test's ten serialized components are a minimum semantic partition. A real
implementation must enumerate every additional authoritative field and map it
into the snapshot. Omitting a mutable cache because it is not a root is forbidden.
The adapter must canonically serialize actual contents, not merely copy the
expected root hash into ten slots. Same-block and reopened-store observations
must be independently obtained. Neither may use a test-side visibility model.

Before the atomic decision, any failed stage returns `NotCommitted`: every
component, generation, count, pre-existing receipt and release eligibility stays
exactly as before. Polling the real release boundary during or after that failure
must produce no new handoff. This includes failure within the store's atomic
operation after internal writes have begun, before its decision.

After the decision, rollback is not a valid answer. Loss of the reply or restart
must resolve the batch identity to `Committed`, with exactly one generation and
one logical publication per output. Repeating the same request returns the same
commit; it must not execute the batch again. If the intended host API permits an
unresolved outcome instead, the coordinator must define its resolution protocol
before implementation; the present assertions deliberately do not accept it.

## Pending stage matrix and fixed assertions

`workchain-i13e-contract.h` is a test-only adapter contract;
`test-workchain-i13e-contract.cpp` supplies the assertions. The adapter factory is
intentionally undefined. No fake publisher, fallback implementation or skip is
provided. `prepare()` only packages the request: the tested stages must execute
inside the real `attempt()`, with probes installed at their actual host sites.

The proposed fixture has three participants, two inbound messages, and three
outputs covering normal and deferred queues. All ten state components change on
success, and old state and old publication receipts are nonempty. The proposed
minimum execution plan has 25 distinct failure positions:

| Position family | Occurrences | Probe placement |
|---|---:|---|
| Participant finalize, AccountBlock stage, account-root stage | 3 each | After each participant's respective private effect |
| Inbound stage | 2 | After each input is privately recorded |
| Outbound descriptor and queue stage | 3 each | After each output's respective private effect |
| Value flow, coverage, shard update, final budget | 1 each | After the corresponding final check/construction |
| Referenced-cell persistence, generation check | 1 each | After persistence/check, before publication |
| Before atomic publish | 1 | Immediately before entering the store decision |
| Atomic store abort | 1 | Inside the real store operation before its durable decision |

This is a proposed semantic schedule, not a claim that 25 existing production
sites have been found. Approval and implementation must map each position to a
concrete file/operation and enumerate **all** additional fallible late stages,
including repeated persistence/store operations. Extend the matrix and assertions
for those operations; do not alias several stages to a convenient final hook.
`AtomicStoreAbort` must induce the real abort path, not bypass the store call.
The normal run visits that checkpoint without aborting.

The assertions require the exact registered catalog and ordered visits. At every
probe, independent readers must still see the before snapshot; polling release
must leave it unchanged. For each selected fault, execution must stop at that
position, report its numeric injected-failure identity and retain the entire
before snapshot, including after another release poll. The success run checks
all new components before release, then all expected handoffs. Two additional
runs cover interruption after the decision before reply and reopening after the
decision. Recovery must use the actual store/process lifecycle, not reset an
adapter variable. Success and both recovery cases retry the same batch.

| Assertion identity | Obligation |
|---|---|
| 60–61 | Required independent fixtures and real adapter/session/request exist |
| 62–63 | Correct initial state; request preparation remains private |
| 64–65 | Complete stage catalog and actual ordered reachability |
| 66–67 | No intermediate state visibility or early handoff |
| 68 | Assertion-owned oracle copies remain unchanged |
| 69–70 | Selected stage reached; exact injected failure and old generation |
| 71–72 | Zero visible changes and no deferred orphan after failure |
| 73–75 | One complete commit, followed by exactly the expected handoffs |
| 76–77 | Retry resolves the same commit without re-execution or new handoffs |

Identities name guards, not independent defenses. Multiple faults can exercise
the same guard; archive their selected stage and observed identity separately.
No production candidate/local-error classification is established here.

## Remaining wiring and instrument calibration

Before any acceptance claim, supply independently reviewed, committed binary
oracles in `before`, `committed`, and `released` directories. Each contains
`generation.txt`, `committed-batches.txt`, `released.bin`, and the ten `.bin`
components named in the assertion source. Missing files fail with identity 60.
The adapter receives no oracle reference or pathname. The future evidence runner
must bind every fixture to committed blob OID and SHA256, verify working bytes,
and check hashes again after execution. Expected outputs must not be generated
by the operation being assessed. These fixtures and that runner do not yet exist;
the executable is not an acceptance command ready for use.

The real adapter, reader mapping, handoff observer, store/restart hooks and stage
mapping are also absent. No behavioral control has run. Once wired, calibrate
each guard by a single compiled shadow mutation with committed-blob/copy-before
identity, numeric failure, byte restoration and restore replay, as in I13c/d.
At minimum cover early installation of each state component, early handoff,
omitted output on successful commit, incomplete store abort, omitted stages,
wrong observer routing, oracle corruption and duplicate retry publication.
Controls must establish that observers see the production surfaces; a self-report
from the publisher is insufficient. Archive every stdout/stderr, including empty
files. Missing dependencies and compile failures are never behavioral evidence.

The object target can be built to check assertion syntax. Linking the executable
without a real adapter must fail. Neither result establishes I13e. Coordinator
ratification is required for the visibility domains, recovery/idempotence contract,
and concrete host stage mapping before assigning production implementation.
