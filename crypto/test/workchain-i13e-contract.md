> **D47 amendment (memo c7d39fa3): obligation split.** The original
> storage-oriented contract and pending assertion source below are retained for
> traceability, not treated as the current single atomicity claim.
>
> (a) Failed construction leaves no residue in the live candidate, including
> same-block consumers and observations later rolled back. (b) Consensus grants
> block authority; workchain construction must introduce no alternative grant.
> (c) Local availability and recovery are a separate work item, outside I13e.
> Neither absence of an identified counterexample nor nonfinal serving proves
> that all external consumers enforce acceptance. Propagation may include final
> signatures; it must not be described uniformly as candidate-only propagation.
>
> Original positions 1–21 and 23–24 belong to (a): 23 construction positions.
> Position 24 is now `BeforeCandidateInstall`, with no storage/finality meaning.
> Positions 22 (`ReferencedCellsPersist`) and 25 (`AtomicStoreAbort`) belong to
> (c). The old durable-decision, reply-loss, reopening and retry assertions also
> remain (c), not construction-isolation evidence. The previous D45/storage
> reachability description below is historical and must not be used to claim
> current stage reachability. No rejection gate is moved by this annotation.
>
> Mapping a position to (a) does not make it implemented or observed. Private
> builders, final context providers and live same-block consumers still require
> concrete wiring and calibrated controls. The original pending adapter remains
> undefined; its missing dependency must not become a skip or a passing model.

# I13e atomic publication contract proposal

**Contract approved by D47, with the clarifications below. Not an implementation
or acceptance result.**
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

Private builder intermediates are excluded from "visible" **if and only if no
consensus-affecting consumer can observe them**. Calling a builder private does
not establish this property. A consumer that can influence validation, subsequent
execution, block contents or publication defeats the exclusion even if it later
rolls back its own state. Internal calculations constructing the private result
are distinct from exposing that intermediate result to such a consumer.

The pending assertion uses `private_visibility_audit()`: real consumer hooks must
retain every such intermediate observation from session creation through the
attempt, release and retry. Assertion 78 rejects any observation; assertion 79
rejects incomplete hook coverage. The sticky record must catch transient exposure
between stage probes, not just compare roots at those probes. The implementation
must enumerate consumers and justify coverage; an adapter-provided boolean alone
is not evidence of completeness. Both hooks and their isolation/coverage controls
remain unwired. No absence of observations is claimed by this contract update.

The last row requires a private recording transport at the real handoff boundary.
It records **every attempt**, including an orphan attempt, without filtering by
commit status or deduplicating observations. It sends no live traffic. Existing
receipts remain visible. Logical handoff is distinguished from subsequent wire
retransmission: this contract does not promise exactly-once network delivery.
The test drives the existing eligibility policy in an isolated fixture; it must
not enable a workchain or bypass production activation/finality checks.

Publication is therefore an atomic commitment of state **and message release
eligibility**, followed by release under the enclosing policy. A fallible direct
send followed by a state commit cannot implement this contract. This D47-approved
interpretation of "publication and commit cannot split" defines the obligation;
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

Every publication field is supplied by an identified host provider; see the
[field/provider specification](../block/workchain-candidate-construction.md). In particular,
the publisher receives the batch identity and committed-batch count explicitly.
It must not compute or repair either value from AccountBlocks, infer count one
from one invocation, or increment a previous count. A separate I13a checker
recomputes from actual block content and compares with the submitted value.
Fields whose providers are missing remain missing inputs, not values derived
inside the publisher. The approved assertion code is unchanged.

The committed-batch count couples I13e to **I13a**, which must enforce exactly
one logical batch per block. I13e requires the count and batch contents to commit
atomically; its increment and retry assertions do not establish I13a's per-block
cardinality rule. That enforcement remains an explicit dependency, not an
additional property claimed by this test.

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

**D45 gate placement:** moving the rejection gate to "Before atomic publish"
means position 24 in this 25-position schedule. These are the same boundary, not
two separate operations. Once that move is implemented, positions 1–24 are on
the real execution path, subject to earlier failures. Position 25,
`AtomicStoreAbort`, is inside the store and remains unreachable while the gate
is closed. Moving the gate therefore does not make the entire matrix acceptable
as covered. Success, post-decision recovery and retry runs also remain blocked;
the full pending assertions must not skip those obligations to produce a pass.
This contract update neither moves nor opens the gate.

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
| 78 | No consensus-affecting consumer observes private builder intermediates |
| 79 | Complete real consumer-hook coverage; unknown or missing coverage fails |

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
For 78, expose an intermediate to a real consensus-affecting consumer while
keeping published roots unchanged, isolating it from root guards 66–67. For 79,
remove a required consumer hook while leaving the observation log empty. These
are required future controls, not executed evidence.
Controls must establish that observers see the production surfaces; a self-report
from the publisher is insufficient. Archive every stdout/stderr, including empty
files. Missing dependencies and compile failures are never behavioral evidence.

The object target can be built to check assertion syntax. Linking the executable
without a real adapter must fail. Neither result establishes I13e. D47 approves the contract;
concrete host stage/consumer mapping and production implementation assignment
remain pending coordinator scheduling. I13a/I13b work is not started here.
