# C2 / C3 minimum closure survey

Read-only source survey, 2026-09-10. Integration source baseline:
`33af64ee8775e89035c5c364615ff6e3ada853a8`. This document proposes closure
conditions and effort estimates; it does not implement them or authorize moving
an execution refusal. Existing mutation evidence cited below was inspected, not
rerun for this survey.

## Staging decision and its limits

Latest owner decision: defer opening D45. M1 is mechanisms complete, seams
prepared, and evidence that the gate remains correctly closed with correct
classification. Joint exposure acceptance and permission to open are outside
M1. The staging discussion below is historical reasoning, not current permission.

The coordinator initially approved the following two stages on 2026-09-10,
then withdrew the core justification and returned staging to **undecided**:

1. M1 prerequisite: deterministic bounds, independent checkability, per-call
   enforcement, block aggregation, and precharge before expensive verification
   with no refund for failed attempts.
2. M6: demonstrate that those bounds fit the minimum hardware's K/block budget.

Neither proceeding with nor ruling out this separation is authorized by this
survey. The following provisional-value convention is not approval to move a
gate. Initial resource values must be explicitly provisional; mainnet remains closed.
The existing convention is visible on B's committed tree
`ba6e289716ab35a54a2f2b6dff1a666fb22829f7`,
`crypto/smartcont/uno-genesis-config.fif:8-10`:
`uno-genesis-resources-approved?` returns false for global ID 1. This is a
reference to that branch, not a claim that this integration baseline already
contains the guard. Reuse the approved convention when integrating it; do not
invent another approval mechanism.

**Budget debit is not monetary payment.** `WorkchainProofVerifier::verify` in
`crypto/block/workchain-proof-work.h` increments `consumed_` before calling the
backend. It neither debits currency nor settles fees. Failure does not restore
that work allowance, but this does not establish that a sender of an invalid
candidate paid anything. The staging decision can separate deterministic
boundedness from hardware capacity; its justification must not rely on an
unestablished economic charge. Per-candidate bounds also do not establish a
network-wide bound over repeated candidates, retries, or concurrent actors.

There is currently a concrete path outside that meter: synchronous
`engine.proof_work(...)`, before its returned value is checked. C3 must close
that inspection gap. Neither a finite configured number nor a meter around the
cryptographic backend bounds arbitrary native engine code outside the wrapper.
An excessively large finite bound can still overwhelm hardware; the first stage
does not constitute deployment-capacity acceptance.

## C2: block-level aggregation

### What exists and what is missing

`crypto/block/workchain-account-engine.h` creates a fresh verifier through
`ProofAdmittedBatchInput::make_verifier()` for a metered execution. The allowance
is the batch's inspected work. The runner checks the verifier's sticky status
after the engine returns, so an engine cannot silently swallow its meter's
failure. This is useful per-call enforcement, not a cross-call accumulator.

The I13b mechanism in `crypto/block/workchain-execution-ledger.h` records input
root hashes and distinguishes duplicate input, bound exhaustion, and allocation
failure. It does not sum verification operations. Its actor members are not
live enforcement call sites at this baseline.

The I13a mechanism in `crypto/block/workchain-batch-scan.h` independently scans
candidate contents and compares completed counts and identities. It is private
mechanism evidence, not a live pre-verification barrier. A scan performed after
the work cannot retroactively prevent that work.

`UnoV2ResourceWorkOutput` in `crypto/block/block.tlb` has `max_proof_units`; there
is no separately specified block aggregate allowance. Thus the missing part is
host lifetime/order enforcement and its acceptance evidence, with a possible
configuration/profile decision—not a replacement operation-count formula.

Two possible implementations must not be silently conflated:

- If exactly one logical batch per block is independently enforced **before any
  extra verification**, one authenticated allowance can serve the block. All
  attempts/phases in that candidate scope must share it. Merely pointing to the
  private I13a scanner or final committed count does not establish this order.
- If multiple batches are admitted and summed, a block allowance needs an
  explicit authenticated meaning. A new independent limit would require a
  configuration/profile decision. Do not invent a local constant or silently
  reinterpret an existing profile's per-batch field.

### Minimum closure

1. Select the authenticated policy and establish a candidate-processing scope.
   The host owns the allowance, independent of engine-reported effects usage.
   Independent validator replay has another scope, not a process-global budget.
2. Use C1's same deterministic units, checked arithmetic, and reservation before
   backend entry. No reset between batches or phases within that scope; failed
   proof attempts do not refund the reservation.
3. Independently enforce the single-batch interpretation before extra work, or
   implement the explicitly authorized aggregate interpretation. Also bound the
   number of inspection attempts: a zero proof-work result must not permit
   unlimited calls to the inspector.
4. Preserve source distinctions: candidate-authenticated budget excess is
   CandidateInvalid; an engine underestimating its own work is a local contract
   failure; genuine allocation failure is LocalUnavailable. These are not one
   catch-all resource error.
5. Demonstrate multiple individually compliant batches cannot trigger additional
   verification beyond the block allowance. Observe actual backend entry, not
   just a final rejection. Include first-call success with a visible debit,
   failure/no-refund, scope-reset isolation, and a mutation that drops aggregate
   retention and fails at the aggregate assertion.

These conditions close C2 only when applied to the concrete execution boundary;
another private counter alone does not close live C2.

### Dependencies, effort, and B's role

C2 needs the existing C1 unit definition and precharge boundary. C3 can be
developed alongside it, but their composition must cap both inspection
multiplicity and verification work before any D45 refusal moves.

Estimate: **1–2 working days** for a fixed policy interpretation, host mechanism,
enforcement points, and isolated controls. This excludes a new wire/profile
decision, full live seam construction, and M6 hardware acceptance. A can own the
host work; B is useful for independent validator ordering and adversarial
review. Shared authorship of the same file is not required.

## C3: bounding inspection itself

### What exists and what is missing

`WorkchainAccountEngine::proof_work` in
`crypto/block/workchain-account-engine.h` documents bounded deterministic shape
inspection. `ProofAdmittedBatchInput::admit` nevertheless calls that synchronous
virtual method first and checks its returned work against `max_proof_units`
afterward. The check limits the returned number, not the computation used to
obtain it.

The registered interface in `crypto/block/workchain-execution-dispatch.h`
also supplies authenticated engine configuration. Registration in
`workchain-execution-dispatch.cpp` checks structural registration conditions;
it does not establish an implementation-specific complexity bound.

`crypto/block/workchain-host-input.h` bounds materialized input cells, bits, and
roots before proof inspection. That provides a finite physical input domain,
but does not by itself bound a callback's traversal: revisiting shared subtrees
can multiply logical work far beyond the number of distinct cells. Nor does it
bound arbitrary loops in native code.

Therefore C3 is missing an engine-specific algorithmic contract, implementation
enforcement/audit, and acceptance evidence. It is not merely missing a timing
sample. There is no registered production account engine in this baseline to
which a universal concrete inspection formula can honestly be assigned.

### Minimum closure

1. Name the engine implementation and exact admission profile. Define a checked
   deterministic operation and auxiliary-storage bound as a function of already
   admitted sizes and authenticated business parameters. State which operations
   are counted. A prose promise that the callback is bounded is insufficient.
2. Establish that the implementation obeys that bound: deduplicate shared-DAG
   visits where appropriate, or explicitly cap logical visits; check limits
   before expensive work/allocation. Count malformed and failing attempts too.
   Recounting after an unbounded traversal does not enforce a bound.
3. Make the complexity obligation part of registration for that implementation
   and profile, rejecting missing/unsupported contracts. A registration field
   alone cannot constrain arbitrary C++; require a reviewed implementation and
   independently checkable controls, not an unverifiable self-report.
4. Exercise deep/shared structures, repeated references, maximum admitted
   shapes, late malformed data, and auxiliary storage. Include a valid positive
   case and controls that omit a visit charge or the relevant traversal bound.
   A lowered formula must fail against an independent observation, not against
   another copy of the formula.
5. Keep provenance explicit: a candidate exceeding an authenticated shape rule
   is invalid; failure of the local implementation's counting contract or true
   allocation failure is local. Exception shape alone does not identify whose
   bytes were being inspected.

No new wire coefficient is inherently required if the operation bound follows
from existing authenticated dimensions and a fixed profile algorithm. A new
independent budget or changed profile semantics requires an explicit decision;
do not retrofit v2/v3 or silently change the meaning of v4.

### Dependencies, effort, and B's role

C3 first needs a concrete input format and engine inspector. It does not require
C2's accumulator to derive a per-inspection bound. Final closure does require
C2 to bound how often inspection can occur, and an inventory of work outside
the proof wrapper so that bounded inspection is not mistaken for bounded total
execution.

Estimate: **1–3 working days for a fixed, simple engine format**, including
controls. A missing real account-engine parser/implementation makes this a
larger, days-scale task whose total cannot be estimated from the abstract
interface alone. A owns the host registration boundary; the engine author must
supply the actual algorithm and bound. B can independently audit traversal and
failure cases. B's participation helps but is not a substitute for specifying
the concrete inspector.

## What C1/C2/C3 do not prove

C1's main mechanism already exists; closure requires applying it to the concrete
path and evidence, not rewriting its formula. See
`doc/uno-v2-proof-operation-profile.md`, especially its concrete-engine binding
limitations. The existing operation trace is evidence for the reviewed backend
algorithm, not a universal execution sandbox.

A meter cannot discover that an engine built the wrong cryptographic statement,
bound a request to the wrong candidate/context, or simply omitted verification.
Those obligations belong to the concrete engine's admission/request construction
and the validator's independent validation, with their own controls. SEND/COLLECT
relation correctness belongs to the relation/M3 work and D34's external
cryptographic review gap. Primitive/patch acceptance in M2 is not an external
oracle for those new relations. C2 aggregation and C3 complexity do not close
any of these correctness obligations.

Ownership is not evidence of enforcement. At this baseline, the missing concrete
live account-engine path means that correct request construction and mandatory
verification on that path have **not** been established. Existing private
controls must not be promoted into that claim. This is an explicit correctness
acceptance gap for the concrete engine and its independent validator integration,
not a hardware-capacity task to defer to M6. Before declaring that path ready,
assign and test these obligations: substitute the wrong candidate/context while
retaining a well-shaped request, and omit a required verification call; each
must fail at an independent binding/completeness assertion. A meter that records
zero calls is not that assertion. No new mechanism is implemented or presumed
approved by naming this gap here.

## D45 reachability remains a separate incomplete measurement

Coordinator update: the measurement target is the shared
`WorkchainExecutionRegistry::validate_required_workchains` readiness boundary,
not four independently reachable seams. Its host call sites on this baseline
are `validator/impl/validate-query.cpp:1129` and
`validator/impl/collator.cpp:2285`. The AccountBinding refusal is in
`crypto/block/workchain-execution-dispatch.cpp:809`. Both host call sites route
its error through fatal_error; that local-abstention classification is unchanged
and is not a subject for reclassification.

For the account-binding path, all four remaining visitor refusals are downstream
of this readiness boundary. Treat readiness closure as one shared prerequisite,
followed by the distinct host connections and their independent validation
obligations. Do not estimate four independent frontier-opening exercises. The
coordinator's staging question remains undecided; inclusion in scope is not
permission to open, bypass, or weaken the boundary.

The next passive measurement must record entry to the required-workchain check,
successful resolution to the AccountBinding family, and the particular readiness
refusal, followed by the final typed local result. Merely seeing -7201 or entry
to the function cannot distinguish this refusal from earlier registration or
configuration failures. Downstream visitor counters must remain zero; record
transactions, candidate export, and telemetry delivery separately. Observer
calibration must not remove the readiness refusal to manufacture reachability.

Historical evidence already contains the collator call chain through this gate:
`doc/measurements/uno-v2-first-seam-adapter-identity/trace.json` records
resolve_account_binding -> resolve_scoped_workchain ->
validate_required_workchains -> Collator::fetch_config_params. Its README
explicitly identifies a checkpoint based on `3822c76ed`, not current-source
evidence. It is useful for choosing observation points, not for claiming a fresh
run. A source-bound real multi-account input for the current tree is still
needed; the older node-link smoke stops earlier and cannot substitute for it.

Accordingly the remaining measurement work is one readiness-frontier study with
host-specific observations, not four gate-removal probes. An executable fixture
and calibrated observations are prerequisites to estimating its runtime effort;
the C2/C3 algorithm estimates above do not include this missing fixture work.

The historical five-counter sequence was measured on Collator, not on all four
current seams. Current source places collator's execution visitor after its old
state/validator-set stages; validator's configuration visitors precede its later
old-state processing, and its transaction visitor is later still. Earlier
registry refusals can prevent those visitors from being reached.

These are source-order observations, **not** fresh counterfactual measurements
showing what each of the four changes makes reachable. B has confirmed that its
completed genesis evidence does not supply a real multi-account candidate and
typed validator outcome for that measurement; singleton fixtures do not replace
it. No seam is thereby declared safe to connect. The four-point mapping remains
open, all refusal points remain unchanged, and this survey does not create an
isolated-test exception to D45.

## Follow-up: what currently limits an attacker's leverage?

Source-only follow-up on the same integration baseline. No attack run or fresh
runtime reachability measurement was performed. Scope: the consensus candidate
broadcast -> Simplex validation-request -> manager facade -> ValidateQuery path.
This is not an audit of every network parser or all node RPC endpoints.

### Restrictions that actually exist

- `validator/consensus/private-overlay.cpp:255-284` rejects unknown peers and
  deserializes before publishing CandidateReceived.
- `validator/consensus/types.cpp:129-137,157-177,209-214` checks the expected
  scheduled leader, candidate sizes, and that leader's session-bound signature.
  The schedule is derived from the validator set in
  `validator/consensus/simplex/collator-schedule.cpp:21-35`. Thus an arbitrary
  outsider cannot generate unlimited distinct authenticated proposals for an
  arbitrary slot without the relevant key. This does not prove a financial
  admission cost, or an inability of a malicious scheduled validator to attack.
- `validator/consensus/simplex/consensus.cpp:163-207` rejects too-future slots,
  ignores already-notarized slots, and retains the first pending candidate for
  a slot **before** starting asynchronous notarization. A second same-slot
  candidate returns without starting that task, whether identical or conflicting.
  Rejection in `try_notarize` at lines 249-258 does not clear that pending entry.
  `simplex/state.h:41-65` rejects finalized old slots and removes their state.
  This is meaningful same-session, same-slot execution deduplication, not a
  permanent process/restart-wide denial record.
- The source search finds one `publish<ValidationRequest>` in this consensus
  tree, at `simplex/consensus.cpp:247`, after parent resolution and the applicable
  minimum-block-interval wait. `block-validator.cpp:96-105` routes that request
  through `bridge.cpp:46-52` to the real validation actor.

These facts refute an unrestricted "replay this broadcast repeatedly and each
copy starts full validation" description of this path. They do **not** show a
safe rate across leader windows, sessions, shards, restarts, or outstanding
tasks. The future-slot filter is relative to the current window, not by itself
a global bound on outstanding validation CPU. Size caps bound bytes, not the
inspection amplification of those bytes. Candidate parsing/signature checks
also precede the pending-slot filter, so execution deduplication does not make
repeated ingress free for receivers.

### Cost and punishment

The submitting validator must possess the scheduled signing key and construct,
sign, and transmit candidate bytes. No source inspected establishes that doing
so costs as much as the recipients' validation, or requires constructing a valid
expensive proof. Recipients perform parsing, state acquisition, and validation
on their own CPU/memory; rejection does not reimburse them. Multiple validating
nodes may independently incur this work for one proposal.

`simplex/consensus.cpp:249-258` emits a MisbehaviorReport for CandidateReject.
`validator/consensus/misbehavior-reporter.cpp`, including its actual handler,
records an allegation fingerprint and LOG(ERROR). It does not submit a slashing
transaction, debit stake, or remove the proposer from the schedule. Its header
explicitly identifies on-chain handling as unimplemented. Therefore this report
path is not evidence of an economic penalty for expensive invalid candidates.
This finding is bounded to that path, not a claim that the repository has no
staking contracts or any other punishment mechanism.

The 60-second request deadline in `block-validator.cpp:105` is also not a
deterministic CPU-work cap. `ValidateQuery::alarm()` at lines 122-126 is an actor
callback (and defers while parallel account validation is pending). It cannot
be treated as preemption of an arbitrary synchronous `proof_work()` loop.

**Conclusion:** identity, slot scheduling, and pending-slot deduplication limit
opportunities on this path. No demonstrated economic disincentive or sustainable
worst-case load bound follows from them. "Nothing limits the attacker" is too
strong; "existing limits make the attack unprofitable or sustainable for honest
hardware" is also unsupported. Current closed account-execution gates remain
the barrier to exposing the proposed deeper work surface.

### Revised closure and estimate boundary

The earlier C2/C3 lists are necessary mechanism conditions, not sufficient
permission to move D45 refusals. Add a joint exposure obligation: establish the
maximum rate and concurrency of costly attempts across the actual ingress,
candidate scopes, sessions/retries, and shards, then combine that with the
per-attempt work and simultaneously retained memory bounds. Demonstrate the
result is tolerable under the chosen threat model, or adopt an explicitly
approved additional exposure restriction. A claim of economic deterrence would
instead need a real enforceable cost/penalty path and its evidence; telemetry
does not qualify. This survey does not select charging, slashing, rate limiting,
or another new protocol policy.

Required controls include repeated same-slot proposals not starting extra
verification, and distinct eligible slots/instances exercising the aggregate
exposure boundary rather than accidentally reusing that dedup guard. Restart
and concurrent-instance behavior must not be inferred from a single actor run.
Concrete engine mandatory-verification and request-binding correctness remains
the separate prerequisite described above.

The earlier 1–2 day C2 and 1–3 day C3 estimates cover mechanisms only. They are
not estimates for this enlarged safe-exposure closure. End-to-end ingress and
concurrency evidence requires additional investigation; hardware sufficiency or
a new protocol restriction cannot be honestly estimated before the coordinator
chooses that scope. B can independently audit ingress/session boundaries while
A traces host execution, if that work is assigned. No such parallel task or new
mechanism has been initiated by this read-only survey.
