# Confidential workchain V2 implementation

Scope: implement the V2 specification in `/home/tomi/memo/TOS_UNO_PRIVACY_WORKCHAIN_V2.md`, with milestone review and corrections before claiming completion. This plan records implementation evidence, not deployment approval. Amounts are confidential; counterparties and transfer relationships are public.

## Authority and current decisions

The owner-fixed D31/D32/D33 mechanisms govern implementation. Byte encoding and
tags within those decisions are authorized; different mechanisms and hidden
local defaults are not. Real-value deployment and irreversible external
operations remain separate from coding.

Current specification/decision baseline: memo `7bc71109`, including D31-D33
and the delegated Deposit-bound clarification; earlier component work used
`274258e5`. Operation fees now follow D24/D25/D32: no public payer,
user-authorized confidential debits flow through custody, with at most one
aggregate accounting settlement per batch and no fee message. D26 congestion
allocation remains an activation obligation, not a property of fixed fees or
admission limits. Process the authenticated inbox against open withdrawals
before closing remaining expired records. Rich bounce messages return original
logical time for scoped matching. Retirement does not remove the workchain
configuration or custody while the native message lifecycle remains unresolved.

`created_lt` must be determined before committing effects. Allocate one transaction per affected account, with a common start strictly beyond authenticated host/inbox timing and every affected account's previous transaction end. Within each account, assign outgoing message times in canonical order. The native wrapper must reproduce those values, never fill an uncommitted identity into state afterward.

The specification separately authorizes a payout and one aggregate operation-fee settlement per batch (D24). The current payout materializer implements only the first output; an amount exposure limit alone is not permission to emit additional messages. Existing obligations retain the settlement period and fee reservation committed when admitted; configuration changes govern new obligations, not retrospective reduction of existing reservations. These are implementation decisions to include in the next design review, not claims of completed host enforcement.

## Milestones and evidence

| Stage | Required outcome | Status |
|---|---|---|
| M0 | Consistent design decisions, configuration semantics and review | Existing design/review; implementation decisions tracked here. Production numeric calibration is not proven by research measurements. |
| M1 | Multi-account wire, one logical execution, exact account coverage, native settlement, version gates, independent replay and synchronization | In progress. Private settlement/replay and outbound queue components exist; dual Native destination admission is integrated. Multi-account execution is not integrated into live collator/validator. None of these component results closes I13 acceptance. |
| M2 | Complete deterministic relations, system encryption, prover/verifier, ABI and supply-chain gates | Kernel, separate wallet prover, patch-layer differential, RNG and supply-chain deliverables are integrated through `9556ab05d`. Optional verifier node-build linkage with execution gates closed remains an integration acceptance item. Deliverable completion does not establish cryptographic correctness or deployment authorization; this row does not mark the milestone complete. |
| M3 | Registered accounts, real candidate source, SEND/COLLECT and pending lifecycle | Not accepted. |
| M4 | Native deposits and fee isolation | Not accepted. |
| M5 | Withdrawals, matched/late returns, reservations and settlement ordering | Not accepted. |
| M6 | Capacity, minimum hardware, state acquisition, lifecycle and migration | Not accepted. |
| M7 | External review and restricted public testnet evidence | Not accepted; no public deployment performed. |
| M8 | Real-value activation gates and operational rehearsal | Not authorized by a coding request. |

## Current integration boundary and next sequence

### Owner-directed sequence after opt-in harness registration

The private I13 harnesses have a separate, manual-only CI entry point:
`.github/workflows/private-i13-acceptance.yml` (`workflow_dispatch`). It
explicitly includes their modules, builds the three targets and selects only
the `i13` label. Both the registered names and the JUnit execution results must
contain exactly the three expected tests; skipped, missing and failed tests
are errors. There is no push, pull-request or scheduled trigger. This manual-only
policy is the owner's decision of 2026-09-09, not an unfinished task. Ordinary
"full regression passed" statements do **not** include these private harnesses;
their separate manual run and result must be cited explicitly. This entry
point does not change default builds, register engines or enable execution.
Merge `eea0e04df` integrates the reviewed registration modules. The same opt-in
configuration lists zero private I13 tests before integration and exactly three
afterwards; the registration assertion rejects the former and accepts the latter.
This is a registration-only check, not a run of the private harnesses or hosted CI.

After the three private I13 harness modules have registered their Python
drivers and demonstrated failing CTest controls, A first resumes the thin
end-to-end connectivity smoke, then I13b, then I13a. B owns I13e publication
work. This sequence supersedes older scheduling paragraphs below; it does not
waive outstanding resource-admission prerequisites or authorize opening a gate.

- Connectivity must use objects constructed by the production path. Record
  the actual stopping point, counters and side effects; private fixture assembly
  is not runtime connectivity evidence. If a closed gate or incomplete resource
  admission prevents progress, report that boundary rather than bypassing it.
- Run connectivity with `TOS_UNO_CRYPTO_NODE_LINK=OFF` and `ON` using the same
  source, authenticated fixture and all other build settings. Actually build
  the node in both modes. Record the registered engine identities (separating
  any explicit test-probe registration from production registration), actual
  capability/profile values, execution-gate state, stopping point and side
  effects. Linking must add zero registrations and make no additional
  workchain-2 execution path reachable. Any difference in these observations
  is a stop-and-report finding, not an implicitly harmless linkage effect.
  Symbol retention alone does not establish runtime reachability isolation.
- I13b requires a host-owned ledger created at candidate-block processing entry
  and destroyed at its end, keyed by the admitted input root hash. Enforce it
  at the stateful engine entry, rejecting a second execution in that scope.
  Independent validator replay has its own scope. A per-call or process-global
  ledger, or counting token copies, does not satisfy this contract.
- I13a requires a bounded scan of all workchain-2 AccountBlocks, extraction of
  actual batch identities, uniqueness enforcement and an independent count
  compared with the claimed committed count. Never use the claim as the source
  of truth. Isolate the guards with three controls: one identity with a wrong
  count; two identities with the correct count of two; and a second identity
  outside the first scanned account. The last must detect premature scan exit.

No capability/profile activation is authorized by these tasks. Preserve all
existing activation gates. Changes to live consensus judgement receive review
at their delivery boundary, not only at milestone completion.

### Revalidated dependency frontier at `31e6ad1f5`

The following source check supersedes historical component-level next-step
statements, including the final joint-pair paragraph below. The full mixed
payout/disposal overlay already exists in `workchain-payout-overlay.h`:
preparation runs once, the coordinator's actual output count feeds the final
LT schedule, and all reconstructed participant messages enter the export list.
`NativeDisposalEntry` in `test-workchain-block.cpp` exercises the runner,
independent replay and private outbound queue construction for three outputs;
it also checks actual-source deferral. Reimplementing that connection would not
advance M1.

The remaining dependency frontier is:

#### Live wiring: required evidence in the same delivery

These are acceptance obligations, not assertions that the private components
already satisfy the live path. Do not defer their tests until after wiring.

- [ ] Bound inbound collection using the same authenticated `max_inbound`
  before growing the caller's array. For a source with a known excessive count,
  observe zero collection-workspace allocations and demonstrate failure when
  the check moves after allocation. For streaming discovery, state and test the
  separate bounds on retained entries and probing the first excess item; do not
  claim zero total allocation when earlier entries were legitimately collected.
- [ ] Encode source provenance in distinct candidate/ authenticated-inbox types,
  with restricted construction at the authentication boundary. A candidate's
  `InMsgDescr` is not authenticated state merely because it parses. Passing it
  directly to an authenticated-inbox API must fail to compile, or fail an
  explicit provenance check with a demonstrated negative control. Malformed
  candidate data must reject, not produce an abstention or authenticated-state
  corruption alert. An installed unsupported profile remains a different case:
  local execution unavailability, not an invalid candidate.
- [ ] Admit old-state closures and proof work independently from the authenticated
  policy. Sharing does not relax per-account closure limits. Input logical roots
  are not a state budget; `max_proof_units` is not the D28 fee-unit schedule.
  The total state meter must include ShardAccounts lookup/absence paths as well
  as selected account wrappers. Measuring only returned account values after
  dictionary lookup misses the first state reads and does not satisfy D31.
  Compare serialized block-state proofs for the same input with metering on
  and off, including repeated/shared reads, as part of the singleton byte
  comparison. A negative control must bypass required usage tracking and make
  that comparison fail. Merely moving a wrapper is not necessarily a faulty
  mutation: a wrapper that preserves tracking may remain byte-identical.
- [ ] Exercise nonempty declarations through the session itself: count/leaf
  rejection, thrown parser errors, and write-role constraints, with typed
  results and runnable mutations. Standalone inspector tests do not prove this
  connection. The current new fixtures are in flight, not accepted live evidence.
- [ ] Demonstrate the section 9.3 order in both live paths: bounded parsing and
  admission, commitment, complete inbox, state, proofs, ordered execution,
  wrapper/value-flow reconstruction, atomic publication. Move checks across a
  boundary and observe failures using actual loads/allocations/engine calls,
  not only error wording. Shallow declaration counts do not certify canonical
  encoding, write-subset semantics, or permission to execute.

The dependency order below remains unchanged.

The reviewed private acquisition-boundary cut confines known Native
exceptions from old-account lookup, record decoding and closure traversal to
local failure, without enclosing candidate Cell decoding or the engine
callback. The closure captures only the old source, decoded declaration values,
access ledger, the old-source prototype dictionary and state-policy/meter
objects. The unmetered prototype preserves its prior exception semantics.
This narrows the private runner's exception gap;
it does not authenticate a raw Cell ref or authorize live execution.

Caller enumeration for this cut finds four detail::execute invocations: the
complete-input wrapper, the retained prototype wrapper, private settlement,
and the test's oversized-state-policy case. The prototype passes no state
policy and deliberately bypasses the new catches. Eight source exception
controls, a broad-engine-catch control and a two-arm explicit-capture compiler
control have been recorded; the instrument's ambiguous-brace restoration failure
is recorded separately and excluded from successful mutation evidence. Four
restored-source regression tests passed before review. Review follow-up added
prototype exception bypass and returned mismatch classification with
red-capable behavioral assertions. Explicit acquired-slice format predicates
now distinguish AuthenticatedStateCorrupt from provider exceptions; generic
Native parser/provider VmError remains LocalUnavailable rather than guessing
whether the decoder or the loader raised it. This is not an exhaustive format
corruption classifier. Root, record, both sibling-augmentation and late closure
fixtures pass. Seven final-logic runtime controls each built successfully and
failed the intended behavior/type assertion. The inner capture list now also
has a two-arm compiler control, alongside the earlier outer-list control.
Capture-list mutation evidence is manual, not a recurring CI enforcement of the
explicit lists. This boundary
contains the listed exceptions, not process-aborting CHECK failures; the direct
runner does not have settlement's nested-usage observer guard. See the
`measurements/uno-v2-state-acquisition-*.json` evidence cuts, including the
followup and structural-positive records; the earlier boundary-only glob did
not include those later files.

Focused follow-up review accepted the scoped classification mechanism and
required sibling-augmentation controls plus final-source mutation evidence.
Both sibling fixtures are now present (invalid fork tail and missing leaf
extra). The review's statement that no positive artifact covers the three new
code hashes is superseded by `uno-v2-state-acquisition-structural-positive.json`,
written during that review: it records those exact hashes and the completed
build/regression runs. The reviewer was asked not to run a binary while its
build was in flight; its report is static review, not an independent rerun.
This correction does not turn the earlier mutation records into evidence for
later source. Final-source production targets and all four regression tests
passed after restoring the exact pre-control headers; final-controls and
final-restored records retain the logs and hashes. These are author-executed
controls after static review, not an independent reviewer's runtime rerun.
The prototype exception fixture depends on Native initialization loading its
root edge once and lookup loading it again; the observed count and mutation
establish that behavior for this source, not for future dictionary revisions.
The redundant augmentation advance check cannot fail under chk_size and has
no independent red claim. Error reasons use static-lifetime literals.

Source-path audit correction: ValidateQuery's full_collated_data_ starts false,
and both assignments that would enable it are commented out. Thus its virtual
candidate-proof replacement branch in compute_prev_state is currently inactive,
not a second live acquisition path. Actual previous-state roots arrive from
Manager or the consensus ChainState preloaded vector. A future activation of
that proof branch must preserve witness provenance; do not apply a local-source
classification merely because a virtual proof has an authenticated root hash.

Old-state acquisition is in flight. NativeStateReadMeter preserves the complete
LoadedCell and always calls the source loader, even when its content hash was
already charged. A shared/repeated-read MerkleProof fixture produces identical
serialized bytes with and without this meter. Clearing the loaded usage node
makes that byte comparison fail; evidence is in
`measurements/uno-v2-state-read-usage-control.json`. That first control alone
does not establish a real collator block-state proof comparison, ShardAccounts
lookup admission, or per-account closure limits. The latter two now have the
private-path connections described below; live proof comparison remains open.
The Native dictionary first validates its root augmentation, which loads
the dictionary root edge; admission must cover that load as well as lookup
branches. A second UsageCell wrapper must not replace the existing proof tree.
The metered lookup now prewalks the key path before calling the unchanged
Native semantic decoder. Its two-account fixture compares existing, absent and
repeated lookup results and proof bytes with the Native-only path. Removing
the prewalk accepts a lookup that only has budget for the wrapper; the typed
limit assertion fails. This control is recorded separately in
`measurements/uno-v2-state-lookup-control.json`. The complete-input private
runner and strict settlement now pass the admitted policy's state record into
this acquisition path. Per-account closures use independent visited sets and
limits while sharing the aggregate physical meter. Aggregate exhaustion is a
candidate rejection; a persisted account outside its installed closure policy
is AuthenticatedStateCorrupt (local failure). Prototype singleton callers remain unchanged. These
connections are in flight; proof-work admission and live authorization are not
granted by them.

State-reader review follow-up: ordinary dictionary reads and opaque encoded
Native closure reads now have explicit entry points. Both reject virtualized
pruned stubs as unavailable content before charging or returning them. This
does not impose the ordinary-candidate profile on all Native state. Interrupted
loads retain the same local code as their exception boundary; physical usage
has only cells/bits, with no misleading zero logical-root field. Closure
traversal visits each local content hash once; depth-12 and depth-20 diamond
fixtures produce 13 and 21 loads. Usage-tree memory depends on bounded path
visits and at most four child pointers per visited node, not merely on global
distinct hashes. The removal and cache-introduction controls and focused review
are recorded below; none is live execution authorization.

The restored private-state unit currently passes the block, admission, disk
integration and account-binding readiness CTests (4/4), and the removed-domain
scan. `measurements/uno-v2-state-admission-controls.json` records the exact
restored source/binary hashes, those results, and three independently rebuilt
negative controls. They remove state-policy forwarding, virtual-pruned content
rejection, and per-account DAG dedup respectively. Each builds successfully and
then fails a behavior/type assertion. This is evidence for those particular
guards, not a claim that every new failure branch has mutation coverage.

The next in-flight connection pre-admits the old sibling augmentation needed
by Native ShardAccounts replacement. A declared write selects replacement-path
admission; a read-only declaration retains read-path admission. Each fork adds
the opposite node's extra-value closure to the same physical state meter,
excluding its account and child-dictionary references. The extra-value decoder
does not load children before the meter; Native replacement and independent
dictionary difference remain the semantic implementations.

The new three-account, three-extra-currency fixture compares all observed old
loads during admission/replacement/difference with charged hashes and separately
requires unrelated account roots to remain unread. A full-input runner fixture
allows all read-only paths/closures but not replacement dependencies and checks
rejection before any engine invocation. These tests are in flight, not complete
settlement or live acceptance. At most 256 sibling augmentations are requested
per declared write; each extra closure uses a visited set bounded by the shared
state-cell allowance. Repeated traversal work can still be proportional to
writes times key width times the admitted state cells. Physical deduplication
does not itself meter semantic currency arithmetic, temporary output allocation
or justify a production CPU limit. Four rebuilt removal/substitution controls
fail: omit siblings (loaded/charged 10/6), omit extra-reference closures (10/8),
force read-only engine dispatch (over-budget batch accepted), and follow the
entire sibling payload (unrelated account loaded). Restored four-target build,
four selected CTests and domain scan pass; raw outputs and hashes are in
`measurements/uno-v2-state-replacement-dependency-controls.json`. Focused review
and the explicitly retained live-enablement blockers are recorded in
`uno-v2-state-replacement-review-disposition.md`; this connection does not open
the live execution gate. Follow-up retains that leaf fixture and adds a fork
sibling, nested overlapping currency dictionaries and two sequential writes.
Omitting deep-reference traversal fails on actual/charged counts 17/14.
The fork-tail negative witness fails before the exact Native-compatible decode
fix, and restoring the implicit Read default fails the compile-time assertion.
See `measurements/uno-v2-state-replacement-deep-control.json` and
`measurements/uno-v2-state-replacement-review-controls.json`. These are manual
one-shot controls, not recurring mutation CI or a complete host CPU bound.

Live settlement must also account for reads after engine execution. Before the
observer cut below, the private meter ended before the allocation/payout overlay, whose Native
dictionary lookups and independent `scan_diff` still use their original read
interfaces. Pre-admitting declared account closures does not alone prove that
every overlay/augmentation/difference read is inside the admitted union or
that all traversal work is bounded. Closing that boundary (including proof
tracking) remains required before enabling the live path; an engine-entry
budget test is not evidence for the complete settlement lifetime.

The next in-flight cut retains the private engine's state meter through
settlement and installs a stack-scoped observer on its existing CellUsageTree
(or creates one only for an otherwise untracked private source). The observer
checks every old-source read against that union before the underlying load,
including nodes loaded before the scope and loads ignored by proof marking.
It does not replace the first-load callback or nest UsageCell wrappers on an
already tracked root. An out-of-footprint access aborts the private attempt as
LocalUnavailable, not CandidateInvalid; no settlement artifacts escape.
The admitted union is by content hash, not by usage path. A separate
pre-acquisition observer detects encountered nested live wrappers, including
tracked descendants below an untracked root, before Native's nesting CHECK.
The observer interface no longer exposes a mutable tree owner. Private tree
ownership must remain local; returned weak usage nodes go inert when it ends.

This is enforcement of the pre-admitted physical footprint, not a new allowance
for late reads or a CPU-work budget. The observer retains no Cell cache, allocates
no per-read state, and uses the existing ordered admitted-hash set. One private
settlement installs one observer. Existing Native algorithms must preserve the
source usage nodes; reads deliberately stripped of tracking are not made safe
by this observer. Full-block proof comparison, source authentication types and
the remaining exception boundary are still live-enablement obligations.
Focused re-review closed the first review's M1-M5 findings. Four follow-up
controls plus direct final-source union/hook controls reached their expected
failures; the final restored regression is recorded with source hashes. No live
acceptance change is claimed. First review findings and current follow-up
status are in `uno-v2-settlement-read-observer-review-disposition.md`.

Second-reader O5 needs a narrower interpretation. In `CellSlice.cpp`,
`load_cell_slice_impl` performs the virtual-pruned availability check first,
then accepts encoded special cells when `can_be_special` is supplied. The
later "trying to load prunned cell" rejection belongs only to ordinary loads.
The state meter follows the encoded branch: it counts the actual encoded
pruned Cell, never the hidden subtree it commits to, and follows present refs
with Native effective-level semantics. This is storage acquisition, not proof
verification or permission for the engine to read unavailable content. Calling
special cells "opaque" meant no interpretation/library resolution, not omission
of their present child refs; that wording needs to be explicit in the API.
A proof-shaped-cell fixture now exercises this distinction: two encoded Cells
use 568 bits, while virtualized hidden content returns local unavailability.

Second-reader B1's specific alternate-path failure claim is disputed after a
direct Native-code check and counterexample: `MerkleProofImpl::dfs_usage_tree`
collects visited content hashes and `dfs` uses that set, rather than pruning
independently by usage-tree path. The depth-12 and depth-20 accounting fixtures
now extract a proof and read reference 1 at every level although accounting
first visited reference 0; both reach the expected leaf value 9. The test passed
after rebuilding. The proposed failure does not occur on this shared DAG.
The fixed traversal order remains explicit and mutation-tested, and this result
does not claim all later block-state accesses were admitted or tracked. A
dedicated missing-proof negative control now fails the alternate-path read.

Follow-up controls now exercise the three previously unexecuted runner verdicts:
lookup-local failure, closure-local failure, and aggregate exhaustion reached
only after the lookup fits. Each one-branch error-code mutation builds and fails
its own code assertion, with zero engine calls. Persisted-state/policy mismatch
is separately reported as AuthenticatedStateCorrupt, not merged with missing
local content. Five state zero fields now fail resolution and installation;
each new resolution test failed before the predicate was extended.

`uno-v2-state-traversal-order-control.json`,
`uno-v2-state-classification-branch-controls.json`,
`uno-v2-state-meter-boundary-controls.json` and
`uno-v2-state-special-proof-controls.json` under `measurements/` record the
follow-up evidence. The special-proof controls reject a blanket ban on encoded
pruned cells and fail when the alternate-path proof is replaced by unavailable
content; both were restored and rebuilt successfully. Meter source caching
reduces callbacks from five to four and fails the test; removing sticky failure
increases source loads from one to two and fails. Cell/bit controls were rerun
with explicit variant assertions rather than incidental bad_variant_access
diagnostics; both fail at those assertions. The restored final tree builds the
block/admission/collator/validator targets, passes all four selected CTests and
the domain scan. Exact hashes and output are in
`measurements/uno-v2-state-final-admission-controls.json`. Focused disposition
review closed B1-B3 and withdrew the alternate-path and encoded-pruned claims
after checking Native source. That archive binds the reviewed cut; subsequent
R1/R2 controls will carry their own final hashes. No live readiness gate is
removed by this unit.

Review follow-up adds a direct raw-policy depth-70000 witness (local failure,
zero engine calls), and compares the successful lookup's distinct loaded hashes
against the meter's read-only charged set. Repeated Native loads are permitted;
an uncharged additional load is not. Removing the raw-policy depth guard accepts
the depth-70000 request and fails its error assertion; introducing an extra
unmetered account read makes loaded/charged sets differ (7 versus 5). Both
controls build successfully and fail with exit 1, then are restored. Final R1/R2
evidence, source hashes (including the legacy invariant comment), four-target
build, four passing CTests and domain scan are in
`measurements/uno-v2-state-review-residual-controls.json`. The five added installation zero cases
passed, but their failure sensitivity is derived from the shared predicate's
five resolution controls, not separately measured installation mutations.

Per-account liveness requires every output wrapper to obey the same closure
bounds and configuration installation/migration to preserve readability of all
persisted accounts. These enforcement paths remain open. Classifying an
already-persisted oversized account as authenticated-state corruption prevents
a false candidate rejection; it does not restore liveness or prove such a
state cannot be installed. Old-state provenance types, the full eight-class
outer exception boundary, whole-settlement metering, proof/output admission and
real collator block-proof comparison also remain live activation obligations.

The reader review's proposed shared arithmetic refactor is deferred, not a
confirmed underflow fix: legacy WorkchainInputPreflight starts usage at zero,
keeps limits/usage private, and increases bits only after a remainder check.
Those operations preserve usage.bits <= limits.bits. A future change could
break that invariant, but no current reachable counterexample was supplied.
Likewise, the ordered hash set is retained until its actual memory cost is
measured; replacing it with an unmeasured container is not this boundary's fix.

The complete-input adaptation now reaches the existing private account runner,
strict Native settlement and independent replay. The new overloads take
AdmittedBatchInput without a second caller-supplied declaration set or resource
cut; the engine receives that exact complete input root, not its candidate
child. Settlement compares the supplied context and Native inbox before reading
accounts or calling the engine. Replay compares the claimed input commitment
before entering settlement and returns rebuilt artifacts after comparison.
Six rebuilt controls remove forwarding, old-account comparison, context/inbox
agreement, replay commitment and rebuilt account comparison respectively; each
fails a state/hash/acceptance/call-count assertion. The final block/admission and
two disk CTests pass. Evidence:
`measurements/uno-v2-admitted-account-pipeline-controls.json`.

This is a private pipeline connection, not a live execution permit. Prototype
settlement/disposal callers still use singleton admission. Live collection,
independent old-state and proof-work admission, effect/output budgets, disposal
conversion and atomic publication remain outstanding. The new private overloads
retain enclosing-host preconditions and are not a safe substitute for completing
those steps. All live readiness refusals remain installed. No milestone or live
I13 acceptance criterion is closed by these tests. The focused replay-boundary
review found no defect blocking this development cut. Its follow-up obligations
remain explicit: enumerate the enforced policy fields, remove the private
template's independently supplied declaration set, account for repeated
canonical decoding, document locally finalized input provenance, add batch
payout coverage, and preserve source-based classification at the live boundary.
The current six controls do not certify these remaining obligations. Review
follow-up removes the batch template's second declaration parameter (only
nullptr is accepted), decodes the admitted declaration once, and shares that
object between execution and settlement. Clearing the decoded result makes
the real complete-input settlement success assertion fail. The six-control
archive retains its original source hashes; the follow-up control is recorded
separately in `measurements/uno-v2-single-declaration-control.json`.

In-flight account-binding dispatch now selects the dual-ingress family from
the authenticated policy, resolves its resource identity from that same Config,
and returns a distinct ResolvedWorkchainAccountBinding. It is not a singleton
execution or an admission permit. The required-role path explicitly refuses
execution readiness even when an account engine is registered and accepts its
configuration. All six live resolution sites now explicitly refuse this
family rather than selecting AccountCompute, including the two early shard-info
checks that previously discarded a successful resolved value. These temporary refusals must be
replaced by the full admitted path, not deleted to enable a placeholder engine.

The registered-engine role control removes that refusal and observes a real
fixture-engine call (1 rather than 0) in a test continuation. This establishes
the role API gate, not live actor side-effect containment: the continuation is
test code, and later live consumers still have their own explicit refusals.
Configuration decoding and callbacks already perform reads and allocations.
No zero-total-allocation or zero-total-state-read claim is made. The registered
disk-test probe now reaches the real collator, records one successful engine
configuration callback and zero execution calls, and checks that no candidate
archive is exported. Removing the earliest collator refusal observes a second
configuration callback and fails CTest; omitting the execution-counter update
fails the probe's separate self-test. The positive fixture runs in CTest, while
these mutations are manual. This is not validator-import coverage, an account
read counter, or a same-input cross-binary singleton byte comparison; those
remain required before this cut's full acceptance. Existing singleton disk
regression alone does not prove that stronger comparison. The initial probe run
overlapped a rebuild and is excluded as ambiguous; the archived removal control
waited for the build to finish. Evidence is in
`measurements/uno-v2-account-binding-live-controls.json`; the earlier in-flight
artifact records only unit controls.

Readiness refusal acceptance is separate from successful binding. The live
removal control above proves earlier continuation (a second configuration
callback), not live engine execution after removing a single gate: later gates
still refuse. Before replacing these refusals, add validator-side coverage and
account-read/publication counters, record configuration allocations separately,
and compare the old singleton artifacts for the same authenticated input across
the boundary. Zero engine calls and no exported candidate alone are not proof
of zero state reads, zero allocations, or zero side effects.

First binding review disposition: the ignored-value entry points (F1) now visit
the returned family explicitly. Account callback VmError/VmVirtError are now
tested through both live resolution and required-role checking (F3), rather
than borrowing the singleton fault sweep. The role wrapper deliberately assigns
local classification to policy failures: its public code assertion does not
pin the internal arm's original code (F2), and no such mutation coverage is
claimed. Do not replace that assertion with error-text-only evidence. The
duplicate table lookup is removed (F6). Configuration work is measured, not
called free (F4); missing-account-engine diagnostics and duplicated temporary
refusal text are not security findings (F5/F7). The removed direct scoped-error
assertion is replaced by successful Config-only binding coverage through that
same descriptor resolver, not an assertion that the old failure remains (F8).

Follow-up review found no correctness defect in the dispatch and disk probe.
Its scheduler-shutdown observation is fixed: the instrument self-test uses
_Exit, as the surrounding actor tool does, after the counter file is written.
Validator-import coverage remains open (G2). The fixture's version substitution
still relies on successful authenticated configuration resolution and the exact
positive callback count rather than a separate textual marker guard (G3); this
is not claimed as independently mutated marker validation. Final regressions
are rerun after the shutdown change.

The reviewed live configuration-source boundary obtains both the descriptor
and policy from one caller-authenticated Config. Classification follows that
source, not a callback's error-code name: CandidateInvalid returned by a
configuration callback is a local contract failure. Configuration installation
remains a separate verdict boundary. Required-role checks run earlier and must
use the same guarded resolution; guarding only the later six scoped calls is
insufficient. A registered callback fault fixture observed eight escaping
exception classes before correcting this early path.

Caller inventory for this boundary: three collator and three validator scoped
calls use Config-only resolution. Required-role checks have three production
callers (collator, validator and validator-engine startup). The retained
map-taking scoped entry rejects any map not owned by the supplied Config,
including a different Config with matching descriptor contents. Low-level
descriptor resolvers remain test/component APIs, not provenance certificates.
The separate AccountCompute resolve_workchain path remains in transaction.cpp
and ext-message-checker.cpp; this change does not claim to convert those Native
paths to V2 admission. Multi-account resolve_account_binding now has live scoped
callers, but all consumers explicitly refuse execution readiness as described
above. Re-enumerate all callers when installing the next
boundary; this inventory is not permission for a future unguarded overload.

Follow-up controls separately reach the AccountCompute policy callback in the
required-role checker: an unsupported policy stays local, and CellCreateError
does not escape. The required-role mode precondition also runs before iterating
the map. Removing each of these checks fails a behavioral assertion. A first
role-map mutation incorrectly stayed green because the fixture lacked unpack
modes; after satisfying that independent precondition, the same mutation fails.
Do not count the earlier green run as protection. All mutations are restored;
`measurements/uno-v2-config-source-controls.json` records substitutions, outputs,
the corrected-fixture rerun and final source/binary hashes. Earlier in-flight
captures are historical, not the final regression. Manual mutations are not CI.

Review's ordinary-transaction missing-engine example is blocked first by this
check_transactions resolver; singleton block replay returns before ordinary
AccountCompute replay. This does not prove later repeated AccountCompute
callbacks cannot fail locally after a successful first resolution. Their boolean
transaction failure carrier and external-message admission remain separate
follow-up scope, not certified V2 execution or a claim of complete local-fault
containment. Keep actual reachability separate from the general classification
requirement. The unchanged descriptor identity consistency guard is not counted
as a newly reachable tested guard under Config parser invariants.

Final regression for this boundary passes the block/admission and singleton
disk tests and builds validator-engine. At that commit the repository-wide
removed-domain scan still failed on B-1 AUTO/ON/OFF build-wiring additions.
The separate reviewed guard revision `a574c6406` closes those omissions without
broadening the retired-symbol rules; six manual injection controls fail and the
final tracked-file scan passes. This is not evidence that every CI gate passes.

The configuration-source boundary changes two authenticated-configuration
failures from candidate rejection to local abstention. This is a real verdict
change, currently unreachable for a production non-test block engine because
none is registered. It is not a general exemption from release/version gates:
enabling such an engine on a deployed network requires the agreed deployment
and first-effective-block discipline; logging a newer global version does not
enforce readiness.

At `54a6fc9ac`, before introducing the multi-account execution alternative, four live dispatch
sites (two collator and two validator) and the earlier required-role policy
dispatch now use exhaustive typed visitors. There is no generic visitor that
can send an unknown family to AccountCompute. A manual control adds a third
variant: all three production translation units fail compilation at all five
visitors. This is deliberately a compile-time control, not a failed runtime
test or a new wire variant. Singleton replay and its exact AccountBlock guard
remained unchanged. The binding handlers described above supersede that cut's
pending dispatch work; early authenticated input admission and multi-account
execution remain unfinished.

Boundary review found no blocking behavior change. The control uses unrelated
`std::monostate`, not a type implicitly convertible to an existing alternative.
The archived compiler diagnostics identify all five visitor instantiations;
diagnostic cascades are not five independent defects. Overload exhaustiveness
does not enforce exact-type dispatch for a future derived/convertible type, nor
prove a new handler correct. In particular, returning nullptr for an account
binding would compile but incorrectly select the ordinary path: introducing
that binding must also replace the binary pointer-dependent execution decisions
and the producer's singleton-only resolution. The current variant cannot become
valueless here: successful results are constructed and never assigned/emplaced
before visitation; failed construction returns no value. No claim is made that
an arbitrary future mutable variant retains this invariant.

The review's out-of-scope candidate-enumerator exception observation needs
source-specific verification at the next admission cut, not a blanket new catch:
builder/allocation failures must not be turned into candidate rejection merely
because they occur during enumeration. Existing callback classification and
catch boundaries are unchanged in this unit. The restored block/admission and
singleton disk CTests pass. Evidence:
`measurements/uno-v2-exhaustive-dispatch-controls.json` (manual controls).

The singleton validator collection path now streams candidate-origin InMsg
slices instead of first allocating a cell and vector slot for every record.
It applies the existing 15-bit final-envelope count before retaining the first
excess final record; transit records consume no retained envelope slots. The
stream may inspect one excess record and then stops. Buffer growth is explicitly
capped at 32767 slots; old/new buffers may coexist during growth, and the bounded
legacy encoder copy is separate. The allocation control measures the largest
collection allocation, not whole-process RSS. This preserves singleton wire
semantics and is NOT V2 authenticated max_inbound wiring or a claim that full
Native dictionary traversal is now admitted before semantic checks. Candidate
enumeration is not an authenticated-state certificate. The V2 provenance types,
earlier admission stage and authenticated resource cut remain required above.

Boundary review found no blocking streaming regression. The comparison uses
the same encoder with an independently specified envelope list: it establishes
collection equivalence, not independent encoder verification. Repeated-envelope
overflow fixtures may also fail the duplicate check, so the evidence is the
allocation-size and visited-count assertions, not merely an error result.
Candidate dictionary VmError now rejects locally instead of escaping to the
outer abstention handler. A missing host enumerator is separately classified as
LocalUnavailable and the live caller preserves that category. Its new test
first failed on an escaping bad_function_call before the guard was added.
An additional injected host-callback VmError initially failed the local-failure
assertion. The generic callback now has a separate local-failure boundary from
candidate slice parsing. The live adapter captures only the candidate dictionary
pointer, not this/config/state, and locally classifies dictionary parsing errors.
This narrows the callable's available objects; it is not a proof against arbitrary
future global state access or a detached-arena provenance certificate. The empty
callback has an API-level test but cannot arise from today's live lambda literal.
Enumerator failure/re-entry and a validator-level targeted mutation remain
uncovered; the existing disk regression is not a dedicated live-path control.
Transit traversal remains uncapped here; 32767 bounds retained final envelopes,
not total visited InMsg records. No source certificate or V2 limit is inferred.
The retained vector compatibility API has no production callers. Its loader
exceptions now cross the generic host-callback boundary as local failures;
this is not full error-category parity with the old helper. Source-specific
classification and dedicated exotic-root tests for that compatibility API
remain follow-up work. Current live validation supplies candidate slices instead.
Post-fix evidence is `measurements/uno-v2-stream-import-final.json`; the earlier
`restored.json` predates review corrections. The separate
`uno-v2-stream-import-state-fault-red.json` records the host-fault classification
control, whereas `callback-red.json` records only the empty-callable control.

M6 minimum-hardware accounting must include auxiliary admission memory, not
only retained input bits/cells: materializer source/detached graphs, map nodes
and allocator overhead, traversal stacks, inbox sorting and collection arrays,
and declaration memoization. Per declaration role there is at most one completed
cache entry per physical trie cell plus 257 active frames; the more conservative
257-times-cell bound must not be confused with observed reachable occupancy.
Read/write caches are processed sequentially. Measure actual allocator/RSS
peaks together with the other simultaneously live objects and worker concurrency
before accepting authenticated max_cells on minimum hardware. Physical counting
does constrain these structures indirectly; it does not itself establish a safe
byte budget or justify a hidden local rejection threshold.

### M6 auxiliary-cost ledger (required aggregate acceptance)

The following costs are additional to retained input/state cells and bits.
Minimum-hardware acceptance must aggregate them with the main workload within
each dimension, not perform independent checks against the same memory or CPU
allowance. Neither table below is itself a column of byte costs to sum.

| Resident object | Cardinality envelope (convert to bytes before aggregation) | Source and qualification |
| --- | --- | --- |
| Declaration shallow-parser memoization | Historical conservative envelope: `257 * input.max_cells`; current structural bound: one completed entry per physical trie cell per role, plus at most 257 active frames | `crypto/block/workchain-account-access-codec.h`: peak bytes include entry, map-node and allocator overhead. Read/write roles are sequential; do not multiply mutually exclusive live caches. Retain the conservative envelope until tighter occupancy is validated on the measured implementation. |
| Inbox collection and sorting | `O(N_inbound)`, bounded by authenticated `max_inbound` before growth | `crypto/block/workchain-host-input.h` and the builder/collector in `crypto/block/workchain-block-execution.cpp`: peak bytes include collection and sorting arrays if simultaneously live, plus traversal/probe state; constructor-only bounds do not certify caller collection. |
| Private output admission | One union set bounded by `work_output.max_output_cells`, plus a per-account set bounded by `state.max_account_cells` and traversal workspaces | `crypto/block/workchain-account-settlement.h`: output roots share the union, but each new account closure is counted independently. Immutable continuation snapshots retain hashes, not cells; extending a copied snapshot temporarily retains both sets. Include set-node/allocator costs and simultaneous effects/state meters, not only the output cell payloads. This does not yet include queue/shard-update construction. |
| Queue-state continuation | Prior immutable state set plus its private copy, each bounded by `state.max_cells`; one temporary probe slice at a time | `crypto/block/workchain-outbound-queues.h`: snapshots retain hashes rather than source cells. Include set-node/allocator overhead and simultaneous output snapshots; the weak usage node does not retain the original state tree. |

| Repeated work | Cumulative count (not peak memory) | Source and qualification |
| --- | --- | --- |
| State traversal while rebuilding writes | Scaling term `O(writes * 257 * admitted_state_cells)`, not a complete operation cap | Account replacement and tracked reads in `crypto/block/workchain-storage-overlay.h`, `crypto/block/workchain-account-dictionary.h` and `crypto/block/workchain-account-settlement.h`: a 256-bit path may contain 257 nodes including its leaf. Include augmentation/probe work and measured constant factors; count lookup and closure-validation work independently of retained-state deduplication. |
| Effects dictionary construction | At most `259 * updates + 36 * transfers + 3` finalized cells | `encode_workchain_account_effects` in `crypto/block/workchain-account-effects.h`, dictionary `dict_set` path reconstruction, bound beside the encoder call in `crypto/block/workchain-account-settlement.h`. The third constant cell is the optional aggregate fee record; the legacy form still uses two wrappers. Use `updates <= max_writes` and `transfers <= max_transfers`; include simultaneously retained intermediate roots and allocator overhead separately in peak measurements. |
| Queue-state observer probes | At most one extra source load and one temporary CellSlice allocation per attempted tracked read | `crypto/block/workchain-outbound-queues.h`: physical hash deduplication does not remove repeated probes. Count dictionary-path revisits and allocator work separately; these are cumulative costs, not one retained slice per visit. Final Merkle-update reads remain outside this helper's scope. |

For memory, sum simultaneously live byte costs (including materializer graphs,
engine working sets and per-worker replication), then measure peak RSS. For CPU,
sum repeated visits, construction, parsing and verification costs over the block
and evaluate the longest dependency chain. Do not add byte counts to operation
counts, or assume cumulative allocation equals peak memory. All evaluated bound
arithmetic must be checked; overflow fails sizing, never wraps to a small budget.
This ledger installs no additional local rejection limit and is not a hardware
acceptance result. New auxiliary structures must extend it before M6 acceptance.

### D31 complete resource-field zero-semantics inventory

The three wire records contain 17 fields. Zero never means unlimited. This
inventory distinguishes a necessary configuration condition from the still-open
joint feasibility check (positive budgets can also be too small).

| Record | Fields | Zero interpretation / required installation treatment |
| --- | --- | --- |
| `UnoV2ResourceInput` | `max_cells`, `max_bits`, `max_roots` | Invalid: a batch has mandatory input structure and three fixed logical roots. |
| `UnoV2ResourceInput` | `max_reads`, `max_writes`, `max_inbound` | Invalid: an executable profile must allow state progress and Native ingress; zero is not a lifecycle pause. |
| `UnoV2ResourceState` | `max_cells`, `max_bits`, `max_account_cells`, `max_account_bits`, `max_account_depth` | Invalid: authenticated account access and complete nonempty wrappers must be possible. |
| `UnoV2ResourceWorkOutput` | `max_effect_cells`, `max_effect_bits` | Invalid: even empty business effects have mandatory encoded structure. Included in the current effects-boundary correction. |
| `UnoV2ResourceWorkOutput` | `max_output_cells`, `max_output_bits` | Invalid: mandatory Native output records cannot fit zero. Included in this correction; independent typed-admission tests failed before the fix, then passed together with the real configuration-installation test. |
| `UnoV2ResourceWorkOutput` | `max_transfers` | A zero cardinality allows no internal Native transfers, not unlimited transfers. It is distinct from payout/message counts; compatibility with required business operations remains an engine-policy check. |
| `UnoV2ResourceWorkOutput` | `max_proof_units` | A zero work allowance allows only zero-proof-work operations, not unlimited proof work. The pending proof-work admission must reject positive work before verification; this inventory does not claim that wiring exists. |

Configuration defects are rejected at installation; an unusable authenticated
execution cut is not relabeled as a candidate defect. Meaningful zero allowances
do not authorize silently disabling mandatory system progress. Compatibility
between these allowances and engine parameters still requires full validation.
In particular, the current effects encoder always emits two wrappers totaling
261 bits even without payloads. Positive allowances below that structural floor
are still not rejected by installation. This is a known pre-live compatibility
gap, not a valid configuration shown by the zero tests. Mandatory input roots
and account/output wrapper floors require the same compatibility audit.
Output-zero evidence is `measurements/uno-v2-output-zero-budget-before-fix.json`
and `measurements/uno-v2-output-zero-budget-restored.json`; this is configuration
admission evidence, not proof that runtime output/proof-work admission is wired.
Effect-zero pre-fix evidence is
`measurements/uno-v2-effects-zero-budget-before-fix.json`.

1. Authenticated resource policy and whole-input admission. D31 in V2 section 12
   approves the three resource groups and `3 + N_inbound` logical roots. The
   accepted structure is described at
   `/home/tomi/memo/UNO_V2_AUTHENTICATED_RESOURCE_POLICY_PROPOSAL.md`
   and separates input, old-state, proof-work and output limits. The resource
   object codec and derived tags are covered in
   [the wire boundary](uno-v2-resource-policy-wire.md); it remains unresolved
   wire data. The configuration boundary now checks framing, supported admission
   version and six nonzero input limits through valid_config_data, with a
   complete-config mutation control. Binding derives the typed policy and its
   identity from the same Config cut. Full limit compatibility and live whole-input
   admission remain unfinished; this is not completion of D31.
   D28 billing units must not silently become proof-work units.
2. D24/D32 authenticated operation-fee reconstruction. The reviewed private
   checkpoint `f5fca8779` now carries an optional fee record separately from the
   payout request: S transfers internally to coordinator and C+T enters Native
   fees_collected, with zero fee messages. The remaining work is not to build
   those transfers again. It is to resolve the explicit fee-enabled profile and
   business parameters from authenticated configuration, read the committed
   base_compute state, and reconstruct S/C/T from verified operations (including
   their proof-bound public fee). Compare each component before allowing the
   resulting debit and its matching N_book update. A decoded engine fee record
   is not an authorized fee schedule; neither conservation nor byte equality
   fills this gap. Withdrawal-specific reserves remain separate from F.
3. Live execution, independent replay and atomic publication. The validator
   still resolves the singleton scoped variant and enforces exactly its
   executor AccountBlock before `replay_resolved_workchain_account_block`.
   Private multi-account helpers and a successfully built queue are not a live
   replacement. Keep that singleton guard until an explicit new path exists.

The approved mechanisms no longer block resource wire work. Full authenticated
admission and legal configuration transitions remain required. Do not invent currency-count
limits to make the D29 bucket appear bounded, or treat missing authenticated
state as an invalid candidate. These boundaries are recorded in
`/home/tomi/memo/UNO_V2_D28_D29_IMPLEMENTATION_CHECK.md`.

This is a source-level dependency correction, not a new implementation or a
milestone acceptance. No resource values, TL-B definitions, exception classes
or live consensus predicates are changed by this update.

Revalidation on 2026-09-08: rebuilding `test-workchain-block` with `-j48`
and running `--filter +NativeDisposalEntry --verbosity 0` passed one existing
test (9.7073 ms reported by the harness). This is only the private integration
fixture, not network synchronization, live publication or a capacity benchmark.
That historical documentation-only update claimed no new mutation evidence.
Subsequent implementation evidence is recorded separately below and in the
resource-policy wire boundary document.

Source audit at `df73ed000`, after the reviewed dual-ingress development
snapshot; this section supersedes older per-component "next step" statements
below where later components already exist.

| Boundary | Current authoritative shape | Remaining connection |
|---|---|---|
| Dispatch | `ResolvedScopedWorkchainExecution` explicitly distinguishes account-compute, singleton block execution and account binding; all live binding consumers refuse readiness | Complete authenticated admission and replay before replacing refusal; do not reinterpret the singleton engine interface |
| Admission | `ResolvedInputPolicy::from_resolved_fields` accepts supplied fields; dual destinations come from Config84 | Resolve every resource limit from the authenticated engine configuration and retain the same policy identity through admission and input commitment; no local defaults |
| Execution | `execute_and_settle_workchain_disposal` calls the account engine and private payout/disposal overlays | Invoke through the live block path only after bounded admission, commitment and complete authenticated inbox reconstruction |
| Validation | `ValidateQuery::check_transactions` still calls `replay_resolved_workchain_account_block` | Add an explicit versioned multi-record path that independently reconstructs every wrapper and dictionary difference; retain the singleton path |
| Publication | `build_workchain_outbound_queues` builds private Native queues from reconstructed exports | Publish accounts, AccountBlocks, InMsg/OutMsg and queue changes together, with rollback evidence; queue construction alone is not I13e |

Implement in that dependency order. The registry work must not invent resource
values: a profile without a fully resolved authenticated policy cannot execute.
The native account-engine interface is separate from the cryptographic kernel;
registering a placeholder is not a real candidate source or M3 completion.
Any immediate consensus-boundary review must include configuration provenance
and the zero-engine-call failures before admission completes.

The development snapshot does not prevent installation of unsupported execution:
`SUPPORTED_VERSION` only causes logging. The sole configuration-installation
code gate is `valid_config_data` through its ingress version/capability checks;
v16 does not prove that a binary has a multi-account executor. Release readiness
and a dry-run of premature v16 activation remain mandatory. No global warning
is changed into reject/fatal as part of this integration.

M1 acceptance requires all seven properties on those live paths: one logical
batch; one engine invocation per authenticated execution context; independent
actual-write-set equality and bound reads; exact account coverage with untouched
accounts unchanged; all-or-nothing state/message publication; the complete fixed
validation order; and independently rebuilt wrappers including payout and
aggregate-operation-fee exceptions. Helper-only fixtures cannot close any of
these live integration gates. Source-aware sticky errors and identical
authenticated budgets for collator/validator are additional required gates.

### Explicit multi-account registry binding (boundary reviewed, not live)

The registry now owns a separate `RegisteredWorkchainAccountEngine` map and an
explicit `resolve_account_binding` path. Three-way key isolation covers
AccountCompute, singleton BlockTransition and multi-account BlockTransition.
The result retains the descriptor-bound dual ingress and exact engine payload
configuration. It does not execute, admit resources, choose configuration values,
or add a multi-account alternative to generic scoped dispatch. Production startup
does not register a multi-account implementation. The dispatch row above describes
the live path and remains incomplete.

The positive binding test first failed against an unimplemented registration
stub. After implementation it verifies callback identity/role retention and
zero execution, and after review it also tests compute registration conflicts,
absent/mismatched entries and callback failures. Six independently rebuilt
mutations fail: registry presence, reserved-key rejection, dual-ingress
requirement, descriptor binding, null-config rejection and retained custody.
These controls are manual, not recurring CI or coverage of every guard. Shared
activation/active predicates are not duplicated for the sake of error wording.
VM exceptions propagate to a source-aware enclosing boundary; plain binding
Status is not a voting classification.

Review scope, disagreements and residual obligations are in
`uno-v2-account-registry-review-disposition.md`; evidence is in
`measurements/uno-v2-account-registry-evidence.json`. This closes a registry
binding prerequisite, not authenticated policy resolution or M1 integration.

### Configuration-sourced descriptor binding (boundary reviewed, not live)

`resolve_account_binding_from_config` obtains Config12 from the same Config
snapshot used for Config84. No caller-supplied workchain map or separately
constructed descriptor enters this wrapper. A snapshot not unpacked with both
workchain-info and capability modes produces an existing LocalUnavailable code;
it is not evidence of an absent descriptor or disabled capability. An intact,
authenticated snapshot remains an enclosing-host requirement, not a certificate
created by this method. Generic live dispatch remains unchanged.

The positive first failed against a compiled stub. After review, the fixture
covers incomplete unpack modes, absent entries, unsupported engines, mismatched
version/mode, and nonzero returned fields. Four independently rebuilt mutations
fail for unpack-mode provenance, descriptor version, mode and address width.
These are manual controls, not recurring mutation CI. Review/disposition:
`uno-v2-config-account-binding-review-disposition.md`; exact evidence:
`measurements/uno-v2-config-account-binding-evidence.json`. This unit does not
freeze the remaining logical-root definition or add engine resource defaults.

## Verification discipline

New tests must fail with the relevant behavior removed. A failed compilation is not such evidence. Preserve mutation logs and source identities. Missing dependencies fail rather than skip. Arithmetic and narrowing must be checked. Classify failures by provenance, not only exception type; local faults must not become candidate judgments.

Review completed milestones with Claude Code; review consensus-judgment changes or new error classifications immediately. Put verbatim reviews in `/home/tomi/memo/reviews/`. Do not label a milestone complete because its helper tests pass. Keep existing single-account semantics until a versioned migration replaces them.

## Participant timing evidence

`crypto/block/workchain-participant-lt.h` now computes the per-account schedule without cells or state writes. It requires strictly sorted, unique account keys, bounds participant/message counts, and checks all LT addition. The host must supply authenticated lower bounds and resolved limits; this helper is not an authentication or consensus-error-classification boundary. Allocation failures are not converted into candidate errors.

Two tests were first executed against unimplemented stubs and failed on positive numerical boundary cases. After implementation, independently disabling the checked-add overflow guard fails `ParticipantLtExhaustion`; disabling strict account ordering fails `ParticipantLtPlan` on duplicate input. Both guards were restored and rebuilt. The two focused tests and the full existing `test-workchain-block` CTest pass. Raw mutation output, restored output and source/binary hashes are in `measurements/uno-v2-participant-lt-evidence.json`.

The new tests are in the existing registered test binary. The mutation operations were manual and are not automatically rerun by CTest. This unit has no new consensus call site or error category; code review awaits M1 under the milestone rule. The preceding wire design review is not represented as a review of this implementation.

## Read/write access ledger

`crypto/block/workchain-account-access.h` now checks canonical unique declarations, authenticated old-hash/absence agreement, read-before-write, sticky failures, and exact actual-change/participant coverage. Every write needs an old-state read, including proof of absence for creation. Multiple semantic writes to one declared account are allowed; only one final physical participant record is allowed. Successful finalization seals the ledger.

Implementation decision: unused read declarations are rejected at finalization, rather than providing alternate padded representations of the same access plan. The host must derive actual old-state hashes and actual changed keys from the authenticated dictionaries. This utility cannot establish I13d by being handed two identical engine-supplied lists. Its declaration lookup must precede old-account fetch; its input vectors must themselves be constructed under bounded admission.

`AccountAccessBinding` and `AccountAccessExactCoverage` run in the existing CTest binary. The binding positive control failed against an unimplemented factory. Independently removing the old-hash/absence comparison makes the binding test fail; removing actual-change equality makes the coverage test fail. Restored focused tests and the complete `test-workchain-block` CTest pass. Evidence is in `measurements/uno-v2-account-access-evidence.json`. These are manual mutation runs, not a CI mutation facility or completed multi-account replay evidence. Review remains due at M1; no consensus entry point or new error classification was changed.

## Native account dictionary adapter

`crypto/block/workchain-account-dictionary.h` reads old Account hashes from Native ShardAccounts entries and obtains actual changed keys using augmented dictionary differences. Tests cover creation, deletion, data replacement, and a last-transaction-only change, plus exact coverage through the access ledger. The change limit bounds collected keys, not traversal cost; bounded admission and source authentication remain host responsibilities. Old-state parse failures propagate to the source-aware boundary, never becoming proof of account absence.

Replacing the actual old hash with its declaration fails the false-absence assertion. Omitting changed-key collection fails the numerical key-count assertion. Both mutations were restored and the full `test-workchain-block` CTest passed. Raw manual logs and restored source/binary identities are in `measurements/uno-v2-account-dictionary-evidence.json`; mutated artifact hashes were not captured. Tests are registered through the existing binary, but mutations are not rerun by CI. There is still no consensus integration or completed I13 acceptance, and milestone review remains pending.

## Access declaration wire

`UnoV2HostRead` and `UnoV2HostAccess` are now independent types in `block.tlb`. Neither extends TransactionDescr or configuration acceptance. The automatic CRC32 tags are `439e6964` and `7bc07a6d`; canonical definition strings and independent CRC results are recorded with the evidence. A read record is 33 or 289 bits, zero references. The access root is 34 bits, zero to two references. These local sizes are not closure, depth or deployment capacity bounds.

`workchain-account-access-codec.h` encodes and decodes the declarations, preserving absent versus existing old Account hashes. Entry bounds apply before copying or materializing entries. The access ledger enforces unique sorted reads/writes and write inclusion in reads. The decoder requires deterministic dictionary encoding by rebuilding and comparing the root hash; alternative valid TL-B label encodings are not accepted as V2 canonical encodings. This rebuild is additional bounded work, not free admission. The caller must admit the entire input closure before invoking the codec; this unit does not solve preflight integration or classify exceptions by provenance.

Both new tests first failed against unimplemented codec stubs. The implemented codec interoperates with generated TL-B validation and rejects malformed read records, unknown tags, root tails, writes without reads, duplicates and limit violations. Removing only the canonical comparison fails the alternate-label negative test. A separate combined mutation removes root size, tail-consumption and canonical checks, failing the trailing-bit test: these overlapping checks are not claimed as independently mutation-covered. All changes were restored and the full CTest passed. Source/binary hashes and logs are in `measurements/uno-v2-account-access-codec-evidence.json`. Mutation runs remain manual; M1 review is pending.

## Host identity wire

Independent domain, policy, context and identity TL-B types now encode the complete host identity. `workchain-host-identity.h` commits all 16 fields, including the full engine selector/mode and the finality reference. It does not authenticate values, recognize policy versions or construct the complete batch input. Finality closure admission is still the caller's responsibility. It introduces no transaction constructor or consensus call site.

`HostIdentityBinding` independently reads field order and extreme signed/unsigned values, checks generated parsing, and changes every field separately to require a distinct root hash. Its initial stub fails; replacing vm_mode with constant zero independently fails the numeric field assertion. Restored CTest passes. Logs and artifact hashes are in `measurements/uno-v2-host-identity-evidence.json`; the manual mutation does not claim removal coverage of all sixteen fields. Native Cell hashing is retained; no new hash backend is introduced.

Integration prerequisite discovered here: the earlier `InputPolicyIdentity` admission prototype omits vm_mode. Before coupling admission to this wire, extend that prototype and its preservation tests, derive engine-format/extended consistently, and prove that the same resolved identity is committed. Do not fill the missing mode with a local default. This pending integration is not represented as a completed input-policy binding gate. M1 review remains due at milestone completion.

### Admission identity agreement

The prototype identity now carries explicit `extended` and `vm_mode` fields; all current source call sites, including the optional measurement target, supply them. `encode_admitted_workchain_host_identity` compares configuration hash, extended flag, selector, mode, descriptor version and admission version with the identity retained by `AdmittedInput` before serializing. A test changes each of these fields while keeping the standalone encoding valid. It fails against an encoder without the agreement check; independently removing only mode comparison also fails. Clearing mode while copying the admitted identity fails the preservation test's numeric assertion. Restored block/admission CTest targets and the measurement self-test pass. Evidence: `measurements/uno-v2-admitted-identity-evidence.json`.

This closes the missing-field utility prerequisite above, not the authentication/configuration gate: the host still must derive resolved values from authenticated configuration and use the guarded encoder in the full input commitment path. Existing standalone encoders are serialization primitives, not authorization. No new error category or consensus entry point was introduced. Mutation runs are manual and milestone review remains pending.

## Complete input envelope construction

`UnoV2HostInput` now references identity, access, admitted candidate and optional canonical Native inbox. The automatic tag is `7c0766c8`; local layout is 33 bits and three/four references. The encoder uses the admitted-policy agreement check and access codec, then canonicalizes the host-provided inbox. Empty inbox is absent, never a fabricated nonempty list. Native envelope profiles remain separate from the ordinary-candidate profile.

This is post-admission construction, not validator preflight. The existing inbox codec performs semantic decoding. The validator must first bound and check the claimed commitment, then authenticate/rebuild the full inbox before using this constructor for replay comparison. The supplied count limits do not bound closure bytes or derived-wrapper cost. Source authentication, completeness, candidate effects and final atomic account commitment remain unimplemented integration work; a root hash here proves none of those independently.

`HostInputCommitment` checks generated parsing, each reference, empty/nonempty inbox, canonical inbox order, candidate/access/context changes, duplicate messages, count limits and policy disagreement. It fails against a stub. Independently omitting the inbox reference fails a numerical reference-count assertion; replacing access with a structurally valid empty declaration fails the access-root comparison after generated validation passes. Restored block/admission CTest targets pass. Logs and hashes: `measurements/uno-v2-host-input-evidence.json`. These mutations are manual, not CI mutation jobs; M1 review remains pending.

## Participant binding payloads

`UnoV2HostRecord` is an independent TL-B payload, tag `35739af6`, exactly 832 bits and no references. It binds input hash, effects hash, account ID and the zero-based position of that account in the canonical account-effects sequence. Record construction accepts a nonempty, strictly ordered write-key set under a supplied participant limit and the uint32 count space. Position narrowing follows a checked size bound and a nonnegative iterator-distance invariant. It performs no amount arithmetic or database writes.

Roles and permissions are not record fields. The host must derive them from authenticated state, check exact actual changes and rebuild every native wrapper. No TransactionDescr tag, payout exception, version gate or multi-account acceptance path is added here. The effects schema and its ordered account sequence still need implementation; a caller-supplied effects hash is not proof that those effects are valid.

`ParticipantRecordBinding` verifies generated parsing, exact local layout and values, changes each bound digest/account, and checks duplicate/reversed/empty/over-limit key sets. It fails against a stub. Forcing every index to zero independently fails the second record's numerical index assertion; removing strict ordering independently fails the duplicate-key test. Restored block/admission CTest targets pass. Raw manual mutation logs and hashes are in `measurements/uno-v2-participant-record-evidence.json`; mutation runs are not CI jobs. M1 remains incomplete and milestone review is pending.

## Per-account Native value-flow arithmetic

`workchain-value-flow.h` checks `old + imported + internal credits = new + exported + fees + internal debits` for every account. Each explicit internal transfer contributes the same CurrencyCollection to its source debit and destination credit, so internal movement cancels when summing the equations. Row keys are unique and canonical; missing endpoints, invalid values and excessive counts are rejected. No persistent state is changed. Native checked add/sub operations cover extra currencies; numeric comparison uses a checked difference, not dictionary-hash equality.

Accumulators explicitly fit unsigned 256 bits: the bigint backing storage may temporarily hold larger values, so add success alone is insufficient for this chosen arithmetic envelope. A boundary test demonstrated that before the width guard was added. This does not widen wire amounts: account/message adapters must enforce their existing TL-B limits independently. The helper accepts wide totals because sums of wire amounts need not fit one wire amount. Closure/resource admission remains external, including the supplied extra-currency validation budget.

Tests cover an operating-budget-to-custody transfer, total-preserving but wrong account allocation, omitted/reversed transfers, invalid amounts, missing accounts, extra-currency conservation and the accumulator boundary. The stub fails. Ignoring extra currencies independently fails their negative case; omitting per-account equality independently fails the total-preserving misallocation case. Restored block/admission CTest passes. Evidence: `measurements/uno-v2-value-flow-evidence.json`. A test-construction compile error was corrected and the stale binary result discarded.

This is not completed independent Native value-flow acceptance: rows must still be extracted from independently rebuilt accounts and message records in the host. It does not authorize transfer edges, prove fee isolation, or establish the confidential backing invariant. No consensus entry point was changed; milestone review remains pending.

## Native storage-participant wrapper (not activated)

The `1010` TransactionDescr constructor carries a participant binding. Generated
and handwritten parsers agree on its four bits and one reference. Preparation
uses a real active Native Account, changes data under existing account limits,
and runs no compute, storage, credit, action or bounce phase. Native value and
fees are pinned; this is the storage-only participant primitive, not custody
payout, coordinator fee settlement or account registration. Existing scope
dispatch still rejects it in both scopes. The named version-16 construction
floor does not activate it, change SUPPORTED_VERSION or replace the required
authenticated multi-account policy gate.

Claude reviewed this consensus-boundary change; the verbatim record is
`~/memo/reviews/uno-v2-storage-participant-review.txt`. Disposition:

| Finding | Disposition |
|---|---|
| M1 address mutation | Fixed using CellSlice contents comparison, including null checks. The suggested Cell hash API does not apply to CellSlice. |
| M2 activation | Named construction floor and descriptor tag added. Deferred full capability/profile activation to the explicit multi-account host switch; no claim that a version bump authorizes this path. Both current scopes remain closed. |
| M3 masked version test | Fixed with successful preparation at 16 followed by serialization at 15. Added field-specific mutation inputs for every new serialization clause. |
| L1 unknown diagnostic | Deferred wording until the explicit profile switch; rejection classification and both closed scopes are unchanged. |
| L2 exception contract | Documented source-aware caller responsibility for VmError, VmVirtError, CellCreateError and CellWriteError. A Status return is not a no-throw promise. |
| L3 role/no-op checks | Deferred role authorization to the host's authenticated role map. This low-level Account wrapper cannot infer a coordinator address from an absent policy. Data equality alone also does not imply an unchanged Native account: last_trans changes. Exact permitted effects and participant coverage remain host checks, not authorization by this helper. |
| L4 zero balance | Fixed: the positive fixture now preserves 1000 nanotomi. |
| L5 comment placement | Fixed. |

The initial unimplemented preparation failed its positive test. Independent
removal of account binding, address comparison, serialization version check,
code preservation, and the storage-specific cache guard each fails a real
assertion after a successful rebuild. Raw logs, patches and artifact hashes
are in `measurements/uno-v2-storage-participant-evidence.json`. These five manual
mutations are not a CI mutation facility or removal coverage of every guard.
The other field cases execute in the registered test, without that stronger
mutation claim. Two test-construction compile errors were corrected; no stale
binary result is used as evidence for those revisions.

Additional integration prerequisite: Transaction exposes mutable staging fields
and `commit()` copies them. Rechecking `serialize()` even with a cached root now
detects guarded mutations, but this is not a seal on arbitrary post-serialization
mutation followed directly by commit. The multi-account overlay must own these
objects without engine access, reconstruct/finalize their native state, and
publish once only after all wrappers and the actual dictionary diff pass. No
Account is committed by this test, and I13c/I13d/I13e are not accepted yet.

### Storage-only Native dictionary overlay

`workchain-storage-overlay.h` now composes the access ledger, authenticated-old
dictionary adapter, checked LT planner and storage wrapper into real Native
Account commits and AccountBlocks. Each Account and Transaction is private to
the function; no engine callback or mutable alias can intervene between
serialization and commit. Commits affect temporary Accounts only. Persistent
ShardAccounts and ShardAccountBlocks roots are returned together after the
actual dictionary diff matches the declared writes and participant keys. Failure
returns neither root and never writes CellDb or modifies the old root.

The fixture changes two of three accounts, parses both new accounts and both
AccountBlocks with Native parsers, checks each transaction's previous link and
its published last_trans hash/LT, and independently compares AccountBlock
old/new hashes against old/new Account roots. The untouched third entry is
byte-for-byte unchanged. Rebuilding from the same input produces the same two
roots. A second-account invalid data cell fails after the first private Account
commit, with no published result; a false old hash fails earlier during reads.

The test failed against an unimplemented builder. Independent mutations replace
the published last_trans LT with 1, and the last_trans hash with zero, each
failing a numeric/hash assertion. Raw logs and identities are in
`measurements/uno-v2-storage-overlay-evidence.json`. These are manual mutations,
not a CI mutation runner. The ordinary test is in the registered block target.

This is still only storage-only materialization. It does not authorize account
roles/effects, authenticate supplied configuration, implement registration,
custody payout or coordinator funding, integrate a full shard Merkle update,
or publish live manager state. Count limits do not replace closure/state-read
budgets. Source-aware exception handling remains at the enclosing admission
boundary. Complete validator replay and I13 acceptance are pending; existing
single-account acceptance stays unchanged. No consensus call site or error
category changed in this step; review is due with M1.

### Payout principal and Native fee allocation

The Native mode-1 sender reports both total forwarding fees and the fraction
collected by the current transaction. `workchain-payout-accounting.h` separates
these: for payment X, total fee F and locally collected C, custody decreases by
X, coordinator decreases by F, and the exported value is X plus F minus C. An
explicit internal funding edge carries F from coordinator to custody; custody's
transaction fee is C. Both per-account conservation equations are checked, not
just the batch total. Native checked CurrencyCollection operations reject
underfunded principal, underfunded operator fees, C greater than F, invalid or
overflowing amounts. Distinct source accounts are mandatory.

This is an allocation helper, not a Native pricing oracle or payout authority.
The next integration must obtain X/F/C from the actual reconstructed send,
match its destination/amount and message LT to effects, and use the resulting
balances in private participant wrappers. Passing self-consistent engine fee
claims here does not authenticate them. No host entry point is changed yet.

The test fails against the unimplemented helper, then checks nonzero payment,
both remaining balances, exported value including residual forwarding fees,
each shortage independently, reversed address order and zero-fee exhaustion.
Independent mutations publish the old operator balance or omit the forwarding
value from the returned export; each fails a numeric amount assertion. These
are publication-consistency controls, not independent removal coverage of
every arithmetic guard. Raw manual evidence is in
`measurements/uno-v2-payout-accounting-evidence.json`; ordinary tests are in
CTest, mutation jobs are not. M1 review and full Native settlement remain due.

### Native payout reconstruction and pricing (boundary reviewed)

`Transaction::price_workchain_payout` reconstructs one mode-1 Native message in
a private scratch transaction, using real configured forwarding prices. It
returns the actual encoded payment, total fee, collected fee and end LT, without
committing the custody account. A fee budget is only a ceiling: the test supplies
500 and observes a fee of 102, not 500. Referenced body storage exercises the
basechain price path: 256 bits and one cell produce 460 with a collected share
of 230 under the fixture's price configuration. These are test prices, not
production initial values. Principal affordability and funding arithmetic are
checked before Native construction; LT additions are checked before entering
the existing constructor and message increment paths.

The request must use rich bounce, no anycast, no caller-quoted forwarding fee,
and positive payment. The returned value is unpacked from the actual generated
message and compared numerically. A zero extra entry passes generated syntax
validation but fails Native's handwritten currency validator, which uses
positive extra amounts before the send normalization path. Such requests remain
rejected; this helper does not widen Native's admissible currency encodings.

Claude Code's boundary review is retained at
`~/memo/reviews/uno-v2-native-payout-pricing-review.txt`. Disposition:

- Findings 1/2: fixed production-version feature flags in the fixture, added
  referenced-body pricing, basechain lookup and surplus-budget assertions.
- Findings 3/4: documented actual escaping exception types. The new path asks
  the existing staging helper to preserve VM exceptions; its default remains
  unchanged for old callers. Injected request-root load faults must propagate,
  including faults during staging. This does not prove all descendant or
  allocation failure paths. Disputed the claim that VmVirtError alone proves
  a local fault: input provenance, not exception class alone, determines that.
  The enclosing authenticated admission boundary still must classify failures.
- Finding 5: added validly encoded profile negatives and context boundaries.
  Independent removal controls cover the special-account guard and version
  floor; no removal coverage is claimed for every guard or redundant check.
- Finding 6: disputed the address interpretation: `-1:X` and `2:X` are different
  addresses; the fee-paying coordinator is not necessarily the payout payee.
  Added an actual `2:custody` to `0:payee` case, including destination checks,
  configured workchain lookup, and rejection when that workchain is absent.
- Finding 7: fixed returned-message value binding. Disputed that removing zero
  entries from virtual funding would make the sample Native-sendable: the new
  sample failed even with that attempted fix, because the existing handwritten
  validator rejects it before send normalization. The attempted normalization
  patch was withdrawn. The test explicitly checks both parser outcomes and
  rejection; this is compatibility evidence, not a new independent guard.
- Finding 8: documented the deliberately repeated principal check and fee
  meanings, restored declaration/comment adjacency, and asserted the changed
  collected share. Structural builder checks are not claimed as independent
  security gates.

Manual controls also disable exception propagation or return the maximum fee
budget instead of the Native fee; each fails an exception/numeric assertion.
Raw controls are in `measurements/uno-v2-native-payout-pricing-evidence.json`.
They are not automated CI mutations. The ordinary test is in the registered
block target. A zero-literal BitArray constructor initially selected a pointer
conversion; explicit `set_zero()` avoids that construction bug.

This helper does not authenticate role assignments, input policy or effects;
it is not a payout-authorizing transaction wrapper. Its local version floor
does not activate the multi-account profile. Effects-to-message binding,
coordinator debit and custody wrapper construction, independent validator
replay, and live shard publication remain M1 work. No retirement transition
removes configuration 84, the descriptor or custody: economic settlement is
not proof that Native messages no longer need those destinations.

### Two-account payout wrapper construction (boundary reviewed; admission pending)

`build_workchain_payout_pair` constructs two private Native transactions from
the real priced message and checked allocation. It returns custody/coordinator
transactions **and** `WorkchainPayoutAccounting`, preserving the internal fee
funding edge and derived flow rows. Those rows are construction results, not
independent verification of external evidence. The enclosing validator must
reconstruct them from authenticated effects and actual Native account/message
artifacts before comparing wrappers and publishing any state.

The new descriptor uses explicit prefix `1011`, following the existing
TransactionDescr four-bit allocation, not an implicit CRC32 tag. It does not
overlap `0000` through `0111`, retired `1000`, batch `1001`, or storage `1010`.
Its referenced UnoV2HostRecord keeps its existing derived tag. Both current
execution scopes reject `1011`; adding structural parser support is not
activation. Old single-account semantics are unchanged. Handwritten skip,
validation and storage-fee extraction must agree with the generated parser.

The strengthened fixture uses principal 137, total fee 100, collected fee 25
and remaining forwarding fee 75. Starting from 1000 each, the serialized
custody and coordinator accounts contain 863 and 900 respectively. Exported
value is 212. The test unpacks Native accounts, checks data and end LTs, reads
transaction fees and message counts, and checks each descriptor's exact binding.
An underfunded coordinator has a real encoded old balance of 99. Failure while
preparing the second account returns no pair and does not commit either old
account; this is not a live CellDb rollback demonstration.

Review transcript: `~/memo/reviews/uno-v2-native-payout-pair-review.txt`.
Disposition:

- Fixed symmetric test values and added serialized-value checks, fee-funding
  evidence, coordinator shortage, configuration and individual binding cases.
  Added skip/storage-phase/storage-fee extraction checks for the new prefix.
- Returned the accounting artifact instead of discarding it. A hash binding
  does not replace effects availability, role authorization or independent
  message/value reconstruction. Neither participant satisfies the ordinary
  per-transaction equation without its internal funding edge; only a dedicated,
  version-gated batch validator may account for that edge.
- Renamed `batch_storage_only` to `batch_metadata_sealed`: it enforces metadata
  preservation and cached serialization checks, not a claim of zero value
  movement. Removed the repeated state-limit traversal; the data/code/library
  roots do not change after storage preparation. This does not establish a
  complete account/message/wrapper resource budget.
- Kept amount/LT arithmetic checked, and documented both old-end LT bounds
  that keep constructors from increasing the already-checked start LT.
- Split context diagnostics, but **deferred source-aware failure classification
  to the enclosing admission boundary**. A configuration mismatch in locally
  derived inputs is not evidence of a bad candidate. Generic serialize failure
  still lacks a detailed Native failure reason, and escaping VM/builder/dictionary
  exceptions still require tested handling at that boundary. This is an explicit
  prerequisite for integration, not an accepted error-classification gate.
- Disputed treating additional error-string assertions as adequate negative
  evidence. Independent removal/publication controls are required; a null data
  case covers construction failure isolation, not every new guard. Also, the
  reseal test already fails if the flag is disabled: the flag's misleading name
  is real, but it is not an untested cache bypass.

The pair is returned in role order, not sorted account-key order. The final
overlay must own the referenced Accounts, derive the complete batch LT plan,
bind roles and all data changes from effects, handle coordinator batch entry
and inbox processing, re-sort for exact write-set coverage, and commit only
after every wrapper and value-flow check succeeds. This factory is a building
block for that overlay, not a replacement for it or evidence of complete I13.

Seven independent manual controls changed the coordinator debit role, collected
fee, input/effects/index binding checks, configuration agreement and published
binding reference. Every rebuilt mutant failed its numeric or acceptance/hash
assertion. Logs, patches and artifact hashes are retained in
`measurements/uno-v2-native-payout-pair-evidence.json`. This is not a CI mutation
facility, nor removal coverage of every context guard. The original stub failed
the positive construction case; ordinary tests run in the registered block
target. Review comments and their scope do not replace M1 end-to-end acceptance.

### Payout plus storage dictionary materialization

`workchain-payout-overlay.h` materializes a single authorized-by-caller payout
alongside the complete supplied storage write set. It authenticates each declared
old hash against the supplied old account dictionary before unpacking that
account, maps roles to canonical key positions, and runs the shared LT planner
over all participants. Custody/coordinator transactions come from the reviewed
pair constructor; other accounts receive storage-only wrappers. The old
storage-only builder and all production entry points remain unchanged.

All Account and Transaction objects are private to the call. No engine callback
can intervene between serialization and a private commit. The final dictionary
diff must exactly match the declared writes and participant set. Account roots,
AccountBlock roots and the one outgoing message are returned only together,
after all checks; the function neither writes CellDb nor publishes a message.

Value-flow rows are re-read from serialized old/new Native Account storage,
Transaction fees and the actual outbound dictionary. The transaction's account
state-update hashes are compared against those Account roots. Exported value
includes the actual message's remaining forwarding fee, not just its payment.
The returned internal fee-funding edge is included in the per-account check.
This removes reliance on allocation rows as proof of serialization consistency;
it does **not** authenticate a withdrawal or replace independent validator
replay of externally supplied block/state artifacts.

The fixture changes three of four funded accounts and puts custody after the
coordinator in key order. It unpacks all three new accounts and AccountBlocks,
checks principal/fee separation, transaction links, data, the outgoing message
hash and LT, and leaves the fourth account byte-for-byte unchanged. A repeated
construction has the same roots. A false old hash is rejected before account
preparation. Invalid storage data after an earlier private commit returns no
result. The original unimplemented builder failed the positive case.

This is post-execution materialization, still not a live multi-account host.
Role/effects authorization, full source-aware admission and exception mapping,
closure/read/serialization budgets, coordinator entry/inbox/storage charges,
and final shard update/replay/queue publication remain required. Count bounds
are not traversal budgets. The single outgoing-message bound is the current
custody participant shape, not a new production throughput setting. No
consensus call site or error category changed here; review is due with M1.

Three rebuilt manual mutants omit the returned message, publish an incorrect
last_trans LT, or omit the remaining forwarding fee from decoded export value.
They fail nullness, numeric-link or successful-construction assertions
respectively. The last control exercises the serialized value-flow check; it
is not an externally supplied malicious-block test. Raw logs and hashes are in
`measurements/uno-v2-payout-overlay-evidence.json`. These controls are not CI
mutation automation; the ordinary fixture runs in the registered block test.

### Claimed payout overlay replay

`replay_workchain_payout_overlay` reconstructs all Native artifacts from the
supplied old state and post-execution inputs, then compares the complete account
dictionary root, AccountBlock dictionary root, outgoing message and end LT.
It returns the reconstructed result, including locally derived fee funding;
the claim type has no field for untrusted accounting rows or fee-funding claims.

The fixture accepts the correct complete result. Negative cases re-encode a
ShardAccount last-trans hash, an AccountBlock hash update and an outgoing
message timestamp as structurally valid Native cells; a fourth changes end LT
with checked arithmetic. Each must be rejected by replay rather than merely
by a syntax decoder. These checks include untouched accounts through the full
dictionary-root comparison, not only listed changed keys.

This is artifact replay, not independent engine execution. Inputs still require
the enclosing source-aware admission boundary, authenticated role/effects
derivation and resource acceptance. Hash comparison does not establish data
availability for unmaterialized claims. No validator/collator call site is
connected, no execution scope is enabled, and neither full shard Merkle-update
replay nor network reception is covered. M1 acceptance remains pending.

The unimplemented replay failed its positive case. Independently removing each
of the four comparisons admits its corresponding negative fixture and fails
the test. Patches, raw logs and artifact hashes are retained in
`measurements/uno-v2-payout-replay-evidence.json`. These manual controls are not
CI mutation automation; normal coverage is in the registered block target.
No consensus entry point or error category changed; milestone review remains
due. The next integration gap is the engine's still-single-state result and
source-aware context, not additional root-comparison helpers.

### Declared account engine interface

`WorkchainAccountEngine` accepts the committed input envelope and a read view
restricted to declared accounts. The post-admission runner checks old account
hashes or absence before invoking the engine once. It does not expose the shard
dictionary or mutable Native Account/Transaction handles. Undeclared reads stick:
even an engine that ignores the read error and returns valid-looking effects
cannot succeed. Returned account data updates must exactly match the declared
ordered write keys, with no missing entries or null data.

This is not yet an authenticated execution boundary. The enclosing host must
authenticate the old shard, bound state closures and inbox construction, accept
resources, resolve policy and authorize effects. Native source exceptions still
propagate to that source-aware boundary. The optional payout request is not a
finalized message or a payment authorization. Actual Native dictionary changes,
participant coverage and value flow remain the settlement overlay's independent
responsibility; matching engine claims alone cannot establish I13c/I13d.

The reference engine fixture checks successful two-account execution, wrong old
hash rejection before any engine call, ignored unauthorized reads, omitted
updates, duplicate/wrong keys and null data. Removing each of the five runner
checks separately makes its corresponding test fail. Raw mutation logs and
artifact hashes are in `measurements/uno-v2-account-engine-evidence.json`.
Normal coverage runs in the registered block target; the mutation runs were
manual, not CI automation. No production call site or error category changed;
M1 review and live integration remain pending. Next is connecting this interface
to independently derived effects and the private Native settlement overlay,
then the source-aware collator/validator boundary and versioned activation.

### Engine effects to Native settlement

`execute_and_settle_workchain_accounts` now connects one declared-account engine
invocation to private Native materialization. The runner returns the exact input
envelope supplied to the engine. The settlement derives both participant hashes
itself, encodes the returned effects, and obtains every storage update and the
optional custody payout from that same result. Callers cannot supply alternate
input/effects hashes or substitute a second update vector. Old account hashes
come from the declarations already checked before execution.

`UnoV2HostEffects` is an independent TL-B type, not an activation or an extension
of accepted TransactionDescr scope. Its initial implicit tag was `0e15071a`, derived by
the repository compiler and independently recomputed with CRC32 from:

```
uno_v2_host_effects updates:HashmapE 256 ^Cell payout:Maybe ^Cell receipts:Maybe ^Cell events:Maybe ^Cell wire_bytes:uint64 verification_units:uint64 written_cells:uint64 = UnoV2HostEffects
```

That initial root had 228 bits and at most four references. The Native-transfer
extension below supersedes that inactive encoding. This is a local encoding size,
not a closure/depth bound. Sorted account keys commit each new data root; optional
payout, receipts and events and all three usage fields are committed. No final
Native transaction, AccountBlock, last-trans hash or shard root is included, so
participant bindings introduce no self-reference. The type has one constructor;
the generated table has no other occurrence of this tag.

The fixture executes storage-only and custody-payout cases. It decodes actual
Native balances, updated data, AccountBlocks and participant binding records;
both hashes must match the committed roots. Test-only initial balances of 1000
and principal 137 produce custody 863 and coordinator 900 under test forwarding
cost 100. They are not production policy values. Both paths call the engine once.
Eight independent mutations replace the input/effects binding, replace the data
source, skip payout dispatch, accept an unsupported inbox, omit receipts/events
or exchange usage fields. Each fails a state, count or numeric assertion. Raw
logs and hashes are in `measurements/uno-v2-account-settlement-evidence.json`;
manual mutation runs are not CI automation.

This is not the complete V2 settlement engine. Roles, configuration, resource
admission and withdrawal authority still need the resolved production boundary;
fees are independently priced in the Native overlay, not yet represented by the
complete protocol's explicit fee effects. Nonempty Native inboxes are rejected
before engine invocation rather than silently omitted from value settlement.
Account creation similarly requires a registration participant. Neither path
is an accepted substitute for coordinator batch-entry/import records. Full
shard-update replay, registry selection, proof/state transitions and live
collator/validator wiring remain M1 work. No consensus judgement file or error
category changed in this unit; milestone review remains pending.

### Coordinator entry record (boundary reviewed)

The inactive `trans_workchain_entry_v3$1100` descriptor carries three references:
the participant binding, complete host input and complete engine effects. Its
four-bit explicit prefix follows TransactionDescr allocation, not CRC tagging
of the separate payload types. Both current execution scopes continue to reject
it. The handwritten skip, validate, classification and storage-phase paths are
updated alongside the generated parser; no activation gate is removed.

`Transaction::prepare_workchain_entry` checks the input/effects hashes, workchain,
time/LT context and this account's data in the effects dictionary. It reuses the
Native inbound-credit validation for messages addressed to this account, then
seals a restricted entry without storage/compute/action/credit/bounce phases or
outbound messages. Only message value changes the balance; remaining forwarding
fees belong to Native InMsg accounting. The legacy credit sum now uses the
explicit checked CurrencyCollection addition API with the same wire-encoding
overflow check. Native source exceptions still propagate to the caller's
source-aware boundary; generic Status does not classify provenance.

The fixture starts at 1000, imports two messages with value 100 and forwarding
fee 67 each, and independently decodes 1200 from the resulting Native account.
After review the shared input also includes a third, foreign-destination message
with value 100; it is retained in the input and does not become coordinator credit.
It checks zero transaction fees, no outputs, unchanged original Account, exact
descriptor references and rejection by both execution scopes. Independently
removing credit application, the two hash guards, data consistency or any of
the three context guards makes its corresponding assertion fail. Evidence is
in `measurements/uno-v2-coordinator-entry-evidence.json`; manual mutation runs
are not CI. The positive case also failed against the unimplemented entry.

This is gross import into a private coordinator transaction, not Deposit
completion. The same logical batch must still allocate principal to custody,
allocate the paid slot fee to the coordinator, update the target pending state,
reconstruct per-account value flow and produce Native InMsg evidence. Custody
imports and wrong-destination handling remain separate unfinished paths. Roles,
inbox completeness, policy resolution and structural/work budgets are not
authenticated by this factory. Entry references provide actual cells in the
transaction; they do not establish archive retention or network availability.
The existing settlement runner still rejects nonempty inboxes until those
paths are connected. No production candidate is enabled by this unit.

The boundary review is retained verbatim at
`~/memo/reviews/uno-v2-coordinator-entry-review.txt`. Its dispositions are:

| Review item | Disposition |
|---|---|
| Shared inbox rejected on a foreign destination | Fixed: the entry selects its own destinations; the complete inbox remains committed, and other records must settle the rest. The legacy single-account call retains strict destination rejection. |
| Unchecked effect index | Fixed: the sole entry scans canonical effects ordering with a checked ordinal, checks the binding index, and tests a coordinator at index 1 as well as a wrong index. |
| Ambiguous diagnostic | Fixed: argument/encoding, input hash, effects hash, workchain, time/LT and data errors now have separate diagnostics. Error text is not a provenance classifier. |
| Descriptor failure after partial preparation | Fixed: construct the descriptor before preparing the storage participant. A child-depth probe raises CellWriteError and leaves the Transaction unserializable. Restoring the old order turns that assertion red. |
| Missing account access checks | Hardened: require this account's write membership and declared old hash before mutation. Both negative controls bind their changed declarations into otherwise correct inputs. |
| Entry necessarily differs from executor because of special status | Disputed: kWorkchainExecutorIsSpecial is false, the same value required by participants. The existing collator address filter is nevertheless a real integration prerequisite. |
| Complete-suite evidence | Expanded to VM, cells and smart-contract tests in addition to block/admission; still not a whole-repository or network acceptance claim. |

The review called descriptor construction failure unreachable because its local
shape is four bits and three references. That overlooks child depth: a valid
input root at depth 1024 cannot be wrapped in another ordinary cell. The test
deliberately supplies this boundary outside an admitted deployment profile; it
proves exception safety, not a live network exploit. The first probe caught only
CellCreateError and correctly failed because finalize_novm actually throws
CellWriteError. The final test catches that actual type and asserts that no
fallback storage transaction can be serialized. No production catch-all was
introduced.

Six additional review-fix mutations cover shared-inbox projection, index
matching, nonzero ordinal calculation, write membership, old hash and preparation
ordering. They all fail state/numeric/structural assertions. Updated evidence is
in `measurements/uno-v2-coordinator-entry-review-fixes.json`. Mutation evidence
remains manual and source/binary pinned. These are engineering corrections under
the already-required complete-inbox and I13 semantics, not new economic policy.
The source-aware replay boundary must still handle actual builder/allocation
exceptions and distinguish authenticated-source faults from candidate defects;
the review's broad classification of all Status failures is not an admission
certificate for future callers.

### Committed internal Native transfers

Engine effects now include canonical directed Native transfers. These are
public physical-account allocations, not the hidden amount in a confidential
SEND. A transfer is not authorization: the engine must derive allocations from
authenticated operations, and the host must independently reconstruct balances
and per-currency value flow. Native endpoints must both be in the account update
set. Self transfers, zero amounts, duplicate edges and noncanonical order are
rejected. Edges are ordered by source then destination; repeated contributions
to one directed edge must be aggregated with checked arithmetic by the engine,
not represented as order-dependent payment attempts.

`UnoV2NativeTransfer` contains source, destination and CurrencyCollection.
`UnoV2NativeEffects` contains the optional payout and a contiguous uint32-indexed
dictionary of those transfers. `UnoV2HostEffects` now references that Native
container in place of the old optional payout field, preserving a maximum of
four root references. The root is now 227 bits plus its referenced closure;
that local size is not a deployment capacity bound. The previous unactivated
encoding is superseded, not accepted as an alternate active format. No currently
accepted transaction profile uses this type.

Implicit CRC32 tags, independently checked against the repository compiler:

| Constructor | Tag |
|---|---|
| uno_v2_native_transfer | 6b953015 |
| uno_v2_native_effects | 0bd47725 |
| uno_v2_host_effects (with Native container) | 4155a803 |

Transfer count has its own explicit caller-supplied bound, separate from account
count. Extra-currency validation also has an explicit budget. These function
arguments do not freeze ConfigParam 84 fields or production values; production
resolution must supply the same authenticated limits to every validator. Wire
indices are narrowed only after the count fits uint32; iterator distances are
nonnegative and within that checked vector. Native amounts must be valid and
nonnegative, extra currencies must validate, and full CurrencyCollection storage
must succeed within Native wire limits. Allocation/source exceptions still
propagate to the enclosing provenance-aware boundary.

The fixture independently decodes both directed edges and amounts through the
generated parser. Eight mutations expose count, self-transfer, reverse order,
duplicate edge, endpoint coverage, zero-value, wire-size and ignored-transfer
failures. Negative/oversize amounts are also exercised. Evidence is retained in
`measurements/uno-v2-native-transfer-effects-evidence.json`; these are manual
source/binary-pinned controls, not CI mutation automation.

At this stage the settlement runner rejected nonempty Native transfers after
encoding rather than silently ignoring them. The message-free allocation
integration below supersedes that restriction, not the inbox or combined-payout
restrictions. No new fee model or production limit is selected here; no consensus
judgement file or error category changed. M1 review and activation remain pending.

### Entry-side Native allocation (boundary reviewed)

The inactive entry factory now derives its final balance from its own imported
message values and the committed internal transfer effects. It independently
decodes the transfer sequence, requires contiguous indices, strictly ordered
source/destination edges, nonzero values, distinct endpoints and endpoint
membership in the updates. All incoming and outgoing allocations are summed
before checked per-currency subtraction. This is simultaneous batch accounting,
not a sequence of payment attempts whose success depends on account order.
The final CurrencyCollection must fit Native wire encoding before any entry
preparation is committed to the temporary Transaction.

`allocate_workchain_native_balance` is post-admission arithmetic, not spending
authorization or a structural/work budget. Engine-derived purposes, roles,
all other participant balances, complete Native import records and independent
whole-batch value flow remain mandatory. In particular, a conserved transfer
graph does not authorize taking custody principal. This public Native allocation
must not be confused with the hidden SEND amount.

Tests decode the actual serialized entry AccountStorage balance, assert that
the original Account remains unchanged, and exercise exact depletion, a
one-unit deficit, and an incoming allocation funding the final outgoing unit.
The second-account entry case is an isolated alternative-role fixture, not two
entry records admitted in one block. A separate decoder test bypasses the
effects encoder's semantic guards using valid generated TL-B, and covers extra
currencies as well as Native TOS. Ten individually rebuilt mutations fail
numeric or status assertions; raw logs and source/binary hashes are in
`measurements/uno-v2-entry-allocation-evidence.json`. They are manual controls,
not automated mutation CI, and do not claim exhaustive independent coverage of
redundant arithmetic-width checks. Expanded VM/cells/smart-contract/block/
admission regression passed 5/5 after source restoration.

At this stage the whole-batch runner rejected nonempty imports and internal
transfers. The later allocation overlay integrates message-free transfers and
their restricted records with independently reconstructed value flow; imports
remain closed pending Native message evidence reconstruction.
Existing execution scopes still reject the new record profile. No configuration
initial value, message-finality rule or activation policy was changed.

The boundary review is retained verbatim at
`~/memo/reviews/uno-v2-entry-allocation-review.txt`. It independently reran the
two focused tests, checked source/binary hashes, and compiled the new header as
the sole include with project flags. Its dispositions are:

| Item | Disposition |
|---|---|
| A1: assignment comment described gross credit only | Fixed: the comment now describes imported values plus incoming minus outgoing allocations, with forwarding fees excluded from credit. |
| B1: updates membership relied on engine validation | Fixed: entry reconstruction checks effects and declared writes in both directions. The former own-write check is subsumed, not retained as an unmeasured duplicate. This enforces existing I13, not a new policy. |
| B2/B3: missing transfer bound and borrowed account-size budget | Fixed at the interface: allocation and entry require explicit transfer-count and extra-currency validation bounds, without defaults. Zero transfers permit an empty graph. No ConfigParam 84 fields or production values are selected here. |
| B4: balance extra-currency count and closure remain unbounded by this helper | Deferred to complete authenticated account/effects resource admission. A message's currency-count limit is not automatically an account-state rule. This inactive helper does not claim full anti-DoS admission. |
| B5: unpinned green baseline | Fixed: original green source/binary hashes independently confirmed by the reviewer are retained in its artifact; review-fix evidence includes new passing output and hashes. |
| B6: canonical leaf guard unmeasured | Fixed: a structurally invalid dictionary leaf with a valid transfer reference plus a trailing bit reaches the decoder directly; removing the guard accepts it and turns the status assertion red. |
| Additional coverage | Controls now reach Native-container parse-before-use and extra-currency accumulation/subtraction, not just Native-TOS projection. |

The invalid-container mutation ignores a failed unpack and then throws VmError
when constructing a dictionary from missing parsed fields. That control proves
the checked parse-before-use boundary; it is not evidence that candidate/local
fault classification is implemented. The other review-fix controls fail numeric
or returned-status assertions. All are manual source/binary-pinned runs, not
mutation CI. Raw results are retained in
`measurements/uno-v2-entry-allocation-review-fixes.json`.

The review's blanket characterization of all Status failures as candidate
invalid is not adopted: invalid resolved limits are a configuration/caller
failure, and provenance determines whether malformed cells came from a candidate
or authenticated state. Its required source-aware exception boundary remains
an integration obligation. Likewise, absence of a production caller is not the
only current barrier: both execution scopes still reject the record tag. The
runner's former blanket transfer rejection is superseded by the message-free
allocation integration below, not by a production activation gate.

Explicit entry/validation bounds do not replace complete closure accounting,
aggregate work admission or the activation gate before execution. Those must be
provided by the real host before its first production call. No message-count
policy or account-currency policy is inferred from these API arguments. The
per-entry scan is also not a plan to rescan the whole transfer graph for every
participant; batch-wide materialization must share checked accounting work.

### Restricted allocation participant (boundary reviewed)

The Native constructor can now materialize the other endpoint of an internal
allocation using the existing inactive settlement-participant descriptor. The
caller supplies per-account incoming/outgoing CurrencyCollection aggregates,
derived once by the enclosing batch from reconstructed effects. This factory
checks the opening balance and both aggregates, sums before checked subtraction,
requires final Native wire encoding, and prepares a sealed restricted record.
It does not receive user messages, emit messages, run ordinary phases, charge
fees or commit a live account. Only the binding is stored in its descriptor;
the full input/effects cells remain on the single entry.

This is a construction API, not authorization: an arbitrary aggregate supplied
by a caller is not proof that a transfer exists. Complete overlay settlement
must derive the aggregates from the replayed graph and independently verify
the actual serialized Native rows against that graph. That integration for
message-free transfers is recorded below; nonempty imports remain closed.
Custody inbound bounce handling and its separate payout exception are not
implemented by this no-message constructor.

The paired fixture now constructs an entry at 1073 and a participant at 1127,
from two opening balances of 1000 and two imported messages of 100 each. It
decodes Native AccountStorage balances and transaction fees, then checks the
per-account equations against the transfer graph. Changing one transfer by a
unit fails the check. The imported 200 is the independently known fixture value,
not production InMsg reconstruction. No AccountBlock/shard publication is
claimed by these two private transaction objects.

Nine independently rebuilt controls cover incoming funding, outgoing debit,
the record tag, Native wire width, validation budget, negative values, balance
sealing and the existing no-inbox/no-output guards as reached by this new API.
Raw output and source/binary hashes are retained in
`measurements/uno-v2-allocation-participant-evidence.json`; these are manual
mutation controls, not mutation CI. No new TL-B constructor, production limit,
activation policy or error-origin category is introduced.

The boundary review is retained at
`~/memo/reviews/uno-v2-allocation-participant-review.txt`. The reviewer reran the
green test and independently confirmed the archived source/binary hashes.

| Finding | Disposition |
|---|---|
| 1: null binding throws before validation | Fixed with an explicit argument check returning Status before descriptor construction. This is not a candidate/local provenance classification. The descriptor remains local and is built before preparation; moving it after preparation would weaken failure atomicity. |
| 2: missing builder exception probe | Fixed: null returns an error without a serializable record; a deliberately non-admitted deep binding exercises CellWriteError with unchanged balance and no serializable record. A valid binding has no references, so the deep fixture is an exception-class instrument, not evidence of a reachable valid-wire attack. |
| 3: extra-currency shortcuts hid coverage | Fixed: an independently encoded Native opening balance of currency 7 grows from 5 by incoming 7 and outgoing 3 to 9 in the serialized account. Tests also reject insufficient extra funds, a 248-bit addition overflow, and a positive but insufficient traversal budget. |
| 4: fault-loop output did not identify the arm | Fixed diagnostics now name each case. Separate controls reach negative outgoing and wrong-account binding. The original nine controls are not claimed to independently prove every fault arm; the insufficient-funding arm is not an independently isolated mutation. |
| 5: tag 11 allegedly requires a new owner decision | Disputed: build_workchain_payout_pair already assigns tag 11 to both records, but only custody has an output and fees. The coordinator already has neither. Tag 11 is not payout authority: the existing effects-based reconstruction requirement determines each physical record, including the custody exception. This helper adds no tag or authorization rule. |
| 6: parser parity | Fixed: generated/handwritten validation, exact skip, absent storage phase, zero storage fees and rejection in both current execution scopes are checked. |

Six additional rebuilt controls are archived with raw output and hashes in
`measurements/uno-v2-allocation-participant-review-fixes.json`. Four fail on
returned-status or numeric assertions; removing the null guard exposes
CellCreateError and changing the artificial probe's catch class exposes
CellWriteError. The latter mutates the test instrument, not production logic.
These are manual controls, not mutation CI. An intermediate compile failed due
to a duplicate local variable name; the following stale-binary pass is excluded
from evidence. A corrected-source rebuild and final regression are recorded.

Per-record nonnegative funding and whole-batch conservation are both necessary:
the first alone permits fabricated mutual credits, and the second alone permits
negative balances. The enclosing overlay must independently derive actual
Native message rows and re-decode the effects graph; this fixture still uses
known fixture imports and the pre-encoding transfer vector. Source-aware error
handling, bounded admission, shared graph aggregation, complete AccountBlock /
shard reconstruction and atomic publication remain integration work.

The concurrent design update at memo@74a4d424 changes operation fees to a public
deduction from the initiating confidential balance and adds an aggregate custody
fee-settlement path. This generic allocation factory neither defines nor
authorizes that path. Subsequent relation and settlement integration must follow
the revised design rather than treat the previous zero-operation-fee model as
complete; unresolved fee/congestion parameters are not supplied by this helper.

### Batch-wide allocation planning (M1 integration in progress)

`workchain-allocation-plan.h` decodes the admitted, replayed effects graph once
and accumulates incoming/outgoing CurrencyCollection values in an ordered map.
Every updated account has a row, including accounts with no internal transfer.
Canonical sequential transfer indices, strict source/destination ordering,
nonzero non-self transfers, endpoint membership, explicit entry bounds and
per-currency checked addition are enforced. Its retained transfer vector is
decoded from the wire, not the encoder's original in-memory object.

This is the shared input for restricted participant materialization, avoiding
one full transfer scan per account. It is not a new authorization boundary:
the enclosing host must authenticate/replay effects and admit complete input
closures before this call. The returned aggregates do not prove sufficient
funds. Constructors must check each account's actual old/imported balance,
and whole-batch validation must independently rebuild Native message and
account evidence before checking conservation against this decoded graph.
The current entry factory still has its one entry-local scan; integration may
share the plan but must preserve its existing input/effects binding checks.

The tests use three accounts and four directed edges with independently stated
totals, zero-transfer accounts, generated valid TL-B that bypasses encoder
semantic guards, malformed leaf layouts and real extra-currency dictionaries.
This header and its tests do not enable any live execution scope, change a
consensus caller, add an error category or select resource/configuration values.
They await the M1 milestone review with the overlay integration; no separate
boundary review is claimed for this unconnected helper.

Twelve rebuilt mutations fail numeric or returned-status assertions, with raw
logs, patch substitutions, source/binary hashes, standalone-header compilation
and the restored five-test regression retained in
`measurements/uno-v2-batch-allocation-evidence.json`. These are manual controls,
not mutation CI or exhaustive independent branch coverage. Endpoint membership,
invalid Native-container decoding, zero configuration budget and overflow have
test cases but no individually isolated mutation in this artifact. M1 remains
incomplete until the shared plan feeds actual Native records and full replay.

### Message-free allocation overlay (M1 integration in progress)

`workchain-allocation-overlay.h` now connects the graph plan to private Native
accounts, a single coordinator entry and restricted allocation participants.
The settlement runner invokes the engine once and passes its encoded input and
effects to this path. Even a zero-transfer, no-payout batch now has the entry
carrying the full input/effects; it no longer falls back to only storage records.
Current execution scopes still reject these tags in real blocks.

The overlay binds the complete identity to the caller's resolved context,
decodes declarations, verifies every old read (including read-only accounts),
requires the update keys to equal the declared write set and requires an entry
role. It derives every participant's data from effects and every allocation
from the decoded graph. One entry-local scan remains, but other accounts use
the shared plan rather than rescanning the graph. Currency validation is an
explicit runner argument with no default, checked before engine invocation;
it is not borrowed from an account-storage limit for this path.

For each constructed transaction, Native AccountStorage balances and transaction
fees are decoded independently. The input inbox, effects payout, transaction
in-message and out-message dictionary must all be absent; this is the evidence
for zero imports and exports, not an assumption about nonempty messages. Actual
rows are compared with the wire-decoded transfer graph. The transaction's prior
hash/LT, state hashes, account address and planned LTs are checked before private
commit. Each account gets its own AccountBlock and last_trans chain. The final
dictionary diff and access ledger require exact write/participant/change sets.
Only complete account and AccountBlock roots are returned; no CellDb write or
live account mutation occurs. Replay rebuilds both roots and the end LT and
compares each artifact, returning reconstructed roots rather than claimed ones.

The engine test now has an untouched third account, bidirectional transfer
checks, actual Native balances and descriptor contents, both AccountBlock
parsers, last_trans and state hashes, and replay mutations of each final artifact.
A failure in the second account follows construction of the first private
record but returns no overlay and leaves the old root unchanged. Foreign
destination inbox and payout-presence tests directly exercise this materializer,
not only the earlier runner guard. An invalid currency budget asserts zero
engine calls, independently of rejection wording.

This is not M1 completion or a production conservation gate. Nonempty Native
inbox settlement, allocations combined with payouts, the revised aggregate
custody fee-settlement path, registration, production admission/classification,
and live collate/validate publication remain open. The older payout-only helper
was subsequently connected to the single full entry below. No message is dropped to
make any of those cases fit this message-free path. Milestone review remains
pending; this unit changes no named production consensus-judgement file and
adds no error-origin classification.

The implementation also checks the actual nullable return of Native
`Transaction::commit`; failure is not interpreted as a successful downgrade.
Eleven rebuilt controls cover identity, required entry role, inbox/payout
exclusion, each allocation direction, the entry profile, three separate replay
artifacts and budget-before-engine ordering. A twelfth control restores the old
storage-field narrowing on the allocation path and fails the API-width test.
Logs, patch substitutions and source/binary hashes are retained in
`measurements/uno-v2-allocation-overlay-evidence.json`. All controls are manual,
not mutation CI. The first eleven precede the explicit commit-return check and
the payout-only narrowing refinement; both subsequent changes have a restored
green regression recorded separately. No exhaustive independent mutation of
every redundant Native consistency check is claimed.

### Native final-import evidence (M1 integration in progress)

`workchain-import-evidence.h` constructs standard final InMsg records referencing
serialized Native transactions. Records are keyed by the message hash, not the
envelope hash. The helper checks destination/account agreement, creation and
emission logical times, original versus remaining forwarding fees, explicit
entry bounds and the currency-validation budget. Native import-fee evaluation
and the actual augmented InMsg dictionary independently reconstruct totals.
Account credit is imported value minus collected fees using checked currency
subtraction; forwarding fees must not increase the recipient's principal.

The paired-entry fixture now feeds its independently decoded value-flow rows
from actual InMsg-derived credits rather than a literal imported amount. Tests
also inspect both InMsg parsers and actual envelope/transaction references.
Extra-currency examples test primitive accounting only: they do not claim that
the changed inbox is authorized by the fixture's original batch commitment.
A zero-value, zero-remaining-fee duplicate is important: aggregate totals cannot
detect that duplicate, so it independently witnesses the dictionary Add rule.

This is a post-admission construction primitive, not queue authentication or
complete batch acceptance. Queue membership, inbox completeness, transaction
roles, own-queue dequeue evidence, DispatchQueue provenance and unexpected
destination disposal remain enclosing-host obligations. Entry-count bounds do
not replace closure admission. Exceptions retain their source for the caller;
this helper introduces no error-origin classification or production wiring.
The runner still rejects nonempty inboxes before engine invocation. M1 review
and production admission remain pending.

Thirteen rebuilt manual controls independently remove credit/fee separation,
message-key selection, transaction-address binding, creation/emission LT checks,
the remaining-fee ceiling, each entry bound, the version gate, each currency
budget guard, zero-value duplicate rejection and the processing-transaction
reference. Each build succeeds and each test fails on a state/value or rejection
assertion, not an error-string comparison. Restored five-target regression and
standalone-header compilation pass. Substitutions, raw output and source/binary
hashes are in `measurements/uno-v2-final-import-evidence.json`; these controls
were run manually and are not mutation CI or exhaustive guard coverage.

### Joint final-import and allocation reconstruction (M1 in progress)

The allocation materializer now has a shared implementation that can reconstruct
coordinator-addressed final imports together with internal allocations. It
returns accounts, AccountBlocks and InMsgDescr together, only after independently
decoded Native balance rows balance against actual InMsg credits and the decoded
allocation graph. Transaction references in InMsgDescr point to the transactions
actually committed to those private AccountBlocks. Remaining forwarding fees
are collected in Native import accounting, not credited to accounts.

The common transaction schedule includes both message creation and emitted LTs;
checked scheduling rejects overflow. Replay independently reconstructs all three
roots and the end LT. Credits and fee totals are derived caches, so replay returns
the reconstruction rather than adopting a claimant's copies of those caches.
The existing message-free API delegates with a zero inbox bound. The settlement
runner still rejects nonempty inboxes before engine invocation: custody imports,
unexpected-destination disposal, own-queue/DispatchQueue provenance, payouts and
full authenticated queue completeness are not made supported by this helper.
The explicit new API rejects non-coordinator destinations, including zero-value
messages that would otherwise leave the balance equation unchanged.

Tests inspect two actual incoming message records, both modified Native accounts,
the untouched account, AccountBlock transaction hashes, exact balances and fees,
each independent LT source, four replay artifact mutations and stale derived
caches. This is a post-admission, existing-account integration fixture, not a
confidential Deposit authorization test, a production queue test or M1 closure.
The existing input decoder's fixed semantic-validation allowance and the entry's
timestamp policy still need their production admission/Native-ingress audit;
this change does not silently choose new policy values or classify their errors.

Ten successful rebuilds followed by failing tests witness destination exclusion,
both LT sources, actual imported-row credit, each of the four replay artifacts,
reconstruction rather than adoption of caches, and the combined inbox limit.
The last control removes both count checks; it is not evidence that either
individual check alone is indispensable. All five regression targets and the
standalone header compile pass after restoration. Raw output, substitutions and
hashes are archived in `measurements/uno-v2-inbound-allocation-evidence.json`.
These are manual controls, not mutation CI. M1 milestone review remains pending;
no named production consensus-judgement file or error classification changed.

### Independent payout currency-validation budget (M1 prerequisite)

Payout pair construction, private overlay and replay now receive the same
explicit currency-validation budget as allocation settlement. Neither the pair
accounting nor the independently reconstructed Native value-flow rows borrow
`max_acc_state_cells`. The runner no longer narrows that storage setting to an
integer before payout; storage limits still apply to actual Native account
serialization. No fallback policy value is introduced. The enclosing resolved
policy and source-aware admission remain required before production wiring.

The budget is rejected when nonpositive. Tests use a Native-encoded coordinator
account with an actual extra-currency dictionary: a sufficient budget preserves
that currency while debiting only the Native forwarding fee; a positive but
insufficient budget rejects. Both runner branches produce identical artifacts
with the same currency budget and an account-storage setting above the signed
integer range. This is a width/independence probe, not a proposed storage limit.
The tests do not claim that each repeated defensive check is indispensable.

At this prerequisite stage the full coordinator entry was not integrated; the
following unit connects it. Combined allocations/payouts and custody inbound
settlement remain M1 work; scopes still reject the inactive participant formats.

The consensus-boundary review prompted extra overlay/replay fixtures, explicit
zero-load ordering assertions at invalid budgets, a persisted-balance decode,
and two legal storage-limit comparisons with real extra currencies. Review
disposition and limitations are in `uno-v2-payout-budget-review-disposition.md`.
Early rejection preserves ordering but does not itself classify the Status.
Production integration still must supply the resolved policy and attach each
failure to its actual source; test-only entry points cannot settle that gate.

Nine successful rebuilds followed by failing controls and the restored five-target
regression are archived with substitutions and hashes in
`measurements/uno-v2-payout-budget-evidence.json`. They are manual evidence, not
mutation CI. The boundary review is complete for this substitution and its
test repairs; the full M1 milestone review and production integration remain open.

### Full coordinator entry on the payout path (M1 integration)

The settlement runner now passes the complete committed input and effects
through payout materialization and replay. The coordinator is a tag-12 entry
with the full roots; custody remains the restricted tag-11 payout record and
other storage participants at that stage remained tag 10 (the mixed unit below
changes full-entry participants to tag 11). The pair checks both context roots,
their binding hashes, the payout request and custody data. Entry preparation
binds coordinator data/access/context. The profile at that stage excluded
Native inbox and extra allocations before any credit could be overwritten;
the mixed unit below adds allocations.

There are no default context arguments. Low-level tests explicitly select two
null roots for the participant-only primitive; this is not a live batch mode.
The full-context overlay verifies committed writes, every update, supplied old
hashes and every authenticated read, including read-only accounts, under an
explicit read bound. It verifies each serialized descriptor independently,
including its role, exact refs and full context. Replay rebuilds Native roots
with the same explicit profile. Nothing is published or written to CellDb.

Tests cover a third changed participant and a separate read-only participant,
incorrect third-account data, a conflicting supplied old hash, a conflicting
host LT boundary, missing writes and an invalid read-only hash. They also check
the actual coordinator description and full-root replay. Boundary review and
its corrections are recorded in `uno-v2-payout-entry-review-disposition.md`.
Custody imports, disposal, aggregate operation-fee settlement and production
admission/publication remain unfinished M1 work. The next unit removes the
combined allocation/payout limitation of this intermediate stage.

Thirteen rebuilt failing controls cover runner/replay profile propagation,
partial context, inbox exclusion, request/custody/third-account data bindings,
supplied old hashes, the host LT boundary, entry preservation, read-only state
authentication and the two composite hash contracts. Restored five-target
regression and standalone-header compilation pass. Logs, substitutions and
source/binary hashes are in `measurements/uno-v2-payout-entry-evidence.json`.
These are manual controls, not mutation CI or exhaustive guard coverage.

### Mixed internal allocations and priced payout (M1 integration)

Full-entry payout batches now apply the committed allocation graph before
debiting custody principal and coordinator forwarding fees. All other changed
accounts receive restricted allocation participants. Every full-entry non-entry
record uses tag 11, including zero-allocation participants; explicitly null-root
primitive tests retain their old storage-only third-record shape. Production
scope acceptance is unchanged.

The full overlay independently reconstructs Native rows from serialized
accounts, transactions and messages, then checks the effects graph plus exactly
one priced fee-funding edge. Shared endpoints do not deduplicate away either
value. A checked extra verification slot accommodates this host edge without
expanding the engine's transfer allowance. Overflow rejects before state reads.
Pricing still checks old custody funds independently of allocated funds; an
incoming edge cannot enlarge the prior payout authorization envelope.

Tests now cover both role balances at exact funding boundaries and one unit
beyond, third-account incoming and outgoing allocations, mixed replay at the
exact edge limit, four altered replay artifacts, the full-entry third-account
tag, direct pair balances and the previously untested old-custody envelope.
The pair remains a partial primitive: any graph touching another account
requires that account's participant and the complete independent value-flow
check. Conservation is not withdrawal or fee authorization.

The boundary review and dispositions are recorded in
`uno-v2-mixed-payout-review-disposition.md`. Fifteen manual controls were rebuilt
successfully and then failed on value, tag, load-count, required-success or
rejection assertions. The zero-allocation tag control intentionally changes
both construction and its independent tag expectation, isolating the explicit
serialized-tag assertion. Raw results, substitutions and artifact hashes are in
`measurements/uno-v2-mixed-payout-evidence.json`. They are not mutation CI or
exhaustive coverage of every redundant guard.

This removes the allocation/payout combination limitation, not the remaining
M1 gates: nonempty custody/coordinator inbox integration, unexpected-destination
disposal, aggregate operation-fee output, registration, source-aware production
admission, actual collate/validate publication and synchronization remain open.
No production policy value, additional payout authority or retirement rule is
silently selected. Full M1 milestone review remains due.

### Shared Native inbox planning (M1 integration)

`workchain-native-inbox.h` now supplies a common post-admission plan for final
imports: a bounded canonical envelope list, an explicit strictly ordered set of
allowed recipient roles, and a lower LT bound covering the host, message
creation and message emission. It rejects the whole unsupported message set;
it never filters a foreign recipient out. This is not Deposit, return or fee
authorization. The allocation materializer now consumes the same plan for its
schedule and actual final InMsg reconstruction. Its allowed role remains the
coordinator until custody settlement is integrated; the planner itself supports
an explicitly supplied multi-role set.

The count check precedes dictionary traversal. It does not replace full closure
admission or bound the caller's recipient vector. Native message bodies retain
Native TL-B semantics, not the ordinary-only candidate closure restriction.
The executable positive control uses an ordinary referenced body with an opaque
library-cell child. A first attempted fixture used a library cell as the direct
`^Any` root, which Native TL-B correctly rejects; that setup failure is not
counted as a planner defect or a successful red control.

The existing inbox decoder still converts some VM exceptions into legacy Status
errors. This extraction does not solve source-aware production classification,
authenticate queues, choose disposal semantics, or establish a network delivery
deadline. The timestamp policy audit and enclosing production admission remain
open. No named consensus-judgment file or new error category changed in this
unit; review remains due at the M1 milestone under the current review rule.

The initial positive test failed against an unimplemented stub. Fifteen later
controls were each rebuilt successfully and failed independently: host/creation/
emission LT sources, recipient and workchain matching, anycast exclusion, role
set order/uniqueness/nonemptiness/domain, complete message retention, count-check
placement before dictionary loads, Native opaque body compatibility, and both
allocation schedule/import call-site uses. Moving the count check after decode
changed observed child loads from zero to one while still returning an error.
After exact source restoration, all five regression targets and standalone
header compilation pass. Logs, substitutions and source/binary identities are
in `measurements/uno-v2-native-inbox-evidence.json`. These are manual controls,
not a recurring mutation CI gate or completed Native inbox/payout integration.

### Importing participant and remaining inbound settlement work

The restricted import participant reuses entry validation of full input/effects,
the old account, its write/index and data, then stores only its tag-11 binding.
It applies its own Native message credit and internal allocations without an
engine invocation, ordinary phases or outputs. The unique coordinator entry
retains the full roots. The importing pair test reconstructs actual final InMsg
records and serialized account/transaction balances before checking independent
value flow. Boundary review prompted twelve negative input/context/access/budget
fixtures at the import wrapper, a cached direct-input rejection, and three
perturbed import-flow rows. All seventeen manual removal controls rebuilt and
failed; restored five-target regression and standalone header compilation pass.
See `uno-v2-import-participant-review-disposition.md` and
`measurements/uno-v2-import-participant-evidence.json`. These are manual evidence,
not mutation CI, production custody authorization or completed M1 acceptance.

The next integration must cover both coordinator and custody receiving roles
in non-payout materialization, and the same two roles in payout materialization.
Full input admission and the shared inbox LT plan precede transaction creation.
In the payout pair, imported values and the committed allocation graph must be
applied before debiting payout principal and forwarding fees. The separate old
custody authorization envelope must not be enlarged by those imports. Actual
InMsg augmentation, actual outputs and serialized account/transaction balances
must supply independent value flow, and replay must compare the reconstructed
InMsg root as well as accounts, AccountBlocks, output and LT. A participant's
local credit selection never licenses omission of another envelope.

The complete runner's nonempty-inbox restriction remains until every supported
role and the mandatory disposal paths are integrated. Mechanical credit is not
proof of queue provenance, Deposit admission or authenticated bounce matching.
Repeated full-context validation must be included in admission costs. Retirement
does not remove the descriptor, parameter 84 or custody; this work makes no new
claim about message termination or a finite network delivery deadline.

### Dual receiving-role allocation materialization (M1 integration)

The non-payout materializer and replay now take both coordinator and custody
explicitly, require distinct roles, and canonicalize the two-element receiving
set before planning the complete inbox. Only these two accounts use full-context
credit preparation. Other changed accounts use allocation-only records even if
they appear in the write set; membership in that set is not permission to
receive Native messages. The message-free wrapper still passes a zero inbox
bound and the complete runner still refuses nonempty inboxes until mandatory
disposal and payout integration are delivered.

The test carries three actual envelopes: two for the coordinator, one for
custody. It checks both credited balances, the complete Native augmentation,
each InMsg's actual processing transaction, both participant bindings and the
unique full entry, last-transaction links, replay roots, and an untouched
account. An unsupported-recipient witness includes that third account in the
real write set and imports zero principal. Thus missing transaction evidence
and independent balance checks cannot mask removal of the receiving-role gate.
Distinct-role rejection is tested with a coordinator-only inbox so foreign
message rejection cannot mask it either.

The pre-change materializer rejected the positive custody import. After
implementation the positive fixture passes. Nine rebuilt removal controls fail:
receiving set, custody preparation and independent credit, actual InMsg
processing reference, distinct roles, an unsupported written recipient,
replayed InMsg root, replayed custody role and canonical role order. The role
alias control also removes the planner's redundant duplicate rejection by
deduplicating its input. Restored five-target regression and standalone header
compilation pass. Exact substitutions, logs and hashes are archived in
`measurements/uno-v2-dual-inbound-allocation-evidence.json`; these are manual
controls, not recurring mutation CI. This unit adds neither a new classification nor a
change to a named live consensus-judgment file; independent review remains due
at the M1 milestone. Shared decoder source attribution, aggregate traversal
admission, authenticated bounce matching and full live publication remain open.

### Inbound allocations combined with payout (M1, internal materializer)

The pair prices against old custody and checks its LT additions before creating
private transactions. With full input/effects it then prepares both receiving
roles, including own imports and committed internal allocations, before
debiting payout principal and forwarding fees. Imported or allocated value
cannot enlarge the separately checked old-custody payout envelope. Null-context
primitive callers retain explicit zero-inbox materialization.

The enclosing payout materializer now accepts an explicit inbox count bound,
plans only coordinator/custody recipients before old-state reads, and includes
message creation/emission LTs in the common schedule. Actual serialized
transactions supply final InMsg references. Their Native augmentation supplies
independent account credits before value-flow verification. Replay compares
the rebuilt InMsg root in addition to accounts, AccountBlocks, payout and end
LT. Import totals are returned as derived artifacts, not trusted claimed caches.
The private account commit result is also checked rather than ignored.

The old pair rejected the new importing positive fixture. The implemented
pair/overlay tests pass, including two imported balances, the independent old
principal boundary, a later inbound LT schedule, actual processing references,
explicit count limits and five changed replay artifacts. Boundary review has
completed; disposition is in `uno-v2-inbound-payout-review-disposition.md`.
An added outgoing-allocation pair tests exactly sufficient custody funding
and a one-unit shortfall after imports. One rebuilt control independently
zeros the Native-derived import credit while preserving credited account
state: the legitimate overlay then fails its value-flow check (exit 1).
The unsupported-recipient fixture includes an actual written account and zero
principal so other invariants do not mask the role check. Ten rebuilt controls
turn red: independent import credit, unsupported written recipient, inbound LT
schedule, the composite count limit, all five replay artifacts, and unfunded
principal with the helper's repeated conservation check also removed. The
early-count-only control survives the downstream repeated bound; no independent
zero-state-load overlay witness is claimed. Raw logs, exact substitutions and
hashes are in `measurements/uno-v2-inbound-payout-evidence.json`; these are manual
controls, not recurring CI. This is not M1 acceptance. The complete runner still rejects nonempty inboxes;
disposal, authenticated return/withdrawal authorization, aggregate operation-fee
output, production classification/publication and synchronization remain open.

### Shared Native bounce body encoding (M1, shared encoding component)

The ordinary bounce caller now delegates body encoding to a stateless helper
that writes only its caller-owned CellBuilder. Format and phase selection stay
in the ordinary caller; address rewriting, pricing, debit and queue publication
are unchanged. This is a prerequisite for sharing bounce construction with
batch disposal, not a second fee algorithm and not completed disposal.

The new test directly decodes legacy prefix/truncation, rich body with and
without references, original value/LT/time and diagnostics. Twenty-four actual
ordinary calls cover flags 0/1/2/3, legacy lengths 0/256 and three phase
outcomes. The reviewed fixture gap is fixed: action result 7 differs from
compute exit 42. Five rebuilt controls fail for source selection, full-body
refs, original LT, truncation and swapped compute counters. A separate
capacity fixture first exposed an ignored prefix-write result; the throwing
store now propagates CellCreateError. The initial catch named the wrong class
and was corrected against runtime and ensure_throw, not hidden from evidence.
Explicit price initialization also fixes an earlier fixture failure, which is
not mutation evidence. Review disposition is in
`uno-v2-native-bounce-body-review-disposition.md`; logs and hashes are in
`measurements/uno-v2-native-bounce-body-evidence.json`. This remains an encoding
component, not full pricing, disposal or production activation.

### Shared Native bounce storage measurement (M1, shared component)

A stateless wrapper now measures the Native bounce pricing closure with one
CellStorageStat, preserving deduplication across optional currency and body
roots. An absent currency root explicitly contributes zero; actual traversal
errors are returned rather than used as partial sizes. The ordinary caller
checks the result before calculating fees or debiting balances. Source
failures are not reclassified. The inherited NoVm walker can fail fatally on
unavailable descendants: future batch callers must authenticate, admit and
fully materialize/validate the closure first, not rely on root is_loaded().
The legacy walker and fee arithmetic are unchanged;
this helper is not resource admission or a source-classification boundary.

Direct tests cover separate/shared currency roots, optional absence and an
actual null body root. Existing ordinary bounce tests now assert exact pricing
cells/bits for legacy and both rich modes. Twelve additional actual Native
calls cover the version/currency switch and exact-funds/nofunds pricing.
Six rebuilt controls fail for currency inclusion, optional absence, shared-root
deduplication, actual body-root failure, caller switch and caller pricing input.
These are manual controls, not recurring mutation CI. Review disposition is in
`uno-v2-native-bounce-storage-review-disposition.md`; raw evidence is in
`measurements/uno-v2-native-bounce-storage-evidence.json`. The defensive phase
reset has no independently demonstrated canonical Native wire trigger.
This is not completed disposal, live admission or M1 acceptance.

### Bounce value isolation (M1, post-selection accounting)

The read-only bounce accounting primitive derives returned value, in-flight
forwarding value and collected fees from an already selected affordable bounce.
Only the imported message funds the return; the processing account's old
balance is unchanged. Extra currencies remain in the returned value. Checked
CurrencyCollection operations and the independent per-account value-flow
equation close the arithmetic before any state write.

This is not a second price algorithm: callers must obtain fees from the shared
Native price rules. It neither chooses the three-way disposal branch nor
authenticates an input or authorizes an address exception. Its Result cannot
be converted into permission to credit the unexpected bucket. No production
caller or new error category is installed. It is queued for the M1 milestone
review; any later consensus-boundary wiring requires immediate review.

The actual test preserves an extra-currency amount of five, returns 23 from
an imported 123 with a total fee of 100, and independently exports 98 including
the remaining forwarding fee. Exact-funds, zero-fee and insufficient-funds
cases are included. Three rebuilt mutations (return debit, remaining forwarding
fee, old-balance preservation) fail. Restored workchain-block CTest passes.
Raw evidence: `measurements/uno-v2-bounce-accounting-evidence.json`; these manual
controls do not claim isolated coverage of every guard or recurring mutation CI.

### Shared Native bounce message encoding (M1, shared component)

The ordinary caller delegates final message serialization to the shared builder.
It retains source/destination rewriting, masking of extra_flags, fee debits and
LT allocation. The builder fixes bounced=true/bounce=false/IHR-disabled, encodes
the admitted CurrencyCollection and remaining forwarding fee, and chooses the
same inline/reference body form. Construction failure is never nofunds.

This is not the assembled multi-account disposal path: address exceptions,
admission, fee affordability and queue publication remain caller obligations.
The direct decoder test covers both body forms and all header fields. Boundary
review exposed two surviving mutations in the original coarse sizes. Eight
revised vectors include adjacent 350/351-bit bodies and extra-currency reference
pressure. The pre-existing ordinary collator exception gap is recorded, not
claimed repaired by this extraction. Review disposition:
`uno-v2-native-bounce-message-review-disposition.md`. This is still not complete
multi-account disposal or production activation.

### Shared Native destination rewrite (M1, shared routing component)

The ordinary Transaction wrapper delegates to the same routing algorithm with
its account address as the explicit anycast prefix source. Batch reconstruction
can reuse it without constructing a mutable ordinary Transaction or copying
the unknown-workchain, accept_msgs, address-length, ingress and normalization
rules. The resolved workchain table and complete admitted address closures are
preconditions; this bool API is not a local-data/configuration error classifier.

Direct tests cover addr_var normalization, masterchain classification, unknown
workchains, disabled receiving, anycast prefix replacement and ingress checks.
The existing actual send test now explicitly initializes both price records;
no default production price is installed. Review found a masked anycast test;
the matching-address negative now isolates that guard. Rebuilt controls for
that guard, allow_anycast and sender prefix all fail. Typed resolved configuration
remains a prerequisite for any new batch caller, not enforced by this bool API.
See `uno-v2-native-destination-review-disposition.md` and
`measurements/uno-v2-native-destination-evidence.json` (manual controls, not CI).
The two-address V2 ingress policy and full disposal are not
implemented merely by exposing this existing single-address policy function.

### Composed Native disposal planning (M1, reviewed component)

A post-admission planner now composes routing, body construction, closure
measurement, Native bigint pricing, checked value-flow accounting and
outgoing message encoding. Already-bounced, bounce-disabled, protocol-unreachable
and insufficient-imported-value paths credit the unexpected balance. Errors and
exceptions do not select credit. The resolved workchain table is supplied by
reference and rebound locally; no nullable cfg pointer is used for routing.

The message's effective final destination is checked against the supplied
workchain/address. The processing account intentionally differs; its authorized
role must be authenticated by the enclosing batch. The result names the branch
explicitly and retains the original message for attribution. Source address,
diagnostics and anycast policy have explicit, non-default profile inputs; the
ordinary-comparison fixture does not select a production profile. A constructor
requires all three profile arguments; empty aggregate construction is disallowed.

This is still not live disposal: legitimate-entry classification,
complete closure materialization/admission,
typed failure provenance, bucket counters and InMsg/OutMsg publication remain
outer obligations, including versioned InMsg/OutMsg address exceptions. The
planner checks its constructed accounting row; this is not independent replay
of Native records. The comparison fixture independently executes an ordinary
Native transaction and compares the complete bounce hash, balance and fees.
The new bigint serializer retains the full 120-bit Tomis wire fee; the existing
ordinary uint64 call remains unchanged. Large measured prices are not truncated
or turned into local faults merely for exceeding uint64. An unaffordable but
representable price selects credit using the actual imported value.

Tests exercise bounce amounts and all four economic credit reasons, invalid
configuration not becoming credit, and compare the returned message hash,
balance and fees with an actual ordinary Native bounce. This measures
composition, not independent implementations of the shared encoding helpers.
Follow-up review fixes include direct diagnostic/anycast/reference-body witnesses
and a stale-but-valid configuration witness that fails without null-pointer UB.
Thirteen rebuilt runtime mutations fail in the named test; a separate removed-
constructor control fails at the intended compile-time assertion. Restored
five-target CTest and standalone-header compilation pass. These are manually
run controls, not recurring mutation CI or exhaustive branch coverage. Evidence:
`measurements/uno-v2-native-disposal-evidence.json`; disposition:
`uno-v2-native-disposal-review-disposition.md`. M1 acceptance remains open.

### Detached Native closure acquisition (M1, boundary reviewed)

NativeCellMaterializer constructs an owned DataCell DAG before Native parsing
or legacy NoVm pricing. It preserves encoded special cells and all significant
hashes/depths, never executes library references, and never replaces an encoded
pruned branch with an imagined complete subtree. Virtualized acquisition,
unavailable data, mismatched metadata and builder/allocation failures are local
failures. Resource exhaustion has a separate NativeClosureLimit result; it is
not authorization to discard a queued message or declare its contents invalid.

The result has a private constructor and contains no lazy descendants. A fresh
call is a new acquisition attempt; no partial result is published on failure.
These are physical acquisition counters, not V2's final logical-root definition.
Production admission must allocate a budget from authenticated policy, account
for the shared candidate/inbox/witness union and derived wrappers, and establish
queue provenance and completeness separately. Zero limits permit empty input.
No configuration fields, defaults, production gate or message profile are
installed by this component. The post-admission multi-account runner now accepts
owned Native input, checks allowed destinations before invoking the engine, and
passes the inbound bound through allocation and payout settlement. This is not
integration into the live collator or validator. Misdelivery disposal, complete
admission and production version gates remain open.

Manual rebuilt controls and their source snapshots are recorded in
`measurements/uno-v2-native-materialization-evidence.json`. All 22 closure
controls failed as intended (21 runtime controls and one constructor compile
control); restoration passed all nine admission tests. The five runner controls
precede the final closure exception-test additions; their snapshots are recorded
separately. These controls are not recurring mutation CI or M1 acceptance.

Retirement remains migration without removal of ConfigParam 84 entries, the
workchain descriptor or custody. Economic settlement does not establish that no
Native message still needs the old destination. Complete workchain removal needs
a separately authorized message-termination design; a failed bounce constructor
must not be interpreted as successful degraded delivery.

### Unified account settlement replay (M1, not live)

`workchain-account-replay.h` reconstructs the input from the separately supplied
admitted context and checks the claimed input before acquiring old accounts or
calling the engine. It then invokes the full settlement runner once in this
independent validation context, rebuilding effects, accounts, AccountBlocks,
InMsg evidence, end LT and the optional outgoing message. Each artifact is
compared, not merely a batch digest. Returned import totals and account credits
are reconstructed caches, never adopted from the claim.

This remains post-admission code: complete source authentication, claimed-cell
materialization, physical/semantic budgets and source-aware error containment
belong to the enclosing host. The preliminary input reconstruction and the
runner's reconstruction are both work that admission must cover. It neither
publishes state nor enables the multi-account consensus version. Missing
misdelivery and operation-fee settlement paths are not made supported by replay.

The positive fixture first failed against an unimplemented replay stub, then
passed for payout and no-payout with a two-role inbox. Ten rebuilt removal
controls fail independently, covering input, effects, accounts, AccountBlocks,
InMsg, end LT, message presence/content, reconstructed caches and missing claims.
The restored positive passes. Raw evidence and the exact replay source are in
`measurements/uno-v2-account-replay-evidence.json`. These are manual controls,
not recurring mutation CI. This new replay integration awaits milestone review;
the preceding materialization boundary review does not cover this later file.
Final checkpoint regression passes all five related CTest targets and standalone
compilation of both new headers. Commands and final source/binary identities:
`measurements/uno-v2-account-replay-regression.json`.

### Candidate acquisition provenance (F11, boundary reviewed)

The candidate factory now classifies a local virtualized view as
`LocalUnavailable::CellIdentity`, matching Native acquisition. An encoded,
profile-forbidden special constructor remains `CandidateInvalid::ForbiddenSpecial`.
These are different representations and different provenance, not two verdicts
on the same wire constructor. The unused prototype `VirtualizedInput` rejection
enumerator is removed; no serialized policy, transaction or ABI changes.

The test explicitly deserializes a nonzero-level pruned BoC to isolate this
boundary from an earlier decoder profile gate. It then creates local views at
the root and below an ordinary root, checking local classification, zero loader
calls and the retained first outcome after the loader changes. On the original
implementation it fails at the local-variant assertion; after the change all ten
admission tests pass. Manual evidence:
`measurements/uno-v2-candidate-provenance-evidence.json`. No claim is made that
this narrow change closes every loaded-metadata, exception or production
admission integration obligation. Immediate classification review confirmed the
decision (`~/memo/reviews/uno-v2-candidate-provenance-review.txt`). Review fixes
clarify the synthetic descendant fixture, remove nondiscriminating retention
assertions and correct the older admission contract. The load counter remains
the independent retention witness. The legacy preflight counter still has plain
Status errors and is explicitly prohibited as a production verdict adapter.
Loaded-metadata validation beyond this view check remains a separate obligation.
After review corrections, three rebuilt controls separately change local views
to candidate rejection, encoded special cells to local failure, and remove the
outcome cache. All fail; restoration passes both related CTest targets (2.76 s).
Exact source, substitutions, raw logs and final hashes:
`measurements/uno-v2-candidate-provenance-controls.json`. These are manual
controls, not recurring mutation CI or completed production admission evidence.

### Candidate loaded identity (boundary reviewed)

Candidate acquisition now checks full significant-level hash/depth identity on
fresh loads and cache hits, and checks loaded virtualization/effective level
before interpreting the candidate's encoded profile. A local metadata mismatch
cannot be converted into either proof of absence or a forbidden-special verdict.
`VmFatal` and `std::length_error` from acquisition are contained as existing local
execution/allocation categories. No new wire error codes or production callers
are introduced. This does not authenticate old shard state or finish aggregate
candidate/inbox/witness admission.

Six separate tests failed on the unchanged implementation: fresh and cached
depth corruption, effective-level mismatch, loaded-view traversal ordering, and
the two exception types. After implementation all sixteen admission tests pass.
The ordering witness observes descendant work, not rejection text. Faulty loader
fixtures are local acquisition models, not alleged serializable peer inputs.
Evidence: `measurements/uno-v2-candidate-identity-evidence.json`. Immediate
error-boundary review confirmed the changes
(`~/memo/reviews/uno-v2-candidate-identity-review.txt`). Test comments now
identify the synthetic masked-loader shape and the query counter that isolates
traversal ordering. The finish-path hash comparison retains its documented
ordinary-only, level-zero induction. As a review follow-up, rebuilding now uses
`finalize_novm`: the ambient-VM test first observed two create callbacks on the
old path, rather than assuming verification was isolated. Existing exception
clauses not exercised by these new candidate tests are not claimed as newly
mutation-covered. Seven rebuilt controls independently remove fresh/cache
identity, effective-level, loaded-view, the two new exception clauses, and
ambient-VM isolation. All fail; restoration passes both related CTest targets
(2.86 s). The admission binary now has seventeen tests. Exact source,
substitutions, raw logs and final hashes:
`measurements/uno-v2-candidate-identity-controls.json`. Manual controls remain
distinct from recurring mutation CI; M1 production integration is still open.

### Routed final-import records (M1, not live)

The explicit routed constructor shares Native import encoding, checked
CurrencyCollection arithmetic and dictionary augmentation with the unchanged
strict constructor. Resolved custody arrivals retain their own transaction;
other arrivals use the resolved coordinator. The original destination and
envelope remain unchanged. The processing account's actual serialized identity
must match the derived role, not merely a key in a supplied map.

This is the common InMsg record shape needed by both disposal outcomes. It
does not decide bounce versus unexpected credit, settle bucket data, construct
OutMsg evidence, or enable a Native semantic-validation exception. The mixed
fixture uses real transaction encodings but does not claim those transactions
already settled its changed inbox. Full disposal settlement and exact replay
integration remain required. Gross imported credits are not backing entries.
No retirement behavior or configuration gate changes here.

The unimplemented constructor first failed at the positive-result assertion.
Subsequent manual controls and regression evidence are recorded in
`measurements/uno-v2-routed-import-evidence.json`; scope and arithmetic are in
`uno-v2-routed-final-imports.md`. These controls are not recurring mutation CI.
This helper-only unit awaits M1 milestone review and is not milestone closure.

### Coordinator disposal transaction (M1, boundary reviewed)

The explicit disposal entry now shares the strict entry's full input/effects,
read/write, ordinal and data checks, then reconstructs foreign final-import
disposal through the Native planner. Own and custody entries are not consumed
twice. The transaction retains unexpected value, applies internal allocations,
serializes its actual balance and fees, and seals all bounce messages with
checked LTs. Existing strict entry and importing-participant behavior is
unchanged. The work still does not publish a queue or accept a live address
exception.

The new two-account fixture is stronger than the preceding record-shape
fixture: the transactions actually prepare against this same committed inbox.
It checks value flow from decoded account balances, serialized out-messages and
fees, and reconstructed InMsg credits. It also exercises an unaffordable bounce
as economic credit with a zero-output budget, one-bounce LT overflow without a
later message masking it, context limits and sealed-output mutation. The
unimplemented factory first failed the success assertion after a build.

Immediate consensus-boundary review ran both the new test and all 82 block
tests. Follow-up adds five isolated custody-context witnesses and a transfer
whose funding depends on retained credit. The latter pins Native cash ordering,
not bucket-spend authorization: preservation and authorized movement of that
liability still belong to the engine. An ordinary Status is not a voting
classification; source-aware configuration and exception adaptation remain
production prerequisites. Review disposition and scope:
`uno-v2-disposal-entry-review-disposition.md`. No M1 completion is claimed.

### Disposal allocation overlay (M1 integration, milestone review pending)

The reviewed disposal entry now feeds the private multi-account overlay. The
coordinator is prepared once before the output-aware LT schedule is finalized;
participants, actual exported value, AccountBlocks and routed final imports are
then reconstructed together. Replay compares every returned root and the end LT,
and returns reconstructed output caches rather than caller-provided caches.
The old strict entry remains strict; the explicit disposal entry requires an
unsplit shard. A third untouched account and a later insolvent participant are
included in the integration fixture.

Ten rebuilt manual removal controls turned red; restored five-test CTest
regression and standalone header compilation passed. Scope and remaining Native
queue/metadata/actual-source FIFO obligations are in
`uno-v2-disposal-allocation-overlay.md`; raw evidence and substitutions are in
`measurements/uno-v2-disposal-overlay-evidence.json`. No live queue publication,
validator address exception or M1 completion is claimed.

### Disposal runner and replay (M1 integration, milestone review pending)

The explicit runner now carries all materialized Native final imports through
one account-engine invocation into the disposal overlay. Independent replay
checks the full input before its own single invocation and reconstructs the
Native roots and derived export caches. The strict existing runner is unchanged.
Unsplit, distinct-role and pricing consistency failures occur before engine
execution. These structural checks do not authenticate configuration.

Ten rebuilt controls failed, including zero-call witnesses for the early checks.
An additional positive payout regression exposed an unnecessarily broad initial
guard; removing it preserves the existing no-foreign-input payout path. Combined
custody payout and coordinator disposal remains the next settlement integration
step, before live queue/validator activation. No input filtering is introduced.
Restored five-test CTest regression and standalone header compilation passed.
See `uno-v2-disposal-runner.md` and
`measurements/uno-v2-disposal-runner-evidence.json`. M1 remains incomplete.

### Joint payout/disposal pair (M1, boundary reviewed)

The private payout pair can now prepare coordinator disposal and custody payout
together, retaining disposal fees/messages while charging payout principal and
forwarding against their separate accounts. The resolved output count is
batch-total and includes custody's message. Pricing and routing tables must come
from the same resolved references. This is not authentication by pointer identity.

Boundary review findings and disagreements are recorded in
`uno-v2-joint-pair-review-disposition.md`. Follow-up added table/context witnesses
and a complete value-flow check decoded from serialized Native artifacts.
Eight rebuilt controls turned red; restored production validator compilation,
five-test CTest regression and standalone header compilation passed.
The next step is integrating the pair into the full write-set overlay with
multi-emitter scheduling and Native queue reconstruction. The old payout overlay
still accepts only its existing single-emitter shape; no mixed-batch publication
or M1 completion is claimed.

### Complete admission for mixed disposal and payout (boundary reviewed)

The existing mixed settlement and replay now have `AdmittedBatchInput` overloads.
They derive read/write/inbound/transfer limits from that permit and retain its
old-state meter; they accept no second declarations root. A duplicated Native
context inbound allowance must match before any state load or engine invocation.
Context mismatch is a local contract failure, not a candidate verdict. Context
authentication and Native queue authentication remain enclosing host obligations.

The integration fixture produces three outputs in one engine invocation and
reconstructs an erased export cache. Five rebuilt removal controls fail: context
classification, input commitment, Native inbox equality, authenticated old-state
budget, and independently rebuilt effects. The context control changes the
error class; the other four cause erroneous acceptance. Substitutions and logs
are in `measurements/uno-v2-complete-disposal-controls.json`. These are one-time
controls, not recurring mutation CI. Restored WorkchainBlock regression passes
111 tests and the removed-domain scan passes. The production validator-engine
target also builds. Prototype overloads remain intact.
This closes a private call-chain gap, not live I13c/I13d: complete provenance,
proof/output admission, D31 completion, D32 and live atomic publication remain
outstanding.

Review disposition (raw review is working material outside this repository):

- Finding 1 accepted as a live prerequisite, not closed: `max_outbound` is still
  supplied by the Native context and has no field in this admitted policy.
  It must have a single authenticated or protocol-derived source before live
  use. `max_transfers` is a different quantity and must not substitute for it.
  This delivery adds neither a field nor a local/default numeric allowance.
  Do not promote `max_inbound + 1` into the complete engine's outbound policy:
  that bound covers this private disposal/single-payout shape only. The approved
  engine also has Native unexpected-bucket sweep outputs (`K_sweep`). It also
  owes registration-deposit returns on account closure; do not assume their
  physical route from the word "return". Enumerate the authorized physical
  output shapes before deriving a whole-batch bound. Internal balance allocations
  and aggregate fee accounting do not themselves emit Native messages.
- Finding 2 accepted: the old-state acquisition scope is contained, but the
  whole settlement/engine/encoding frame is not. Known exception classes must
  be tested at their source-aware boundary before live authorization; a broad
  candidate-error catch is not a fix. The present overloads retain this limit.
- Finding 3 accepted for the provenance gap; a blanket reclassification is not
  justified. Mismatch alone cannot identify which side is wrong. A wrong
  candidate inbox and a missing authenticated host inbox need different
  treatment. The new test proves early rejection and zero state/engine calls,
  not authentication or a final source-specific verdict for this mismatch.
- Finding 4 fixed above: D31 explicitly remains unfinished. The reviewer
  independently ran all 111 tests and matched the three source hashes; the
  production build was run by the implementer, not by the reviewer.

All three residuals are prerequisites to opening the live execution gate; no
private helper signature or passing replay fixture discharges them.

The private effects-admission connection has completed its boundary review and
implementer controls; it does not enable live execution. The batch
settlement template now walks the engine's update, extra-currency, payout,
receipt and event references before effects encoding, then charges the encoded
effects root into the same effects-only cells/bits union before Native overlay.
The prototype path remains unmetered. An independent `CellStorageStat` fixture
accepts exact limits and rejects one-less limits for each dimension. Six rebuilt
controls cover the final wrapper, cells, bits, pre-encoding receipt acquisition,
local acquisition classification and transfer-count-before-read ordering.
`measurements/uno-v2-effects-admission-inflight-controls.json` distinguishes
earlier controls from that tested logic. The archived tested-header preimage
allows comparison with the later construction-bound, closure-dependency and
enforcement-summary comment corrections. The original restored artifact records
that earlier stage's hashes, 111-test regression and passing scan, not the
subsequent expanded tests or current-tree hashes. A production build also ran.

This connection does not bound allocations already performed by the engine or
claim incremental charging of dictionary path copies. The current encoder's
cumulative construction bound is `259*U + 36*T + 2` Cells (U admitted updates,
T admitted transfers); the code states the decreasing-key-width argument and
the separate final-union budget. Complete output and proof-work admission,
source-aware whole-frame exception containment and live authorization remain
unfulfilled. The follow-up review was read-only, not an independent test run.

Effects-boundary follow-up review disposition (2026-09-08):

- Accepted: zero effects/output budgets must fail configuration installation,
  and later authenticated-cut failures remain local. The 17-field inventory
  above is not full positive-budget compatibility. The effects encoder's
  two-cell/261-bit structural floor is an explicit remaining installation gap;
  mandatory input/account/output floors also belong to that pre-live audit.
- Accepted: prewalk witnesses need actual independent deletion runs, not merely
  correct-looking assertions. Expanded tests cover all five reference groups,
  count-before-read at transfer limits zero and one, both early quota dimensions,
  and an opaque-receipt old-permit comparison. Assertions guard vector indexes
  before access and log the active field/dimension. Ten additional independent
  builds now fail their assertions and are restored in
  `measurements/uno-v2-effects-admission-followup-controls.json`: five group
  deletions, moving the transfer gate after acquisition, installing a meter on
  the legacy permit, disabling each pre-encoding quota, and interpreting zero
  transfers as unlimited. The older six-control artifact is not evidence for
  these expanded witnesses. This is archived implementer-run mutation evidence,
  not a claim that CI automatically reruns the mutations.
- Disputed as a fix: rejecting only `max_proof_units == 0` would not supply the
  missing proof-work enforcement. Positive values are equally unenforced today.
  A source-text test pinning that absence would preserve the gap, not test the
  intended operation. Keep the live gate closed and implement deterministic
  proof-work admission with a zero-work/positive-work boundary control. No
  implicit unlimited convention or numeric weight is installed here.
- Accepted: meaningful `max_transfers == 0` needs a behavioral control; it must
  reject a nonempty transfer vector before touching its payloads. This does not
  prove compatibility between a chosen allowance and required engine actions.
- Accepted: keep the historical artifact hashes historical. The tested-header
  preimage establishes the old tested logic; later comment changes and expanded
  tests require their own current-source evidence. The follow-up reviewer did
  not build or execute tests. Its claim of no run is supported only as an
  absence of a recorded run in the artifacts it inspected; implementer runs
  outside those artifacts are not substituted for archived evidence.
- Accepted: split the auxiliary ledger into resident-object and cumulative-work
  tables with implementation sources; sum measured bytes and measured work in
  their own dimensions, accounting for lifetimes and concurrency.

These dispositions do not close the whole-frame exception boundary or authorize
live execution. The new legacy receipt assertion was added after the follow-up
review snapshot; its independent mutation is included in the ten-control
artifact. It fails on an extra receipt load, not just a changed error message.
The final restored-source hashes and complete 111-test block / 30-test admission
runs, production validator build, scan and whitespace check are archived in
`measurements/uno-v2-effects-admission-final.json`. This supersedes the earlier
restored-stage artifact for the current tree, without rewriting that evidence.

### D31 private Native output-record admission (in progress)

The existing complete-input settlement now walks the newly rebuilt Accounts,
AccountBlocks, final InMsgDescr and exported message/transaction closures under
one authenticated output cells/bits union. Each new Account independently obeys
the same authenticated per-account cells/bits/depth bounds as state acquisition;
sharing content with another account does not exempt its local closure. A new
output exceeding policy is CandidateInvalid. Unavailable locally rebuilt content
is LocalUnavailable, not a candidate defect or persisted-state corruption.

Only validated write keys select new Accounts. The complete ShardAccounts tree
is deliberately not treated as an output closure: untouched accounts are not
new output. Native account-dictionary and shard/queue update evidence remains a
later root group. An immutable private meter snapshot carries the accumulated
union for that continuation; replay recomputes it and never trusts the claimed
snapshot. Copying and extending a snapshot preserves limits and sticky failure
without sharing mutable accounting state.

This is post-construction record admission, not an allocation preflight or a
final execution permit. Dictionary construction and repeated work still require
their independent bounds. Proof-work admission, whole-frame source-aware
exception handling and final queue/shard-update admission remain open. No live
multi-account gate is opened and no I13 acceptance row changes here. The legacy
singleton permit does not acquire the new meter.

Review disposition:

- Findings 1/7: full 111-case block and 30-case admission runs, production node
  build and scan were completed while the reviewer was running, and archived in
  `measurements/uno-v2-output-records-restored.json`. The reviewer did not run
  tests; its absence claim applies to the artifacts it inspected. A subsequent
  test rearrangement needs its own restored-tree run, not retroactive attribution
  to that artifact. The before-fix record is an earlier draft of the first quota
  assertion; the twelve-control record identifies the later tested source hashes.
- Finding 2: accepted. The first whole-state mutation hit the old-state observer
  before the separate cold-account test. Move the cold-account witness into the
  first complete settlement, followed by a warm-source hash comparison. Record
  an independent whole-state mutation against that arrangement. Whole-state
  traversal is not merely overbilling: it can read tracked untouched content
  outside the preadmitted state union. Queue/shard continuation must preserve and
  satisfy that observer as well as output policy; increasing output limits alone
  cannot make such reads admissible.
- Finding 3: remove the unreachable null-root return; document that all three
  dictionary outputs are finalized wrapped roots, including empty dictionaries.
  Their construction failures throw and belong to the pending local boundary.
- Finding 4: accepted. AccountBlocks reference transactions whose descriptions
  reference host input and effects. Those closures are therefore included again
  in the separate output union (deduplicated within that union). Admission under
  an input/effects allowance does not exempt them from output limits. Joint
  policy compatibility and minimum-hardware sizing must include this coupling;
  this is not newly retained state or new physical allocation of every cell.
- Finding 5: retained as an explicit pre-live obligation. Own-output dictionary
  construction/lookup and allocation exceptions require a local-failure boundary;
  no broad candidate-invalid catch is introduced around mixed sources here.
- Finding 6: do not add a second unreachable range guard. The existing comment
  identifies the checked runtime invariant: this same immutable policy passed
  `account_engine_detail::execute`'s `0 < depth <= UINT16_MAX` check before the
  output stage can run, including empty declarations. This is not reliance on a
  numeric default. The authenticated output depth value is independently removed
  in a failing control. Any future stage bypassing acquisition must establish its
  own checked narrowing, not inherit this statement.

The twelve independent red controls and their exact substitutions are in
`measurements/uno-v2-output-record-controls.json`. They are archived one-time
implementer runs, not an automatic mutation CI job. Production and test hashes
remain tied to their actual run stage; later follow-ups do not rewrite them.

The follow-up cold-account control now fails at the first unavailable-account
settlement's success assertion after a whole-state walk triggers LocalUnavailable
in the old-state observer. This demonstrates the cold-source noninterference
requirement, not a claim that the observer permits an actual load of that account.
The independent warm-source result has the same rebuilt account hash. Follow-up
red and final restored regression evidence is archived in
`measurements/uno-v2-output-record-review-followup.json`.

### D31 own-output exception boundary (in progress)

Before adding the queue/shard continuation, contain the existing own-output
admission stage. The outbound builder accepts current private queues after
Native processing, not raw previous-state roots; treating those roots as a
whole old-state closure is not a correct shortcut for path-aware state admission.
That integration must carry both state and output accounting with the original
proof tracking and distinguish already-built nodes from old source reads.

The new narrow output closure explicitly captures rebuilt artifacts, decoded
declaration keys, immutable resource limits and a capture-free traversal helper.
It cannot call the engine or decode the candidate without changing that capture
boundary. Native read/decode, virtualization, gas/fatal, cell-create/write and
allocation exceptions become LocalUnavailable. Returned quota overruns remain
CandidateInvalid. The custom old-state footprint signal still reaches its
existing sticky observer, and no snapshot is returned on failure. Legacy
singleton calls do not enter this boundary.

Eight independent exception types are injected at the last observed output
read, after a successful identical-source calibration. On the unchanged
implementation every type escaped and the aggregate assertion failed at 8 != 0.
This concerns recoverable injected exceptions, not a guarantee that Status
allocation succeeds under process-wide memory exhaustion. It does not contain
the earlier engine/effects/Native preparation frame or authorize live execution.

Review disposition: accepted the exception-inventory coupling concern. The meter
and output boundary now cross-reference one another; a final std::exception
handler contains other standard own-output faults without catching the unrelated
custom footprint signal. A ninth runtime_error witness first escaped the eight-
clause implementation (1 != 0). The capture comment now distinguishes absence of
direct engine/parser access from arbitrary load callbacks on engine-produced
Cells. The latter are local implementation behavior, not fresh candidate parsing.

Evidence is indexed in `measurements/uno-v2-output-exception-controls.json`
(original eight-class red run, compile-capture controls, classification mutation,
historical initial-green hashes) and `measurements/uno-v2-output-exception-restored.json`
(that stage's complete regression). The classification mutation aborts at kind 0:
localization of kinds 1-7 follows from their same calibrated injection point and
the shared return, not seven extra mutation runs. Final ninth-class follow-up
and restored-source evidence is in `measurements/uno-v2-output-exception-followup.json`.
The reviewer inspected source and archived evidence, but did not build or run.

### Private outbound descriptor admission continuation

The outbound builder now has a settlement-derived continuation: no second
message list is accepted. It copies the immutable output-meter snapshot and
charges the rebuilt per-block OutMsgDescr into that same union, preserving
shared message and transaction deduplication across stages. A failed continuation
does not mutate its predecessor's snapshot. Missing continuation context is a
local contract failure, while exceeding the authenticated output allowance is
CandidateInvalid. Excess export count and illegal deferral choices are likewise
candidate errors; authenticated dispatch corruption retains its separate code.
Local queue construction and reads use the own-output exception
boundary, not a candidate parsing boundary.

This is not complete queue admission. The supplied roots are the host's private
queues after earlier Native processing; old-state reads still require their own
authenticated admission. Persistent outgoing/dispatch roots are intentionally
not whole-tree charged as new output: doing so would traverse untouched history.
Their update proofs, the final shard update, preconstruction work bounds and
the live invocation remain outstanding. Public result structs are not unforgeable
authorization tokens; replay must construct this continuation from its own
settlement, never from a claimed meter. No live execution gate is opened here.

Initial review disposition: accepted the export-count classification and the
missing deferral/nonempty-descriptor coverage. Disputed the proposed two-batch
failure scenario: one logical engine batch per block is required, and the D31
output budget is for the block, not a fresh budget for each builder invocation.
OutMsgDescr is a per-block record dictionary; unlike the persistent outgoing
and dispatch queues, earlier Native records in it are part of this block's
output and must be charged. A resumed nonempty fixture now checks the final
union against an independent storage oracle. This fixture rearranges local
records and is not evidence of multi-batch authorization.

Deferral is an externally proposed choice, so its explicit ordering failure is
preserved as CandidateInvalid. Message contents, transaction metadata, queue
roots and Native policy remain local reconstruction inputs. Their public types
do not prove provenance; the enclosing live adapter still must exclude claimed
records from those inputs. The review's assertion that metadata and duplicate
message identities are supplied by candidate queues does not hold for this
settlement-derived interface, but the absence of a live provenance adapter is
real and remains an activation limitation.

Four independent rebuilt controls failed: omitted descriptor charging and
returning the prior meter each produced 82 versus 91 cells; classifying either
export-count excess or illegal deferral as local failure produced -7201 versus
-7200. Each mutant was generated from one full-file baseline, not cumulatively.
After complete-file restoration all four original snippets occurred exactly once,
and reapplying each recorded substitution reproduced its archived source SHA256.
The controls are manual, not a CI mutation facility. Records and substitutions
are in `measurements/uno-v2-outbound-continuation-controls.json`; restored-source
111 block tests, 30 admission tests and scan results are in
`measurements/uno-v2-outbound-continuation-restored.json`.

Follow-up review accepted the per-block descriptor dispute and the classification
corrections, with one precommit evidence request. The additional one-site control
replaced the incoming descriptor dictionary with an empty one. Earlier empty-root
cases passed, then the resumed descriptor hash comparison failed at line 2881;
the complete source was immediately restored and the targeted test passed.
`measurements/uno-v2-outbound-seeded-control.json` records this control. It proves
the resumed hash comparison is sensitive; it does not independently kill every
assertion that follows that comparison. Live provenance for prior Native records,
deterministic backlog derivation, queue update admission and the final shard
update remain required. The Native maximum-output count is a separate per-call
bound; the cells/bits union budget is the per-block bound described above.

### Private outbound state-budget continuation (reviewed; live integration pending)

Settlement now carries an immutable copy of its old-state meter and a weak
usage-tree node. The complete host must keep that original tree alive; the result
does not prolong a private temporary tree's lifetime. Outbound construction
copies the same meter and installs a scoped observer on the existing tree.
It does not nest UsageCells or cache LoadedCell values. Each observed source is
probed before Native performs its original tracked read: at most one additional
source load per attempted read, with the original read still marking its node.
Quota refusal is CandidateInvalid; unavailable content and nested tracking are
local failures. A private failed attempt returns no new snapshot and cannot
mutate the preceding snapshot.

The bound applies to reads which traverse the retained authenticated usage tree.
The live adapter must still prove queue roots/backlog provenance and exclude
untracked authenticated descendants; this helper alone cannot identify arbitrary
bare references as old state. Before-load probes add repeated work independently
of physical-content deduplication, and meter copies temporarily retain both hash
sets. M6 must include both costs. This does not admit final Merkle-update reads
or output proofs, and does not open live execution.

The queue fixture is serialized/reopened to remove unrelated live wrappers.
Independent first-load callbacks count observed physical cells/bits, retaining
the prior account union. Exact and one-less state limits, a local queue-read
exception, and byte equality of both queue-subtree MerkleUpdate and MerkleProof
are checked. This is not a whole-shard proof or live I13 acceptance.

Four independently rebuilt controls failed and were individually restored:
omitted accounting gives 11 versus 15 cells; unwrapping the dispatch root hides
subsequent reads from its UsageTree and fails the MerkleUpdate byte comparison;
quota abstention fails at -7201 versus -7200; removing the outer boundary lets
the injected VmError escape. The proof-control failure is at the first byte
comparison, not independent evidence for the second comparison. Full-file
restoration and all four mutant SHA256 values were independently recomputed.
Evidence is in `measurements/uno-v2-queue-state-controls.json` and
`measurements/uno-v2-queue-state-restored.json`; 111 block tests, 30 admission
tests and the scan passed on that restored source. The archived validator build
reported no work: neither changed header reaches a production validator
translation unit yet. That command is not evidence for this implementation.
Boundary review requested controls for missing tracking, nested tracking,
propagation of an enclosing observer's signal, and the extra-read multiplier.
The follow-up controls now cover them: removing the missing-meter predicate
causes a null-source fault; removing nested-source refusal reaches Native's
anti-nesting CHECK; consuming the outer signal fails the propagation assertion;
a second probe produces three source loads instead of two. The measured source
is the fixture's dispatch root, not every possible state source or a block-wide
cost measurement. Empty and expired tree contexts also return LocalUnavailable;
the lower observer constructor independently rejects them, so no claim is made
that the upper empty-node predicate is uniquely load-bearing.
`measurements/uno-v2-queue-state-followup-controls.json` records all four rebuilt
failures and immediate byte-exact restores. It also records a stopped attempt
whose partial-line restoration lost indentation: the full-file comparison caught
it before a second mutation, the indentation was restored, and all controls were
rerun with full-line substitutions. These are manual mutation records, not
automated CI mutation jobs.

The retained node identifies a live tree, not a subtree filter: its observer
sees all reads in that tree. The live host must retain one original tree covering
both accounts and queues. The reopened fixture deliberately tests only the queue
subtree; its accumulated account hashes do not prove common live-tree provenance.
The snapshot and node must be checked together, including for prototype results.
Encoded-cell probing is deliberate: an observer cannot distinguish a dictionary
path from legitimate special-cell closure content; Native dictionary decoding
still validates the structure it consumes. No content is declared ordinary by
this accounting probe.

M6 must also count one transient CellSlice allocation per attempted successful
probe, along with the extra source read, repeated traversal, and simultaneous
meter hash sets. The auxiliary costs are additive, not independent allowances.

Review qualifications retained: the observed-hash oracle alone cannot detect a
read escaping tracking; the byte comparison is the instrument that caught that
mutation. The second proof comparison is cheap corroboration, not independently
controlled evidence. Snapshot immutability follows from the const-owned type;
the unchanged-usage assertions are diagnostics, not a separate mutation proof.
Successful account acquisition supplies a clean state meter: every non-slice
read outcome exits acquisition as an error. No additional public meter-health
API is introduced just to recheck that success-path invariant. The continuation
still requires authenticated construction of that context before live use.

Follow-up review accepts this private unit. The final expanded test source and
binary are covered by `measurements/uno-v2-queue-state-final-checks.json`: 111
block tests, 30 admission tests, the domain scan and whitespace check passed.
The earlier restored-source artifact remains evidence for its earlier test-file
hash, not for these added controls. All eight original header substitutions were
reproduced from the final header, independently by the reviewer as well.

One implementation constraint remains visible: the observer is still installed
when the completed meter is moved into the result snapshot. There are no tracked
reads between that move and observer destruction; inserting one would invalidate
the observer's reference to an intact meter. Such a change must instead end the
observer's scope before moving the snapshot. No extra meter copy or public API
is introduced for a read that the current path does not perform.

### Private proof-work preflight connection (reviewed; live D31 incomplete)

The account runner now receives the admitted batch object rather than separate
root/state-policy arguments. Both private batch call sites retain that same cut;
the retained prototype explicitly passes its raw root through the other template
instantiation. The admission session retains the detached candidate reference
used in its wrapper, so preflight needs neither a second candidate argument nor
another envelope decode. A mandatory engine `proof_work(candidate, identity)` method
performs bounded shape inspection only; there is no default zero implementation.
The runner compares its result with authenticated `max_proof_units` before
acquiring old state or calling execution. The prototype overload remains outside
this batch preflight. All four concrete engine fixtures, including the disk
binding probe, explicitly implement the new contract.

No production work weights or SEND/COLLECT formula are installed here. They
remain engine/admission-profile semantics, distinct from D28 fees; the test
engine's zero/one units are fixture values with no cryptographic backend.
Explicit malformed-shape errors are candidate failures. Exceptions and unknown
error categories escaping the trusted preflight callback are local contract
failures, not inferred candidate verdicts. Actual engine decoders must return
candidate errors for malformed proof encodings, not throw across this boundary.
The callback receives neither snapshots nor authenticated Native inbox data;
this is an interface restriction, not a sandbox against arbitrary engine code.

Positive tests cover zero/exact/one-over allowances, zero state-source reads and
zero execution calls on overrun, candidate and policy identity, retained prototype
isolation, and thirteen error/exception cases through both settlement and direct
runner. The final expanded tree passes 111 block tests, 30 admission tests and
the disk account-binding readiness test. Boundary follow-up review accepts this
private interface and caller cut, not the complete D31 requirement.
Live ordering before commitment and complete inbox, production unit definitions,
actual crypto-backend accounting, and the live gates remain unimplemented. The
private runner currently begins after its caller's inbox reconstruction, so its
early state refusal alone cannot certify the complete section 9.3 ordering.

Initial boundary-review disposition: the contract now explicitly requires a
pure function of candidate bytes and authenticated profile identity and a
conservative bound on every subsequent verification branch. This is not proved
by a programmable test fixture: the production engine must establish cost
correspondence and cross-build determinism before live acceptance. Duplicate
envelope decoding was removed rather than adding a test for an unreachable
error. The zero-read control now asserts one inspection and zero execution and
also exercises successful reads with the same fixture at the allowed boundary.
Known and unknown callback throws are contained in one catch-all; its scope
passes no authenticated state view. A custom non-std throw and an invalid
AuthenticatedStateCorrupt status exercise those contract failures.

The requested zero-value distinction already appears in the resource-field
inventory above: max_proof_units is mandatory on wire; zero is an explicit
allowance for zero work, not omission or an unlimited default. The host does not
infer engine-policy compatibility from that allowance. Installation of a
production policy must still prove mandatory progress remains possible. No new
owner numeric decision or default is installed by this private connection.

Ten rebuilt one-site controls now fail and restore byte-exact, recorded in
`measurements/uno-v2-proof-work-controls.json`: omitted allowance, rejecting an
exact allowance, one premature state read (1 != 0), skipped inspection (0 != 1),
lost identity (admission version 0 != 2), escaping callback exception, passing
an unclassified status, hiding bad installed policy behind candidate overrun,
retaining the original candidate source, and passing declarations as candidate.
The source-owner control makes the original source unavailable after admission;
the detached candidate remains readable without touching that original source.
Identity fields are compared, but the single identity mutation is demonstrated
at admission_version, not independently at every identity field. Each recorded
substitution was recomputed in memory against the restored source and reproduced
its archived mutant hash. These are manual controls, not automatic CI mutation
jobs. The earlier final-checks artifact and ten controls retain their earlier
test-file hash; they are not evidence that the later test additions were run at
that hash.

Follow-up review's test refinements are now included. A separate instrument
counts settlement-entry state reads, with positive reads on successful execution
and zero reads on overrun. The immutable old-root hash assertion was removed:
it could not observe a premature read. Fault 13 explicitly returns
LocalUnavailable rather than reaching that category only through normalization
or exception containment. Two additional manual controls, recorded in
`measurements/uno-v2-proof-work-followup-controls.json`, fail after successful
compilation: inserting a settlement-entry read produces 1 != 0, and turning
the explicit local status into CandidateInvalid produces -7200 != -7201.
Each complete source file was restored byte-exact before the next mutation.

`measurements/uno-v2-proof-work-followup-final-checks.json` records the expanded
test source, final binaries, all three build targets, both suites, the disk
readiness test and final source checks. All twelve substitutions are individually
recomputed against the restored headers before submission. These results do not
install production proof weights or open the live execution gates. The trusted
engine's cost correspondence and deterministic shape decoder remain obligations
of production registration; a programmable fixture cannot establish them.

The follow-up review also correctly identified the escaping-exception control's
mechanism: settlement's guarded_run catches only UnadmittedStateRead, so removing
the proof callback catch-all allows VmError to escape settlement itself. It is
not evidence that some outer settlement catch will contain engine exceptions.
The natural admitted-envelope decode guard's untyped error remains a separate
inventory item; this unit removed the duplicate decode, not that natural site.

### Proof-work inventory after independent review of `6034b6aaf`

- At that checkpoint actual cost correspondence was not enforced. Closing it requires an actual
  verification-work meter using the same unit definitions as shape inspection,
  charging before expensive backend calls, and checking actual attempted work
  against the admitted declaration. A post-execution assertion alone discovers
  an undercount only after paying its CPU cost. Failed proof attempts count too;
  an engine's effects.usage report is not an independent measurement. The
  production integration must distinguish an engine counting-contract failure
  from an invalid cryptographic proof, without inferring provenance from an
  untyped backend error. The profile-4 C1 cut now provides a typed, precharged
  backend wrapper and an independently instrumented operation correspondence
  trace; see [the exact profile and its evidence](uno-v2-proof-operation-profile.md).
  It leaves live registration and statement construction unclaimed and does
  not close the next two items. In particular it does not reinterpret profiles
  2 or 3, and an invocation-local meter is not a block accumulator.
- Block-level proof-work acceptance is not implemented. The current limit is
  per batch, with no cross-batch accumulator. I13a requires exactly one logical
  batch per block; only independent enforcement of that live invariant can make
  the one-batch allowance also bound a block. A test must attempt multiple
  individually within-limit batches and demonstrate rejection before additional
  verification. If multiple verification phases are needed for the one batch,
  their attempted work must share its meter, not reset at each phase. D32 fee
  aggregation does not supply this proof-work budget. Neither a live uniqueness
  proof nor a block-total counter is claimed by `6034b6aaf`.
- Preflight complexity itself is not enforced by its returned proof units.
  Because shape inspection belongs before commitment, even a bad commitment
  can demand one inspection. Production engine registration must declare an
  upper-bound function for inspection operations and auxiliary memory in terms
  of admitted physical cells/bits and bounded logical objects. It must provide
  worst-shape tests, including deeply shared DAGs, repeated encodings and
  maximum object counts; bounded input alone does not rule out quadratic or
  exponential expansion. The implementation and its work counters must support
  that bound, and minimum-hardware acceptance must include the resulting total.
  A timing sample is not a WCET proof, a contract comment is not enforcement,
  and `max_proof_units` is not an inspection timeout. This C3 obligation is
  separate from C1 actual verification work and C2 whole-block acceptance.

### Private proof admission phase transition

This cut separates declared proof-work admission from the runner. A privately
constructed ProofAdmittedBatchInput retains the same owned structural input and
inspecting engine; replay can inspect before commitment, then carry that result
through semantic inbox processing and execution without repeating inspection.
The raw-root prototype remains separate. The boundary follow-up review passed;
this is not live host ordering evidence and does not close any of the three
inventory items above. No production weights or numeric limits are introduced.

First-review guard coverage is strengthened without freezing diagnostic text.
The settlement guard is tested while the runner guard remains intact: removing
only the former makes the old-state metadata observer count one access instead
of zero. The runner guard has a separate direct-entry control that does not pass
through the settlement guard; removing only it makes two state reads instead
of zero. A matching-engine successful settlement must produce both state and
metadata reads. Removing only the metadata callback makes that positive
assertion fail, so an inert observer cannot satisfy the zero-read test silently.
These controls are part of 17 runtime mutations, each compiled successfully and
failed at its intended behavior/type assertion. Each source edit was restored
before the next mutation. The record is
`doc/measurements/uno-v2-proof-phase-controls.json`. For the two large test-file
mutations, restoration is supported by full-file SHA-256, not the controller's
truncated text capture. `doc/measurements/uno-v2-proof-phase-restore-audit.json`
independently reconstructs all 17 complete mutated files from the restored tree
and reproduces every recorded hash. No mutation is represented as a CI job.

Final regression (`doc/measurements/uno-v2-proof-phase-final-checks.json`): three
targets built, 111 block tests, 30 admission tests, disk binding-readiness test,
removed-domain scan and whitespace check passed. The follow-up review was
read-only: its author inspected code and archived evidence, not independently
executed the mutations or regression. It closed first-review B1/B2/B3 and D1
without blockers. Its statements that regression was pending were superseded
by the completed final-check artifact, not by a new acceptance claim.

Nonblocking follow-up disposition: the stale progress text is fixed here.
The inner null-source guard is retained for direct calls to the detail helper;
public wrappers already enforce it. The duplicate typed-disposal inbound check
is acknowledged as redundant, not counted as independent protection. Pointer
versus reference spelling and the less precise "before execution" comment are
not behavioral fixes; the token factory/precondition is documented above and
in its type. Additional per-entry local-context controls remain a coverage
limitation: the six disjuncts are tested through disposal, while source inspection
confirms the other wrappers invoke the same helper. No claim is made that this
proves every future call site. These nonblocking cleanups do not justify delaying
the authorized connectivity smoke with another private-helper expansion.

The first review's proposed error-message comparison is not adopted: counters
and disjoint entry paths identify the responsible guard without turning prose
into a protocol contract. Likewise, tests do not freeze the private Native
parser's current untyped error code. They assert the preflight invocation and
execution counts around malformed inbox input. Local scalar context is checked
before invoking the engine; resource admission before commitment follows the
required phase order. A local preflight failure therefore abstains even if a
later commitment check could have rejected the claim. This does not certify
the unchecked claim.

Observer scope remains a separate boundary: the five production-header factory
call sites (the direct engine convenience entry, two settlement convenience
entries, and two replay entries) inspect before the settlement runner installs
either old-state observer. The factory supplies no authenticated state view,
but this is not a sandbox against a trusted engine accessing ambient objects.
Its exception containment returns LocalUnavailable, never an admitted token,
if an observer or other callback throws. An enclosing sticky observer must
retain its own failure state; catching its signal must not clear that state.
The generic public factory does not prove that arbitrary future callers install
no observer. Live integration must preserve the current ordering and the pure
inspection contract, rather than treating the token as such a proof.

### Next integration boundary: connectivity before deeper admission work

After the current proof-admission unit completes its controls, full regression,
follow-up review and commit, the next cut is a thin end-to-end connectivity
smoke through account-engine registration, live dispatch and replay. Keep the
capability/execution gates closed: this does not enable workchain 2, weaken
I13, or supply milestone acceptance evidence. Exercise real entry interfaces
to expose type, lifetime and failure-provenance mismatches. A failed connection
is a useful result to document and resolve, not a reason to relax a gate. Then
resume the remaining D31 obligations.

M2 status update after integration `9556ab05d`: deterministic relation and system
encryption kernels, the separate wallet prover, patch-layer differential, RNG
and supply-chain deliverables are present. The earlier scheduling statement
that differential and supply-chain delivery remained outstanding is superseded.
The remaining integration acceptance item here is optional verifier node-build
linkage with capability/execution gates closed; the default-disabled link option
already exists. Build/link availability must not imply engine registration or
execution permission. Differential evidence covers primitives and local patches,
not an independent oracle for the new SEND/COLLECT relations. Deliverables do
not establish relation soundness/completeness or close the explicitly retained
external cryptographic-review gap. Wallet prover dependencies remain separate
from the node. Mutation controls, byte-exact restoration, full regression and
independent review remain required for each completed unit.

Connectivity investigation at `ffedd9d21` found the first missing seam before
runtime replay: `resolve_account_binding` returns a validated `engine_config`,
but neither `proof_work` nor `execute_accounts` receives it. The existing
complete-input identity binds the configuration hash; it does not supply the
decoded business parameters. Existing engines in these tests do not require
those parameters and therefore cannot establish their propagation.

The initial probe at `ffedd9d21` used the real resolved-binding and admission
types with the normal test translation unit's compiler flags. Passing the
resolved configuration to admission failed to compile; dropping configuration
compiled. Historical commands and diagnostics are in
`doc/measurements/uno-v2-connectivity-config-probe.json`; they describe that
pre-adapter interface, not the current probe's expected results.
This establishes the missing explicit-argument seam, not impossibility of all
other designs, runtime error classification, or end-to-end success. The probe
is outside default targets and is not a failing CI test. No execution gate or
production registry changes accompany it.

The working adapter, `ConfiguredWorkchainAccountEngine`, owns the resolved
immutable configuration and passes it explicitly to shape inspection and
execution. Registered account engines no longer inherit the unconfigured
prototype interface; `ProofAdmittedBatchInput::admit` remains a two-argument
operation over the adapter. The current manual compile probe exercises that
adapter, with dropping configuration now intended to fail compilation.

The smoke exercises a local registration, the real scoped resolver, settlement
and independent replay with synthetic parameters. Actor execution gates remain
closed. Review found that the first lifetime assertion had another shared owner
masking the claimed property; the corrected control moves the resolved binding
and requires exactly one owner. A mismatched-cut test also enters through
settlement rather than only calling the adapter directly. The controls below
are complete; follow-up review passed without blockers. This is not live execution or
M1 acceptance.

The adopted compile pair is recorded separately in
`doc/measurements/uno-v2-connectivity-adapter-compile-control.json`: the adapter
path compiles and the implicit configuration-dropping path does not. The old
JSON remains historical evidence rather than being relabeled as a current run.
The ownership-fixture control in
`doc/measurements/uno-v2-connectivity-owner-control.json` restores the accidental
copy from the first review and fails with two owners instead of one. This
control catches a masked lifetime assertion; it is distinct from removing the
adapter's ownership itself. Neither manual control is a standing CTest gate.

The independent first review is a source review, not executed evidence. Its
ownership finding was accepted: moving from `Result::ok()` copied a const
variant, leaving another shared owner alive. `ok_ref()` now permits the intended
move. Removing the adapter's shared ownership separately fails at owner count
zero, before any dangling configuration access; this run and exact restoration
are in `uno-v2-connectivity-adapter-owner-control.json` in the same measurements
directory. The mismatch path now uses a separately admitted, internally
consistent input from another host-resolved configuration cut. Direct mismatch
calls cover the other identity fields, not configuration hash, so they cannot
mask the settlement-entry control.

The review's non-blocking API limitations remain explicit: the public resolved
binding is trusted local data, not an unforgeable certificate; the adapter is
only for batch entry points that perform proof admission, not retained singleton
prototype overloads. No current production caller uses it. A generic equality
operator for policy identity and a stronger binding-construction API are not
claimed by this smoke. Both require their own controls if adopted later.

Post-fix controls: extra fixture owner, removed adapter ownership, removed
configuration-hash guard, dropped proof-stage configuration, dropped execution
configuration, and changed encoded parameter value each compiled successfully
and failed at runtime (the two ownership runs predate the immaterial deltas
reconstructed in the restore audit; the other four use the reviewed source).
In particular, removing the hash guard made the
other-cut settlement succeed, so the negative test fails on acceptance rather
than on an unrelated error. Each mutation was restored before the next one.
The six `uno-v2-connectivity-*-control.json` runtime records and separate compile
pair retain their outcomes; `uno-v2-connectivity-restore-audit.json` reconstructs
the final-source mutants and earlier ownership-control source hashes.

`uno-v2-connectivity-final-checks.json` records the restored build, 112 block
tests, 30 admission tests, disk account-binding readiness, removed-domain scan
and whitespace checks, all successful. This is the scoped connectivity
regression, not all repository tests, proof-cost acceptance, production engine
registration or live actor execution. The existing actor gate is unchanged.

Follow-up review independently reconstructed the recorded mutants and earlier
ownership sources, and confirmed B1-B5 fixed. The added configuration path also
makes a gate-opening prerequisite explicit: configuration resolution must be
deterministic from the authenticated cut, with independent-node differential
controls for equal resolved parameters and proof units. A header contract is
not that evidence; this prerequisite remains open, alongside C1-C3. The adapter
guard proves input-cut equality with its stored identity; only trusted resolver
construction currently ties that identity to the supplied parameter object.
Unforgeable bindings, future identity-field completeness, execution exception
containment, a dedicated effects-equality mutation and a post-replay resolution
counter assertion remain outside this smoke's claims. No live gate is opened.

The follow-up's determinism clarification changes comments only. The exact
inverse edits back to the reviewed header hashes are recorded in
`uno-v2-connectivity-postreview-source-audit.json`; restored full scoped checks
were rerun in `uno-v2-connectivity-postreview-checks.json`. Both tested binary
hashes remain identical to the reviewed regression. The private configuration
seam is connected; production registration and actor replay remain future work.

The independent review of `ffedd9d21` also leaves two explicit integration
obligations. The convenience account-engine runner now rejects a null
old-account root before proof inspection as LocalUnavailable. Its same-input
positive control executes inspection and engine once; the null-root control
requires both counts zero. The added test failed before the fix at work_calls
1 != 0, so later state acquisition cannot mask removal of the early guard.
`doc/measurements/uno-v2-runner-null-context-control.json` preserves the complete
run and exact reconstruction from final header to the measured pre-fix bytes.
Live integration must keep proof-admission tokens synchronous and strictly
shorter-lived than the inspecting engine: they must not be retained, queued or
cross an asynchronous boundary. Pointer equality alone cannot prevent address
reuse after destruction. Tokens remain copyable, not one-shot execution
permission; they do not establish I13b. The later disposal guards remain
reachable through the retained prototype entry and must not be removed as
dead code or credited as the early-ordering guard.

### Experimental node linkage, not host invocation

The default-OFF `TOS_UNO_CRYPTO_NODE_LINK` option can retain all three kernel
FFI entries in the actual node without registering or calling an engine. This
is a build seam only: it establishes no I13 property or milestone acceptance.
The independent wallet prover and its standalone CI were subsequently delivered
in `62771b318` and `0b120a07d`; they never join the node dependency graph. Full
differential, RNG and supply-chain deliverables were subsequently integrated
in `9556ab05d`; the older outstanding-delivery statement is superseded.
Production host invocation remains open. Optional linkage acceptance now
requires the OFF/ON runtime connectivity comparison described above, not
another implementation of the already existing link option.
The scoped review disposition and evidence index for node linkage are
in `doc/measurements/uno-v2-node-link-review-disposition.md`; execution matrix
in `uno-v2-node-link-matrix.json`, initial controls in the retention/cargo-fixture
JSONs and domain-controls Markdown, exact reconstruction in
`uno-v2-node-link-restore-audit.md`, and the default-OFF follow-up control and
final checks in `uno-v2-node-link-default-control.json` and
`uno-v2-node-link-followup-final.md` (all under `doc/measurements/`). The baseline
scan omitted untracked evidence and is explicitly not final-tree evidence.

### Retired pool source boundary

The former `uno/core` and `uno/test` pool components and their measurement driver
are preserved byte-for-byte under `uno/archive/v1`, with original commit and
hash mapping. They have no active target or include. This also removes the old
note accounting, bundle permissions and slot arithmetic; their names must not
be mistaken for implemented V2 business objects.

Native snapshot/reopen/GC and account-limit tests remain active, using only a
plain test dictionary in `crypto/test/workchain-fixture-dictionary.h`. That
fixture is not a production state schema and carries no permanent-spent or
asset semantics. Historical measurements remain historical, not V2 capacity
acceptance. The build-wiring suite checks retired tests are absent from actual
CTest/all-tests graphs and forbids active includes of archived state. That suite
runs when `TOS_UNO_COUNTER_PYTEST` is enabled; it is not an unconditional gate.

This closes the source-cleanup task, not any live I13 property. The policy-bound
host identity source remains a separate pre-live clarification. The wallet's
four-site CT guard is already in its standalone CTest/CI, but is not a
general verifier of secret dependence at newly introduced group-operation sites.

The machine-readable patch follow-up now records all adapted files and exact
reverse edits in `SOURCE_MANIFEST.json`. The existing kernel CTest and wallet
source-gate chain verify current bytes equal recorded upstream plus declared
patches, including required patch presence. Rehash-only drift and removal of the
CT patch are rejected. This closes undeclared-byte-drift detection, not semantic
review of new secret-dependent sites, remote provenance attestation, seed-copy
erasure, or full supply-chain acceptance. No dependency source/revision changed.

- [x] File-level independent review of
  `uno/crypto/vendor/bulletproofs/src/range_proof/deterministic.rs` found no defect
  in that file: independent residual checks, retained transcript challenge events,
  and intentional identity padding were checked. The caller's range-shape
  finding is addressed by exact pre-padding counts; see
  `uno-v2-range-shape-review-disposition.md` for its controls and scope.
- [ ] Independently establish completeness for the full application relations,
  the correctness of all five local patch rationales, and the complete indirect
  verification call graph for RNG reachability. The
  source reconstruction gate does not establish these mathematical or semantic
  properties, and the file has no upstream blob to inherit such assurance from.
  Earlier `SUPPLY_CHAIN.md` already described the local deltas in prose; the new
  machine-readable inventory strengthens enforcement, not prior semantic approval.

### Real-entry runtime stop points and error transport

The disk manager now records the actual collation promise result before moving
or logging it. The observation path is owned by the asynchronous callback, not
borrowed from a test stack. The test does not create admitted input, proof tokens,
or replay claims: the real collator resolves the disk-authenticated configuration.
It stops at the existing account-binding refusal, or earlier at an injected
configuration callback failure. No admission, proof work, or replay connectivity
is inferred from this observation; the production refusal remains unchanged.

Error-code fidelity is a prerequisite of every runtime classification assertion,
not a generic property inferred from a passing promise test. This collation path
checks success (0), gate/local failure (-7201), and authenticated corruption
(-7202). A deliberately mislabelled configuration error (-7200) must normalize
to -7201; bypassing that boundary fails even with zero engine execution. Other
actor/promise paths, including live validation, still require their own controls;
this test cannot certify that they preserve codes or do not rewrap errors.

### Aggregate fee settlement (D32, in progress; not live)

The private settlement path is being extended to preserve separate state,
compute and tip components. State fees allocate internally from custody to
coordinator; compute plus tip becomes custody's Native transaction `total_fees`.
There is no fee message. A payout in the same batch must add its independently
priced fee rather than overwrite the aggregate fee. Disposal retains its own
coordinator-funded transaction fee. The legacy no-fee constructor is preserved;
the fee-bearing constructor is separately tagged.

Current tests exercise serialized account balances, transaction fees, output
counts and independent replay, including aggregate fees plus payout plus
disposal. This is not an authenticated fee schedule or business-state test:
fee-table reconstruction, the matching `N_book` update, live admission/replay
and block publication remain unconnected. No D32 completion or live I13
acceptance follows from the private Native arithmetic tests. The private
checkpoint has completed two consensus-boundary reviews, seven recorded red
controls and restored-state regressions. Coverage is explicitly limited below;
this does not close the remaining D32 integration obligations.

Initial review disposition: the proposed "fees have priority over payout"
policy is **disputed**, not an open decision. Both are staged privately and
must be fully funded before a batch may publish. I13e permits one complete
commit or zero commits; partial fee collection or shrinking an authorized
payout would contradict that atomicity. Evaluation order therefore establishes
no economic priority and must not be turned into such a protocol rule.

The prior C/T-swap replay rejection established only effects-byte binding.
Independent numeric controls now distinguish S from C+T, including zero-S and
zero-collected cases. Rejecting unauthorized splits at the candidate boundary
still requires independent reconstruction from the authenticated fee schedule
and verified operations. In particular, swapping C and T preserves their Native
recipient, so settlement totals alone cannot detect that unauthorized swap.

Review inventory rule: monetary assertions must compare numeric values, never
`RefInt256 == RefInt256`. The latter can select reference identity: two aliases
then pass without checking any amount. Use explicit numeric comparison or the
numeric `CurrencyCollection` overload. The corrected fee round-trip assertion
compares scalar values; its earlier test-only failure is not mutation evidence.

#### D32 checkpoint review disposition and evidence limits

The follow-up review found no blocking defect in this private settlement change.
The accepted fixes include numeric S versus C+T allocation cases, disposal-local
role validation before staging, generated tag assertions, checked fee-cell
storage, and explicit descriptions of derived-graph and comparison tripwires.
Raw review transcripts remain working material outside this repository.

Evidence must be read as a pair:

- `measurements/uno-v2-d32-fee-controls.json` records seven individual mutations,
  successful builds, failing tests, and exact mutant/restored source hashes.
- `measurements/uno-v2-d32-fee-final-checks.json` records the restored source,
  generated codec and binary hashes, the passing full workchain-block test,
  and thirteen existing counter/disk compatibility tests. These are existing
  singleton/closed-gate regressions, not multi-account live acceptance.

That final-checks artifact is historical evidence for `f5fca8779`, not a
moving assertion about subsequent test binaries. The numeric-pair follow-up
records its own test and binary hashes and full regression. It does not modify
production sources or the separate collator tool: both the collator source
hash `a17d045c...` and binary hash `7d1fb613...` still match the historical
artifact. A review claim that those two collator hashes had changed was checked
and rejected; the workchain-block test and its binary did change as expected.
This is why the previous compatibility run remains applicable to the unchanged
production code, not evidence of new live behavior.

The payout-overwrite control fails at `charged_result.is_ok()`, before the
numeric fee assertion. Source inspection attributes this to value-flow
conservation; the recorded runtime result establishes rejection, not a uniquely
identified conservation error. An error string would not strengthen that into
a typed or numeric behavioral control. The debit mutation likewise aborts at
the balance assertion: later fee assertions were not observed in that run.
Successful restored runs exercise those later assertions, but do not establish
that each has an independently isolated mutation witness.

The review's request for a green baseline is satisfied by the companion
final-checks artifact, not by the controls artifact alone. Its claim that the
existing unfunded case specifically exercises a funded aggregate fee followed
by an unfundable payout is not adopted: that case is aggregate-only. The
atomicity argument remains valid; the subsequent direct pair control described
below now supplies that private combined-failure witness. The proposed fee-priority policy remains
disputed for the I13e reason above, not deferred for implementation.

Open coverage and integration obligations:

- D42 selects authenticated admission version 3 for the fee-bearing
  constructor; version 2 must retain its original meaning. The
  generic codec recognizes both constructors but does not authorize either.
  Do not reinterpret admission version 2 as a fee capability: it already names
  a resource-accounting contract. A candidate presenting fees without profile
  permission must be rejected as CandidateInvalid; authenticated configuration
  or local capability failures must retain their distinct provenance. Private
  same-effects/different-profile controls now demonstrate the typed gates;
  removing each changes its result without relying on the still-closed live
  execution gate. Live integration remains open.
  Current implementation work is restricted to that authorization and its
  source-specific failures. Fee-table recomputation, operation-derived S/C/T,
  N_book changes and D43 state placement are not part of this unit.
  After this unit's controls, regression, review and commit, the next unit is
  exclusively the runtime vertical-slice continuation: production-constructed
  objects in production call order, observed stop point, counters and side
  effects, with execution gates closed. No other D32 dimension, differential
  work or system-state encoding precedes that checkpoint. Private replay tests
  in this unit do not satisfy that runtime requirement.
  Focused review identified missing malformed-claim framing coverage; separate
  outer, short-native, special-native and unknown-tag witnesses now close that
  predicate-level gap, with refusal-to-success controls. Their call-site
  reachability is covered separately by the two typed replay controls, not by
  malformed-claim end-to-end tests. The special-native test concerns encoded
  candidate data, not missing authenticated data; live claim materialization
  and its provenance boundary must preserve that distinction.
  The version-agreement factory guard is not reachable from today's registry,
  which derives both fields from the same value; its control proves the public
  factory contract only. The v2-only-node probe observes classification under
  a temporarily restricted support set; the installation test supplies the
  separate red control. Do not describe the probe itself as a red control.
  Do not move fee-claim checks ahead of shape admission: the existing host
  order remains in force. The review's assertion that max_proof_units bounds
  shape-inspection work is rejected; it bounds a returned value, not callback
  CPU, and the separate preflight-complexity obligation remains open.
  The factory disagreement cannot reach today's registry diagnostic (both
  versions are constructed from one field); its generic unsupported-version
  wording is not a demonstrated live misdiagnosis. Native tag constants remain
  anchored by the existing generated-tag static assertions. The account-only
  replay positive fee case is not established by the disposal positive case.
  Claim loading adds a live-integration obligation: authenticate/materialize
  candidate closures and preserve acquisition-failure provenance at the outer
  boundary. Prototype overloads carry no authenticated profile permission and
  must not be substituted for the typed path during live wiring.
- The charged payout now has a direct pair-level numeric control before the
  enclosing conservation check: restoring the overwrite reaches and fails the
  custody fee assertion (53), after the prepared-pair success and balance
  assertions pass. See `measurements/uno-v2-d32-payout-pair-control.json` for
  the red output, exact restoration and restored full regression. The subsequent
  funded-fee/unfunded-payout witness stages fees successfully (custody 127,
  collected fees 1083), then rejects the unchanged payout of 137 at the pair
  boundary before overlay conservation. Returning the fee-only prefix on that
  allocation failure makes the direct error assertion fail. Original accounts
  are const inputs and finalized cells are immutable; their unchanged bytes
  are structural, not behavioral rollback evidence. The enclosing batch also
  rejects after one engine call, but its failure site is not mutation-localized.
  This is private staging evidence, not a live atomic-publication test; see
  `measurements/uno-v2-d32-unfunded-payout-control.json`.
- Add isolated controls for fee constructor selection, malformed/unknown tags,
  coincident roles, invalid/zero components, combined 120-bit bounds, and the
  payout-specific role guard. Seven existing controls do not prove all of these.
- The allocation overlay's fee comparison is a cross-derivation tripwire,
  not independent fee authorization. The payout overlay currently relies on
  independently reconstructed value flow instead of duplicating this comparison.
- Plain-entry role binding remains an enclosing caller obligation; disposal
  entry additionally checks its authenticated custody locally. Live wiring must
  preserve provenance across every caller and exception boundary. Generic
  status code zero does not by itself prove candidate origin. Quiet decoding
  must not be treated as a universal exception barrier either.
- Account for repeated effects decoding in the aggregate auxiliary-work budget:
  entry preparation decodes directly and again through balance allocation;
  enclosing paths may repeat it further. Charge this with account count and
  admitted effects size, in addition to the constructed-cell bound, rather than
  inferring zero work from shared physical cells. Before live admission, enumerate
  the complete call path to establish the actual multiplicative bound.
- The prepared-participant fee-check exemption currently concerns the
  coordinator disposal entry; custody is distinct and must never be exempt.
  Changing prepared-participant roles requires re-establishing this property.
- Independent authenticated fee-table reconstruction, correspondence with
  verified operation fees, the matching confidential `N_book` debit, and live
  publication remain unimplemented. No gate may open on this checkpoint alone.

### Closed-gate runtime adapter observation

The earliest live collator account-binding branch constructs the configured
adapter from the production resolver result, samples configuration ownership,
destroys the adapter synchronously, and returns the existing refusal. It does
not assemble an admitted input in the disk fixture. The observed ownership
increase is a resource side effect on the same failed-query path; its release
is not an account-state rollback test. No proof work or replay is authorized.

The offline result observer joins statistics delivery with the result callback.
Its sidecar starts as `delivery=pending` and changes to `delivery=recorded` only
after statistics are written successfully. Missing delivery cannot be read as
zero transactions. A one-second offline observation deadline records
`delivery=unconfirmed` without counters and releases the original result. It
does not prove statistics do not exist or impose a protocol delivery bound;
startup failures before the collator becomes busy legitimately emit none.
Process interruption before confirmation leaves `pending`. Neither is a
consensus error code or an observation of zero work.
An empty result path retains the unobserved tool route. This join is scoped to
the disk manager's single collation query, not a general actor-delivery theorem
or per-attempt resource accounting. Failed writes terminate the disk tool.

The measured stop is the unchanged refusal after adapter construction, not
commitment checking or replay. Authenticated domain construction is a separate
static frontier: the existing two-reference configuration shell and resolver
do not supply genesis/instance metadata for `WorkchainHostIdentity`. No zero,
fixture constant, or locally chosen domain may substitute for that missing
production source. This observation does not install the pending instance
sequence mechanism or authorize a new state layout.

The transaction counter and absence of a candidate export have narrow meanings.
They do not count earlier authenticated-state reads, all allocations, or all
possible external side effects, and they are not a state-proof byte comparison.
All validator refusal gates and the registry's production registration status
remain unchanged. I13a-e acceptance remains open.

Eight final-source controls are recorded in
`measurements/uno-v2-runtime-adapter-controls.json`: omit construction, sample
release early, drop statistics, erase the visit marker, label missing delivery
as recorded, flatten the measured interval, flatten the transaction counter,
and shorten the actual alarm without changing its reported window. Each has a
red assertion, exact source/test/binary restoration, and a green readiness run.
The construction control intentionally leaves `visited=1`: entry occurred but
construction did not. Erasing entry is a separate control. The review suggestion
that omitting construction should flip entry is rejected as conflating stages.

In five consecutive final-source runs, normal query-to-record intervals were
15.209--21.061 ms and measured no-stats waits were 1.002859--1.004521 s. The
slowest normal sample leaves more than 47-fold headroom against the one-second
offline deadline. This is a local normal-run cohort, not a worst-case delivery
claim. The test separately observes the actual wait within a 0.9--2 s band; it
does not infer timer behavior from the printed constant. Earlier checkpoints
are not substituted for this cohort. Bootstrap's observed transaction count
of one supplies the nonzero witness for the same stats field reported as zero
at refusal. Configuration-error and authenticated-state-error observations
both assert no entry into the binding branch.

The initial review's mismatched-workchain/previous-block example aborts in the
disk manager before collation and is not a no-stats witness. The actual fixture
uses a matching shard with excessive depth, reaching the pre-busy collator
refusal. The legacy scalar result sidecar cannot distinguish successful code
zero from an uncoded error with code zero; exit status and observation status
remain separate. Do not generalize named nonzero-code preservation to all
statuses. The terminal observation flag prevents subsequent writes; late-message
reordering itself is not exercised by this production call chain. The disk
manager remains a single-query observer, not a multi-query statistics service.

Final relevant regression and restored hashes are recorded separately in
`measurements/uno-v2-runtime-adapter-final-checks.json` (17 CTests, not the full
repository suite). Final review independently reconstructed all eight controls.
Its minor timing-robustness concern is retained: a loaded runner may fail the
100 ms headroom assertion without a functional defect. This assertion deliberately
tests tenfold normal-run headroom, not only an initialized clock; increasing it
to 500 ms would weaken that requirement to twofold. Keep the measured failure
visible and reproduce under controlled load before diagnosing a code defect.
The interval begins just before launching collation, not at subprocess startup
or database open. No arbitrary-load timing guarantee follows from these tests.

The timing diagnostic reports the measured seconds, configured wait window,
and their headroom ratio from the same sample. The 100 ms threshold is unchanged.
These values quantify a failure; they cannot alone distinguish scheduler load
from a genuine delivery-path regression. Investigate repeatability and load
before attributing cause. An injected 200 ms sample checks that the failure
prints a fivefold ratio; it is a diagnostic control, not a performance sample.

Before enabling the account path, remove the temporary construct/sample/destroy
observation or place it behind an explicit diagnostic build gate. Do not add
per-collation adapter churn merely to maintain these telemetry fields. The closed
seam is not behavior-identical to its predecessor: a local bind failure can
return before the old refusal, although both outcomes are LocalUnavailable.
The late-message terminal guard is inspected, not a demonstrated late-reordering
delivery experiment. Keep that distinction separate from measured missing stats.

### Approved coordinator container layout

The final system placement is coordinator StateInit.data -> versioned container
-> system reference. The container's explicit tag is 46ff26c1 with layout 1,
48 bits and exactly one reference; the system tag is bbd85560 with independent
layout 1, 192 bits and no references. Both reject version zero and unsupported
versions. The earlier two-reference proposal is superseded, not an alternative
accepted encoding. Registration bonds require a later container layout; no
placeholder/default is installed. See `uno-v2-coordinator-state-wire.md`.
Codec delivery does not close D32 fee reconstruction or live state acquisition.

Codec field-order witnesses must use distinguishable values for same-type
fields and assert each decoded component. Equal extreme values remain useful
width-boundary tests, but are not field-order evidence. ResourcePolicyWire has
distinct per-record values and now reads each raw wire field independently of
generated unpack, avoiding a self-consistent encoder/decoder swap. Aggregate fee
checks read all three unequal amounts and both distinct role addresses directly,
before conservation/overlay checks. Coordinator ExactFraming reads 7/8/9 from a
hand-built system record. ResultWireRoundTrip adds distinct 101/102/103 usage
beside its separate extreme-value case. Declaration keys/hashes and executor
witness roots already have distinguishable fixtures; ingress role fixtures use
different executor/custody addresses. This is a targeted codec-test sweep, not
a claim about all equal-valued integration fixtures or all repository codecs.
Open followup: the block-result usage triple still has no independent raw
positional witness for a coordinated encoder-and-decoder reorder. Distinct
101/102/103 values catch one-sided edits only; do not claim that stronger
wire-compatibility property. Keep width-boundary and order claims separate.
Mutation tooling must retain unique patch context and compare applied bytes
against the intended replacement before building; a non-red misapplied patch
is not evidence about the intended path.
