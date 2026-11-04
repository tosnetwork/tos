# TOS testing philosophy

## Purpose and status

TOS tests must establish that the intended production path ran, that its
observable result satisfies an independently stated rule, and that the test
would detect a violation. A quiet tool, a successful build, a merged change,
or agreement between two implementations establishes only its own narrow claim.

This document summarizes existing repository rules and proposes a broader
whole-chain testing program. [AGENTS.md](../AGENTS.md) and the
[review checklist](../doc/REVIEW.md) remain authoritative. It does not change
merge requirements or declare a release accepted.

The implementation examples below were inspected at
`dbff59dac708c75076928626162e273b1ac87faa`
on 2026-11-04. Their presence is evidence of an implemented test mechanism,
not evidence that it passed on a later commit. No runtime suite was executed
to prepare this document. Proposed extensions are explicitly labeled.

## 1. The principles we already hold

### Prove the instrument can detect the defect

For a new regression test, remove or mutate the protection and record a red
run; restore it and record green. A negative test must reach the intended
branch and assert its specific error, refusal, or state transition. An unrelated
setup error is a broken experiment, not a successful rejection test.

Apply this discipline to comparators, collectors, parsers, timeouts and final
artifact validators as well as production code. Prove that missing, duplicate,
stale, truncated and extra records are rejected. A runner must establish that
the expected tests were registered, built and executed. Report attempted,
executed, compared, passed, failed, skipped and unsupported populations separately.

These are existing requirements in AGENTS and review items TE-1, TE-2, TE-6,
TE-9, TE-10 and TE-13. Mutation controls test the observer; high coverage or a
large number of passing cases cannot substitute for them.

### State the rule independently of the implementation

Before writing a case, state the invariant, its assumptions, the inputs that
reach it and the observable outcome. Use authored assertions from protocol
rules and price constants where possible. Differential testing catches
disagreement; two implementations can still agree on the same defect.

The existing
VM-parity methodology (`vm-parity/METHODOLOGY.md` in the companion memo repository)
uses the native version-16 implementation to fill expected effects, subject to
independent assertions. Preserve that disposition: an unexpected reference
result is investigated and escalated, not silently made normative or changed
just to make both implementations agree. Its VM/getter/transaction/replay scope
must not be presented as full block regeneration or whole-network acceptance.

### Compare the full effect and preserve authentic context

For transaction parity, compare actual Transaction and new ShardAccount roots
from complete original inputs; decoded fields explain a mismatch. Never copy
reference fields into the candidate, invent missing context, normalize output
hashes, or reconstruct selected fields to manufacture equality. Preserve exact
failure classes and distinguish no-transaction rejection from an accepted
transaction whose compute or action phase failed.

Version, capabilities, configuration, address/workchain, time, logical time,
seed, libraries, predecessor and signature policy are inputs, not convenient
defaults. Carry state across transactions when the claim concerns persistence
or cache reuse; independently seeded single-transaction cases cannot establish
that property. See [transaction roots](executor-parity/TRANSACTION-ROOTS.md) and
[generated roots](executor-parity/GENERATED-ROOTS.md) for existing, finite scopes.

### Exercise the real execution and failure boundaries

Compile the source and regenerate the frozen artifact that the test actually
loads. Verify artifact identity. Contracts that emit actions require real
compute, action, storage and bounce behavior, not compute-only success.

At node and operator boundaries, exercise the real caller, transport and
persistence path. Test failure before and after durable writes, replies,
broadcast and acknowledgment. Recovery must be demonstrated after the actual
interruption, with on-disk and on-chain observations where applicable.
Verification stays read-only; state changes belong in apply operations.

For value transfers, distinguish requested, broadcast, pending, unknown,
rejected and settled. Identify and decode the actual transaction and its phases
under the stated trust model. Balance changes, sequence numbers, CLI success
and timeouts alone do not prove settlement or authorize a fresh signed attempt.

### Treat resource bounds as correctness

For each queue, cache, actor, timer, buffer, promise, file or connection, identify
the count and byte bounds, admission point, full behavior and cleanup on
success, error, timeout, cancellation and restart. Test at and beyond the bound.
Measure retained capacity and shared backing storage, not only logical size.

Long-lived growth needs a representative soak with load, duration, host,
resident/anonymous memory and other relevant resources recorded. Low-cost
malformed input must not induce unbounded verification, allocation or fan-out.
Gas, latency and memory claims belong to a measured commit and environment.

### Keep evidence small, durable and reviewable

Commit the reproducer, required fixtures and a concise result index. Retain
large logs outside version control with location, hash, size and retention period. An
inaccessible artifact cannot independently support a claim merely because its
hash is present. Never commit credentials or private runtime payloads.

Map each changed boundary to the smallest sufficient relevant checks. Preserve
mandatory branch-protection gates. Documentation-only edits need documentation
validation, not a claim that native tests passed. Static analysis remains a
manual two-build comparison when requested, with positive controls and proof
that affected compilations were analyzed.

## 2. Existing mechanisms and their limits

| Inspected mechanism | What it establishes by design | What must not be inferred |
| --- | --- | --- |
| [Transaction root adapter and comparisons](executor-parity/TRANSACTION-ROOTS.md) | Complete context and exact output-root checks for named fixture families, with explicit refusal handling | Whole-VM coverage, every caller migrated, or continuous executor-state carry |
| [Generated configuration/root bundles](executor-parity/GENERATED-ROOTS.md) | Configuration identity, ordered population, native effects, artifact provenance and cross-architecture checks for documented families | Coverage of arbitrary configurations or all future runs |
| [Crash-boundary recovery](integration/crash_boundary_recovery.py) | A real worker/manager interruption followed by durable-state reconciliation at a specific cleanup cut point | Exhaustive crash consistency of every database and lifecycle |
| [Readiness controls](pq-readiness/test_controls.py) | Fail-closed evidence checks and relayer state-machine controls; the source identifies fake transports as orchestration tests | Live network execution, real signature validation or activation merely because a proposal passes |
| Test registration in the root test build definition | Concrete target registration and explicitly isolated optional signature experiments | That all test files are registered or all optional configurations executed |

Use these as starting points, not a completion scoreboard. A source review,
a local run, hosted CI and an operational acceptance run are distinct evidence.

## 3. Lessons from advanced blockchain testing practice

The useful comparison is between testing mechanisms and the risks they expose.
The following synthesis draws on public primary-source testing documentation
reviewed on 2026-11-04. It presents reusable methods without product names or
external links. It makes no ranking or claim that a particular tool remains
maintained. The TOS applications below are recommendations, not implemented
capabilities merely because another system demonstrates the method.

| Method observed in mature testing systems | What it contributes | TOS application and limit |
| --- | --- | --- |
| Versioned context/effects interfaces and shared conformance fixtures | The same inputs can exercise independent implementations at VM, syscall, instruction, transaction and block boundaries | Keep independent adapters and complete effects at each TOS boundary. Agreement alone cannot expose a shared defect; retain independently authored assertions. |
| Fast in-process program and instruction harnesses | Explicit account/input setup makes small cases quick to construct, repeat and diagnose | Maintain a fast contract feedback layer, then add real action/bounce and multi-node acceptance at the relevant TOS boundaries. A lightweight VM is not consensus or network evidence. |
| Common orchestration for real client processes | Reproducible launch/configuration and integration checks through actual network and API interfaces | Exercise production RPC/P2P traffic, sync and version transitions. Process or container orchestration alone does not prove deterministic scheduling or complete consensus coverage. |
| Deterministic runtime and network simulation | Controlled execution and fault histories make concurrency failures reproducible | Add replayable scheduling where TOS architecture permits. A stored random seed is insufficient if clocks, scheduling, network or I/O remain uncontrolled. This is a proposed extension, not an existing whole-node simulator. |

TOS already shares important ideas with these approaches: complete effects,
frozen counterexamples, real execution, and observer controls. The next useful
step is to apply them consistently across the full chain lifecycle, rather
than replace existing tests with a particular tool or borrowed terminology.

## 4. Proposed whole-chain acceptance matrix

The following matrix is a target for systematic coverage, not a declaration
that every row is implemented or accepted. Each scenario needs a protocol
assumption, reachable trigger, independent oracle and sensitivity control.

| Area | Invariant and required scenarios | Observable acceptance evidence |
| --- | --- | --- |
| Consensus safety | No conflicting finalized states under the protocol fault assumptions; no equivocation across crash/restart; reject duplicate, unknown, wrong-session or stale signers | Exact certificates, signer weights and finalized block/state identities from independent nodes |
| Consensus liveness | Progress when the protocol's timing/connectivity and honest-weight assumptions hold; no liveness guarantee outside them; preserve safety within the protocol fault model; recover after partition heals | Bounded progress/rejoin measurements tied to the actual configured thresholds and load |
| Elections and key rotation | Chain-authorized membership and keys agree across contract, decoder and vote acceptance before, at and after transition | Installed set, signature checks and session-boundary traces; offline/late participant scenarios |
| VM and transactions | Deterministic full effects, checked financial arithmetic, phase-correct rollback, bounded execution | Roots plus independently authored outcome assertions; malformed input, exact gas and one-short cases |
| Contracts and funds | No unauthorized movement or replay; solvency/accounting follows the applicable fee/burn rules; partial cascades cannot duplicate settlement | Real action/storage/bounce outcomes and transaction-level accounting, including concurrent messages |
| Storage and recovery | Durable accepted state survives supported crashes; interrupted cleanup/import is recoverable; corrupt or incomplete state fails explicitly | Crash-cut evidence, reopened database state, snapshot verification and peer-independent state/root checks |
| Networking and admission | Invalid traffic cannot poison valid-message deduplication, exhaust unbounded resources or starve required work | Loss/reorder/duplication/delay/partition cases, peer churn, per-source and aggregate resource measurements |
| RPC and tooling | Replies preserve the trust model; failures remain distinct; ambiguous broadcast cannot silently become a second payment | Real transport calls, proof/refusal checks, durable journals and reconciliation across restarts |
| Upgrades and releases | Tested source, generated artifacts and deployed binary match; activation follows the chain rules and supported upgrade procedure | Artifact digests, mixed-version tests where required, activation-boundary replay and explicit acceptance decision |

Do not import an unweighted node-count rule from another chain. Derive quorum
and fault thresholds from TOS's actual signed weights and active configuration,
including exact rounding, duplicate identities and validator-set transitions.
Separate safety assertions during a partition from liveness assertions after
the required connectivity and timing conditions return.

Retired formats should be refused or removed according to the approved upgrade
policy; do not invent backward-compatibility requirements for them. Likewise,
proposed features need design-level invariants until implementation and real
execution evidence exist. A design cannot be counted as a tested capability.

## 5. Incident-driven acceptance engineering

### Threat assumptions and evidence states

Selected public incident analyses within the five-year window from 2021-11-04
through 2026-11-04 expose failures across implementation, consensus, contracts,
operations and software delivery. This is a mechanism-focused selection, not
an exhaustive incident census or a claim to have reviewed every year equally. Translate the failure mechanism
into a reachable TOS scenario before adding a gate. Similar terminology does
not establish an identical architecture or vulnerability. Historical incidents
motivate these checks; they do not establish that TOS has the same defect.

Every acceptance case declares its adversary and trust boundary: unauthenticated
peer, authenticated but malicious participant, compromised signing authority,
malicious contract/caller, untrusted state provider, or compromised build input.
Record the allowed faulty weight, authorized key set, network assumptions,
trusted checkpoints and storage guarantees. Do not promise safety after those
assumptions are exceeded. Still test detection, containment and recovery for
credible outside-model events, with their weaker guarantee stated explicitly.

Use these evidence states in each release's coverage register:

- **Observed mechanism:** a source-inspected test or harness exists. It needs a
  run on the release candidate and does not automatically cover the whole row.
- **Proposed extension:** the scenario or stronger oracle remains work to do.
- **Not applicable:** an owner-reviewed architecture/deployment reason shows the
  attack surface is absent. Reassess when that boundary is introduced.
- **Executed result:** attach a separate pass, fail, skipped or blocked receipt
  to the exact case and commit. Source presence is never a substitute.

The matrix below is a set of proposed acceptance obligations. Existing anchors
identify partial reusable mechanisms only. No row is certified complete here.
The broad matrix in section 4 identifies domains; A1-A13 below refine specific
acceptance risks within those domains. Not-applicable, skipped, blocked, timed-out
and unsupported cases remain visible and outside the pass numerator. No item may
disappear because its harness is inconvenient or a run timed out.

### Failure-mechanism acceptance matrix

| ID and security property | Reachable adversarial or failure scenario | Oracle, control and acceptance condition | Existing anchor / remaining work |
| --- | --- | --- | --- |
| A1: Execution terminates and is deterministic | Exercise deploy/use, evict, reload, upgrade and reuse with cold/warm caches; replay valid historical inputs across supported versions and architectures | Compare complete effects against independent assertions; bound compilation/retry work; detect repeated non-progress. Mutate invalidation/version binding to make the case fail | Root comparison mechanisms exist; systematic cache-lifecycle and version replay is proposed |
| A2: Valid traffic cannot consume unbounded work | Replay correctly signed but obsolete messages; churn peers and requests; exceed every per-source and aggregate count/byte budget while legitimate work continues | Measure actual retained memory, queue/CPU/disk work and legitimate progress under a declared load envelope, then resource recovery. Removing the bound must trigger the observer | [Admission tests](test-security-boundaries.cpp) and [cache retention tests](test-liteserver-cache.cpp) exist; combined sustained consensus-load qualification is proposed |
| A3: Malformed input cannot halt the process or fork interpretation | Send malformed, deeply nested, truncated, noncanonical and boundary-sized messages through real ingress; mutate every parser field affecting identity or execution | Exact refusal without unexpected state change; no crash, undefined behavior or unbounded work; valid near-boundary controls still execute; compare independent decoders | [Exception and null-input tests](test-vm-exception-hardening.cpp) exist; broad structure-aware corpus and ingress coverage require an inventory |
| A4: Finality is never fabricated from the wrong authority | Duplicate signers, omit weight, use unknown/expired/wrong-epoch keys, reorder messages around set transitions and restart signed state from a stale copy | Recompute signed weight and context independently; inspect conflicting votes/certificates and durable signing history. Arithmetic controls cover exact threshold, one below and rounding boundaries; certificate controls use the nearest reachable signer-weight subsets below and meeting the threshold | [Quorum arithmetic](test-quorum.cpp), [key rotation](test-pq-consensus-key-rotation.cpp), and [signing restore drills](integration/signing_fence_drills.py) exist; their composition remains a proposed acceptance case |
| A5: Verification binds the exact object and trust root | Pair a well-formed proof, signature or receipt with the wrong network, account, payload, state root, session or verifier configuration; include empty/default/uninitialized authority cases | Each binding mutation is refused before value release or live-state import; a valid counterpart succeeds. No caller-controlled metadata may assert that verification already happened | Existing review requirements cover these bindings; enumerate each proof/receipt consumer and add missing independent controls before claiming coverage |
| A6: Asynchronous contract settlement remains solvent | Interleave payment, receipt, bounce, refund and retry messages; fail each action/hop; vary fee/storage prices and expiry at exact boundaries | Check per-transaction balance/obligation/reserve accounting after fees and actual phase outcomes; no duplicate release and accounting stays safe at every step. Under declared delivery, timing and authority assumptions, complete release/refund/reconciliation within the preapproved bound. Mutate sender/nonce checks to expose the intended invariant | Real transaction-root mechanisms exist; each contract needs its own executable accounting model and cascade coverage |
| A7: Recovery does not trust an attacker-selected state | Supply structurally valid but wrong-root state, stale checkpoints, interrupted imports, truncated files and disk/write failures; restart before/after promotion or cleanup | Verify trusted identity/root before promotion; preserve or recover the valid durable state; release temporary resources; distinguish transient retry from permanent refusal | [State-download recovery](test-state-download-recovery.cpp) uses production paths with fixture-supplied trusted proof metadata; [cleanup crash recovery](integration/crash_boundary_recovery.py) covers one cut point. End-to-end trust establishment and all write cuts remain separate work |
| A8: Released bytes are the reviewed bytes | Replace a dependency, compiler/build input, generated contract, cached package or published artifact; attempt publication using a revoked or over-broad release identity in an isolated exercise | Verify pinned immutable inputs and artifact identities against independently retained expectations; reject substitution and unauthorized publication. Document residual trust in the build/release authority | Existing artifact-reproduction principles apply; dependency provenance, publisher privilege review and revocation rehearsal are proposed process gates |
| A9: Operational recovery restores the intended chain | Combine overload or partition with restart, partial rollout and stale state; exercise the approved recovery procedure with a declared validator-weight subset slow or absent, within the recovery assumptions | Independent observers agree on finalized identities, account results and membership after recovery; retained signing history remains safe; recovery time and lost/unknown operations are explicitly accounted for | Local crash and signing drills exist; a combined release rehearsal and measured recovery objectives are proposed |
| A10: Missing initialization never grants authority | Exercise fresh, partially initialized and upgraded instances with empty/default roots, zero-valued identifiers, missing owners and interrupted migration | Uninitialized state cannot authorize proof acceptance, release or privileged mutation; exact valid initialization enables only its intended authority. Remove the initialization guard to show red | Proposed explicit cases for each authority-bearing state machine; apply only to existing components, with old-to-new state fixtures where supported |
| A11: One logical value-moving operation has at most one business effect | Crash before/after durable intent, signing, broadcast, execution and receipt persistence; lose replies; reorder or duplicate callbacks; retry concurrently from two workers | Reconcile by transaction identity and durable intent; resubmit only the same signed attempt where allowed; no new attempt while the prior effect is unknown. Count the actual chain effect, not API calls or signatures | [Readiness/relayer controls](pq-readiness/test_controls.py) cover orchestration and durable unknown states; full real-chain cut-point and concurrent-worker coverage is proposed |
| A12: Partition and recovery respect weighted consensus assumptions | Partition by reachable validator-weight subsets below, meeting and above configured decision thresholds; heal with delayed/reordered votes, stale nodes and a set transition | Within the stated fault model, no conflicting finalized identity; when timing and honest connectivity assumptions recover, progress returns within the preapproved envelope. Outside-model runs report containment/recovery only, never a safety proof | Quorum arithmetic and signing/key-transition anchors exist; combined weighted-network fault exploration is proposed. Node counts and a few successful seeds are insufficient |
| A13: Economic/accounting failure is detected and contained | Where applicable, violate a reserve/accounting invariant or supply stale/manipulated market data while operations are pending | Independently recompute obligations and observe a bounded-latency alert plus the specifically approved refusal, pause or escalation behavior; preserve pending-operation evidence and reconcile recovery | Proposed for deployed components with an explicit economic model and authorized response. Absent integrations are not applicable with a recorded reason; design-only resource-pricing features cannot claim implementation or acceptance |

The state-download anchor deliberately supplies trusted proof metadata through
its fixture manager. Do not use it to claim that trust-root acquisition itself
was tested. Likewise, signature-valid messages may still be adversarial, and
arithmetic threshold tests do not prove cryptographic certificate verification.

### Conditional application and economic tests

Bridges, wrapped assets, price feeds, lending, governance execution and external
signing services require additional models only where they exist in the
approved deployment. Before marking a row applicable, identify the real contract,
trusted parties, external finality rule and value at risk. Otherwise record a
reasoned not-applicable decision rather than inventing a deployed capability.

For an applicable value-release integration, test forged or replayed receipts,
wrong-domain proofs, stale or reorganized external state, signer compromise
within and beyond the assumed threshold, and delayed/censored delivery. Verify
locked collateral versus minted/released obligations under the specified model.
For an applicable market-dependent system, test stale/manipulated observations,
liquidity shocks, precision/rounding boundaries and feedback between price,
collateral and incentives. Correct execution alone does not prove economic
stability. A simulator demonstrates its stated model, not real-market safety.

### Make each matrix row executable and falsifiable

Before a release relies on a row, create a case record with a stable ID, owner,
source/test path, command, setup and cleanup, exact candidate configuration,
preconditions, failure injection, independent expected outcome and red control.
Specify the safety predicate and the liveness/resource envelope separately.
Choose measurable limits from the protocol and deployment budget before seeing
the result, and obtain the responsible owner's approval. Undefined load, duration,
resource, recovery or alert thresholds make the affected acceptance case blocked,
not passed. Do not invent a universal timeout or throughput target here.

Record intermediate and final state, not only the last success flag. Run both
isolated faults and risk-driven combinations, such as cache churn plus replay,
partition plus key rotation, or disk failure during upgrade. Preserve the
minimal triggering sequence and test sibling paths. Use independently stated protocol rules as the oracle, then independent observers
that do not share the same helper, cache or trust assertion as the implementation
under test; explicitly document unavoidable shared dependencies.

An incident regression needs: a confirmed failure mechanism, a minimized local
reproducer, the guard-removal or old-behavior red result, a corrected green run,
and a classification of the coverage gap. Never reproduce harmful traffic on
shared or live networks without separate operational authorization. Run release
credential and recovery exercises with isolated identities and disposable state.

## 6. Proposed execution program

1. **Fast, targeted feedback.** Keep unit, property, contract and frozen-vector
   tests close to the changed boundary. Test the intended error and include a
   reachable positive control. Preserve cross-architecture determinism where
   the execution rules require it.
2. **Differential discovery.** Generate structured, bounded inputs; retain the
   first divergence; minimize it; add authored assertions; freeze the
   counterexample; demonstrate red before green. Keep unsupported inputs and
   approved exceptions outside the parity-pass numerator.
3. **Stateful and schedule exploration.** Extend single-step cases to sequences
   that cross caches, persistence, message cascades, validator epochs and
   upgrades. Record seed, scheduler/fault history, configuration and toolchain;
   replay the failing history and minimize events. First demonstrate that the
   harness controls the sources of nondeterminism it claims to control.
4. **Real multi-node integration.** Exercise production consensus, transport,
   storage and tooling with stop/restart, network partitions and rejoin. A
   model or mocked transport does not substitute for this lane.
5. **Release and sustained-load qualification.** Use the exact release candidate
   and representative hardware/load. Measure resource recovery after overload,
   not only peak throughput. Run the approved activation/upgrade rehearsal and
   retain the final evidence index and decision.

Existing tests may already cover individual cases in these lanes. New coverage,
cadence, CI budgets, hosts and owners must be established in scoped changes;
this document does not schedule jobs, allocate infrastructure, authorize live
fault injection or activate a network feature.

## 7. Minimum evidence record for a claim

Record the following together so another person can reproduce and challenge it:

- Claim, boundary, invariant and explicit exclusions.
- Exact candidate and base commits; source/generated-artifact/binary hashes;
  protocol version, capabilities and configuration identity.
- Runner command, toolchain, platform, feature flags and host/resource class.
- Fixture provenance, population/counts, seed and fault/schedule history when
  applicable; expected outcomes derived independently where possible.
- Passed, failed, skipped, unsupported, timed-out and not-run results; no silent
  omissions or retries that erase a failure history.
- Red/green control identifying the changed guard or observer field and the
  specific failure it detects.
- Bounded raw evidence or retained artifact location, digest, size and retention.
- Review scope, unresolved findings, approved exceptions and the acceptance
  decision for this exact commit.

Completion language must remain precise: **implemented**, **locally tested**,
**CI verified**, and **operationally accepted** are separate states. A merge
does not automatically advance a feature through them. When a defect escapes,
classify which review item should have caught it, strengthen its evidence,
search sibling paths and keep the smallest permanent regression.
