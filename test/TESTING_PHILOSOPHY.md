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

## 5. Proposed execution program

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

## 6. Minimum evidence record for a claim

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
