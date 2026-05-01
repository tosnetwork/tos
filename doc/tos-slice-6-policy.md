# TOS Slice 6 Policy RFC

Supervision, scheduled messages, delivery failure semantics, and
capability handles.

## 0. Status, scope, and references

**Status.** Draft v0.1, 2026-05-01. This opens Slice 6 Stage 0 design
review. It is not an implementation approval and must pass security
review before Stage 1 code starts.

Slice 6 is the first protocol-heavy actor-layer slice after the Slice
1-5 contract-language and stdlib substrate. It promotes the remaining
actor-model runtime concerns from "application convention" to explicit
protocol, Tol, stdlib, and release-package design:

- delivery failure and dead-letter semantics from `actor.md` section
  5.7;
- scheduled messages and cancellation from `actor.md` section 5.2;
- links, monitors, supervision, restart intensity, and crash reports
  from `actor.md` sections 5.1, 6.3, 6.4, and 6.6;
- capability addressing from `actor.md` section 5.4.

Detailed companion RFCs:

- `doc/tos-delivery-sla-policy.md`
- `doc/tos-time-policy.md`
- `doc/tos-supervision-policy.md`
- `doc/tos-capability-policy.md`

References:

- `doc/actor.md`
- `doc/tol.md`
- `doc/roadmap.md`
- `doc/tos-message-policy.md`
- `doc/tos-language-syntax-policy.md`
- `doc/tos-postponement-policy.md`
- `doc/tos-slice-4-policy.md`
- `doc/tos-slice-5-policy.md`
- `doc/tos-account-permission-model.md`
- `doc/GlobalVersions.md`

## 1. Ground facts carried into Slice 6

Slice 1 is complete. Rich bounce scaffolding, `OP_ERROR`,
`ErrorClass`, request/reply correlation, `extra_flags` named
constants, gas gates, and conformance fixtures exist. `extra_flags`
bit 3 is reserved for supervision links but remains invalid until the
protocol mask is widened in lockstep.

Slice 2 is complete. Tol has `contract`, typed `receive(...)`, state
machines, `@deploy`, unknown-opcode policy, `receive_external`, getters,
`require`, and receiver-local query-id handling.

Slice 3 is complete. First-wave stdlib packages, replay fixtures,
scaffolding, and manifest-driven checks exist.

Slice 4 is complete. Bounded postponement exists as explicit contract
storage. This is not a protocol mailbox and does not imply native
scheduled delivery.

Slice 5 is complete. Second-wave stdlib packages and the ABI manifest
freeze exist. External production-intent candidates have exposed the
main Slice 6 pressure points: caller-controlled `now` is unsafe, payout
and refund dispatch need explicit accounting, and receive-handler tests
that depend on TVM context need emulator coverage.

Therefore Slice 6 must not treat supervision, timers, or capabilities
as surface syntax first. It must define resource ownership, funding,
failure classification, and upgrade activation before adding developer
vocabulary.

## 2. First-principles constraints

1. **No free protocol messages.** A failure signal, scheduled delivery,
   monitor notification, dead-letter, or restart request is a
   consensus-visible message. It consumes forwarding fees, storage,
   compute, and block space. The sender, supervised child, supervisor,
   or scheduler escrow must be named for every message path.
2. **No unbounded queues.** Timer queues, dead-letter queues, failure
   logs, monitor sets, supervisor child tables, and capability grant
   registries must have explicit count, cell, gas, age, and rent
   bounds.
3. **No exact-time guarantee.** A scheduled message is "not before T",
   not "exactly at T". Validators must have a bounded delivery window
   and a priced failure path when the window expires.
4. **Failure semantics before restart semantics.** A supervisor cannot
   make a safe restart decision until failures have canonical classes:
   transient, permanent, authorization, protocol, back-pressure, and
   undeliverable.
5. **Supervision is not automatic resurrection.** On-chain "restart"
   means a funded recovery message or reinitialization action under a
   declared strategy. Validators do not silently rewrite contract state
   after a crash.
6. **Links and monitors are different.** A link is a failure
   relationship that may escalate; a monitor is one-way observation.
   They need different tags, costs, and delivery semantics.
7. **BackPressure cannot be activated without delivery SLA.**
   `ErrorClass.BackPressure` remains reserved until the delivery-SLA RFC
   defines queue pressure, retry advice, and dead-letter behavior.
8. **Capabilities are not hidden addresses.** Base account addresses
   remain public and content-derived. Capability handles can only add
   entry-point authorization. They do not restore pure locality of
   reference at the address layer.
9. **Secret bearer handles are unsafe on a public chain by default.**
   If a token appears in a message body, observers can read it.
   Reusable capability handles must therefore be sender-bound,
   signature-bound, stateful, single-use, or otherwise non-replayable.
10. **Activation is versioned.** Any protocol mask widening, new action
    kind, scheduler state, dead-letter behavior, or supervision flag is
    gated by `ConfigParam 8` / global-version capability and by explicit
    conformance fixtures.

## 3. Non-goals

Slice 6 does not copy Erlang mailboxes. There is no protocol operation
that scans, reorders, or selectively consumes a contract's inbound
message queue.

Slice 6 does not guarantee wall-clock precision. Block timestamps and
masterchain time are consensus inputs with bounded uncertainty.

Slice 6 does not make every existing contract supervised. Legacy
contracts remain valid. Supervision relationships are opt-in and
manifested.

Slice 6 does not make bearer secrets private if they are posted on
chain. Capability design must assume public message bodies unless the
handle is single-use, encrypted for a recipient, or verified by a
signature over fresh context.

Slice 6 does not activate protocol back-pressure or `extra_flags` bit 3
until the corresponding policy, global-version gate, validator code,
Tol stdlib constants, and conformance fixtures land in the same stage.

## 4. Dependency order

The safe order is:

1. Delivery failure taxonomy and dead-letter semantics.
2. Scheduled-message resource model.
3. Monitor/link failure signals.
4. Supervision strategies with restart intensity and circuit breakers.
5. Capability handles.
6. System-contract dogfood and release gate.

This order follows the resource dependency rather than the user-facing
feature order. Timers need delivery failure. Supervision needs delivery
failure and monitor/link semantics. Capabilities can be developed in
parallel as a public RFC, but protocol activation must wait until the
authorization and revocation story is reviewed.

## 5. Stage plan

### Stage 0 - RFC and security-review lock

Deliverables:

- this umbrella RFC;
- delivery-SLA/dead-letter RFC;
- time/scheduled-message RFC;
- supervision RFC;
- capability RFC;
- roadmap update that promotes `actor.md` sections 5.7, 6.3, 6.4, and
  6.6 into Slice 6 scope;
- security review findings closed before implementation.

Exit criterion: no Stage 1 code starts until Stage 0 review accepts the
dependency order, resource model, version gates, and non-goals.

### Stage 1 - delivery failure and BackPressure foundation

Deliver the smallest protocol/test/docs slice that can classify
undeliverable and congested delivery without changing contract source
semantics.

Expected work:

- define canonical delivery failure records;
- define the dead-letter sink model and retention bounds;
- define queue-pressure metrics that are safe to expose;
- define when `ErrorClass.BackPressure` may be emitted;
- add conformance fixtures for old contracts remaining unchanged.

Exit criterion: delivery failure can be represented and audited, but no
scheduled messages or supervisors depend on it yet.

### Stage 2 - scheduled-message protocol substrate

Expected work:

- add a version-gated scheduled-delivery action or equivalent protocol
  representation;
- define sender-funded escrow for forwarding, storage, cancellation, and
  expiry;
- define `not_before`, `expire_after`, cancellation, frozen-account,
  deleted-account, and sender-gone semantics;
- add validator/emulator fixtures for delivery order and expiry.

Exit criterion: a contract can schedule and cancel a bounded future
internal message under emulator and conformance tests.

### Stage 3 - Tol and stdlib time surface

Expected work:

- add `@stdlib/time` helpers for `sendAfter`, `sendAt`, and
  `cancelScheduled`;
- add Tol compiler checks for explicit timer budgets and manifest-backed
  scheduled-message declarations;
- add tests showing that external callers cannot spoof `now`;
- extend scaffold/replay artifacts with timer traces.

Exit criterion: authors use `blockchain.now()` and stdlib scheduling
helpers rather than caller-controlled `msg.now` fields.

### Stage 4 - monitors and links

Expected work:

- define one-way monitor and bidirectional link registration;
- activate `extra_flags` bit 3 only if the link tag is fully specified;
- define monitor notification delivery and funding;
- define behavior for frozen, deleted, and rent-expired observed
  accounts.

Exit criterion: a monitor can receive a bounded structured DOWN-style
notification without implying restart.

### Stage 5 - supervision stdlib and restart intensity

Expected work:

- add `@stdlib/supervision`;
- define child specs, supervisor state, restart strategies, and recovery
  messages;
- enforce restart intensity, cooldown, gas escrow, and circuit breaker
  limits;
- add behavior manifests and static checks for supervised actors.

Exit criterion: an official example can supervise a child contract
without creating message amplification under repeated failure.

### Stage 6 - capability handles

Expected work:

- freeze the capability handle model from `doc/tos-capability-policy.md`;
- add a contract-level stdlib and manifest shape first;
- add protocol support only if the public-grant / revocation / replay
  model passes review;
- integrate with account capability discovery where appropriate.

Exit criterion: one official example uses sender-bound or
signature-bound capability grants without relying on a reusable secret
posted on chain.

### Stage 7 - observability and release package

Expected work:

- add bounded crash/failure trace artifacts;
- add scheduler, monitor, supervisor, and capability audit checklists;
- extend release checkers so generated examples include budgets,
  manifests, and replay/emulator fixtures;
- update compatibility matrix and release notes.

Exit criterion: operators can inspect supervised failures and scheduled
messages without replaying raw chain history by hand.

### Stage 8 - system-contract dogfood and production gate

Expected work:

- apply scheduled messages, supervision, and structured failures to at
  least one official system contract or workchain-local service;
- run full conformance, emulator, gas, and release gates;
- record activation height/capability plan and rollback plan.

Exit criterion: Slice 6 success criterion in `roadmap.md` is met:
supervision, scheduled messages, and structured errors are in
production on at least one workchain and used by at least one official
system contract.

## 6. Security review checklist

- Every protocol-generated message has a named payer and failure path.
- Every queue has count, cell, byte, age, and rent bounds.
- Every retry path has idempotency and replay rules.
- Every restart strategy has an intensity limit and circuit breaker.
- Every scheduled message has cancellation and expiry semantics.
- Every monitor/link notification is bounded and cannot recursively
  amplify failure.
- Every capability handle is bound to sender, signature, nonce,
  expiry, or stateful grant; reusable public bearer tokens are rejected.
- Global-version activation includes old/new compatibility fixtures.
- Existing Slice 1-5 conformance and gas gates stay green.

## 7. Open questions for Stage 0 review

1. Should scheduled delivery be keyed by masterchain time, masterchain
   seqno, logical time, or a pair of `not_before` and `expire_after`?
2. Should the dead-letter sink be system-wide, workchain-local, or
   sender-selected with a system default?
3. Is `extra_flags` bit 3 sufficient for link tagging, or does
   supervision need a new body constructor instead?
4. Can queue-pressure metrics be exposed without leaking exploitable
   cross-shard congestion information?
5. Should capability handles remain contract/stdlib-level in Slice 6,
   with protocol admission control deferred to a later slice?

