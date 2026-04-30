# TOS Slice 4 Policy RFC

Bounded postponement and behaviour traits.

## 0. Status, scope, and references

**Status.** Draft v1.1, 2026-04-30. This is the Slice 4 Stage 0
implementation input candidate after the first security-review closure
pass. It is not yet an approved release gate.

Slice 4 implements `actor.md` section 5.9 and section 6.5 on top of the
completed Slice 1 message envelope, Slice 2 contract/state syntax, and
Slice 3 stdlib/scaffolding/static-analysis substrate.

References:

- `doc/actor.md` section 5.9 and section 6.5.
- `doc/tol.md` Year 2 plan.
- `doc/roadmap.md` section 6, Slice 4.
- `doc/tos-postponement-policy.md`.
- `doc/tos-language-syntax-policy.md`.
- `doc/tos-slice-3-policy.md`.
- `doc/slice-3-pattern-manifest-schema.json`.

## 1. Ground facts carried into Slice 4

Slice 1 is complete. `Envelope`, `Error`, `OP_ERROR`, error classes,
query-id propagation warnings, gas gates, and conformance fixtures are
already part of the implementation baseline.

Slice 2 is complete. Tol has `contract`, typed `receive(...)`,
state-aware dispatch, `become`, `keep_state`, `@deploy`, unknown-opcode
modes, `receive_external`, contract-local getters, `require`, and
receiver-local `@disclaim_query_id`.

Slice 3 is complete. The stdlib has stable first-wave packages for
ownable, Jetton, NFT, wallet, and multisig. Pattern manifests, scaffold
generation, deterministic replay fixtures, release package checks, and
manifest-backed reply-correlation analysis exist.

The Slice 4 risk is not lack of syntax. The risk is accidentally adding
unbounded mailbox semantics or a trait abstraction that changes bytecode
before it proves safety.

## 2. First-principles constraints

1. **No Erlang mailbox transplant.** TOS validators process one
   consensus-ordered inbound message at a time. There is no contract
   operation that scans or reorders the protocol mailbox.
2. **Postponement is explicit storage.** The first implementation stores
   postponed message snapshots in `c4` through a bounded stdlib queue.
3. **No automatic time.** Without Slice 6 scheduled messages, expiry is
   checked only when contract code touches the queue.
4. **No new wire surface in the foundation stages.** Stages 1-4 of this
   RFC introduce no TL-B constructor, TVM opcode, bounce-body format, or
   `extra_flags` widening.
5. **Traits are compile-time conformance first.** Behaviour traits start
   as manifest-backed checks over ordinary Tol code. They do not create
   runtime trait objects or dynamic dispatch.
6. **Dogfood gates abstraction.** A behaviour trait is accepted only
   after it covers an existing official reference pattern without
   exceeding the Slice 1 bytecode/gas budget.
7. **Raw escape hatches remain possible.** Contracts can keep manual
   code where wire compatibility or gas requires it, but raw code may be
   warning-only for behaviour checks.

## 3. Non-goals

Slice 4 does not implement protocol supervision, scheduled messages,
capability addressing, cross-language ABI freeze, protocol-level
delivery SLA, or `ErrorClass.BackPressure` emission.

Slice 4 does not replace the Slice 3 pattern manifests. It extends them
into behaviour manifests where the compiler can check callback shapes,
message coverage, replies, errors, and bounded postponement policy.

## 4. Stage plan

### Stage 0 - Policy and resource-model lock

Deliverables:

- `doc/tos-postponement-policy.md` defines the bounded postponement
  queue model, budgets, expiry, duplicate handling, and security review
  checklist.
- This RFC defines the Slice 4 implementation sequence and trait
  abstraction boundary.
- `doc/slice-4-behaviour-manifest-schema.json` defines the initial
  machine-readable behaviour-manifest shape, including constrained
  wire-compatibility exceptions, real `ErrorClass` names, optional
  `query_id` replay-key semantics, and enabled-queue budget minimums.
- `doc/roadmap.md` records Slice 4 stages and current status.

Exit criterion: maintainer approval of the policy docs. Compiler and
stdlib implementation begins only after this gate is approved.

Status: draft v1.1 created 2026-04-30 after closing the first
security-review findings on schema constraints and drain failure
semantics.

### Stage 1 - Postponement stdlib foundation

Deliverables:

- Add `@stdlib/postponement`.
- Define `PostponedItem`, `PostponedQueue`, budget structs, and error
  constants.
- Implement enqueue, duplicate detection, FIFO drain, expiry cleanup,
  and accounting helpers.
- Add focused tol-tester cases for enqueue, queue full, duplicate
  query-id, optional-`query_id` without author key, oversized body,
  cell-depth budget, expiry cleanup, callback throw rollback, explicit
  drop/expiry, and FIFO drain.

Exit criterion: stdlib helper tests pass without changing any reference
contract or wire body. Stage 1 is a trust-period implementation only:
contracts written before Stage 2 hardening are not eligible for the
official reference package.

Implementation status: complete as of 2026-04-30. The helper surface
is `@stdlib/postponement`, with focused coverage in
`tol-tester/tests/slice4-postponement-stdlib-positive.tol`. It remains
trust-period code until Stage 2 compiler hardening lands.

### Stage 2 - Postponement compiler hardening

Deliverables:

- Add a check pass that rejects direct writes to stdlib queue internals
  in manifest-backed mode.
- Reject external-message postponement attempts.
- Require explicit budgets for stdlib queue construction.
- Warn on raw map-based postponement that bypasses the stdlib helper.

Exit criterion: hardening tests prove bounded queues cannot be bypassed
through ordinary Tol field access or raw external-message paths.

### Stage 3 - First postponed reference contract

Deliverables:

- Add one official Slice 4 reference contract that genuinely needs
  "too early" message deferral. The default target is an auction or
  escrow-style state machine because it naturally defers settlement or
  completion messages until a later state.
- Add replay fixtures covering early message enqueue, state transition,
  drain, expiry, queue full, duplicate, and malformed-body rejection.
- Record gas and bytecode budget against a hand-written no-stdlib
  equivalent.

Exit criterion: bounded postponement is used by one shipped reference
contract and remains within the Slice 1 budget threshold.

### Stage 4 - Behaviour manifest foundation

Deliverables:

- Add behaviour manifests for `request_server`, `state_machine`, and
  `postponing_state_machine`.
- Add a compiler check that validates ordinary Tol contracts against a
  selected manifest without changing generated bytecode.
- Warning mode for raw code; error mode for stdlib/generated contracts.

Exit criterion: the compiler can prove callback/message/error shape for
  a small generated contract while preserving bytecode.

### Stage 5 - Trait coverage for three official patterns

Deliverables:

- Cover at least three official Slice 3 patterns with behaviour
  manifests. Candidate order: Jetton wallet, NFT item, multisig.
- Keep all existing BoC hashes or explain any delta under the Slice 1
  budget rule.
- Extend scaffold manifests so generated projects declare the behaviour
  they conform to.

Exit criterion: traits cover three official reference patterns without
bytecode regression beyond budget.

### Stage 6 - Tooling, docs, and release surrogate

Deliverables:

- Extend `tol new` output with behaviour-manifest declarations where
  applicable.
- Add author docs for bounded postponement and behaviour conformance.
- Add a release-package check that validates Slice 4 docs, manifests,
  generated examples, and focused tests.
- Run a repo-side author surrogate trial unless a human trial is
  explicitly available.

Exit criterion: a contract author can generate or inspect a behaviour
manifest and run the bounded-postponement tests without reading compiler
source.

## 5. Acceptance criteria

Slice 4 is complete only when:

- bounded postponement is used by at least one shipped reference
  contract;
- traits cover at least three official reference contracts or stdlib
  patterns;
- no Slice 1, Slice 2, or Slice 3 compatibility gate regresses;
- no new wire surface is introduced unless a separately approved policy
  revision says so;
- the final release package documents the remaining protocol gaps:
  delivery SLA, scheduled wakeups, supervision, and
  `ErrorClass.BackPressure` activation.

## 6. Security review focus for Slice 4

Reviewers should treat these as blocker-class surfaces:

- any path that allows unbounded postponed queue growth;
- any path that stores external signed wallet requests as postponed
  internal messages;
- any hidden self-message or wakeup that changes wire observability;
- any queue drain path that can loop without a contract-declared bound;
- any trait lowering that changes bytecode while presenting itself as a
  check-only abstraction;
- any use of `ErrorClass.BackPressure` before `actor.md` section 5.7 is
  designed.

## 7. Open questions

1. Which reference contract should be the Stage 3 dogfood target:
   auction, escrow, or a smaller state-machine reference.
2. Whether behaviour conformance should be spelled in source syntax or
   remain manifest-selected during the first compiler stage.
3. Whether a later Slice 4 revision should allow optional self-message
   wakeups. Draft v1 keeps them out to preserve wire minimality.
