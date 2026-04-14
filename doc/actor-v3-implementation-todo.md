# TOS Actor V3 Implementation TODO List

**Status:** Draft v0.1  
**Audience:** Claude Code / Codex / implementation engineers  
**Source of truth:** [actor-v3.md](actor-v3.md)

---

## 0. Purpose

This document converts the current `actor-v3.md` specification into an implementation-oriented task list.

It is intentionally written at a granularity that can be assigned directly to Claude Code / Codex sessions.

The target outcome is:

- V1 remains the active product engineering track
- V2 implementation begins only after Module 0 freeze outputs are complete
- V2 work proceeds in small, verifiable slices
- every slice has:
  - owned files
  - clear invariants
  - explicit tests
  - a defined dependency boundary

---

## 1. Execution Model Summary

Before implementation starts, every worker must use the following terminology consistently:

- **Admission**: external actor-targeted work is authenticated, deduplicated, checked, and stored in a pending layer. No actor code runs here.
- **Preview Execution**: actor-local execution runs in a reversible, checkpointed mode. Tentative results are produced.
- **Canonical Merge and Adopt**: accepted preview results are merged in deterministic order and become canonical.
- **Pending runtime**: node-local, non-canonical, optionally persisted for liveness only.
- **Canonical runtime**: the only runtime representing canonical state.
- **Replay runtime**: scratch runtime used for replay/import validation.
- **Wave discipline**:
  - one wave executes at most one mailbox item per actor
  - each wave begins from a frozen ready set
  - a wave ends only after every selected item has produced a tentative result, been rejected, or been deferred
  - emitted messages become eligible only in a later wave
  - later-wave execution is eligible, not guaranteed
  - same-wave recursive execution is forbidden

Any implementation task that violates those semantics is out of scope.

---

## 2. Global Rules for Claude Code Sessions

Every implementation session MUST follow these rules:

1. Do not change V2 semantics while implementing.
2. Do not silently collapse pending, canonical, and replay state into one logical runtime.
3. Treat pending runtime as non-consensus state: it may be persisted for liveness, but it must be safely discardable or reconstructible without affecting canonical replay.
4. Do not introduce same-wave recursion.
5. Do not let Admission mutate canonical actor state.
6. Do not let imported replay mutate canonical state before validation succeeds.
7. Add tests together with behavior changes whenever feasible.
8. Keep feature flags or actor-mode gates explicit where mixed legacy/V2 behavior still exists.

---

## 3. Recommended Delivery Order

Implementation should proceed in this order:

1. Module 0 — Spec Freeze Outputs
2. Module A — TL-B Schema and Account Structure
3. Module B — VM / Opcode Support
4. Module F — OutMsgQueue Key Extension
5. Module G — Merkle Proof Support
6. Module C — Transaction Execution Engine
7. Module D — Collator Flow and Wave Scheduling
8. Module E — Validator Replay and Validation
9. Module H — Lite-client / SDK / Emulator
10. End-to-end integration, mixed legacy/V2 blocks, and transition tests

Reason:

- A/B/F/G define the protocol surface and data layout
- C depends on A/B
- D depends on C
- E depends on C/D
- H depends on the finalized protocol/API surface

---

## 4. Module 0 — Spec Freeze Tasks

### Goal

Freeze the normative inputs that later implementation modules must not reinterpret.

### Claude Code Tasks

#### Task 0.1 — Extract Frozen V2 Schemas Into a Reviewable Checklist

**Files**

- [doc/actor-v3.md](actor-v3.md)

**Deliverable**

- A machine-readable checklist or markdown table containing:
  - `ActorDescriptor` fields
  - actor-mode `AccountStorage`
  - `ActorAddress` binary/text encoding
  - canonical actor transaction fields
  - merge ordering rule
  - later-wave visibility rule
  - VM compatibility matrix freeze points

**Validation**

- Every frozen item in `30A` and Appendix D is represented exactly once.

#### Task 0.2 — Generate Golden Serialization Vectors

**Files**

- new test data under `test/` or `crypto/test/`

**Deliverable**

- golden fixtures for:
  - actor-mode `AccountStorage`
  - `ActorDescriptor`
  - `ActorAddress`
  - 608-bit queue key examples

**Validation**

- serialization round-trip tests pass
- bit-exact vectors are committed

#### Task 0.3 — Freeze the VM Compatibility Matrix

**Files**

- [doc/actor-v3.md](actor-v3.md)
- optional generated matrix file under `doc/` or `test/fixtures/`

**Deliverable**

- explicit table for:
  - allowed actor-local values
  - forbidden account-global values
  - trap/sentinel/remap behavior

**Validation**

- every opcode/getter mentioned in section 21 is covered

---

## 5. Module A — TL-B Schema and Account Structure

### Goal

Add actor-mode data structures and parsing/packing support.

### Claude Code Tasks

#### Task A.1 — Add ActorDescriptor and Actor-Mode AccountStorage to TL-B

**Files**

- [crypto/block/block.tlb](crypto/block/block.tlb)

**Deliverable**

- `ActorDescriptor`
- actor-mode `AccountStorage`
- actor-mode transaction actor fields if required by schema design

**Validation**

- `tlbc` generation succeeds
- no legacy schema regressions

#### Task A.2 — Regenerate TL-B Outputs

**Files**

- generated files under `crypto/block/`

**Deliverable**

- updated generated headers/sources from `block.tlb`

**Validation**

- build succeeds

#### Task A.3 — Add Actor-Mode Parsing / Packing Branches

**Files**

- [crypto/block/block-parse.h](crypto/block/block-parse.h)
- [crypto/block/block-parse.cpp](crypto/block/block-parse.cpp)
- [crypto/block/transaction.h](crypto/block/transaction.h)
- [crypto/block/transaction.cpp](crypto/block/transaction.cpp)

**Deliverable**

- unpack actor-mode account storage
- detect actor-mode vs legacy
- commit actor-local state back to account storage representation

**Validation**

- round-trip tests for actor-mode account serialization
- legacy account unpack/pack still passes

#### Task A.4 — Add Actor-Mode Fields to In-Memory Account / Transaction Structures

**Files**

- [crypto/block/transaction.h](crypto/block/transaction.h)
- [crypto/block/transaction.cpp](crypto/block/transaction.cpp)

**Deliverable**

- fields for:
  - actor-mode flag
  - shared balance
  - actor dictionary root
  - current actor id / budget / state / actor_lt
  - tentative transaction result fields

**Validation**

- compile succeeds
- no mixed legacy/actor-mode ambiguity

---

## 6. Module B — VM / Opcode Support

### Goal

Implement actor-mode VM surface: c6 register, c7 additions, and actor opcodes.

### Claude Code Tasks

#### Task B.1 — Add c6 Register Support

**Files**

- [crypto/vm/vm.h](crypto/vm/vm.h)
- [crypto/vm/continuation.h](crypto/vm/continuation.h)

**Deliverable**

- c6 lifecycle support for actor-local state root

**Validation**

- VM unit tests for c6 set/get

#### Task B.2 — Register Actor Opcodes

**Files**

- [crypto/vm/tosops.cpp](crypto/vm/tosops.cpp)
- [crypto/vm/tosops.h](crypto/vm/tosops.h)

**Deliverable**

- `STATEGET`
- `STATESET`
- `STATEDEL`
- `ACTORSEND`
- `BUDGETGET`
- `ACTORCLAIM`
- `ACTORRELEASE`

**Validation**

- opcode dispatch tests
- invalid-opcode behavior in legacy mode

#### Task B.3 — Implement Actor-Mode c7 Behavior

**Files**

- [crypto/vm/tosops.cpp](crypto/vm/tosops.cpp)
- any VM context plumbing files used by transaction execution

**Deliverable**

- actor-mode `GETBALANCE`, `LTIME`, `TXHASH`, `GETPARAM(...)` behavior per section 21

**Validation**

- sentinel behavior tests
- actor-local remap tests
- forbidden-field tests

#### Task B.4 — Add OutAction Variants

**Files**

- [crypto/block/block.tlb](crypto/block/block.tlb)
- action handling code in `crypto/block/transaction.cpp`

**Deliverable**

- actor send / claim / release actions in action list encoding

**Validation**

- action serialization/deserialization tests

---

## 7. Module F — OutMsgQueue Key Extension

### Goal

Extend queue keys from 352 bits to 608 bits and preserve deterministic ordering.

### Claude Code Tasks

#### Task F.1 — Extend Queue Key Width

**Files**

- [crypto/block/output-queue-merger.h](crypto/block/output-queue-merger.h)
- [crypto/block/output-queue-merger.cpp](crypto/block/output-queue-merger.cpp)
- [crypto/block/block.cpp](crypto/block/block.cpp)
- [crypto/block/block.h](crypto/block/block.h)

**Deliverable**

- 608-bit queue key support
- actor_id inclusion in key computation

**Validation**

- golden sort-order tests
- legacy zero-filled actor_id compatibility tests

#### Task F.2 — Update Validation and Collator Call Sites

**Files**

- [validator/impl/collator.cpp](validator/impl/collator.cpp)
- [validator/impl/validate-query.cpp](validator/impl/validate-query.cpp)

**Deliverable**

- all queue key consumers updated

**Validation**

- queue merge tests

---

## 8. Module G — Merkle Proof Support

### Goal

Add actor-level proof traversal.

### Claude Code Tasks

#### Task G.1 — Add Actor Proof Verification Helper

**Files**

- [crypto/block/check-proof.cpp](crypto/block/check-proof.cpp)
- [crypto/block/check-proof.h](crypto/block/check-proof.h)

**Deliverable**

- actor proof verification path:
  - block
  - shard
  - container
  - actor dictionary
  - actor descriptor
  - state key

**Validation**

- proof fixture tests
- negative proof tests

---

## 9. Module C — Transaction Execution

### Goal

Implement actor-mode execution semantics inside the transaction engine.

### Claude Code Tasks

#### Task C.1 — Add Actor Transaction Result Structures

**Files**

- [crypto/block/transaction.h](crypto/block/transaction.h)

**Deliverable**

- result object for Preview Execution output
- balance request representation
- tentative actor-local result container

**Validation**

- compile succeeds
- unit tests for result object serialization if needed

#### Task C.2 — Make Credit Phase Actor-Aware

**Files**

- [crypto/block/transaction.cpp](crypto/block/transaction.cpp)

**Deliverable**

- targeted actor value -> actor budget
- legacy/account-level value -> shared balance

**Validation**

- actor-targeted inbound value tests
- unknown-actor handling tests

#### Task C.3 — Make Compute Phase Actor-Aware

**Files**

- [crypto/block/transaction.cpp](crypto/block/transaction.cpp)

**Deliverable**

- gas charged from actor budget
- c6 initialized from actor state
- c7 actor fields populated
- actor-local VM context isolation enforced

**Validation**

- actor-mode VM execution tests
- budget deduction tests

#### Task C.4 — Make Action Phase Actor-Aware

**Files**

- [crypto/block/transaction.cpp](crypto/block/transaction.cpp)

**Deliverable**

- record actor send / claim / release intents
- unknown actor send failure behavior

**Validation**

- action-phase tests
- deferred claim/release tests

#### Task C.5 — Split Preview Output From Canonical Commit

**Files**

- [crypto/block/transaction.cpp](crypto/block/transaction.cpp)

**Deliverable**

- preview result path
- canonical adopt path
- no canonical mutation during Preview Execution

**Validation**

- rollback tests
- rejected result leaves canonical state unchanged

---

## 10. Module D — Collator Flow and Wave Scheduling

### Goal

Implement Admission, wave-based Preview Execution, and Canonical Merge and Adopt in the collator.

### Claude Code Tasks

#### Task D.1 — Add Pending Layer and Per-Wave Frontier Tracking

**Files**

- [validator/impl/collator-impl.h](validator/impl/collator-impl.h)
- [validator/impl/collator.cpp](validator/impl/collator.cpp)

**Deliverable**

- pending actor work structures
- actor_lt counters
- per-actor prefix validity
- wave frontier selection state
- ready-set freezing and next-wave eligibility bookkeeping

**Validation**

- unit tests for frontier selection if feasible

#### Task D.2 — Add Admission Path

**Files**

- collator ingress paths in [validator/impl/collator.cpp](validator/impl/collator.cpp)

**Deliverable**

- external actor message admission into pending layer
- no execution at admission

**Validation**

- admission-only ingress test

#### Task D.3 — Implement Wave Builder

**Files**

- [validator/impl/collator.cpp](validator/impl/collator.cpp)

**Deliverable**

- select at most one mailbox item per actor per wave
- freeze ready set
- execute selected wave items in parallel where allowed
- hold emitted messages for later wave eligibility only
- close the wave only after all selected items are resolved or deferred

**Validation**

- one-mailbox-item-per-actor-per-wave test
- same-wave recursive self-send forbidden test
- next-wave ordering test

#### Task D.4 — Implement Defer / Enqueue-Only Behavior

**Files**

- [validator/impl/collator.cpp](validator/impl/collator.cpp)

**Deliverable**

- stop opening new waves when block limits are reached
- preserve emitted work in pending state for later wave or later block
- ensure later-wave execution remains eligible but not guaranteed under pressure

**Validation**

- defer-under-pressure test

#### Task D.5 — Implement Canonical Merge and Adopt

**Files**

- [validator/impl/collator.cpp](validator/impl/collator.cpp)
- new helper such as `crypto/block/actor-merge.cpp`

**Deliverable**

- deterministic ordering
- prefix commit enforcement
- shared balance settlement
- final lt assignment
- canonical out message materialization

**Validation**

- shared balance overdraw rejection test
- prefix rejection cascade test

---

## 11. Module E — Validator Replay and Validation

### Goal

Make validator/import replay reproduce committed actor execution from canonical parent state.

### Claude Code Tasks

#### Task E.1 — Add Actor-Mode Prechecks

**Files**

- [validator/impl/validate-query.cpp](validator/impl/validate-query.cpp)
- [validator/impl/validate-query.hpp](validator/impl/validate-query.hpp)

**Deliverable**

- actor_lt monotonicity checks
- actor result shape checks
- actor-mode diff prechecks

**Validation**

- unit tests for actor-mode validation failures

#### Task E.2 — Add Replay Runtime Path

**Files**

- validator replay path in [validator/impl/validate-query.cpp](validator/impl/validate-query.cpp)

**Deliverable**

- replay runtime initialized from canonical parent state
- no mutation of canonical state before replay success

**Validation**

- replay runtime isolation test

#### Task E.3 — Replay Preview Execution and Canonical Merge

**Files**

- [validator/impl/validate-query.cpp](validator/impl/validate-query.cpp)

**Deliverable**

- replay committed actor results
- verify merge ordering, prefix rules, and final outputs

**Validation**

- validator replay equals collator result

#### Task E.4 — Validate Later-Wave Visibility

**Files**

- [validator/impl/validate-query.cpp](validator/impl/validate-query.cpp)

**Deliverable**

- reject same-wave recursive execution
- verify emitted message ordering across waves

**Validation**

- no same-wave actor-send consumption
- next-wave ordering

---

## 12. Module H — Lite-Client / SDK / Emulator

### Goal

Expose actor-aware state and transaction APIs.

### Claude Code Tasks

#### Task H.1 — Add Lite API Methods

**Files**

- [tl/generate/scheme/lite_api.tl](tl/generate/scheme/lite_api.tl)
- [lite-client/lite-client.cpp](lite-client/lite-client.cpp)

**Deliverable**

- `getActorState`
- `getActorList`
- actor transaction query support if needed

**Validation**

- lite-client tests for actor queries

#### Task H.2 — Add SDK Types

**Files**

- [tl/generate/scheme/toslib_api.tl](tl/generate/scheme/toslib_api.tl)
- SDK client code under `toslib` / `test/tostester`

**Deliverable**

- actor-aware SDK request/response types

**Validation**

- SDK integration tests

#### Task H.3 — Extend Emulator

**Files**

- [emulator/transaction-emulator.h](emulator/transaction-emulator.h)
- emulator implementation files

**Deliverable**

- actor-mode emulation hooks

**Validation**

- emulator actor-mode tests

---

## 13. Cross-Cutting Test Matrix

The following tests are implementation-gating:

### Determinism

- identical committed result set for repeated collations
- deterministic tertiary tie-breaker for duplicate `(actor_id, actor_lt)`
- validator replay equals collator output

### Runtime Separation

- admission does not mutate canonical state
- replay failure does not mutate canonical or pending runtime
- pending state can be discarded/rebuilt without affecting canonical replay
- pending frontier persistence does not become a consensus dependency

### Wave Discipline

- one mailbox item per actor per wave
- no same-wave actor-send consumption
- same-wave recursive self-send forbidden
- emitted work eligible only in later wave
- later-wave execution is not guaranteed under block pressure

### Balance Semantics

- actor budget debit rules
- shared balance settlement rules
- claim/release deferred effect rules
- overdraw rejection

### Mixed Legacy / V2

- legacy account and actor-mode account in same block
- no legacy behavior regression

### Proof / Client

- actor proof verification
- queue key proof/ordering checks
- lite-client actor queries

---

## 14. First Coding Slice Recommendation

If one implementation sprint starts immediately, the recommended first slice is:

1. Module 0 Task 0.1
2. Module 0 Task 0.2
3. Module A Task A.1
4. Module A Task A.2
5. Module A Task A.3
6. Add one minimal actor-mode serialization round-trip test

Reason:

- it produces concrete frozen artifacts
- it exercises the schema boundary early
- it de-risks all later modules

The recommended second slice is:

1. Module B Task B.1
2. Module B Task B.2
3. Module B Task B.3
4. VM compatibility tests

The recommended third slice is:

1. Module C Task C.1-C.5
2. minimal Module D Task D.1-D.3
3. acceptance tests for:
  - admission-only ingress
  - same-wave recursive self-send forbidden
  - next-wave ordering

---

## 15. Definition of Done for V2 MVP

V2 MVP is done only when all of the following are true:

1. actor-mode account/container state can be serialized, parsed, and committed
2. actor-mode VM execution works with the frozen compatibility matrix
3. Admission does not execute actor work
4. Preview Execution is reversible and actor-local
5. Canonical Merge and Adopt is deterministic
6. validator replay starts from canonical parent state and matches collator output
7. emitted messages do not execute in the same wave
8. mixed legacy + actor-mode blocks validate and commit correctly
9. actor-aware proofs and lite-client queries work
10. the acceptance tests in Appendix C of `actor-v3.md` all pass

---

## 16. Suggested Claude Code Prompt Template

Use the following prompt structure for implementation sessions:

> Implement Task X from `doc/actor-v3-implementation-todo.md`.  
> Follow `doc/actor-v3.md` as the semantic source of truth.  
> Do not change protocol semantics.  
> Keep legacy behavior working unless the task explicitly changes actor-mode paths only.  
> Add or update tests for the task.  
> At the end, report:
> - files changed
> - invariants preserved
> - tests run
> - known follow-up tasks

---

## 17. Immediate Next Tasks

If work starts now, the immediate next three Claude Code assignments should be:

1. **Freeze extraction and golden vectors**
   - complete Module 0 Tasks 0.1 and 0.2
2. **Actor-mode TL-B branch**
   - complete Module A Tasks A.1-A.3
3. **VM actor-mode base support**
   - complete Module B Tasks B.1-B.3

These three assignments create the minimum stable base for all later execution work.
