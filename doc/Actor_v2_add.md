# TOS Protocol-Level Actor Execution Redesign
## Volume II — Protocol Upgrade Track Beyond Account-as-Actor

**Status:** Draft v0.1  
**Audience:** protocol engineers, validator implementers, VM engineers, client/SDK maintainers, Claude Code implementation workflows  
**Prerequisite:** The **TOS Account-as-Actor Architecture Yellow Paper** is assumed to be implemented as the baseline architecture. This document specifies the **next-layer protocol redesign** required to move from **`Account = Actor`** to **`Account contains multiple protocol-native Actors`**.

---

# Abstract

TOS v1 treats each existing on-chain Account as a logical Actor. This yields a practical actor-oriented architecture without changing validator execution, block formats, Merkle proofs, queue keys, or native address semantics.

This Volume II document specifies the **protocol-level execution redesign** that becomes possible once the v1 Account-as-Actor system is already deployed and validated in production.

The purpose of this redesign is to move from:

- **one Account = one execution object**

to:

- **one Account = one container**
- **multiple Actors inside one Account = independent execution objects**

This redesign introduces:

- actor-native storage inside accounts
- actor-local budgets
- account-level shared balance
- two-phase execution
- actor-native transaction semantics
- actor-aware queue routing
- actor-level proof paths
- actor-aware client and explorer interfaces

This is a **hard-fork-level protocol redesign**. It is not required for the v1 Account-as-Actor model, but it defines the long-term protocol direction once the application-level actor system proves its value.

This document is intentionally written at a level where an engineering agent such as Claude Code can implement the system module by module, assuming the v1 architecture already exists.

---

# 1. Purpose

## 1.1 Why a Second Volume Exists

The first yellow paper established an architecture in which every existing on-chain Account is treated as an Actor. That design provides strong practical benefits but leaves one major limitation intact:

> the base protocol still treats one Account as the smallest execution unit.

As a result:

- one Account still has one serial execution stream
- all logic inside one Account still shares one account state object
- actor roles remain architectural conventions rather than protocol-native objects
- proofs, queues, and validation remain account-centric

This second volume exists to describe the next step:

> how to make **Actors** the protocol-native execution units while preserving compatibility with the actor-oriented application architecture already built in v1.

## 1.2 Main Goal

The goal of this redesign is:

> **to transform Account from a protocol execution object into a protocol container, and to make Actor the new minimum execution unit.**

## 1.3 Main Benefit

This redesign enables:

- protocol-native modular execution
- parallel execution across Actors inside one Account
- actor-local state and budget isolation
- actor-level proofs and tooling
- a clean upgrade path from today’s Virtual Account and Wallet Actor architecture

---

# 2. Scope

## 2.1 In Scope

This document specifies:

1. account container redesign
2. actor descriptor format
3. actor-local state and logical time
4. hybrid balance model
5. actor-native transaction model
6. two-phase execution model
7. actor-aware collator flow
8. actor-aware validator replay
9. actor-aware OutMsgQueue key
10. actor-level proof path
11. lite-client / SDK / emulator changes
12. migration from v1 Account-as-Actor architecture

## 2.2 Out of Scope

This document does not fully specify:

1. final token economics changes
2. cross-chain interoperability
3. a new high-level programming language beyond required runtime hooks
4. actor-native privacy protocol design
5. final explorer UI implementation
6. consensus replacement

---

# 3. Design Goals

## 3.1 Primary Goals

The protocol redesign MUST:

1. make Actor the minimum execution unit
2. preserve deterministic validator replay
3. allow parallel Phase 1 execution across different actors
4. isolate actor-local state from account-global state
5. keep message-driven asynchronous semantics
6. support a migration path from v1 contracts and user-facing abstractions
7. preserve backward compatibility where practical during transition

## 3.2 Secondary Goals

The redesign SHOULD:

1. minimize semantic mismatch with the v1 Account-as-Actor architecture
2. make Wallet/Registry/Treasury actor sets portable into native actor containers
3. avoid unnecessary protocol churn beyond what actor-native execution requires
4. keep client-side addressing understandable

## 3.3 Non-Goals

The redesign does NOT attempt to:

1. eliminate all account-level metadata
2. make all actor interactions synchronous
3. preserve exact legacy transaction formatting in all tools
4. avoid hard fork coordination costs

---

# 4. Terminology

## 4.1 Account Container

A top-level protocol object identified by the existing account address. After the redesign, it is no longer the minimum execution unit.

It contains:

- account-level metadata
- shared balance
- actor dictionary
- optional shared code or code registry reference
- migration compatibility data

## 4.2 Actor

A protocol-native execution object inside an Account Container.

Each Actor has:

- actor_id
- actor-local state
- actor-local budget
- actor-local logical time
- mailbox / message targetability
- behavior binding

## 4.3 ActorAddress

A protocol address that identifies one actor inside one account container.

Suggested format:

```text
ActorAddress = workchain : account_id : actor_id
```

## 4.4 Shared Balance

The account-level balance pool used for:

- storage fees
- legacy inbound value staging
- inter-actor balance movements
- shared account solvency

## 4.5 Actor Budget

The actor-local working balance used in execution for:

- gas
- outbound value
- actor-local spending operations

## 4.6 Phase 1

Parallel speculative actor-local execution.

## 4.7 Phase 2

Deterministic sequential merge and finalization.

---

# 5. Baseline Assumption from Volume I

This redesign assumes that the v1 architecture already exists and is deployed.

That means the system already has:

- a Primary Wallet Actor concept
- Treasury / Recovery / Policy role separation
- actor registry semantics
- actor-oriented token system patterns
- Virtual Account UX abstractions
- developer familiarity with actor-oriented contract design

The purpose of this document is not to redefine those concepts, but to make them **protocol-native**.

In other words:

- in v1, Wallet / Treasury / Recovery are separate Accounts interpreted as Actors
- in v2, Wallet / Treasury / Recovery can become separate protocol Actors inside one Account Container

---

# 6. Architectural Transition

## 6.1 Before Redesign

```text
Virtual Account
 ├─ Primary Wallet Actor    (= Account A)
 ├─ Treasury Actor          (= Account B)
 ├─ Recovery Actor          (= Account C)
 ├─ Policy Actor            (= Account D)
 └─ Token / App Actors      (= separate Accounts)
```

## 6.2 After Redesign

```text
Account Container
 ├─ shared_balance
 ├─ actor_registry
 ├─ Wallet Actor
 ├─ Treasury Actor
 ├─ Recovery Actor
 ├─ Policy Actor
 ├─ Token Actor(s)
 └─ App Actor(s)
```

## 6.3 Key Semantic Shift

Before redesign:

- the base protocol executes Accounts

After redesign:

- the base protocol executes Actors
- the Account is a namespace/container and merge boundary

---

# 7. Protocol Object Model

## 7.1 Account Container State

Each Account Container MUST store:

- `last_trans_lt`
- `shared_balance`
- `actors_root`
- `account_flags`
- `shared_metadata`
- compatibility fields needed during migration

Suggested conceptual layout:

```text
AccountContainer
 ├─ last_trans_lt:uint64
 ├─ shared_balance:CurrencyCollection
 ├─ actors:HashmapE(actor_id -> ActorDescriptor)
 ├─ account_flags:uint32
 └─ shared_state:Cell / metadata
```

## 7.2 Actor Descriptor

Each ActorDescriptor MUST contain:

- actor-local state root
- actor-local budget
- actor-local logical time
- behavior binding
- actor flags

Suggested conceptual layout:

```text
ActorDescriptor
 ├─ state_root:HashmapE / Cell
 ├─ budget:CurrencyCollection
 ├─ actor_lt:uint64
 ├─ behavior_ref:Cell / code_ref / code_hash
 └─ actor_flags:uint32
```

## 7.3 Behavior Binding

The redesign MUST support one of the following behavior binding approaches:

### Option A: Shared Account Code + actor-local dispatch
One shared code object for all actors in the account container.

### Option B: Actor-local behavior reference
Each actor stores its own `behavior_ref`.

### Option C: Behavior registry
Account container references a registry of behavior definitions.

### Recommended v2 Design
Use **Actor-local behavior reference** or **behavior registry**, not shared global account code as the only model.

Reason:

- more faithful actor identity
- cleaner modularity
- smoother migration from the v1 multi-account actor system

---

# 8. Addressing Model

## 8.1 Account Address

The legacy account address remains the top-level container identity.

## 8.2 Actor Address

A new actor-level address MUST be introduced.

Suggested abstract format:

```text
ActorAddress = { workchain, account_id, actor_id }
```

## 8.3 actor_id Rules

### Requirements

The actor_id MUST:

1. be globally stable within the account container
2. be unambiguous
3. be available in transaction records, proofs, queue keys, and client APIs
4. be fixed-width

### Recommended Size

- `bits256`

### Recommended Derivation

```text
actor_id = sha256(account_address || discriminator)
```

This MUST be deterministic for predictable actor creation and external tooling.

---

# 9. Execution Model

## 9.1 Core Principle

The protocol must stop treating the account as the minimum state machine.

Instead:

- the account container groups related actors
- each actor processes one message at a time
- actors inside one account may execute in parallel in Phase 1
- shared effects are resolved in Phase 2

## 9.2 Actor-Local Execution Rules

During actor execution, the VM MUST be given access to:

- actor-local state
- actor-local budget
- actor-local logical time
- actor id
- inbound message
- account container identity

The VM MUST NOT directly mutate:

- shared_balance
- account-global logical time
- account-global transaction hash
- block-level queue state
- block-level statistics

## 9.3 Seriality Rule

Each Actor remains internally serial.

That means:

- one Actor cannot process two messages simultaneously
- actor-local ordering remains strict
- parallelism exists only across different actors

## 9.4 Parallelism Rule

Different actors in the same account container MAY execute in parallel in Phase 1, provided that they only mutate actor-local tentative state.

---

# 10. Hybrid Balance Model

## 10.1 Purpose

The redesign MUST prevent shared-balance contention during parallel execution.

## 10.2 Components

### Shared Balance
Used for:

- storage fees
- legacy account-targeted value
- inter-actor movements
- account solvency

### Actor Budget
Used for:

- actor gas
- actor outbound value
- actor-local spending

## 10.3 Rules

### Rule 1
Gas MUST be deducted from actor budget during Phase 1 tentatively.

### Rule 2
Outbound value MUST be deducted from actor budget during Phase 1 tentatively.

### Rule 3
Storage fees MUST be charged against shared_balance in Phase 2.

### Rule 4
Actor-to-shared or shared-to-actor balance transfer MUST be deferred until Phase 2.

---

# 11. Inbound Value Routing

## 11.1 Actor-Targeted Message

If an inbound message explicitly targets an actor_id, attached value MUST be credited tentatively to that actor budget.

## 11.2 Legacy Account-Targeted Message

If an inbound message targets only the account container without actor_id, attached value MUST be credited to shared_balance.

## 11.3 Compatibility Goal

This routing model allows legacy senders to continue sending to the account container while actor-native callers may target specific actors.

---

# 12. Two-Phase Execution Model

## 12.1 Why Two Phases Are Required

If multiple actors in one account execute in parallel and share account-global fields, immediate commit would create nondeterministic state races.

Therefore execution MUST be split into:

- actor-local speculative execution
- deterministic merge and commit

## 12.2 Phase 1 Responsibilities

Phase 1 MUST produce tentative results only.

Each tentative result MUST contain at least:

- actor_id
- tentative actor_lt
- tentative post-state
- tentative post-budget
- balance transfer intents
- outbound message list
- execution status
- gas usage
- actor-local receipts

## 12.3 Phase 1 Forbidden Effects

Phase 1 MUST NOT commit:

- shared_balance changes
- account-global lt
- canonical transaction hash
- block-level descriptors
- canonical queue insertion

## 12.4 Phase 2 Responsibilities

Phase 2 MUST:

1. sort speculative results deterministically
2. apply prefix commit rules
3. apply balance transfer intents
4. charge shared_balance storage fees
5. assign final account-global lt
6. materialize outbound messages
7. commit actor snapshots
8. update block-level state

---

# 13. Deterministic Merge Rules

## 13.1 Sorting Rule

Speculative results MUST be sorted by:

1. `actor_id ASC`
2. `actor_lt ASC`
3. deterministic tertiary key if required by implementation

## 13.2 Prefix Commit Rule

For a given actor, only a contiguous prefix of speculative results may be committed.

If one speculative transaction for actor X is rejected in Phase 2, all later speculative results for actor X in the same block MUST also be rejected.

## 13.3 Atomic Rollback Rule

If a speculative result is rejected, all its Phase 1 effects MUST be discarded:

- tentative state
- tentative budget
- tentative outgoing messages
- tentative balance requests
- tentative actor_lt advancement

---

# 14. Actor Logical Time Model

## 14.1 actor_lt

Each Actor MUST maintain its own monotonic `actor_lt`.

## 14.2 account-global lt

The Account Container MUST maintain account-global `last_trans_lt` for canonical transaction ordering and compatibility with external observers.

## 14.3 Relationship

- `actor_lt` is a local sequencing tool
- `last_trans_lt` is the canonical account-container transaction ordering value

## 14.4 No-Gap Recommendation

Rejected speculative actor results SHOULD NOT consume canonical actor_lt values.

---

# 15. Same-Block Message Visibility

## 15.1 Default Rule

Messages newly emitted by actors during block `N` MUST NOT be executed by other actors in the same block `N`.

They become executable in block `N+1`.

## 15.2 Reason

This preserves:

- deterministic merge
- clean block boundaries
- no same-block cyclic dependencies
- simpler validator replay

## 15.3 Future Extension

Same-block actor-to-actor execution MAY be introduced later, but MUST be specified separately with explicit scheduling rules.

---

# 16. VM and Opcode Model

## 16.1 Required New Runtime Concepts

The VM MUST gain access to:

- actor-local state root
- actor-local budget
- actor id
- actor-local logical time

## 16.2 Recommended New Instructions

At minimum, the redesign SHOULD define the following actor-oriented instructions:

### State
- `STATEGET`
- `STATESET`
- `STATEDEL`

### Messaging
- `ACTORSEND`
- later optionally `ACTORSENDX`

### Budget
- `BUDGETGET`
- `ACTORCLAIM`
- `ACTORRELEASE`

## 16.3 Execution Semantics

### STATEGET / STATESET / STATEDEL
Operate only on current actor-local state.

### ACTORSEND
Initial version SHOULD target only actors inside the same account container.

### BUDGETGET
Returns current actor budget.

### ACTORCLAIM / ACTORRELEASE
Record deferred balance intents. They MUST NOT synchronously move shared_balance in Phase 1.

---

# 17. VM Context Compatibility Matrix

This section MUST be implemented as a formal engineering table before coding is finalized.

## 17.1 Required Categories

For every relevant getter/opcode/runtime field, define:

- legacy behavior
- actor-mode phase-1 behavior
- actor-mode phase-2 canonical behavior
- whether value is actor-local, zeroed, placeholder, or trap-only

## 17.2 High-Risk Fields

The following MUST be explicitly handled:

- current transaction hash
- account-global lt
- shared balance
- outbound message envelope lt
- current actor_lt
- current actor budget
- sender identity
- block timestamp

---

# 18. Transaction Model

## 18.1 Need for New Transaction Record Semantics

The redesign MUST introduce actor-aware transaction records.

Each canonical actor transaction SHOULD include:

- account address
- actor_id
- actor_lt
- final account-global lt
- canonical tx hash
- actor-local status
- actor-local gas usage
- actor-local state root delta reference
- balance request summary
- outbound message references

## 18.2 Tentative vs Canonical Artifacts

The implementation MUST clearly distinguish:

- tentative Phase 1 results
- canonical Phase 2 transaction records

These MUST NOT be conflated in data structures.

---

# 19. Collator Redesign

## 19.1 Core Requirement

The collator MUST support:

- legacy serial transaction handling
- actor-mode speculative execution collection
- per-account merge and commit
- deferred outbound materialization

## 19.2 Required New Collator Components

The collator implementation SHOULD include:

- `pending_actor_results`
- per-actor logical time counters
- prefix-valid tracking
- actor-mode message admission logic
- phase-2 merge runner

## 19.3 Hybrid Handling

During migration, the collator MUST support both:

- legacy accounts
- actor-mode accounts

---

# 20. Validator Redesign

## 20.1 Core Requirement

Validators MUST be able to replay:

- actor-mode Phase 1 execution
- actor-mode Phase 2 merge
- actor-native queue generation
- canonical transaction construction

## 20.2 Validation Rules

Validators MUST verify:

1. actor_lt monotonicity per actor
2. deterministic merge ordering
3. prefix commit correctness
4. balance transfer correctness
5. shared_balance solvency rules
6. same-block visibility rules
7. canonical transaction outputs

---

# 21. Queue and Routing Redesign

## 21.1 Why Queue Redesign Is Required

If messages may target actors inside an account, queue keys and routing identity must carry actor-level information.

## 21.2 New Queue Key

Recommended key structure:

```text
workchain(32) | shard_prefix(64) | actor_id(256) | msg_hash(256)
```

## 21.3 Compatibility Rule

For legacy non-actor messages, actor_id MAY be zero-filled during transition.

---

# 22. Merkle Proof Redesign

## 22.1 New Proof Path

The proof system SHOULD support:

```text
block -> shard -> account container -> actor dictionary -> actor descriptor -> actor state -> key
```

## 22.2 Lite-Client Impact

Clients MUST be able to verify:

- actor existence
- actor-local state
- actor-local transaction references
- actor-local proofs

---

# 23. Client / SDK / Explorer Changes

## 23.1 Lite-Client

Must support:

- actor address parsing
- actor list query
- actor state query
- actor proof query

## 23.2 SDK

Must support:

- ActorAddress object model
- actor-aware transaction parsing
- actor-aware emulation
- actor-aware registry resolution

## 23.3 Explorer

Must display:

- account containers
- contained actors
- actor-local transaction streams
- actor-local budgets if available
- actor-native routing events

---

# 24. Migration Strategy from Volume I

## 24.1 Migration Goal

The redesign must preserve the usefulness of the v1 actor-oriented contract architecture.

## 24.2 Transition Mapping

### v1
- Wallet Actor = independent account
- Treasury Actor = independent account
- Recovery Actor = independent account

### v2
- Wallet Actor = actor inside container
- Treasury Actor = actor inside same container
- Recovery Actor = actor inside same container

## 24.3 Migration Options

### Option A: New Accounts Only
Only newly created accounts use actor-mode.

### Option B: Opt-In Migration
Existing v1 actor sets may migrate into actor containers via explicit migration procedures.

### Option C: Full Network Migration
All accounts eventually move to actor-mode.

### Recommended Initial Strategy
Use **New Accounts Only** or **Opt-In Migration** first.

## 24.4 Required Migration Data

Migration tools SHOULD preserve:

- actor role mapping
- owner/recovery/policy semantics
- treasury balances
- actor-local code/state references
- user-facing address mapping

---

# 25. Required Modules

The following are mandatory implementation modules for protocol-level redesign.

## 25.1 Protocol Schema Module
- account container schema
- actor descriptor schema
- actor-native transaction schema
- queue key width changes

## 25.2 VM Module
- actor state register support
- actor budget support
- actor id support
- new actor-native instructions

## 25.3 Execution Module
- Phase 1 actor execution
- Phase 2 merge engine
- tentative/canonical artifact split

## 25.4 Collator Module
- actor-mode collection
- merge
- deferred message handling

## 25.5 Validator Module
- actor-mode replay
- actor-aware checks
- merge verification

## 25.6 Queue Module
- actor-aware key generation
- queue merge logic

## 25.7 Proof Module
- actor proof generation
- actor proof verification

## 25.8 Client Module
- actor-aware lite-client
- actor-aware SDK
- actor-aware emulator

## 25.9 Migration Module
- account-to-container conversion tooling
- opt-in migration logic
- compatibility handling

---

# 26. Deferrable Modules

The following are useful but may be postponed until the core protocol executes correctly.

## 26.1 Built-In Standard Actor Library
- token actors
- governance actors
- AMM actors
- escrow actors

## 26.2 High-Level Compiler Support
- actor-native language sugar
- code generation templates
- actor schema generation

## 26.3 Advanced Same-Block Scheduling
- same-block actor-to-actor execution
- topological scheduling

## 26.4 Advanced Actor Address UX
- short forms
- alias resolution
- wallet display rules

---

# 27. Explicit Boundaries

This redesign explicitly does NOT promise, in its first implementable version:

1. same-block cyclic actor execution
2. synchronous actor call semantics
3. automatic full legacy compatibility in all clients
4. zero migration cost
5. zero performance overhead in initial versions

---

# 28. Security Model

## 28.1 New Risk Classes

The redesign introduces new consensus-sensitive risks:

- phase boundary leakage
- nondeterministic merge
- actor-level proof mismatch
- queue key mismatch
- storage fee attribution ambiguity
- merge order divergence

## 28.2 Required Safety Invariants

The implementation MUST preserve:

1. actor-local seriality
2. deterministic merge order
3. no Phase 1 shared writes
4. no same-block actor re-entry in v2 baseline
5. canonical transaction construction only after Phase 2
6. validator replay equivalence with collator execution

---

# 29. Recommended Repository Work Breakdown

A practical protocol-engineering work tree could look like:

```text
/protocol
  actor-volume-2.md
  tlb/
    account_container.tlb
    actor_descriptor.tlb
    actor_transaction.tlb
    actor_queue.tlb

/vm
  actor_ops.cpp
  actor_ops.h
  vm_actor_context.cpp

/execution
  actor_phase1.cpp
  actor_phase2_merge.cpp
  actor_tx_types.h

/collator
  actor_collator.cpp
  actor_collator.h

/validator
  actor_validate.cpp
  actor_validate.h

/proofs
  actor_proof.cpp
  actor_proof.h

/client
  actor_lite_api.tl
  actor_sdk_types.ts
  actor_emulator.cpp

/migration
  actor_migration_spec.md
  actor_migration_tool.cpp

/tests
  phase1_unit_tests.cpp
  phase2_merge_tests.cpp
  queue_key_tests.cpp
  actor_proof_tests.cpp
  actor_validator_replay_tests.cpp
  migration_tests.cpp
```

---

# 30. Claude-Code-Oriented Implementation Guidance

## 30.1 Recommended Implementation Order

### Step 1
Freeze protocol schema and actor transaction model.

### Step 2
Implement VM actor context and new instructions.

### Step 3
Implement tentative actor execution artifacts.

### Step 4
Implement Phase 2 merge engine.

### Step 5
Integrate collator actor-mode flow.

### Step 6
Integrate validator replay.

### Step 7
Integrate queue and proof changes.

### Step 8
Integrate lite-client / SDK / emulator support.

### Step 9
Implement migration and compatibility tooling.

## 30.2 Coding Rules

Claude Code SHOULD:

1. separate tentative and canonical structures in code
2. write deterministic sort logic explicitly
3. never infer protocol ordering from container iteration
4. implement validator replay as a first-class module, not as an afterthought
5. add negative tests for same-block visibility violations
6. add golden serialization tests before integration work
7. preserve legacy paths until actor-mode is clearly isolated

## 30.3 Required Deliverables Per Module

For each protocol module, Claude Code SHOULD produce:

1. source code
2. schema changes if applicable
3. tests
4. migration notes
5. validator replay notes
6. short implementation spec markdown

---

# 31. Roadmap

## Phase 0 — Spec Freeze
Deliverables:

- finalize Volume II specification
- freeze schema deltas
- freeze actor address rules
- freeze merge ordering rules
- freeze VM compatibility matrix

## Phase 1 — Runtime Foundations
Deliverables:

- actor descriptor schema
- account container schema
- VM actor context
- new actor-native opcodes

## Phase 2 — Execution Engine
Deliverables:

- Phase 1 tentative execution
- Phase 2 merge engine
- prefix commit
- rollback logic
- actor logical time handling

## Phase 3 — Validator and Collator
Deliverables:

- collator actor-mode flow
- validator replay
- same-block visibility enforcement
- actor-mode transaction construction

## Phase 4 — Queue, Proof, Client
Deliverables:

- actor-aware queue key
- actor proof path
- lite-client actor queries
- SDK / emulator actor support

## Phase 5 — Migration
Deliverables:

- opt-in migration path
- migration tools
- compatibility documentation
- testnet rollout procedures

## Phase 6 — Ecosystem Upgrade
Deliverables:

- explorer support
- actor-native standard libraries
- advanced tooling
- developer documentation

---

# 32. What Can Be Reused from Volume I

The following concepts from the Account-as-Actor yellow paper remain valid and SHOULD be reused:

- Virtual Account abstraction
- Wallet / Treasury / Recovery / Policy roles
- Session semantics
- Actor-oriented token patterns
- actor registry semantics
- user-facing one-account UX

Only the **protocol placement** of those concepts changes.

---

# 33. Final Summary

Volume I proved that actor-oriented architecture can be built on top of the existing protocol by interpreting each Account as an Actor.

Volume II defines the next step:

> **make Actors protocol-native execution objects, and make Accounts protocol-native containers.**

This transition is powerful but expensive. It requires:

- schema changes
- VM changes
- execution changes
- collator changes
- validator changes
- queue and proof changes
- client changes
- migration tooling

For that reason, this redesign should only be pursued after the Volume I architecture is already implemented and validated in practice.

---

# Appendix A — Minimum Engineering Freeze Checklist

Before coding begins, the following MUST be frozen:

1. ActorDescriptor schema
2. AccountContainer schema
3. ActorAddress format
4. actor_lt rules
5. merge ordering rules
6. same-block visibility rules
7. VM context compatibility matrix
8. tentative vs canonical transaction structures
9. queue key layout
10. proof path format

# Appendix B — Minimum Acceptance Test Scenarios

1. single actor legacy-equivalent execution
2. two actors in one container executing in parallel
3. one actor rejected causing same-actor prefix rejection
4. shared_balance overdraw rejection
5. no same-block actor-send consumption
6. actor-aware queue key round-trip
7. actor proof verification
8. validator replay equals collator result
9. migration from v1 actor set to one actor container
