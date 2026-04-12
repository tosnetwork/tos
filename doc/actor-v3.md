# TOS Actor Architecture — Unified Specification

**Status:** Draft v3.0
**Audience:** Protocol designers, smart contract engineers, wallet/SDK engineers, validator implementers, VM engineers

---

## Abstract

This document is the unified specification for the TOS Actor architecture. It defines a two-phase rollout:

* **Phase V1 — Account-as-Actor:** every existing on-chain Account is treated as a first-class Actor. A human-facing Virtual Account is constructed as a coordinated set of Actors. No base protocol changes are required.

* **Phase V2 — Protocol-Native Actors:** the base protocol is redesigned so that one Account becomes a container holding multiple protocol-native Actors, each with isolated state, independent budget, and independent logical time. This is a hard-fork-level change.

V1 delivers the practical benefits of the Actor Model today — isolation, modularity, message-driven design, parallelism across actors, and better wallet architecture — without the cost and risk of protocol redesign. V2 builds on V1 once the actor-oriented patterns are proven in production, making Actors the protocol-native execution unit and enabling intra-account parallel execution.

---

# Part I — Motivation and Design Philosophy

## 1. Problem Statement

Traditional account-based smart contract systems overload a single account with too many responsibilities: user identity, permissions, treasury, spending policy, session keys, recovery logic, token balances, and application state. This creates monolithic account logic, weak modularity, poor upgradability, insufficient fault isolation, and ambiguous user abstraction.

## 2. Why the Actor Model

The Actor Model provides a simpler and more composable foundation:

* each Actor owns its own state
* each Actor processes messages independently
* actors interact only via asynchronous messages
* each Actor is internally serial
* concurrency exists naturally across actors

A TON-like execution environment already provides most of the required runtime properties: every Account has its own address, its own state, is triggered by messages, processes messages serially, and communicates asynchronously. The C++ node already uses an actor-based runtime through `td::actor`.

## 3. Two-Phase Rollout Strategy

Instead of attempting a single massive protocol redesign, TOS adopts a phased approach:

| | V1: Account-as-Actor | V2: Protocol-Native Actors |
|---|---|---|
| Core idea | Account = Actor | Account = Container, Actor = execution unit |
| Protocol changes | None | Hard fork |
| Parallelism | Natural cross-Account (already exists) | Intra-Account across Actors |
| Balance model | Each Account has own balance; Treasury Actor coordinates | Hybrid: per-actor budget + account shared_balance |
| Implementation layer | Smart contracts + SDK | Protocol: validator, collator, block format, proofs |
| Timeline | Immediate | After V1 is validated in production |

**V1 is the correct tradeoff for today.** V2 defines the long-term protocol direction.

## 4. Current Base-Layer Architecture

One account = one execution unit:

```
Account (unique address)
 +-- code: Cell         <- one contract
 +-- data: Cell         <- one monolithic state tree
 +-- balance: Coins
 +-- last_trans_lt      <- one timeline -> forced serialization
```

All transactions for the same account are serialized because they share the same data Cell, balance, logical time, and storage state.

Key code locations:

| Component | File | Lines |
|-----------|------|-------|
| Account struct | `crypto/block/transaction.h` | 263-345 |
| Transaction execution | `validator/impl/collator.cpp` | 3466 (`impl_create_ordinary_transaction`) |
| Collator state management | `validator/impl/collator.cpp` | 3395, 3743 |
| Validation | `validator/impl/validate-query.cpp` | 7674 lines |
| OutMsgQueue key | `crypto/block/output-queue-merger.h` | 30 |
| TL-B schema | `crypto/block/block.tlb` | 270-292 |
| TVM instructions | `crypto/vm/tosops.cpp` | 2430+ lines |

---

# Part II — V1: Account-as-Actor Architecture

## 5. V1 Design Goals

### 5.1 Primary Goals

1. Treat every on-chain Account as an Actor
2. Provide a Virtual Account abstraction for one human user
3. Split wallet logic into specialized Actors
4. Allow funds to be centralized and redistributed through a Treasury Actor
5. Support session authorization and recovery mechanisms
6. Support actor-oriented token/application patterns
7. Require no base protocol changes
8. Be implementable using normal smart contracts, wallet tooling, and SDK code

### 5.2 Explicit Non-Goals for V1

V1 does **not** attempt to provide:

1. Multiple Actors inside one Account
2. Actor-native protocol addresses distinct from Account addresses
3. Actor-aware validator execution
4. Actor-aware OutMsgQueue keys
5. Actor-level Merkle proof paths
6. Two-phase execution at the protocol level
7. Shared account-internal execution budgets enforced by consensus

## 6. V1 System Model

### 6.1 Core Principle

> **The protocol executes Accounts. The TOS architecture interprets them as Actors.**

Every Actor in TOS V1 obeys:

1. Single owner of local state
2. Single inbox execution stream
3. All interactions via asynchronous messages
4. No implicit shared mutable memory
5. No direct synchronous multi-actor state mutation

### 6.2 Virtual Account

A Virtual Account is a human-facing logical account composed of multiple Actors. It is not a base-layer execution unit — it is a coordinated set of Actors under one user's control and presentation layer.

```
Virtual Account (logical)
 +-- Primary Wallet Actor     (= Account A)
 +-- Treasury Actor           (= Account B)
 +-- Recovery Actor           (= Account C)
 +-- Policy Actor             (= Account D)
 +-- Privacy Actor            (= Account E, optional)
 +-- Session authorization set
 +-- Token Actors
 +-- Application Actors
```

Each item above is a separate on-chain Account, and therefore a separate Actor.

### 6.3 Funds Model

There is no protocol-level shared balance pool in V1. Instead:

* each Actor has its own native account balance
* the Treasury Actor acts as the coordination center for funds
* budgets are allocated by explicit treasury messages
* budget return, accounting, and enforcement are implemented at the contract layer

This means V1 uses **logical budget orchestration**, not protocol-native shared balance settlement.

## 7. Primary Wallet Actor Specification

### 7.1 Purpose

The Primary Wallet Actor is the control hub of one Virtual Account. It is the user-facing entry Actor and the default externally visible wallet address.

### 7.2 Responsibilities

1. Owner-signed request execution
2. Replay protection
3. Actor registry maintenance
4. Treasury routing
5. Policy integration
6. Recovery integration
7. Session authorization
8. Lock / recovery / frozen modes

### 7.3 Minimal State Layout

```
wallet_id:uint32
seqno:uint32
owner_pubkey:uint256
pending_owner_pubkey:Maybe<uint256>
mode:uint8                          // NORMAL=0, LOCKED=1, RECOVERY=2, FROZEN=3
flags:uint32
registry_root:Cell
session_root:Cell
guardian_root:Cell
policy_actor:Maybe<Address>
treasury_actor:Maybe<Address>
recovery_actor:Maybe<Address>
```

### 7.4 External Interface

**SignedRequest** — owner-authorized action bundle:

```
op:uint32  wallet_id:uint32  seqno:uint32  valid_until:uint32
request_id:uint64  actions:^Cell  signature:bits512
```

**ExtensionRequest** — message from a registered internal Actor:

```
op:uint32  role_id:uint16  actions:^Cell
```

**RecoveryRequest** — recovery-specific control path:

```
op:uint32  subop:uint8  payload:^Cell
```

**SessionRequest** — restricted, lower-risk delegated action:

```
op:uint32  session_pubkey:uint256  session_nonce:uint32
valid_until:uint32  actions:^Cell  signature:bits512
```

### 7.5 Required Actions

```
ACT_SEND_MSG=0x01  ACT_REGISTER_ACTOR=0x02  ACT_UNREGISTER_ACTOR=0x03
ACT_SET_TREASURY=0x04  ACT_SET_POLICY=0x05  ACT_SET_RECOVERY=0x06
ACT_ADD_SESSION=0x07  ACT_REVOKE_SESSION=0x08  ACT_LOCK=0x09
ACT_UNLOCK=0x0A  ACT_FORWARD_TO_ACTOR=0x0B
ACT_PROPOSE_OWNER=0x0C  ACT_COMMIT_OWNER=0x0D
```

## 8. Treasury Actor Specification

### 8.1 Purpose

The Treasury Actor is the financial coordination center of a Virtual Account. It replaces the need for protocol-native shared balance in V1.

### 8.2 Core Interfaces

**AllocateBudget:**

```
op:uint32  target_actor:Address  amount:Coins  budget_id:uint64  memo:Maybe<Cell>
```

**ReturnBudget:**

```
op:uint32  source_actor:Address  amount:Coins  budget_id:uint64  memo:Maybe<Cell>
```

**TreasuryTransfer** — treasury-initiated payment or routing.

The Treasury Actor should optionally consult the Policy Actor before executing sensitive transfers.

## 9. Recovery Actor Specification

### 9.1 Purpose

The Recovery Actor handles emergency governance and owner recovery flows.

### 9.2 Core Interfaces

* **ProposeOwnerChange** — `new_owner_pubkey:uint256  recovery_id:uint64`
* **FreezeWallet** — `reason_code:uint16`
* **EnterRecoveryMode** — `recovery_id:uint64`
* **CommitRecovery** — `recovery_id:uint64`

### 9.3 Safety Requirements

Recommended recovery capability set: freeze, propose owner change, revoke sessions, switch wallet mode. Not recommended as default: arbitrary treasury drain, arbitrary actor reconfiguration without timelock.

## 10. Policy Actor Specification

### 10.1 Purpose

The Policy Actor enforces account-level risk and spending policy: daily spend limits, destination whitelists, approval requirements, timelocks, emergency deny rules.

### 10.2 Core Interface

**EvaluateAction:**

```
op:uint32  request_type:uint16  request_id:uint64  origin_actor:Address
target_actor:Address  value:Coins  context:^Cell
```

**Response:** `allowed:bool  policy_code:uint16  extra_delay:uint32  memo:Maybe<Cell>`

## 11. Session Authorization

### 11.1 Session Fields

```
session_pubkey:uint256  expires_at:uint32  spend_limit:Coins
allowed_roles_mask:uint64  allowed_dest_hash:Maybe<uint256>
nonce:uint32  flags:uint32
```

### 11.2 Session Rules

Sessions must be: created by owner authority, revocable by owner and recovery authority, limited by time, scope, and replay-protected nonce. Sessions are for low-risk automation, app-level delegation, frequent small operations, and temporary device authorization — not full owner replacement.

## 12. Actor Registry

The Actor Registry maps semantic roles to concrete Actor addresses.

Required roles: `ROLE_PRIMARY=0`, `ROLE_TREASURY=1`, `ROLE_POLICY=2`, `ROLE_RECOVERY=3`, `ROLE_PRIVACY=4`.

Registry data model: `role_id:uint16 -> actor_address:Address`.

Operations: register, unregister, replace, lookup, enumerate.

## 13. Token-as-Actors

### 13.1 Architecture

```
Token System
 +-- TokenMasterActor       (metadata, total supply, wallet discovery, mint/burn authority)
 +-- TokenBalanceActor(owner) (one holder's balance, credit, transfer, local auth)
```

### 13.2 Transfer Model

1. User authorizes transfer via Primary Wallet Actor
2. Primary Wallet Actor routes to sender TokenBalanceActor
3. Sender TokenBalanceActor debits local balance
4. Sender TokenBalanceActor sends credit message to recipient TokenBalanceActor
5. Recipient TokenBalanceActor credits local balance

## 14. V1 Security Model

Every specialized Actor is a separate fault domain. Rules:

* Primary Wallet Actor: minimal, deterministic, strongly replay-protected
* Treasury Actor: no arbitrary budget requests without authentication and policy checks
* Recovery Actor: narrowly scoped, not overpowered by default
* Policy Actor: deterministic and side-effect predictable
* Sessions: time-bounded, nonce-bound, scope-bound

## 15. V1 Roadmap

| Phase | Deliverables |
|-------|-------------|
| Phase 0: Spec Freeze | Finalize interfaces, freeze op codes, action encodings, role IDs |
| Phase 1: Wallet Core | `wallet_v6.fc` MVP, owner-signed requests, seqno, registry, lock/recovery modes, TS client, tests |
| Phase 2: Treasury & Recovery | Treasury Actor, Recovery Actor, Policy Actor MVP, budget allocation flow, recovery flow, cross-actor integration tests |
| Phase 3: Session & SDK | Session authorization, Virtual Account SDK abstraction, actor registry helper, one-address UX wrapper |
| Phase 4: Token Actors | TokenMasterActor, TokenBalanceActor, deployment scripts, mint/transfer/burn flows |
| Phase 5: Hardening | Audits, policy edge cases, guardian enhancements, SDK stabilization, documentation |

### First Engineering Milestone

Complete when: deploy Primary Wallet -> deploy Treasury -> register in registry -> fund Treasury -> add session key -> owner transfer through treasury -> trigger recovery -> revoke session -> restore normal mode -> all integration tests pass.

---

# Part III — V2: Protocol-Native Actor Execution

## 16. V2 Purpose and Prerequisites

V1 proves that actor-oriented architecture can be built on top of the existing protocol. V2 defines the next step: **make Actors protocol-native execution objects, and make Accounts protocol-native containers.**

V2 assumes V1 is already deployed and validated. That means: Primary Wallet / Treasury / Recovery / Policy role separation already exists, actor registry semantics are established, developer familiarity with actor-oriented contract design is in place. V2 does not redefine those concepts — it makes them protocol-native.

### Architectural Transition

```
V1:                                    V2:
Virtual Account                        Account Container
 +-- Wallet Actor  (= Account A)        +-- shared_balance
 +-- Treasury Actor (= Account B)       +-- Wallet Actor
 +-- Recovery Actor (= Account C)       +-- Treasury Actor
 +-- Policy Actor   (= Account D)       +-- Recovery Actor
 +-- Token / App Actors (= separate)    +-- Policy Actor
                                         +-- Token / App Actors
```

V2 is a **hard-fork-level protocol redesign**. It requires changes to: block format, account serialization, transaction execution, validation logic, message routing, Merkle proofs, and client tooling. The Cell/BOC encoding format itself is unchanged — only the semantic structure stored in Cells changes.

## 17. Account Container Model

### 17.1 Account Container State

```
AccountContainer
 +-- last_trans_lt:uint64
 +-- shared_balance:CurrencyCollection
 +-- actors:HashmapE(actor_id -> ActorDescriptor)
 +-- account_flags:uint32
 +-- shared_state:Cell / metadata
```

### 17.2 Actor Descriptor

```
ActorDescriptor
 +-- state_root:HashmapE / Cell      <- actor-local KV state
 +-- budget:CurrencyCollection       <- actor-local working balance
 +-- actor_lt:uint64                 <- actor-local logical time
 +-- behavior_ref:Cell / code_ref    <- actor-local behavior binding
 +-- actor_flags:uint32
```

Each Actor has its own `behavior_ref` rather than sharing a single global code Cell. This is more faithful to Actor identity, enables cleaner modularity, and smooths migration from V1 where each Actor is already an independent contract with its own code.

### 17.3 TL-B Schema

```tlb
actor_descriptor$_ state:(HashmapE 256 ^Cell)
    budget:CurrencyCollection actor_lt:uint64
    behavior_ref:^Cell actor_flags:uint32 = ActorDescriptor;

account_storage$_ last_trans_lt:uint64                      // legacy (tag=0)
    balance:CurrencyCollection state:AccountState
  = AccountStorage;

account_storage_actor$_ last_trans_lt:uint64                // actor-mode (tag=1)
    shared_balance:CurrencyCollection
    actors:(HashmapE 256 ^ActorDescriptor)
    account_flags:uint32
    state:AccountState
  = AccountStorage;
```

Legacy accounts use the existing `account_storage$_` tag. Actor-mode accounts use `account_storage_actor$_`. The parser branches on tag, ensuring backward compatibility.

### 17.4 Protocol Change Summary

| Component | Change Required |
|-----------|----------------|
| Account state layout | Add `actors` HashmapE (state + budget + actor_lt + behavior_ref per actor), replace `balance` with `shared_balance` |
| Account serialization (TL-B) | New schema for actor sub-structure |
| Block format | ActorAddress in transaction records |
| OutMsgQueue key | Extended from 352 to 608 bits with actor_id |
| Transaction execution | Actor-level state isolation, two-phase model |
| Validation logic | Actor-level proof and consistency checks |
| Merkle proofs | Extended proof path: block -> shard -> account -> **actor** -> key |
| lite-client / SDKs | Must understand ActorAddress and new proof format |
| Block explorers | Must display actor-level transactions |

What stays unchanged: Cell encoding, BOC format, Consensus (Catchain/Simplex), Network transport (ADNL/RLDP/DHT/QUIC), Sharding mechanism, Storage engine, td::actor runtime.

## 18. Addressing Model

### 18.1 ActorAddress

```
ActorAddress = { workchain : account_id : actor_id }
```

`actor_id` is a full 256-bit field. Recommended derivation:

```
actor_id = sha256(account_address || discriminator)
```

This is deterministic for predictable actor creation and external tooling.

### 18.2 ACTORSEND Scope

`ACTORSEND` targets only Actors within the **same account container**. The `actor_id` operand is sufficient because `workchain` and `account_id` are implicitly inherited from the executing account context. Cross-account Actor messaging requires the full `ActorAddress` and is deferred to a future `ACTORSENDX` instruction.

## 19. Hybrid Balance Model

### 19.1 Design Rationale

If two Actors under the same Account shared a single balance and executed in parallel, they would concurrently modify the shared balance, producing a non-deterministic result. A pure reservation model solves this but adds significant complexity. A fully per-actor balance eliminates contention but fragments capital and complicates storage fee attribution.

**Solution: hybrid balance model** — each Actor has its own `budget` for gas and value transfers, while the Account retains a `shared_balance` for storage fees, inbound value staging, and inter-actor fund movement.

```
Account Container
 +-- shared_balance: 2 TON          <- storage fees, inbound value, inter-actor pool
 +-- actor_0: { state, budget: 3 TON, actor_lt }
 +-- actor_1: { state, budget: 5 TON, actor_lt }
```

**Why this works for parallel execution:**

* Gas is deducted from the Actor's own `budget` -> no cross-actor contention
* Value attached to outbound messages is deducted from the Actor's `budget` -> no contention
* `shared_balance` is only mutated by `ACTORCLAIM` / `ACTORRELEASE` and storage fee deduction, all deferred to the sequential Phase 2
* The TVM compute phase (the expensive part) runs in Phase 1 with **zero shared writes**

### 19.2 Actor-Local vs Account-Global Fields

**Actor-local (fully parallel in Phase 1):**
* Actor state (HashmapE)
* Actor budget (gas deduction, value transfer)
* Actor logical time (`actor_lt`)
* TVM compute phase

**Account-global (sequential in Phase 2):**
* `shared_balance` (ACTORCLAIM / ACTORRELEASE commits, storage fees)
* `last_trans_lt` / `last_trans_hash`
* Outgoing message ordering and materialization
* Block-level statistics

### 19.3 Inbound Value Routing

When an external or internal message carrying value arrives at the Account:

1. If the message targets a specific `actor_id`, the value is credited directly to that Actor's `budget`.
2. If the message targets the Account without specifying an `actor_id` (legacy format), the value is credited to `shared_balance`.
3. An Actor can later pull funds from `shared_balance` via `ACTORCLAIM`.

This ensures backward compatibility: existing wallets sending to an Account address still work.

### 19.4 Storage Fee Attribution

Storage fees are charged at the **account level**, not per-actor:

* The total Cell tree size (including all Actor states) determines the storage fee.
* Storage fees are deducted from `shared_balance` during Phase 2.
* If `shared_balance` is insufficient, the Account enters the standard freeze/deletion path — all Actors are affected.
* Actors are expected to periodically `ACTORRELEASE` surplus budget back to `shared_balance`. The protocol may enforce a minimum `shared_balance` threshold.

## 20. Two-Phase Execution Model

### 20.1 Why Two Phases

If multiple actors in one account execute in parallel and share account-global fields, immediate commit would create nondeterministic state races. Therefore execution is split into actor-local speculative execution and deterministic merge.

### 20.2 Phase Boundary (Normative)

**Phase 1 (parallel, per-actor) produces tentative snapshots only:**
* Post-execution Actor state root (tentative, not yet committed)
* Compute-phase status: success, revert, exception code
* Gas deducted from Actor `budget` (tentative)
* Value transfers deducted from Actor `budget` (tentative)
* Outbound message list in Actor-local order (tentative, not yet materialized)
* Tentative `ACTORCLAIM` / `ACTORRELEASE` intents (recorded, not yet applied)

**Phase 1 must NOT touch:**
* `shared_balance` (mutated only in Phase 2)
* `last_trans_lt` / `last_trans_end_lt` / `last_trans_hash` (account-global)
* Account storage statistics
* Block-level InMsg / OutMsg descriptors
* Shard OutMsgQueue

**Phase 2 (sequential, single-threaded) finalizes:**
* Apply all `ACTORCLAIM` / `ACTORRELEASE` intents against `shared_balance` in deterministic order; reject any that would overdraw
* Deduct storage fees from `shared_balance`
* Assign final logical time and transaction hash (see 22)
* Commit the tentative Actor state / Actor budget snapshot only for transactions that survive Phase 2 validation
* Materialize outbound messages into block descriptors and queues
* Update block-level accumulators

No Phase-1 artifact is part of canonical state until Phase 2 accepts it.

### 20.3 Rollback Rule (Normative)

If Phase 2 rejects a speculative result for any reason, all of its Phase-1 outputs must be discarded atomically:

* Tentative Actor state changes are dropped
* Tentative Actor budget changes are dropped
* Tentative outbound messages are dropped
* Tentative claim/release intents are dropped
* Tentative `actor_lt` advancement is dropped (no gaps; see 22.3)

This is an all-or-nothing rule. There is no partial commit of a speculative result.

### 20.4 Prefix Commit Rule (Normative)

For any fixed `actor_id`, Phase 2 may commit only a **contiguous prefix** of that Actor's speculative results ordered by `actor_lt`.

```
actor_7 speculative results: [lt=11, lt=12, lt=13]
if lt=12 is rejected in Phase 2:
  - lt=11 may commit
  - lt=12 is rejected
  - lt=13 MUST also be rejected
```

Later speculative results for the same Actor depend on the tentative post-state produced by earlier ones. Rejecting a middle result invalidates all later same-Actor snapshots. The merge phase tracks a per-actor "prefix still valid" bit; once a transaction is rejected, all later results for the same `actor_id` in the current block are discarded automatically.

### 20.5 Same-Block Message Visibility (Normative)

Messages newly emitted by actors during block `N` are recorded in block `N` but become executable only from block `N+1`. No Actor may observe another Actor's newly emitted same-block message during its own Phase-1 execution.

This trades latency for determinism: no same-block cyclic dependencies, no merge-order-dependent visibility, clean block boundary.

Same-block actor-to-actor execution may be introduced as a future protocol extension with explicit topological scheduling rules.

## 21. VM Context Isolation (Normative)

Phase 1 executes the TVM compute phase speculatively. The VM must be presented with a restricted execution context so that results remain valid after Phase 2 assigns final account-global values.

### 21.1 Available to the VM in Phase 1

| Field | Value | Source |
|-------|-------|--------|
| Actor-local state | Actor's HashmapE | c6 register |
| Actor budget | Actor's own budget | `BUDGETGET` / `GETBALANCE` |
| Inbound message | Body, value, source address | Standard |
| Account address | `workchain:account_id` | c7[8] |
| Actor id | `actor_id` | c7[18] |
| Block reference | seqno, shard, workchain | Standard |
| Unix timestamp | Block candidate time | c7[3] |
| Actor-local lt | Tentative `actor_lt` | c7[5] (returns actor_lt, NOT account lt) |

### 21.2 NOT Available to the VM in Phase 1

| Field | Behavior | Reason |
|-------|----------|--------|
| Transaction hash | Returns 0 / sentinel / trap | Final hash depends on merge order |
| Account-level lt (`last_trans_lt`) | NOT returned | Assigned only in Phase 2 |
| `shared_balance` | NOT readable | Only mutated in Phase 2 |
| Outbound message envelope lt | Placeholder | Overwritten in Phase 2 |
| `last_trans_end_lt` / `last_trans_hash` | NOT returned | Account-global, Phase 2 only |

**Consequence:** Contracts must depend only on actor-local state, actor budget, and message content — not on account-global transaction metadata.

## 22. Actor Logical Time Model (Normative)

### 22.1 actor_lt

Each Actor maintains its own monotonic `actor_lt` counter, independently of the account-level `last_trans_lt`.

**Phase 1:** The collator reads the current `actor_lt` and increments it to produce a tentative value. This value is stable within Phase 1. If multiple messages target the same Actor in one block, they are serialized per-actor with distinct ascending `actor_lt` values. `actor_lt` is used as the secondary sort key for the deterministic merge: `ORDER BY (actor_id ASC, actor_lt ASC)`.

**Phase 2:** The merge phase iterates results in `(actor_id, actor_lt)` order. For each committed result, Phase 2 assigns a final account-level logical time from the account's global lt counter. The final account-level lt is strictly monotonically increasing across all committed transactions.

### 22.2 Relationship Between Timelines

```
actor_lt (per-actor, Phase 1)     account lt (global, Phase 2)
-----------------------------     ------------------------------
actor_0: 100, 101                 -> final lt: 5000, 5001
actor_1: 200                      -> final lt: 5002
actor_0: 102                      -> final lt: 5003
```

`actor_lt` provides stable per-actor ordering known before merge. Account-level lt provides global ordering for the block format and external observers. Both are monotonic within their scope; neither is derivable from the other.

### 22.3 No-Gap Rule for Rejected Transactions

A speculative transaction receives a tentative `actor_lt` in Phase 1. That value becomes canonical only if committed in Phase 2. If rejected, the tentative `actor_lt` is discarded. The persisted `actor_lt` advances only across committed transactions. No gaps.

## 23. TVM Opcodes

### 23.1 New Instructions

Using the 0xFB09-0xFB0F range (currently unoccupied). All gated behind `->require_version(N)` for the hard-fork version.

```
// State operations (operate on actor-local HashmapE via c6 register)
0xFB09  STATEGET      key_hash:uint256 -> value:slice
0xFB0A  STATESET      key_hash:uint256 value:slice -> ()
0xFB0B  STATEDEL      key_hash:uint256 -> bool

// Messaging
0xFB0C  ACTORSEND     actor_id:uint256 body:cell -> ()

// Balance operations
0xFB0D  BUDGETGET     -> amount:coins
0xFB0E  ACTORCLAIM    amount:coins -> request_id:uint64
0xFB0F  ACTORRELEASE  amount:coins -> request_id:uint64
```

### 23.2 Implementation Patterns

| Opcode | Pattern |
|--------|---------|
| STATEGET | `Dictionary(st->get_d(6), 256).lookup(key)` -> push slice |
| STATESET | `Dictionary(st->get_d(6), 256).set(key, value)` -> `set_d(6)` |
| STATEDEL | `Dictionary(st->get_d(6), 256).delete_key(key)` -> push bool |
| ACTORSEND | Build action cell -> chain to c5 (same pattern as SENDRAWMSG at `tosops.cpp:2010`) |
| BUDGETGET | `get_param(st, 18)` reads actor budget from c7 tuple |
| ACTORCLAIM | Build claim action cell -> chain to c5, push request_id |
| ACTORRELEASE | Build release action cell -> chain to c5, push request_id |

The c6 register is a new data register for actor state HashmapE root (alongside existing c4 for contract data, c5 for actions). STATEGET/STATESET/STATEDEL wrap `vm::Dictionary` from `crypto/vm/dict.h`.

### 23.3 ACTORCLAIM / ACTORRELEASE Semantics

These instructions do **not** synchronously move funds during Phase 1. They append a **balance-transfer intent** to the current Actor transaction:

* `ACTORCLAIM(amount)` records: "if committed, move `amount` from `shared_balance` to this Actor's `budget`"
* `ACTORRELEASE(amount)` records: "if committed, move `amount` from this Actor's `budget` to `shared_balance`"

The returned `request_id` is an opaque identifier for tracing/receipts only. It is **not** a success indicator. Success or failure is determined only in Phase 2. Contracts must treat claim/release as **deferred effects**, not synchronous conditionals.

### 23.4 New OutAction Variants

```tlb
action_actor_send#... actor_id:bits256 body:^Cell = OutAction;
action_actor_claim#... amount:Coins = OutAction;
action_actor_release#... amount:Coins = OutAction;
```

## 24. Collator Redesign

### 24.1 Core Flow Change

```
Current flow (serial):
  for each message:
    result = impl_create_ordinary_transaction(msg, account)
    update_block_state(result)

Proposed flow (parallel + merge):
  // Phase 1: parallel execution (per-actor, no shared writes)
  for each message (can be parallel across different actors):
    actor = account.actors[msg.actor_id]
    result[actor_id] = execute_actor_transaction(msg, actor)
    // gas and value applied only to a tentative actor snapshot

  // Phase 2: deterministic merge (single-threaded)
  sort results by (actor_id ASC, actor_lt ASC)
  for each result in deterministic order:
    // 1. Apply ACTORCLAIM/ACTORRELEASE against shared_balance
    for each claim_request in result.balance_requests:
      if !apply_balance_request(claim_request, account.shared_balance):
        reject_transaction(result); continue  // prefix invalidation
    // 2. Deduct storage fees from shared_balance
    apply_storage_fees(account)
    // 3. Commit tentative actor snapshot, assign final lt
    commit_actor_snapshot(result, account)
    assign_final_lt(result, account)
    materialize_outbound_messages(result, block)
    update_block_state(result)
```

### 24.2 Hybrid Handling

During migration, the collator must support both legacy accounts (serial execution) and actor-mode accounts (two-phase execution) in the same block.

## 25. Validator Redesign

Validators must be able to replay actor-mode Phase 1 execution and Phase 2 merge, producing identical results. They must verify:

1. `actor_lt` monotonicity per actor
2. Deterministic merge ordering
3. Prefix commit correctness
4. Balance transfer correctness against `shared_balance`
5. `shared_balance` solvency after all operations
6. Same-block visibility rules (no same-block actor message consumption)
7. Canonical transaction outputs match

## 26. OutMsgQueue Key Extension

```
Old: workchain(32) | shard_prefix(64) | msg_hash(256)                    = 352 bits
New: workchain(32) | shard_prefix(64) | actor_id(256) | msg_hash(256)    = 608 bits
```

Both `actor_id` and `msg_hash` are kept at full 256 bits. For non-actor messages, `actor_id` is zero-filled to preserve sort order compatibility. This changes the key length constant in `output-queue-merger.h:30` and affects all queue sorting, merging, and routing logic.

## 27. Merkle Proof Extension

Proof path extended from:

```
block -> shard -> account -> state -> key
```

to:

```
block -> shard -> account container -> actor dictionary -> actor descriptor -> state -> key
```

Lite-clients must be able to verify: actor existence, actor-local state, actor-local transaction references, and actor-local proofs.

## 28. Execution Paths

Two execution paths, sharing the same state interface (vm::Dictionary / HashmapE):

| Path | For | Performance | Safety |
|------|-----|-------------|--------|
| Native C++ | Built-in/system actors | Fastest | Trusted (ships with node) |
| TVM | User-deployed contracts | Medium | TVM sandbox |

## 29. V2 Risks

1. **Hard fork coordination** — requires simultaneous upgrade of all validators, lite-clients, SDKs, and explorers
2. **Two-phase execution correctness** — Phase 1/Phase 2 boundary must be correctly enforced; incorrect isolation breaks consensus
3. **Balance fragmentation** — per-actor budgets may lead to idle capital; need policies for minimum `shared_balance`
4. **Shared balance overdraw** — multiple Actors issuing `ACTORCLAIM` in the same block may collectively overdraw; Phase 2 must reject deterministically
5. **Prefix rejection cascades** — rejecting one speculative result forces rejection of later same-Actor results, reducing throughput in pathological cases
6. **Validation complexity** — validate-query.cpp (7674 lines) needs significant changes; actor-level proofs add new attack surface
7. **State migration** — existing accounts must be migrated; requires migration protocol
8. **Client compatibility** — all wallets, SDKs, and block explorers must upgrade

## 30. V2 Open Questions

1. **Initial budget allocation:** When an Actor is first created, what is its initial budget? Zero (must ACTORCLAIM first)? Or does the creation message's value seed it?
2. **ACTORCLAIM conflict resolution:** Whole-transaction rejection is recommended over partial claim failure. Is that too restrictive for practical contract patterns?
3. **Minimum shared_balance policy:** Protocol-enforced minimum to cover N blocks of storage fees, or left to contract logic?
4. **Cross-account Actor messages:** `ACTORSEND` is intra-account only. Future `ACTORSENDX` needs design for cross-account / cross-shard delivery.
5. **Actor lifecycle:** Can Actors be destroyed? Remaining `budget` auto-released to `shared_balance`?
6. **Backward compatibility period:** How long do old and new formats run in parallel?
7. **Actor count limits:** Maximum Actors per Account? Storage cost model for actor metadata?
8. **VM forbidden-field enforcement:** Hard-trap vs sentinel when actor-mode code reads Phase-2-only fields?
9. **Behavior binding model:** Per-actor `behavior_ref` vs shared code vs behavior registry — final decision needed before implementation.

---

# Part IV — Migration: V1 to V2

## 31. Migration Strategy

### 31.1 Transition Mapping

| V1 | V2 |
|----|-----|
| Wallet Actor = independent Account A | Wallet Actor = actor inside Account Container |
| Treasury Actor = independent Account B | Treasury Actor = actor inside same container |
| Recovery Actor = independent Account C | Recovery Actor = actor inside same container |
| Token / App Actors = separate Accounts | Token / App Actors = actors inside containers |

### 31.2 Migration Options

* **Option A: New Accounts Only** — only newly created accounts use actor-mode. Recommended initial strategy.
* **Option B: Opt-In Migration** — existing V1 actor sets may migrate into actor containers via explicit migration procedures.
* **Option C: Full Network Migration** — all accounts eventually move to actor-mode. Long-term goal.

### 31.3 What V1 Concepts Carry Forward

The following from V1 remain valid and should be reused in V2:

* Virtual Account abstraction
* Wallet / Treasury / Recovery / Policy role decomposition
* Session semantics
* Actor-oriented token patterns
* Actor registry semantics
* User-facing one-address UX

Only the **protocol placement** of those concepts changes.

---

# Part V — Implementation Plan

## 32. Module Breakdown

### Module A: TL-B Schema & Account Structure

**Scope:** Foundation of the on-chain data format. All other modules depend on this.

| File | Changes |
|------|---------|
| `crypto/block/block.tlb:270-292` | Add `ActorDescriptor` type, actor-mode `AccountStorage` variant, add `actor_id:(Maybe bits256)` to Transaction, OutMsgQueue 352->608 bits |
| `crypto/block/block-auto.h/cpp` | Auto-generated from block.tlb by `tlbc` |
| `crypto/block/block-parse.h:522-528` + `.cpp` | Branch `AccountStorage` `skip()/validate_skip()` for actor-mode; add `ActorDescriptor` parser |
| `crypto/block/transaction.h:263-345` | Add Account fields: `actor_mode`, `shared_balance`, `actors_dict_root`, `current_actor_id/budget/state/lt` |
| `crypto/block/transaction.h:348-481` | Add Transaction fields: `actor_mode`, `actor_id`, `actor_lt_start/end`, `actor_budget`, `actor_state`, `balance_requests`, `phase2_committed` |
| `crypto/block/transaction.cpp:476-530` | `Account::unpack()` detects actor-mode; add `unpack_actor()` / `commit_actor()` |
| `crypto/block/transaction.cpp:4022-4075` | `Transaction::commit()` actor-mode branch: write only actor-local fields, defer account-global to Phase 2 |

**Complexity:** HIGH | **Estimate:** 3-4 weeks

### Module B: TVM Opcodes

**Scope:** 7 new instructions using the 0xFB09-0xFB0F range.

| File | Changes |
|------|---------|
| `crypto/vm/tosops.cpp:2388` | Add `register_tos_actor_ops(OpcodeTable&)`, call from `register_tos_ops()` |
| `crypto/vm/tosops.h` | Declare `register_tos_actor_ops` |
| `crypto/vm/vm.h:278-315` | Add c6 register (`get_c6()/set_c6()`) |
| `crypto/vm/continuation.h:39` | Extend `d[]` array for c6 |
| `crypto/block/block.tlb` | Add OutAction variants: `action_actor_send`, `action_actor_claim`, `action_actor_release` |

**Complexity:** MEDIUM | **Estimate:** 1-2 weeks

### Module C: Transaction Execution (Two-Phase)

**Scope:** Split transaction execution into Phase 1 tentative + Phase 2 commit.

| File | Changes |
|------|---------|
| `crypto/block/transaction.h` | Add `ActorTransactionResult` and `BalanceRequest` structs |
| `crypto/block/transaction.cpp:~1020` | `prepare_storage_phase()`: actor-mode defers storage fees to Phase 2 |
| `crypto/block/transaction.cpp:~1135` | `prepare_credit_phase()`: actor-targeted value -> budget; legacy -> shared_balance |
| `crypto/block/transaction.cpp:~1960` | `prepare_compute_phase()`: gas from budget; set c6=actor_state; c7 adjustments |
| `crypto/block/transaction.cpp:~2150` | `prepare_action_phase()`: handle actor_send/claim/release actions |
| `crypto/block/transaction.cpp:4022` | Split `commit()` into `commit_phase1()` + `commit_phase2()` |
| New: `crypto/block/actor-merge.cpp` | Phase 2 merge: sort, prefix rule, balance requests, assign final lt |

**Complexity:** HIGH | **Estimate:** 3-4 weeks

### Module D: Collator Restructuring

**Scope:** Transform block production from serial to Phase 1 parallel + Phase 2 merge.

| File | Changes |
|------|---------|
| `validator/impl/collator-impl.h` | Add `pending_actor_results_`, `actor_lt_counters_`, `actor_prefix_valid_` |
| `validator/impl/collator.cpp:2379` | `do_collate_inner()`: add Phase 2 merge step |
| `validator/impl/collator.cpp:3349` | `create_ordinary_transaction()`: actor-mode uses `execute_actor_transaction()` |
| `validator/impl/collator.cpp:4184` | `process_inbound_internal_messages()`: identify actor-mode targets |
| `validator/impl/collator.cpp:3654` | `process_one_new_message()`: defer actor_send to next block |
| `validator/impl/collator.cpp:4945` | `register_new_msgs()`: actor-mode messages registered after Phase 2 only |
| `validator/impl/collator.cpp:3061` | `combine_account_transactions()`: include actor_id |

**Complexity:** HIGH | **Estimate:** 3-4 weeks

### Module E: Validation Logic

**Scope:** Validators reproduce two-phase execution and verify results.

| File | Changes |
|------|---------|
| `validator/impl/validate-query.cpp:3098` | `precheck_account_updates()`: actor-mode diffs |
| `validator/impl/validate-query.cpp:3291` | `precheck_account_transactions()`: actor_lt monotonicity, prefix rule |
| `validator/impl/validate-query.cpp:5574` | `check_one_transaction()`: replay Phase 1 + Phase 2 |
| `validator/impl/validate-query.cpp:3872` | `check_in_msg()`: intra-account actor messages |
| `validator/impl/validate-query.cpp:4437` | `check_out_msg()`: 608-bit queue keys |
| `validator/impl/validate-query.cpp:6412` | `check_message_processing_order()`: actor-mode ordering |
| `validator/impl/validate-query.hpp` | Per-actor validation state tracking |

**Complexity:** HIGH | **Estimate:** 3-4 weeks

### Module F: OutMsgQueue Key Extension

**Scope:** Extend queue key from 352 to 608 bits.

| File | Changes |
|------|---------|
| `crypto/block/output-queue-merger.h:30` | `max_key_len` 352->608 |
| `crypto/block/output-queue-merger.cpp` | `unpack_node()`, comparison, split logic |
| `crypto/block/block.cpp:2008-2021` | `compute_out_msg_queue_key()`: insert actor_id |
| `crypto/block/block.h:731` | Signature update to `BitArray<608>` |
| `validator/impl/collator.cpp` | All `compute_out_msg_queue_key()` call sites |
| `validator/impl/validate-query.cpp` | Queue key validation width |
| `crypto/block/block.tlb:243` | `HashmapAugE 352 -> 608` |

**Complexity:** MEDIUM | **Estimate:** 2 weeks

### Module G: Merkle Proofs

| File | Changes |
|------|---------|
| `crypto/block/check-proof.cpp:152-207` | Add `check_actor_proof()` |
| `crypto/block/check-proof.h` | Declaration |

**Complexity:** MEDIUM | **Estimate:** 2 weeks

### Module H: Lite-Client / SDK

| File | Changes |
|------|---------|
| `tl/generate/scheme/lite_api.tl` | `getActorState`, `getActorList` queries |
| `lite-client/lite-client.cpp` | `get_actor_state()`, `get_actor_list()` commands |
| `tl/generate/scheme/toslib_api.tl` | Actor-aware SDK types |
| `emulator/transaction-emulator.h` + `emulator-extern.cpp` | Actor-mode emulation |

**Complexity:** MEDIUM | **Estimate:** 2-3 weeks

## 33. Implementation Sequencing

```
Week 1-4:   Module A (TL-B & Account)              <- foundation for all modules
Week 3-5:   Module B (TVM Opcodes)                  <- depends on A
Week 3-5:   Module F (OutMsgQueue Key)              <- depends on A, parallel with B
Week 4-6:   Module G (Merkle Proofs)                <- depends on A, parallel
Week 5-8:   Module C (Two-Phase Execution)          <- depends on A+B
Week 7-11:  Module D (Collator Restructuring)       <- depends on A+B+C
Week 9-13:  Module E (Validation Logic)             <- depends on A+C+D
Week 10-13: Module H (Lite-Client / SDK)            <- depends on A+G
```

Parallelizable module group: {B, F, G} can be developed simultaneously.

## 34. Effort Estimate

| Layer | Complexity | Effort |
|-------|-----------|--------|
| Account struct + serialization | High | 3-4 weeks |
| Two-phase execution model | High | 3-4 weeks |
| Collator restructuring | High | 3-4 weeks |
| TVM new instructions (7 opcodes) | Medium | 1-2 weeks |
| Message routing (OutMsgQueue) | Medium | 2 weeks |
| Validation logic | High | 3-4 weeks |
| Proof/lite-client upgrade | Medium | 2-3 weeks |
| Built-in Token Actors | Medium | 2 weeks |
| Testing + integration | High | 4-6 weeks |

**V2 total: approximately 6-9 months for a small team (2-3 engineers).**

## 35. Verification

| Module | Method |
|--------|--------|
| A | Compiles; tlbc generation passes; unpack/pack round-trip tests |
| B | Unit tests per opcode (normal + exception paths); Fift scripts |
| C | Phase 1 tentative results correct; Phase 2 merge prefix and rollback rules |
| D | Multi-actor parallel block production; same-block visibility; block limits |
| E | Validator passes validate-query on blocks produced by D |
| F | Queue merge tests; 608-bit key sort correctness |
| G | lite-client getActorState proof verification |
| H | lite-client actor state/list queries return correct results |

**End-to-end:** start local testnet -> deploy actor-mode contract -> multi-actor parallel transactions -> verify block consistency.

---

# Appendices

## Appendix A: Minimal Role IDs

```
ROLE_PRIMARY   = 0
ROLE_TREASURY  = 1
ROLE_POLICY    = 2
ROLE_RECOVERY  = 3
ROLE_PRIVACY   = 4
```

## Appendix B: Minimal Action IDs

```
ACT_SEND_MSG=0x01  ACT_REGISTER_ACTOR=0x02  ACT_UNREGISTER_ACTOR=0x03
ACT_SET_TREASURY=0x04  ACT_SET_POLICY=0x05  ACT_SET_RECOVERY=0x06
ACT_ADD_SESSION=0x07  ACT_REVOKE_SESSION=0x08  ACT_LOCK=0x09
ACT_UNLOCK=0x0A  ACT_FORWARD_TO_ACTOR=0x0B
ACT_PROPOSE_OWNER=0x0C  ACT_COMMIT_OWNER=0x0D
```

## Appendix C: V2 Minimum Acceptance Tests

1. Single actor legacy-equivalent execution
2. Two actors in one container executing in parallel
3. One actor rejected causing same-actor prefix rejection
4. `shared_balance` overdraw rejection
5. No same-block actor-send consumption
6. Actor-aware 608-bit queue key round-trip
7. Actor proof verification
8. Validator replay equals collator result
9. Migration from V1 actor set to one V2 actor container

## Appendix D: V2 Spec Freeze Checklist

Before V2 coding begins, the following must be frozen:

1. ActorDescriptor schema (including behavior_ref model)
2. AccountContainer schema
3. ActorAddress format
4. actor_lt rules
5. Merge ordering rules
6. Same-block visibility rules
7. VM context compatibility matrix (section 21)
8. Tentative vs canonical transaction structures
9. Queue key layout
10. Proof path format

## Appendix E: Code References

| Component | File | Reference |
|-----------|------|-----------|
| Account struct | `crypto/block/transaction.h` | 263-345 |
| Transaction struct | `crypto/block/transaction.h` | 348-481 |
| Account::unpack | `crypto/block/transaction.cpp` | 476-530 |
| Transaction::commit | `crypto/block/transaction.cpp` | 4022-4075 |
| TL-B schema | `crypto/block/block.tlb` | 270-292 |
| Collator main loop | `validator/impl/collator.cpp` | 2379 (`do_collate_inner`) |
| Transaction creation | `validator/impl/collator.cpp` | 3466 (`impl_create_ordinary_transaction`) |
| Message processing | `validator/impl/collator.cpp` | 4184 (`process_inbound_internal_messages`) |
| Validation | `validator/impl/validate-query.cpp` | 7674 lines |
| TVM instructions | `crypto/vm/tosops.cpp` | 2388 (`register_tos_ops`) |
| vm::Dictionary | `crypto/vm/dict.h` | HashmapE API |
| OutMsgQueue key | `crypto/block/output-queue-merger.h` | 30 (`max_key_len`) |
| Queue key construction | `crypto/block/block.cpp` | 2008-2021 (`compute_out_msg_queue_key`) |
| Merkle proofs | `crypto/block/check-proof.cpp` | 152-207 (`check_account_proof`) |
| Lite-client | `lite-client/lite-client.cpp` | 4723 lines |
| Block-parse | `crypto/block/block-parse.h` | 522-528 |
| Emulator | `emulator/transaction-emulator.h` | Transaction emulation |
