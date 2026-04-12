# TOS Account-as-Actor Architecture Yellow Paper

**Status:** Draft v1.0
**Target audience:** protocol designers, smart contract engineers, wallet/SDK engineers, Claude Code implementation workflows
**Scope:** This document specifies the **Account = Actor** architecture for TOS on top of a TON-like asynchronous smart contract base layer, without protocol-level execution redesign.

---

## Abstract

This document defines the **Account = Actor** architecture for TOS.

Instead of redesigning the base protocol so that one on-chain account contains multiple execution actors, TOS adopts a pragmatic approach:

* every existing on-chain **Account** is treated as a first-class **Actor**
* a human-facing **Virtual Account** is constructed as a coordinated set of Actors
* funds, permissions, recovery, and application logic are decomposed across multiple specialized Actors
* no protocol-level changes to validator logic, block format, proof format, queue keys, or execution semantics are required in v1

This architecture preserves the strongest practical advantages of the Actor Model:

* isolated state
* message-driven execution
* explicit ownership boundaries
* fault isolation
* natural parallelism across actors
* modular composability

At the same time, it avoids the complexity of protocol-level in-account multi-actor execution, such as two-phase merge, hybrid balance settlement, actor-aware validation, actor-level Merkle proofs, and hard-fork migration.

This paper is written to be concrete enough that an engineering agent such as Claude Code can implement the system module by module.

---

# 1. Motivation

## 1.1 Problem Statement

Traditional account-based smart contract systems often overload a single account with too many responsibilities:

* user identity
* permissions
* treasury
* spending policy
* session keys
* recovery logic
* token balances
* application state

This creates several problems:

1. **Monolithic account logic** — one contract becomes too complex
2. **Weak modularity** — security domains are mixed together
3. **Poor upgradability** — changing one concern risks breaking others
4. **Insufficient fault isolation** — one bug can compromise the entire account
5. **Ambiguous user abstraction** — “one person = one account” is often not the right systems model

## 1.2 Why the Actor Model

The Actor Model provides a simpler and more composable foundation:

* each Actor owns its own state
* each Actor processes messages independently
* actors interact only via asynchronous messages
* each Actor is internally serial
* concurrency exists naturally across actors

A TON-like execution environment already provides most of the required runtime properties:

* every Account has its own address
* every Account has its own state
* every Account is triggered by messages
* every Account processes messages serially
* different Accounts communicate asynchronously

Therefore, instead of forcing a new execution model into the protocol, TOS adopts the following interpretation:

> **One on-chain Account is one Actor.**

This is the basis of the Account-as-Actor architecture.

## 1.3 Why Not Protocol-Level In-Account Multi-Actor Execution in v1

A more ambitious design would make one Account contain multiple Actors and introduce:

* actor-local state trees
* actor-local budgets
* shared account-level balance pools
* two-phase speculative execution and merge
* actor-level transaction proofs
* actor-aware queue routing
* validator replay changes

That design is theoretically powerful, but it is a hard-fork-level protocol redesign.

For v1, TOS explicitly chooses **not** to make those changes.

Instead, TOS focuses on building a powerful actor-native account and application architecture at the smart contract and SDK level.

---

# 2. Design Goals

## 2.1 Primary Goals

The v1 Account-as-Actor architecture must achieve the following:

1. **Treat every on-chain Account as an Actor**
2. **Provide a Virtual Account abstraction for one human user**
3. **Split wallet logic into specialized Actors**
4. **Allow funds to be centralized and redistributed through a Treasury Actor**
5. **Support session authorization and recovery mechanisms**
6. **Support actor-oriented token/application patterns**
7. **Require no base protocol changes**
8. **Be implementable using normal smart contracts, wallet tooling, and SDK code**

## 2.2 Secondary Goals

1. Clean role separation across wallet subsystems
2. Stronger operational safety through modularization
3. Clear upgrade paths for wallet/account components
4. Better compatibility with existing TON-like async execution
5. A migration path toward a future protocol-level Actor redesign if ever needed

## 2.3 Non-Goals

This v1 architecture does **not** attempt to provide:

1. Multiple Actors inside one Account
2. Actor-native protocol addresses distinct from Account addresses
3. Actor-aware validator execution
4. Actor-aware OutMsgQueue keys
5. Actor-level Merkle proof paths
6. Two-phase execution at the protocol level
7. Shared account-internal execution budgets enforced by consensus

---

# 3. Terminology

## 3.1 Account

A base-layer on-chain object with:

* a unique address
* code
* persistent state
* balance
* message-driven execution

In this architecture, **Account** is the base protocol term, but conceptually it is treated as an **Actor**.

## 3.2 Actor

A logical execution unit with the following properties:

* owns its own state
* has its own address
* processes messages serially
* communicates only via messages

In v1:

> **Actor = Account**

## 3.3 Virtual Account

A human-facing logical account composed of multiple Actors.

A Virtual Account is not a base-layer execution unit. It is a coordinated set of Actors under one user’s control and presentation layer.

## 3.4 Primary Wallet Actor

The main entry Actor for a Virtual Account.

Responsibilities:

* owner authentication
* session management
* recovery coordination
* actor registry
* routing to treasury/policy/recovery/app actors

## 3.5 Treasury Actor

The Actor responsible for:

* receiving and holding consolidated funds
* allocating budgets to other Actors
* reclaiming or accounting for budgets
* maintaining treasury-level accounting rules

## 3.6 Policy Actor

The Actor responsible for enforcing spending and authorization rules, such as:

* spend limits
* timelocks
* whitelists
* emergency vetoes
* multi-step approvals

## 3.7 Recovery Actor

The Actor responsible for account recovery and emergency controls, such as:

* guardian workflows
* owner key rotation
* freezing sessions
* entering recovery mode

## 3.8 Session Actor / Session Authorization

A short-lived or restricted authority used for low-risk actions.

In v1, session functionality may be implemented either:

* directly inside the Primary Wallet Actor via session keys, or
* as separate Session Actors if needed by the product model

## 3.9 Registry

The mapping that identifies all important Actors belonging to one Virtual Account.

---

# 4. Architectural Overview

## 4.1 High-Level Model

```text
Virtual Account (logical)
 ├─ Primary Wallet Actor
 ├─ Treasury Actor
 ├─ Recovery Actor
 ├─ Policy Actor
 ├─ Privacy Actor (optional)
 ├─ Session authorization set
 ├─ Token Actors
 └─ Application Actors
```

Each item above is a separate on-chain Account, and therefore a separate Actor.

## 4.2 Key Principle

> **The protocol executes Accounts. The TOS architecture interprets them as Actors.**

That means:

* a single Actor remains internally serial
* concurrency happens across Actors
* no shared mutable state exists across Actors
* coordination must be encoded via message protocols

## 4.3 Core Separation of Concerns

### Primary Wallet Actor

Responsible for identity and control.

### Treasury Actor

Responsible for fund custody and budget allocation.

### Recovery Actor

Responsible for emergency and guardian procedures.

### Policy Actor

Responsible for risk control and approval rules.

### Application and Token Actors

Responsible for product-specific logic.

This prevents the “single giant wallet contract” anti-pattern.

---

# 5. System Model

## 5.1 Actor Properties

Every Actor in TOS v1 must obey the following model:

1. **Single owner of local state**
2. **Single inbox execution stream**
3. **All interactions via asynchronous messages**
4. **No implicit shared mutable memory**
5. **No direct synchronous multi-actor state mutation**

## 5.2 Virtual Account Properties

A Virtual Account must provide a coherent user abstraction over multiple Actors:

* one human-facing identity
* one main wallet entrypoint
* one treasury model
* one recovery model
* one actor registry view
* one UX layer that hides internal fragmentation where appropriate

## 5.3 Funds Model

There is no protocol-level shared balance pool in v1.

Instead:

* each Actor has its own native account balance
* the Treasury Actor acts as the coordination center for funds
* budgets are allocated by explicit treasury messages
* budget return, accounting, and enforcement are implemented at the contract layer

This means TOS v1 uses **logical budget orchestration**, not protocol-native shared balance settlement.

---

# 6. Actor Taxonomy

## 6.1 Required Actor Types

### 6.1.1 Primary Wallet Actor

Required.

### 6.1.2 Treasury Actor

Required.

### 6.1.3 Recovery Actor

Required.

### 6.1.4 Policy Actor

Required.

## 6.2 Recommended Actor Types

### 6.2.1 Privacy Actor

Optional in base implementation, recommended for privacy-oriented flows.

### 6.2.2 Token Master Actor

Required whenever a token system is deployed.

### 6.2.3 Token Balance Actor

Required per holder when using actor-oriented token architecture.

### 6.2.4 Application Service Actor

Used by dApps and services to isolate application logic.

---

# 7. Primary Wallet Actor Specification

## 7.1 Purpose

The Primary Wallet Actor is the control hub of one Virtual Account.

It is the user-facing entry Actor and should be the default externally visible wallet address in most products.

## 7.2 Responsibilities

The Primary Wallet Actor must support:

1. owner-signed request execution
2. replay protection
3. actor registry maintenance
4. treasury routing
5. policy integration
6. recovery integration
7. session authorization
8. lock / recovery / frozen modes

## 7.3 Minimal State Layout

The Primary Wallet Actor SHOULD store at least:

```text
wallet_id:uint32
seqno:uint32
owner_pubkey:uint256
pending_owner_pubkey:Maybe<uint256>
mode:uint8
flags:uint32
registry_root:Cell
session_root:Cell
guardian_root:Cell
policy_actor:Maybe<Address>
treasury_actor:Maybe<Address>
recovery_actor:Maybe<Address>
```

## 7.4 Wallet Modes

The wallet MUST support the following modes:

* `NORMAL`
* `LOCKED`
* `RECOVERY`
* `FROZEN`

### NORMAL

Standard operation.

### LOCKED

Transfers and sensitive actions restricted.

### RECOVERY

Recovery flow in progress.

### FROZEN

Emergency hard stop.

## 7.5 External Interface

The Primary Wallet Actor MUST support at least the following message families:

### 7.5.1 SignedRequest

Purpose: owner-authorized action bundle.

Suggested fields:

```text
op:uint32
wallet_id:uint32
seqno:uint32
valid_until:uint32
request_id:uint64
actions:^Cell
signature:bits512
```

### 7.5.2 ExtensionRequest

Purpose: message from a registered internal Actor.

Suggested fields:

```text
op:uint32
role_id:uint16
actions:^Cell
```

### 7.5.3 RecoveryRequest

Purpose: recovery-specific control path.

Suggested fields:

```text
op:uint32
subop:uint8
payload:^Cell
```

### 7.5.4 SessionRequest

Purpose: restricted, lower-risk delegated action.

Suggested fields:

```text
op:uint32
session_pubkey:uint256
session_nonce:uint32
valid_until:uint32
actions:^Cell
signature:bits512
```

## 7.6 Required Actions

The wallet MUST support an internal action DSL or equivalent structured action set.

Required action types:

* `SEND_MSG`
* `REGISTER_ACTOR`
* `UNREGISTER_ACTOR`
* `SET_TREASURY`
* `SET_POLICY`
* `SET_RECOVERY`
* `ADD_SESSION`
* `REVOKE_SESSION`
* `LOCK`
* `UNLOCK`
* `PROPOSE_OWNER`
* `COMMIT_OWNER`
* `FORWARD_TO_ACTOR`

## 7.7 Security Requirements

The Primary Wallet Actor MUST enforce:

1. strict replay protection
2. deterministic action parsing
3. actor role authorization
4. session expiry checks
5. session nonce checks
6. clear separation between owner path and extension path
7. explicit recovery authority boundaries

---

# 8. Treasury Actor Specification

## 8.1 Purpose

The Treasury Actor is the financial coordination center of a Virtual Account.

It replaces the need for protocol-native shared balance in v1.

## 8.2 Responsibilities

The Treasury Actor SHOULD support:

1. receiving consolidated user funds
2. allocating budget to other Actors
3. reclaiming or accounting for unused budget
4. recording treasury transfers
5. enforcing treasury-specific policy hooks

## 8.3 Core Interfaces

### 8.3.1 Receive Funds

Accept native token transfers and optionally structured metadata.

### 8.3.2 AllocateBudget

Suggested fields:

```text
op:uint32
target_actor:Address
amount:Coins
budget_id:uint64
memo:Maybe<Cell>
```

### 8.3.3 ReturnBudget

Suggested fields:

```text
op:uint32
source_actor:Address
amount:Coins
budget_id:uint64
memo:Maybe<Cell>
```

### 8.3.4 TreasuryTransfer

Treasury-initiated payment or routing.

## 8.4 Treasury Policy Integration

The Treasury Actor SHOULD optionally consult the Policy Actor before executing sensitive transfers.

---

# 9. Recovery Actor Specification

## 9.1 Purpose

The Recovery Actor handles emergency governance and owner recovery flows.

## 9.2 Responsibilities

The Recovery Actor SHOULD support:

1. guardian registration model
2. owner recovery proposal
3. delayed owner commit
4. wallet mode escalation
5. session freeze
6. emergency freeze

## 9.3 Core Interfaces

### 9.3.1 ProposeOwnerChange

```text
op:uint32
new_owner_pubkey:uint256
recovery_id:uint64
```

### 9.3.2 FreezeWallet

```text
op:uint32
reason_code:uint16
```

### 9.3.3 EnterRecoveryMode

```text
op:uint32
recovery_id:uint64
```

### 9.3.4 CommitRecovery

```text
op:uint32
recovery_id:uint64
```

## 9.4 Recovery Safety Requirements

The Recovery Actor MUST NOT silently gain unrestricted transfer authority unless explicitly designed and approved.

Recommended recovery capability set:

* freeze
* propose owner change
* revoke sessions
* switch wallet mode

Not recommended as default:

* arbitrary treasury drain
* arbitrary actor reconfiguration without timelock

---

# 10. Policy Actor Specification

## 10.1 Purpose

The Policy Actor enforces account-level risk and spending policy.

## 10.2 Responsibilities

The Policy Actor SHOULD support:

* daily spend limits
* destination whitelists
* approval requirements
* timelocks
* emergency deny rules
* role-specific policy evaluation

## 10.3 Core Interface

### EvaluateAction

```text
op:uint32
request_type:uint16
request_id:uint64
origin_actor:Address
target_actor:Address
value:Coins
context:^Cell
```

### Return Value

Suggested response:

```text
allowed:bool
policy_code:uint16
extra_delay:uint32
memo:Maybe<Cell>
```

---

# 11. Session Authorization Specification

## 11.1 Purpose

Sessions provide temporary, restricted authority for low-risk operations.

## 11.2 Recommended Session Fields

Each session record SHOULD include:

```text
session_pubkey:uint256
expires_at:uint32
spend_limit:Coins
allowed_roles_mask:uint64
allowed_dest_hash:Maybe<uint256>
nonce:uint32
flags:uint32
```

## 11.3 Session Rules

A session MUST be able to be:

* created by owner authority
* revoked by owner authority
* revoked by recovery authority
* limited by time
* limited by scope
* limited by replay-protected nonce

## 11.4 Session Non-Goals

Sessions are not full owner replacements.

They are for:

* low-risk automation
* app-level delegation
* frequent small operations
* temporary device authorization

---

# 12. Actor Registry Specification

## 12.1 Purpose

The Actor Registry maps semantic roles to concrete Actor addresses.

## 12.2 Required Roles

At minimum, the registry SHOULD support:

* `PRIMARY`
* `TREASURY`
* `POLICY`
* `RECOVERY`
* `PRIVACY`

## 12.3 Registry Data Model

Suggested mapping:

```text
role_id:uint16 -> actor_address:Address
```

## 12.4 Registry Operations

Required operations:

* register actor
* unregister actor
* replace actor
* lookup actor
* enumerate key system actors

---

# 13. Token-as-Actors Specification

## 13.1 Purpose

TOS recommends an actor-oriented token architecture.

Instead of one monolithic contract holding a giant balances map, a token system SHOULD be decomposed into specialized Actors.

## 13.2 Minimal Token Actor Set

```text
Token System
 ├─ TokenMasterActor
 └─ TokenBalanceActor(owner)
```

## 13.3 TokenMasterActor Responsibilities

The TokenMasterActor SHOULD manage:

* token metadata
* total supply
* wallet derivation or wallet discovery
* wallet deployment
* mint and burn authority routing

## 13.4 TokenBalanceActor Responsibilities

The TokenBalanceActor SHOULD manage:

* one holder’s balance
* inbound token credit
* outbound token transfer
* local authorization policy if needed

## 13.5 Token Transfer Model

A token transfer SHOULD be modeled as actor-to-actor message flow.

Example:

1. User authorizes transfer via Primary Wallet Actor
2. Primary Wallet Actor routes to sender TokenBalanceActor
3. Sender TokenBalanceActor debits local balance
4. Sender TokenBalanceActor sends credit message to recipient TokenBalanceActor
5. Recipient TokenBalanceActor credits local balance

## 13.6 Optional Token Actor Extensions

Optional later additions:

* `MintPolicyActor`
* `ComplianceActor`
* `AllowanceActor`
* `TreasuryActor`
* `VestingActor`

---

# 14. Interface Definitions Summary

## 14.1 Required Contract Interfaces

### Primary Wallet Actor

* `SignedRequest`
* `ExtensionRequest`
* `RecoveryRequest`
* `SessionRequest`
* `get_wallet_id`
* `get_seqno`
* `get_mode`
* `get_actor(role_id)`
* `get_session(session_pubkey)`

### Treasury Actor

* `AllocateBudget`
* `ReturnBudget`
* `TreasuryTransfer`
* `get_treasury_balance_state`
* `get_budget_record(budget_id)`

### Recovery Actor

* `ProposeOwnerChange`
* `FreezeWallet`
* `EnterRecoveryMode`
* `CommitRecovery`
* `get_recovery_state`

### Policy Actor

* `EvaluateAction`
* `get_policy_state`

### TokenMasterActor

* `Mint`
* `Burn`
* `GetWalletAddress(owner)`
* `GetMetadata`
* `GetTotalSupply`

### TokenBalanceActor

* `Transfer`
* `Credit`
* `Burn`
* `GetBalance`

---

# 15. Required Modules

The following modules are mandatory for the first serious implementation.

## 15.1 Required Smart Contract Modules

1. **Primary Wallet Actor contract**
2. **Treasury Actor contract**
3. **Recovery Actor contract**
4. **Policy Actor contract**
5. **Actor Registry logic**
6. **Session authorization logic**
7. **TokenMasterActor contract**
8. **TokenBalanceActor contract**

## 15.2 Required Tooling Modules

1. deployment scripts
2. actor address registry library
3. wallet SDK abstraction for Virtual Account
4. action builder / serializer library
5. local integration test harness

## 15.3 Required Documentation Modules

1. contract interface specs
2. action encoding spec
3. wallet usage guide
4. recovery guide
5. token actor guide

---

# 16. Deferrable Modules

The following modules are useful but may be postponed.

## 16.1 Optional Smart Contract Modules

1. Privacy Actor
2. dedicated Session Actor contracts
3. advanced guardian quorum logic
4. timelocked policy escalation
5. allowance-specific token actors
6. vesting actors
7. compliance actors
8. NFT actor set

## 16.2 Optional Tooling Modules

1. explorer-level Virtual Account aggregation
2. visual actor graph UI
3. automated treasury accounting dashboard
4. actor policy simulator
5. actor orchestration CLI

## 16.3 Optional Language/Compiler Modules

1. TOS-specific actor contract templates
2. higher-level actor DSL
3. codegen for action schemas

---

# 17. Explicit Boundaries of the No-Protocol-Change Approach

This section defines what v1 does **not** do.

## 17.1 No Base Protocol Changes

TOS v1 Account-as-Actor MUST NOT require changes to:

* validator logic
* block format
* queue key structure
* Merkle proof path
* native address format
* consensus rules
* transaction ordering semantics

## 17.2 No In-Account Multi-Actor Execution

TOS v1 MUST NOT attempt to execute multiple Actors inside one Account.

## 17.3 No Protocol-Native Shared Balance

TOS v1 MUST NOT assume a protocol-level shared balance pool across Actors.

## 17.4 No Actor-Aware Validator Semantics

Validators are not aware of:

* treasury actor role
* policy actor role
* recovery actor role
* virtual account grouping

These remain application architecture concepts.

## 17.5 No Actor-Level Proof Format

Proofs remain account-level.

Any actor-oriented proof view in v1 is an application-level interpretation, not a protocol-native proof object.

---

# 18. Security Model

## 18.1 Security Boundary Principle

Every specialized Actor is a separate fault domain.

This is a primary benefit of the architecture.

## 18.2 Security Rules

### Primary Wallet Actor

Must be minimal, deterministic, and strongly replay protected.

### Treasury Actor

Must not accept arbitrary budget requests without authentication and policy checks.

### Recovery Actor

Must be narrowly scoped and not overpowered by default.

### Policy Actor

Must be deterministic and side-effect predictable.

### Session Authorization

Must be time-bounded, nonce-bound, and scope-bound.

## 18.3 Recommended Security Practice

1. minimize each actor’s authority
2. separate treasury from identity
3. separate recovery from spending
4. avoid hidden backdoors via extension paths
5. prefer explicit actor registry changes
6. log or emit clear event-style receipts where practical

---

# 19. Recommended Repository Layout

A practical repository layout could be:

```text
/contracts
  /wallet_v6
    wallet_v6.fc
    wallet_v6.tlb
    wallet_v6.spec.md
  /treasury_actor
    treasury_actor.fc
    treasury_actor.tlb
    treasury_actor.spec.md
  /recovery_actor
    recovery_actor.fc
    recovery_actor.tlb
    recovery_actor.spec.md
  /policy_actor
    policy_actor.fc
    policy_actor.tlb
    policy_actor.spec.md
  /token_master_actor
    token_master_actor.fc
  /token_balance_actor
    token_balance_actor.fc

/sdk
  /ts
    actor-registry.ts
    virtual-account.ts
    wallet-v6-client.ts
    treasury-client.ts
    token-client.ts

/scripts
  deploy-wallet-v6.ts
  deploy-virtual-account.ts
  deploy-token-system.ts

/tests
  wallet_v6.spec.ts
  treasury_actor.spec.ts
  recovery_actor.spec.ts
  policy_actor.spec.ts
  token_actor_flow.spec.ts
  virtual_account_e2e.spec.ts

docs
  yellow-paper.md
  interfaces.md
  action-encoding.md
  roadmap.md
```

---

# 20. Claude-Code-Oriented Implementation Guidance

This section is written specifically for coding-agent workflows.

## 20.1 Implementation Order

Recommended order:

### Step 1

Implement `wallet_v6.fc` minimal owner-signed action execution.

### Step 2

Add actor registry support.

### Step 3

Add treasury actor integration.

### Step 4

Add recovery actor and wallet modes.

### Step 5

Add session authorization.

### Step 6

Implement TokenMasterActor and TokenBalanceActor.

### Step 7

Implement SDK layer and Virtual Account aggregation.

## 20.2 Coding Rules

Claude Code SHOULD follow these rules:

1. implement one contract at a time
2. define message schemas before writing contract logic
3. keep action decoding deterministic and minimal
4. write get methods for every critical internal mapping
5. write unit tests before adding cross-contract orchestration
6. prefer explicit op codes over ambiguous payload interpretation
7. avoid hidden privilege escalation through extension paths

## 20.3 Minimum Deliverables Per Module

For each contract module, Claude Code SHOULD produce:

1. `.fc` contract source
2. `.tlb` schema or interface description
3. TypeScript wrapper/client
4. deployment script
5. unit tests
6. integration test scenario
7. short spec markdown

---

# 21. Roadmap

## Phase 0: Specification Freeze

Deliverables:

* finalize this yellow paper
* freeze interface schemas
* freeze op codes and action encodings
* freeze role IDs and registry conventions

## Phase 1: Wallet Core

Deliverables:

* `wallet_v6.fc` MVP
* owner-signed requests
* seqno protection
* registry
* lock/recovery modes
* TypeScript client for wallet
* wallet unit tests

## Phase 2: Treasury and Recovery

Deliverables:

* Treasury Actor
* Recovery Actor
* Policy Actor MVP
* budget allocation flow
* recovery flow
* cross-actor integration tests

## Phase 3: Session and Virtual Account SDK

Deliverables:

* session authorization
* Virtual Account SDK abstraction
* actor registry helper library
* one-address UX wrapper for the user

## Phase 4: Token Actor System

Deliverables:

* TokenMasterActor
* TokenBalanceActor
* token deployment scripts
* mint / transfer / burn flows
* token integration tests

## Phase 5: Production Hardening

Deliverables:

* audits
* policy edge cases
* guardian enhancements
* treasury accounting refinement
* SDK stabilization
* documentation and examples

## Phase 6: Optional Extensions

Deliverables:

* Privacy Actor
* advanced policy workflows
* NFT actor architecture
* explorer aggregation
* actor graph visualization

---

# 22. Migration and Future Evolution

## 22.1 Short-Term Migration Strategy

Short term, TOS should not attempt to migrate protocol internals.

Instead:

* deploy new wallet/account systems using Account-as-Actor architecture
* gradually move users and apps into actor-oriented patterns
* standardize actor roles and interfaces

## 22.2 Long-Term Upgrade Path

If future evidence shows that contract-layer actor orchestration is insufficient, TOS may revisit protocol-level Actor redesign.

That future redesign may include:

* actor-native address layers
* actor-aware proofs
* in-account multi-actor execution
* shared balance and budget settlement at the protocol level
* two-phase execution in validators

This yellow paper deliberately does **not** specify those future protocol changes.

---

# 23. Final Summary

The TOS Account-as-Actor architecture adopts a simple but powerful principle:

> **Treat every existing on-chain Account as an Actor.**

On top of that, TOS builds a higher-order abstraction:

> **A human-facing Virtual Account is a coordinated set of Actors, not a single monolithic contract.**

This design gives TOS the practical benefits of the Actor Model today:

* isolation
* modularity
* message-driven design
* parallelism across actors
* better wallet and account architecture

without requiring the cost and risk of immediate protocol redesign.

For v1, this is the correct tradeoff.

---

# Appendix A: Minimal Role IDs

```text
ROLE_PRIMARY   = 0
ROLE_TREASURY  = 1
ROLE_POLICY    = 2
ROLE_RECOVERY  = 3
ROLE_PRIVACY   = 4
```

# Appendix B: Minimal Action IDs

```text
ACT_SEND_MSG         = 0x01
ACT_REGISTER_ACTOR   = 0x02
ACT_UNREGISTER_ACTOR = 0x03
ACT_SET_TREASURY     = 0x04
ACT_SET_POLICY       = 0x05
ACT_SET_RECOVERY     = 0x06
ACT_ADD_SESSION      = 0x07
ACT_REVOKE_SESSION   = 0x08
ACT_LOCK             = 0x09
ACT_UNLOCK           = 0x0A
ACT_FORWARD_TO_ACTOR = 0x0B
ACT_PROPOSE_OWNER    = 0x0C
ACT_COMMIT_OWNER     = 0x0D
```

# Appendix C: Suggested First Engineering Milestone

A milestone is complete when the following flow works end to end:

1. deploy Primary Wallet Actor
2. deploy Treasury Actor
3. register Treasury Actor in wallet registry
4. fund Treasury Actor
5. add a session key
6. use owner path to route a transfer through treasury
7. trigger recovery mode
8. revoke session
9. restore normal mode
10. pass integration tests
