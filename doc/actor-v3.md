# TOS Actor Architecture — Unified Specification

**Status:** Draft v3.1
**Audience:** Protocol designers, smart contract engineers, wallet/SDK engineers, validator implementers, VM engineers

---

## Abstract

This document is the unified specification for the TOS Actor architecture. It defines a two-phase rollout:

* **Phase V1 — Account-as-Actor:** every on-chain Account is treated as a first-class Actor. A human-facing Virtual Account is constructed as a coordinated set of Actors. No base protocol changes are required.

* **Phase V2 — Protocol-Native Actors:** the base protocol is redesigned so that one Account becomes a container holding multiple protocol-native Actors, each with isolated state, independent budget, and independent logical time. This is a protocol-level change.

V1 delivers the practical benefits of the Actor Model today — isolation, modularity, message-driven design, parallelism across actors, and better wallet architecture — without the cost and risk of protocol redesign. V2 builds on V1 once the actor-oriented patterns are proven in production, making Actors the protocol-native execution unit and enabling intra-account parallel execution.

V1 is the active engineering track. V2 is the protocol research-and-implementation track that starts only after V1 interfaces and actor patterns are proven in production.

### Document Status Matrix

| Part | Track | Normative Level | Status |
|------|-------|----------------|--------|
| Part I — Motivation | Both | Informational | Stable |
| Part II — V1 | V1 | Normative (interfaces, encodings, role IDs) | Active engineering |
| Part III — V2 | V2 | Partially normative / partially design-level | Research; blocked on V1 validation |
| Part IV — V1 to V2 Transition Path | Both | Design-level | Draft |
| Part V — Implementation | V2 | Planning-level | Draft |
| Appendices | Both | Reference | Maintained alongside Parts II-III |

### Freeze Sections Precedence Rule

The following sections are implementation-freeze sections and take precedence over descriptive prose when conflicts arise:

- **15A. V1 Interface Freeze** — authoritative for all V1 smart contract implementations
- **30A. V2 Spec Freeze** — authoritative for all V2 protocol implementation decisions
- **31A. Transition Freeze** — authoritative for all V1-to-V2 transition planning

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

The TOS execution environment already provides most of the required runtime properties: every Account has its own address, its own state, is triggered by messages, processes messages serially, and communicates asynchronously. The C++ node already uses an actor-based runtime through `td::actor`.

## 3. Two-Phase Rollout Strategy

Instead of attempting a single massive protocol redesign, TOS adopts a phased approach:

| | V1: Account-as-Actor | V2: Protocol-Native Actors |
|---|---|---|
| Core idea | Account = Actor | Account = Container, Actor = execution unit |
| Protocol changes | None | Protocol upgrade |
| Parallelism | Natural cross-Account (already exists) | Intra-Account across Actors |
| Balance model | Each Account has own balance; Treasury Actor coordinates | Hybrid: per-actor budget + account shared_balance |
| Implementation layer | Smart contracts + SDK | Protocol: validator, collator, block format, proofs |
| Timeline | Immediate | After V1 is validated in production |

**V1 is the correct tradeoff for today.** V2 defines the long-term protocol direction.

This document is normative for V1 where explicitly marked, and partially normative / partially design-level for V2.

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

### 4.1 Design Boundary

V1 operates entirely within the existing protocol surface. It does not introduce new transaction types, new block fields, or new consensus rules. All V1 constructs -- Virtual Accounts, Actor Registries, Treasury coordination, session authorization -- are contract-layer conventions enforced by smart contract logic and SDK tooling. The base-layer architecture described in this section is the immovable substrate on which V1 is built.

V2 proposes changes to this substrate. No V2 change is activated, implemented, or testable until the V2 Spec Freeze Checklist (Appendix D) is fully resolved and the V1 interfaces have been validated in production.

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
9. Produce interface-freeze-ready specifications (op codes, action encodings, role IDs, state layouts) that are stable enough to serve as the V2 transition baseline

### 5.2 Explicit Protocol Non-Goals for V1

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

**Abstraction level:** V1 provides **operational account abstraction, not protocol-atomic account abstraction**. The Wallet, Treasury, Policy, and Recovery actors are independent on-chain accounts. Fund allocation, policy checks, and recovery actions are all cross-account asynchronous messages. No multi-actor operation in V1 is atomic at the protocol level — each message is a separate transaction that may succeed or fail independently. V2 introduces protocol-level actor containers that enable tighter coordination, but V1 deliberately does not attempt this.

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

In V1, Treasury coordination is a contract-layer convention, not a consensus-enforced balance-sharing mechanism.

### 6.3.1 Default Native Coin Receiving Rule (Normative)

The Primary Wallet Actor is the default externally visible address for a Virtual Account. External senders naturally send native coins to this address. The following rule defines how received funds are handled in the **baseline wallet profile**:

1. The Primary Wallet Actor MUST accept inbound native coin transfers.
2. In the baseline wallet profile, upon receiving native coins the Primary Wallet Actor MUST auto-forward the received value to the Treasury Actor via an internal `DepositToTreasury` message, unless no Treasury Actor is currently registered.
3. The auto-forward MUST be a separate internal message (not a synchronous state change) so that the Treasury Actor's balance is updated through normal message-driven execution.
4. If no Treasury Actor is registered, the Primary Wallet Actor retains the funds in its own balance and emits an event or receipt indicating unrouted funds.
5. The auto-forward gas cost is paid from the received value. If the received value is less than the minimum gas cost for forwarding, the funds are retained in the Primary Wallet Actor's balance.

This is the **baseline wallet profile**, not a universal protocol-level constraint. The baseline profile is the **interoperability default**: all standard wallet deployments, SDK integrations, and exchange deposit flows MUST assume the baseline profile unless explicitly configured otherwise. Alternative wallet profiles (e.g., a vault profile where the Wallet itself is the long-term custody address with Treasury used only for operational budgets) MAY disable auto-forwarding and retain funds in the Wallet balance. Such profiles MUST be explicitly named, documented, and communicated to integrators to prevent deposit-routing mismatches.

SDK implementations MUST present the Primary Wallet address as the user's deposit address and MUST NOT require users to know the Treasury Actor address for normal deposits.

### 6.4 Virtual Account Discovery

A Virtual Account is discoverable from any of its constituent Actors. Given the Primary Wallet Actor address, the full Virtual Account topology can be reconstructed by reading the Actor Registry stored in the Primary Wallet state. Given any non-primary Actor address, the reverse mapping is possible only if that Actor stores a backlink to its Primary Wallet address. Implementations SHOULD store a `primary_wallet:Address` field in every non-primary Actor's state to enable bidirectional discovery.

SDK tooling MUST provide a `resolveVirtualAccount(address)` function that:

1. Reads the Actor's state to determine whether it is a Primary Wallet or a subordinate Actor.
2. If subordinate, follows the `primary_wallet` backlink to the Primary Wallet.
3. Enumerates the Actor Registry to reconstruct the full Virtual Account graph.

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
registry_version:uint32
config_version:uint32
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

`registry_version` is incremented on every registry mutation (register, unregister, replace). `config_version` is incremented on every configuration change (set treasury, set policy, set recovery, mode change, owner change). Both counters start at zero and never wrap.

### 7.4 External Interface

**SignedRequest** -- owner-authorized action bundle:

```
op:uint32  wallet_id:uint32  seqno:uint32  valid_until:uint32
request_id:uint64  actions:^Cell  signature:bits512
```

**ExtensionRequest** -- message from a registered internal Actor:

```
op:uint32  role_id:uint16  actions:^Cell
```

**RecoveryRequest** -- recovery-specific control path:

```
op:uint32  subop:uint8  payload:^Cell
```

**SessionRequest** -- restricted, lower-risk delegated action:

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

### 7.6 Authentication Matrix

| Path | Can call |
|------|----------|
| SignedRequest (owner key) | All actions |
| ExtensionRequest (registered Actor, ROLE_TREASURY) | ACT_SEND_MSG (treasury-routed only) |
| ExtensionRequest (registered Actor, ROLE_RECOVERY) | ACT_LOCK, ACT_UNLOCK, ACT_PROPOSE_OWNER, ACT_REVOKE_SESSION |
| ExtensionRequest (registered Actor, ROLE_POLICY) | None directly; consulted by wallet before executing policy-gated actions |
| RecoveryRequest | ACT_LOCK, ACT_PROPOSE_OWNER, ACT_COMMIT_OWNER (with timelock) |
| SessionRequest (valid session key) | ACT_SEND_MSG (within session scope), ACT_FORWARD_TO_ACTOR (within session scope) |

Any request not matching a row in this matrix MUST be rejected with error code `ERR_UNAUTHORIZED`.

### 7.7 Error Codes

| Code | Name | Meaning |
|------|------|---------|
| 0x0001 | ERR_INVALID_SEQNO | Seqno mismatch (replay or stale) |
| 0x0002 | ERR_EXPIRED | `valid_until` has passed |
| 0x0003 | ERR_UNAUTHORIZED | Caller lacks permission for the requested action |
| 0x0004 | ERR_INVALID_SIGNATURE | Signature verification failed |
| 0x0005 | ERR_UNKNOWN_ACTION | Action opcode not recognized |
| 0x0006 | ERR_LOCKED | Wallet is in LOCKED or FROZEN mode; action not permitted |
| 0x0007 | ERR_ACTOR_NOT_FOUND | Referenced actor not in registry |
| 0x0008 | ERR_ROLE_OCCUPIED | Attempting to register a role that already has an assigned actor |
| 0x0009 | ERR_INSUFFICIENT_FUNDS | Attached value insufficient for the requested operation |
| 0x000A | ERR_POLICY_DENIED | Policy Actor denied the action |

### 7.8 Get Methods

| Method | Signature | Returns |
|--------|-----------|---------|
| `get_wallet_data` | `() -> (int, int, int, int, int, cell, cell, cell)` | wallet_id, seqno, registry_version, config_version, owner_pubkey, registry_root, session_root, guardian_root |
| `get_mode` | `() -> int` | Current wallet mode (NORMAL/LOCKED/RECOVERY/FROZEN) |
| `get_actor_address` | `(int role_id) -> slice` | Address of the actor registered for the given role, or null |
| `get_session` | `(int session_pubkey) -> (int, int, int, int, int)` | expires_at, spend_limit, allowed_roles_mask, nonce, flags |
| `is_action_allowed` | `(int action_id, int caller_role) -> int` | 1 if the action is permitted for the caller role in the current mode, 0 otherwise |

### 7.9 Action Encoding Rules

Each action in the `actions:^Cell` list is encoded as a sequential chain of cells. Each action cell contains:

```
action_id:uint8  payload:remainder
```

Multiple actions are chained via cell references: the first action occupies the root cell, and each subsequent action is stored in the first reference of the previous cell. The chain terminates when there is no further reference.

The wallet processes actions in chain order (root first). If any action fails, the entire request is reverted -- there is no partial execution of an action bundle. The wallet MUST validate all actions before executing any of them to avoid partial state mutations on revert.

Maximum actions per bundle: 255 (limited by the uint8 action_id field and practical gas constraints).

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

**TreasuryTransfer** -- treasury-initiated payment or routing.

The Treasury Actor should optionally consult the Policy Actor before executing sensitive transfers.

### 8.3 Treasury State

```
primary_wallet:Address
total_allocated:Coins
pending_allocations:HashmapE(budget_id:uint64 -> AllocationRecord)
config_flags:uint32
```

`AllocationRecord`:

```
target_actor:Address  amount:Coins  allocated_at:uint32  memo:Maybe<Cell>
```

The Treasury tracks outstanding allocations so that budget returns can be matched and audited. `total_allocated` is the sum of all outstanding (not yet returned) allocations and MUST equal the sum of all `AllocationRecord.amount` values.

### 8.4 Authorization Rules

* Only the Primary Wallet Actor (verified by source address matching `primary_wallet`) may call `AllocateBudget` and `TreasuryTransfer`.
* Any registered Actor may call `ReturnBudget`, but only for budget IDs that were previously allocated to that Actor.
* If a Policy Actor is configured, the Treasury MUST forward policy-gated transfers to the Policy Actor for evaluation before execution. If the Policy Actor is unreachable or returns a deny verdict, the transfer MUST be rejected.

### 8.5 Get Methods

| Method | Signature | Returns |
|--------|-----------|---------|
| `get_treasury_data` | `() -> (slice, int, int, cell)` | primary_wallet, total_allocated, config_flags, pending_allocations |
| `get_allocation` | `(int budget_id) -> (slice, int, int)` | target_actor, amount, allocated_at |
| `get_balance` | `() -> int` | Current treasury contract balance |

## 9. Recovery Actor Specification

### 9.1 Purpose

The Recovery Actor handles emergency governance and owner recovery flows.

### 9.2 Core Interfaces

* **ProposeOwnerChange** -- `new_owner_pubkey:uint256  recovery_id:uint64`
* **FreezeWallet** -- `reason_code:uint16`
* **EnterRecoveryMode** -- `recovery_id:uint64`
* **CommitRecovery** -- `recovery_id:uint64`

### 9.3 Safety Requirements

Recommended recovery capability set: freeze, propose owner change, revoke sessions, switch wallet mode. Not recommended as default: arbitrary treasury drain, arbitrary actor reconfiguration without timelock.

### 9.4 Recovery State

```
primary_wallet:Address
guardian_set:HashmapE(guardian_id:uint16 -> GuardianRecord)
active_recovery:Maybe<RecoveryProposal>
recovery_config:RecoveryConfig
```

`GuardianRecord`:

```
pubkey:uint256  weight:uint16  added_at:uint32
```

`RecoveryProposal`:

```
recovery_id:uint64  new_owner_pubkey:uint256  proposed_at:uint32
approvals:HashmapE(guardian_id:uint16 -> approval_timestamp:uint32)
total_weight:uint16  required_weight:uint16  timelock_until:uint32
```

`RecoveryConfig`:

```
timelock_seconds:uint32  required_weight:uint16  max_guardians:uint16
```

### 9.5 Recovery Authorization Model

* **FreezeWallet** may be invoked by any single guardian. This is a safety-critical fast path -- no quorum required.
* **ProposeOwnerChange** requires a single guardian to initiate, but does not execute until the approval threshold is met and the timelock expires.
* **EnterRecoveryMode** requires guardian quorum (total approved weight >= required_weight).
* **CommitRecovery** may only be called after: (a) the timelock period has expired, (b) the approval threshold is met, and (c) the wallet is in RECOVERY mode.
* The Primary Wallet Actor verifies recovery requests by checking the source address against its registered ROLE_RECOVERY actor.

### 9.6 Recovery Sequencing

The full recovery flow proceeds in strict order:

1. Guardian calls `FreezeWallet` -> wallet enters LOCKED mode.
2. Guardian calls `ProposeOwnerChange` with new owner pubkey -> proposal recorded with timelock.
3. Additional guardians call `ProposeOwnerChange` with the same recovery_id to add their approval weight.
4. Once quorum is reached, any guardian calls `EnterRecoveryMode` -> wallet enters RECOVERY mode.
5. After timelock expiry, any guardian calls `CommitRecovery` -> Recovery Actor sends `ACT_COMMIT_OWNER` to Primary Wallet -> wallet applies new owner pubkey and returns to NORMAL mode.

If the existing owner regains access during the timelock period, they may cancel the recovery by calling `ACT_UNLOCK` from the Primary Wallet (requires valid owner signature). This resets the recovery state and returns the wallet to NORMAL mode.

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

### 10.3 Policy Determinism Requirements

The Policy Actor MUST be a deterministic function of its inputs and stored state. Given the same on-chain state and the same `EvaluateAction` message, the Policy Actor MUST return the same verdict. Side effects (e.g., updating a daily spend counter) are permissible only as part of the same transaction that produces the verdict.

The Policy Actor MUST NOT depend on external oracles, off-chain state, or randomness for verdict computation. Any policy rule that requires external data (e.g., price feeds) must use on-chain data committed before the evaluation transaction.

### 10.4 Policy Verdict Semantics

The `allowed:bool` and `policy_code:uint16` fields together encode four verdict types:

| Verdict | allowed | policy_code | Meaning |
|---------|---------|-------------|---------|
| ALLOW | true | 0x0000 | Action is permitted; execute immediately |
| DENY | false | 0x0001-0x00FF | Action is permanently denied for the stated reason |
| DELAY | true | 0x0100-0x01FF | Action is permitted but must wait `extra_delay` seconds before execution |
| REQUIRE_SECONDARY_APPROVAL | false | 0x0200-0x02FF | Action is denied pending secondary approval from a guardian or co-signer |

The Primary Wallet Actor interprets these verdicts as follows:

* **ALLOW**: execute the action immediately.
* **DENY**: reject the action and return ERR_POLICY_DENIED to the caller.
* **DELAY**: store the action in a pending queue and execute it after `extra_delay` seconds have elapsed, unless cancelled by the owner.
* **REQUIRE_SECONDARY_APPROVAL**: store the action in a pending queue and execute it only after an authorized secondary signer confirms it.

## 11. Session Authorization

### 11.1 Session Fields

```
session_pubkey:uint256  expires_at:uint32  spend_limit:Coins
allowed_roles_mask:uint64  allowed_dest_hash:Maybe<uint256>
nonce:uint32  flags:uint32
```

### 11.2 Session Rules

Sessions must be: created by owner authority, revocable by owner and recovery authority, limited by time, scope, and replay-protected nonce. Sessions are for low-risk automation, app-level delegation, frequent small operations, and temporary device authorization -- not full owner replacement.

### 11.3 Session Enforcement Boundary

Session authorization is enforced entirely within the Primary Wallet Actor. When a `SessionRequest` arrives, the wallet:

1. Verifies the session_pubkey exists in `session_root` and has not expired.
2. Verifies the session nonce matches the stored nonce for that session and increments it.
3. Verifies each action in the bundle is permitted by the session's `allowed_roles_mask`.
4. Verifies the total value of all actions does not exceed the session's remaining `spend_limit`.
5. If all checks pass, executes the actions as if they were owner-signed, but with the session's scope restrictions.

No Actor other than the Primary Wallet Actor needs to be aware of sessions. From the perspective of the Treasury, Recovery, and Policy Actors, a session-authorized message is indistinguishable from an owner-authorized message -- the Primary Wallet is the sender in both cases.

### 11.4 Session Failure Codes

| Code | Name | Meaning |
|------|------|---------|
| 0x0080 | ERR_SESSION_EXPIRED | Session has passed its `expires_at` timestamp |
| 0x0081 | ERR_SESSION_NONCE | Nonce mismatch (replay or stale) |
| 0x0082 | ERR_SESSION_SCOPE | Action not permitted by `allowed_roles_mask` |
| 0x0083 | ERR_SESSION_SPEND_LIMIT | Transfer value exceeds remaining session spend limit |
| 0x0084 | ERR_SESSION_NOT_FOUND | session_pubkey not present in `session_root` |
| 0x0085 | ERR_SESSION_INVALID_SIG | Session signature verification failed |

### 11.5 Session Revocation Semantics

Sessions can be revoked through three paths:

* **Owner revocation**: the owner sends `ACT_REVOKE_SESSION` via a `SignedRequest`. Immediate effect.
* **Recovery revocation**: the Recovery Actor sends `ACT_REVOKE_SESSION` via an `ExtensionRequest` with ROLE_RECOVERY. Immediate effect. This path is available even when the wallet is in LOCKED or RECOVERY mode.
* **Expiry**: the session's `expires_at` timestamp has passed. The session record MAY be garbage-collected lazily on the next wallet transaction, or eagerly by an explicit cleanup action.

Revocation is final. A revoked session_pubkey MUST NOT be re-added without a new `ACT_ADD_SESSION` request from the owner. Implementations SHOULD maintain a revocation counter or tombstone to prevent replay of old `ACT_ADD_SESSION` messages that reference a previously revoked session_pubkey.

## 12. Actor Registry

### 12.1 Registry as Source of Truth

The Actor Registry is the authoritative mapping from semantic roles to concrete Actor addresses within a Virtual Account. It is stored in the Primary Wallet Actor's `registry_root` Cell as a `HashmapE(uint16 -> Address)` keyed by `role_id`.

The registry is the single source of truth for Virtual Account topology. All intra-account authorization decisions (e.g., "is this message from my Treasury?") are resolved by comparing the sender address against the registry entry for the expected role. No Actor should hardcode another Actor's address -- always resolve through the registry.

### 12.2 Registry Mutation Rules

* **Register**: assigns an Actor address to an unoccupied role. Fails with ERR_ROLE_OCCUPIED if the role already has an entry.
* **Unregister**: removes the Actor address from a role. The role becomes unoccupied.
* **Replace**: atomically removes the existing Actor from a role and registers a new one. This is equivalent to unregister + register but executes in a single action to avoid a window where the role is unoccupied.
* **Lookup**: returns the Actor address for a given role_id, or null if unoccupied.
* **Enumerate**: returns all (role_id, actor_address) pairs in the registry.

Every mutation increments `registry_version`. The registry MUST reject mutations when the wallet is in FROZEN mode.

### 12.3 Role Cardinality

Each role_id maps to exactly one Actor address. There is no multi-actor-per-role support. If a use case requires multiple Actors for a logical function (e.g., multiple recovery guardians), the single registered Actor for that role acts as a coordinator and manages the sub-set internally.

Required roles: `ROLE_PRIMARY=0`, `ROLE_TREASURY=1`, `ROLE_POLICY=2`, `ROLE_RECOVERY=3`, `ROLE_PRIVACY=4`.

Role IDs 0-15 are reserved for protocol-defined roles. Role IDs 16-65535 are available for application-defined roles.

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

### 13.3 TokenMasterActor Interface

| Op | Name | Parameters | Auth |
|----|------|-----------|------|
| 0x0100 | `mint` | `to:Address  amount:Coins  memo:Maybe<Cell>` | Mint authority only |
| 0x0101 | `burn_notification` | `from:Address  amount:Coins  response_to:Address` | Any TokenBalanceActor |
| 0x0102 | `update_metadata` | `key:uint256  value:^Cell` | Admin authority only |
| 0x0103 | `discover_wallet` | `owner:Address` | Anyone (get method) |

Get methods: `get_jetton_data() -> (int total_supply, int mintable, slice admin, cell content, cell wallet_code)`, `get_wallet_address(slice owner) -> slice`.

### 13.4 TokenBalanceActor Interface

| Op | Name | Parameters | Auth |
|----|------|-----------|------|
| 0x0200 | `transfer` | `amount:Coins  to:Address  response_to:Address  forward_payload:Maybe<Cell>` | Owner or owner's Primary Wallet |
| 0x0201 | `internal_transfer` | `amount:Coins  from:Address  response_to:Address  forward_payload:Maybe<Cell>` | Peer TokenBalanceActor only |
| 0x0202 | `burn` | `amount:Coins  response_to:Address` | Owner or owner's Primary Wallet |

Get methods: `get_wallet_data() -> (int balance, slice owner, slice master, cell code)`.

### 13.5 Token Authorization Semantics

A TokenBalanceActor MUST verify that transfer and burn requests originate from the owner's Primary Wallet Actor address or from the owner's direct external message (for standalone wallets not using the Virtual Account pattern). The `internal_transfer` op MUST be accepted only from addresses whose code hash matches the expected TokenBalanceActor code hash -- this is the standard Jetton wallet discovery pattern.

V1 token implementation may reuse Jetton-compatible patterns where practical.

## 14. V1 Security Model

### 14.1 Wallet Security Domain

The Primary Wallet Actor is the security root of the Virtual Account. It MUST be:

* Minimal: only action dispatch, replay protection, registry management, and mode transitions.
* Deterministic: no randomness, no external oracle dependencies, no unbounded loops.
* Strongly replay-protected: seqno for owner requests, nonce for session requests.
* Mode-aware: actions are gated by the current wallet mode (NORMAL/LOCKED/RECOVERY/FROZEN).

### 14.2 Treasury Security Domain

The Treasury Actor is a separate fault domain from the Primary Wallet. Rules:

* No arbitrary budget requests without authentication (source address must match registered Primary Wallet).
* Policy Actor consultation is mandatory for transfers exceeding configurable thresholds.
* Budget allocations are tracked and auditable; unmatched returns are rejected.

### 14.3 Recovery Security Domain

The Recovery Actor is a narrowly scoped emergency mechanism. Rules:

* Recovery capabilities are limited to: freeze, propose owner change, revoke sessions, switch wallet mode.
* Arbitrary treasury drain and arbitrary actor reconfiguration without timelock are NOT recommended as default recovery capabilities.
* Guardian quorum and timelock provide defense-in-depth against compromised single guardians.

### 14.4 Policy Security Domain

The Policy Actor enforces risk rules deterministically. Rules:

* Policy verdicts are final for the transaction in which they are issued.
* The Policy Actor has no direct mutation authority over other Actors -- it only returns verdicts.
* A compromised or buggy Policy Actor can deny legitimate actions (liveness risk) but cannot authorize actions beyond the caller's existing permissions (safety preservation).

### 14.5 Session Security Domain

Sessions are a delegated, restricted subset of owner authority. Rules:

* Sessions are time-bounded, nonce-bound, and scope-bound.
* Session compromise does not compromise owner keys.
* Session revocation is immediate and available through both owner and recovery paths.

### 14.6 Cross-Actor Security Invariants

No V1 actor may assume synchronous finality of another actor's state update. Because all inter-actor communication is asynchronous (separate on-chain accounts, separate transactions), an actor that sends a message to another actor MUST NOT assume the message has been processed until it receives a confirmation reply. State reads across actors are always potentially stale.

Every specialized Actor is a separate fault domain. Compromise of one Actor (e.g., a buggy application Actor) does not propagate to other Actors unless the compromised Actor holds registry-level authority.

## 15. V1 Roadmap

### 15.1 Required Deliverables Per Phase

| Phase | Deliverables |
|-------|-------------|
| Phase 0: Spec Freeze | Finalize interfaces, freeze op codes, action encodings, role IDs; freeze wallet state layout; freeze error codes; freeze get method signatures; produce reference encoding test vectors |
| Phase 1: Wallet Core | `wallet_v6.fc` MVP, owner-signed requests, seqno, registry, lock/recovery modes, TS client, tests |
| Phase 2: Treasury & Recovery | Treasury Actor, Recovery Actor, Policy Actor MVP, budget allocation flow, recovery flow, cross-actor integration tests |
| Phase 3: Session & SDK | Session authorization, Virtual Account SDK abstraction, actor registry helper, one-address UX wrapper |
| Phase 4: Token Actors | TokenMasterActor, TokenBalanceActor, deployment scripts, mint/transfer/burn flows |
| Phase 5: Hardening | Audits, policy edge cases, guardian enhancements, SDK stabilization, documentation |

**Phase 0 Freeze Items:**

* Op codes: all action IDs in section 7.5 and token ops in sections 13.3-13.4
* Role IDs: Appendix A
* Error codes: sections 7.7 and 11.4
* State layouts: sections 7.3, 8.3, 9.4
* Get method signatures: sections 7.8, 8.5, 13.3, 13.4
* Action encoding rules: section 7.9
* Authentication matrix: section 7.6

### First Engineering Milestone

Complete when: deploy Primary Wallet -> deploy Treasury -> register in registry -> fund Treasury -> add session key -> owner transfer through treasury -> trigger recovery -> revoke session -> restore normal mode -> all integration tests pass.

## 15A. V1 Interface Freeze (Normative)

This section is normative for all V1 smart contract implementations.

If any descriptive text in earlier V1 sections conflicts with this section, this section takes precedence.

### 15A.1 Scope

This freeze applies to the following V1 modules:

- Primary Wallet Actor
- Treasury Actor
- Recovery Actor
- Policy Actor
- Session authorization
- Actor Registry
- TokenMasterActor
- TokenBalanceActor

### 15A.2 Message Schema Freeze

All V1 contract interfaces MUST use explicitly versioned and opcode-stable message schemas.

Each contract interface definition MUST specify:

1. opcode
2. request body schema
3. response body schema (if any)
4. failure / reject conditions
5. get methods
6. caller authorization rules

### 15A.3 Authorization Matrix Freeze

The following authorization matrix is the V1 baseline:

| Path | Authority Level | Allowed Operations |
|---|---|---|
| Owner SignedRequest | highest | all wallet-admin and routing actions |
| SessionRequest | limited | low-risk actions only, subject to session limits |
| ExtensionRequest | internal-only | only role-authorized actor-origin actions |
| RecoveryRequest | emergency/recovery | recovery mode, freeze, owner proposal, session revoke |

Any implementation that expands authority beyond this matrix MUST be explicitly documented and versioned.

### 15A.4 Required Wallet Get Methods

The Primary Wallet Actor MUST expose at least:

- `get_wallet_id`
- `get_seqno`
- `get_mode`
- `get_owner_pubkey`
- `get_pending_owner`
- `get_actor(role_id)`
- `get_session(session_pubkey)`

### 15A.5 Required Treasury Get Methods

The Treasury Actor MUST expose at least:

- `get_treasury_state`
- `get_budget_record(budget_id)`
- `get_wallet_actor`
- `get_policy_actor`

### 15A.6 Required Recovery Get Methods

The Recovery Actor MUST expose at least:

- `get_recovery_state`
- `get_guardian_set`
- `get_pending_recovery`
- `get_wallet_actor`

### 15A.7 Required Policy Get Methods

The Policy Actor MUST expose at least:

- `get_policy_state`
- `get_policy_version`
- `evaluate_preview(...)` or equivalent simulation-safe read method if supported

### 15A.8 Session Enforcement Baseline

V1 baseline rule:

> Session checks are enforced by the Primary Wallet Actor. Downstream Actors MAY perform secondary checks, but MUST NOT assume session validity unless explicitly passed and verified.

### 15A.9 Error Code Freeze

Each V1 contract MUST define stable error codes for at least:

- invalid signature
- invalid seqno / nonce
- expired request
- unauthorized caller
- unknown action
- locked mode violation
- frozen mode violation
- session expired
- session scope violation
- insufficient budget / balance
- policy denial

### 15A.10 Token Interface Freeze

The V1 token baseline MUST expose:

**TokenMasterActor:**
- `Mint`
- `Burn`
- `GetWalletAddress(owner)`
- `GetMetadata`
- `GetTotalSupply`

**TokenBalanceActor:**
- `Transfer`
- `Credit`
- `Burn`
- `GetBalance`

### 15A.11 Implementation Rule

Claude Code or any implementation workflow MUST treat this section as the authoritative V1 interface layer. No V1 module should be implemented from descriptive prose alone if this freeze section provides a more specific rule.

### 15A.12 V1 Unified Interface Reference Table

The following table is the single-lookup reference for all V1 contract interfaces. Each row defines one callable endpoint. The `Caller` column specifies who may invoke it. The `Section` column points to the detailed specification.

**Primary Wallet Actor** (`wallet_v6`):

| Op | Name | Caller | Request Schema | Response | Section |
|----|------|--------|---------------|----------|---------|
| 0x7369676E | SignedRequest | owner (external) | wallet_id:u32 seqno:u32 valid_until:u32 request_id:u64 actions:^Cell sig:b512 | none (actions executed) | 7.4 |
| 0x6578746E | ExtensionRequest | registered actor (internal) | role_id:u16 actions:^Cell | none (actions executed) | 7.4 |
| 0x7265636F | RecoveryRequest | recovery actor (internal) | subop:u8 payload:^Cell | none (action executed) | 7.4 |
| 0x73657373 | SessionRequest | session key (external) | session_pubkey:u256 session_nonce:u32 valid_until:u32 actions:^Cell sig:b512 | none (actions executed) | 7.4 |

Get methods: `get_wallet_id`, `get_seqno`, `get_mode`, `get_owner_pubkey`, `get_pending_owner`, `get_actor(role_id)`, `get_session(session_pubkey)` (see 15A.4).

**Treasury Actor**:

| Op | Name | Caller | Request Schema | Response | Section |
|----|------|--------|---------------|----------|---------|
| 0x616C6C6F | AllocateBudget | wallet actor (internal) | target_actor:Addr amount:Coins budget_id:u64 memo:Maybe<Cell> | ack/nack | 8.2 |
| 0x72657462 | ReturnBudget | any registered actor (internal) | source_actor:Addr amount:Coins budget_id:u64 memo:Maybe<Cell> | ack | 8.2 |
| 0x74786672 | TreasuryTransfer | wallet actor (internal) | dest:Addr amount:Coins memo:Maybe<Cell> | ack/nack (may consult Policy) | 8.2 |
| 0x00000000 | ReceiveFunds | any (internal/external) | (empty or metadata) | none (balance credited) | 8.2 |

Get methods: `get_treasury_state`, `get_budget_record(budget_id)`, `get_wallet_actor`, `get_policy_actor` (see 15A.5).

**Recovery Actor**:

| Op | Name | Caller | Request Schema | Response | Section |
|----|------|--------|---------------|----------|---------|
| 0x70726F70 | ProposeOwnerChange | guardian (external/internal) | new_owner_pubkey:u256 recovery_id:u64 | ack | 9.2 |
| 0x667265657A | FreezeWallet | any guardian (external/internal) | reason_code:u16 | -> wallet LOCKED | 9.2 |
| 0x656E7265 | EnterRecoveryMode | guardian quorum (internal) | recovery_id:u64 | -> wallet RECOVERY | 9.2 |
| 0x636F6D6D | CommitRecovery | guardian (after timelock) | recovery_id:u64 | -> wallet new owner | 9.2 |

Get methods: `get_recovery_state`, `get_guardian_set`, `get_pending_recovery`, `get_wallet_actor` (see 15A.6).

**Policy Actor**:

| Op | Name | Caller | Request Schema | Response | Section |
|----|------|--------|---------------|----------|---------|
| 0x6576616C | EvaluateAction | wallet or treasury (internal) | request_type:u16 request_id:u64 origin:Addr target:Addr value:Coins context:^Cell | verdict:u8 policy_code:u16 delay:u32 memo:Maybe<Cell> | 10.2 |

Verdict values: `0x01`=allow, `0x02`=deny, `0x03`=delay, `0x04`=require_secondary_approval.

Get methods: `get_policy_state`, `get_policy_version` (see 15A.7).

**TokenMasterActor**:

| Op | Name | Caller | Request Schema | Section |
|----|------|--------|---------------|---------|
| 0x6D696E74 | Mint | authorized minter | to:Addr amount:Coins | 13.3 |
| 0x6275726E | Burn | authorized burner | from:Addr amount:Coins | 13.3 |

Get methods: `GetWalletAddress(owner)`, `GetMetadata`, `GetTotalSupply` (see 15A.10).

**TokenBalanceActor**:

| Op | Name | Caller | Request Schema | Section |
|----|------|--------|---------------|---------|
| 0x74786672 | Transfer | owner wallet (internal) | to:Addr amount:Coins | 13.4 |
| 0x63726564 | Credit | sender's TokenBalanceActor (internal) | from:Addr amount:Coins | 13.4 |
| 0x6275726E | Burn | owner wallet or master (internal) | amount:Coins | 13.4 |

Get methods: `GetBalance` (see 15A.10).

---

# Part III — V2: Protocol-Native Actor Execution

## 16. V2 Purpose and Prerequisites

V1 proves that actor-oriented architecture can be built on top of the existing protocol. V2 defines the next step: **make Actors protocol-native execution objects, and make Accounts protocol-native containers.**

V2 assumes V1 is already deployed and validated. That means: Primary Wallet / Treasury / Recovery / Policy role separation already exists, actor registry semantics are established, developer familiarity with actor-oriented contract design is in place. V2 does not redefine those concepts — it makes them protocol-native.

V2 MUST NOT begin implementation before the V2 Spec Freeze Checklist in Appendix D is fully resolved.

### Architectural Transition

```
V1:                                    V2:
Virtual Account                        Account Container
 +-- Wallet Actor  (= Account A)        +-- shared_balance
 +-- Treasury Actor (= Account B)       +-- Wallet Actor
 +-- Recovery Actor (= Account C)       +-- Recovery Actor
 +-- Policy Actor   (= Account D)       +-- Policy Actor
 +-- Token / App Actors (= separate)    +-- Token / App Actors
```

V2 is a **protocol-level redesign**. It requires changes to: block format, account serialization, transaction execution, validation logic, message routing, Merkle proofs, and client tooling. The Cell/BOC encoding format itself is unchanged — only the semantic structure stored in Cells changes.

## 17. Account Container Model

### 17.1 Account Container State

```
AccountContainer
 +-- last_trans_lt:uint64
 +-- shared_balance:CurrencyCollection
 +-- actors:HashmapE(actor_id -> ActorDescriptor)
 +-- account_flags:uint32
 +-- registry_root:Cell                <- actor registry (role_id -> actor_id) for intra-container discovery
 +-- container_status:ContainerStatus  <- active or frozen (NOT AccountState; see 17.3)
```

The `registry_root` carries the same semantic role as the V1 Actor Registry but is now stored at the container level rather than inside an individual actor's state. This enables the protocol to resolve role-based addressing without entering any actor's execution context.

### 17.2 Actor Descriptor

```
ActorDescriptor
 +-- state_root:HashmapE / Cell      <- actor-local KV state
 +-- budget:CurrencyCollection       <- actor-local working balance
 +-- actor_lt:uint64                 <- actor-local logical time
 +-- behavior_ref:Cell / code_ref    <- actor-local behavior binding
 +-- actor_flags:uint32
```

Each Actor has its own `behavior_ref` rather than sharing a single global code Cell. This is the baseline binding model: each actor carries an actor-local `behavior_ref` that points to its code. This is more faithful to Actor identity, enables cleaner modularity, and smooths the transition from V1 where each Actor is already an independent contract with its own code.

The `behavior_ref` binding model is a decided design choice. Per-actor `behavior_ref` is the baseline. A shared behavior registry is **explicitly not part of the V2 baseline**. Any future introduction of a behavior registry MUST be treated as a separate protocol extension with its own specification, freeze checklist, and transition rules. V2 implementations MUST NOT assume or depend on a registry existing.

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
    registry_root:^Cell
    container_status:ContainerStatus
  = AccountStorage;

container_status_active$1 = ContainerStatus;
container_status_frozen$01 state_hash:bits256 = ContainerStatus;
```

Legacy accounts use the existing `account_storage$_` tag with `AccountState` (which carries `code`, `data`, `library` semantics). Actor-mode accounts use `account_storage_actor$_` with `ContainerStatus` instead of `AccountState`.

**Why `ContainerStatus` replaces `AccountState` in actor-mode:** In legacy accounts, `AccountState` holds code/data/library for the single execution unit. In actor-mode, each Actor has its own `behavior_ref` (code) and `state_root` (data) inside the `ActorDescriptor`. Reusing `AccountState` in actor-mode would create a canonical state ambiguity: the container-level `AccountState.code` would conflict with each actor's `behavior_ref`, and `AccountState.data` would conflict with each actor's `state_root`. `ContainerStatus` carries only the container's lifecycle status (active or frozen), not execution-level code/data. This distinction is critical for parser correctness, validator replay, proof verification, and lite-client interpretation.

### 17.4 Protocol Change Summary

| Component | Change Required |
|-----------|----------------|
| Account state layout | Add `actors` HashmapE (state + budget + actor_lt + behavior_ref per actor), replace `balance` with `shared_balance`, add `registry_root` |
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

ACTORSENDX is outside the baseline V2 implementation scope. It will be specified as a separate protocol extension after the intra-account actor model is validated.

### 18.3 ActorAddress Canonical Encoding

The canonical serialization of an `ActorAddress` for hashing, signing, and external representation is:

```
workchain:int8  account_id:bits256  actor_id:bits256
```

Total: 521 bits (8 + 256 + 256). For human-readable encoding, the format is:

```
<workchain>:<account_id_hex>/<actor_id_hex>
```

Example: `0:a1b2...f3/00aa...bb`. When `actor_id` is zero (legacy account or account-level addressing), the `/<actor_id_hex>` suffix is omitted, preserving compatibility with the V1 address format.

## 19. Hybrid Balance Model

### 19.1 Design Rationale

If two Actors under the same Account shared a single balance and executed in parallel, they would concurrently modify the shared balance, producing a non-deterministic result. A pure reservation model solves this but adds significant complexity. A fully per-actor balance eliminates contention but fragments capital and complicates storage fee attribution.

**Solution: hybrid balance model** — each Actor has its own `budget` for gas and value transfers, while the Account retains a `shared_balance` for storage fees, inbound value staging, and inter-actor fund movement.

```
Account Container
 +-- shared_balance: 2 TOS          <- storage fees, inbound value, inter-actor pool
 +-- actor_0: { state, budget: 3 TOS, actor_lt }
 +-- actor_1: { state, budget: 5 TOS, actor_lt }
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

This ensures compatibility: V1 wallets sending to an Account address without specifying an actor_id still work.

If a message targets a specific `actor_id` that does not exist in the account's actor dictionary, the message is bounced. The collator MUST NOT create a transaction for a nonexistent actor. This prevents value from being silently absorbed into an unreachable actor budget.

### 19.4 Storage Fee Attribution

Storage fees are charged at the **account level**, not per-actor:

* The total Cell tree size (including all Actor states) determines the storage fee.
* Storage fees are deducted from `shared_balance` during Phase 2.
* If `shared_balance` is insufficient, the Account enters the standard freeze/deletion path — all Actors are affected.
* Actors are expected to periodically `ACTORRELEASE` surplus budget back to `shared_balance`. The protocol may enforce a minimum `shared_balance` threshold.

Storage fees are charged once per account-container finalization, not once per committed actor result. Multiple actor transactions within the same block produce a single storage fee deduction during Phase 2, computed from the final aggregate state size after all actor commits.

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

### 20.6 Deterministic Tertiary Ordering

The primary sort key for Phase 2 merge is `(actor_id ASC, actor_lt ASC)`. When two speculative results have the same `actor_id` and the same `actor_lt` (which should not occur under correct collator behavior, but must be handled for deterministic validation), the tiebreaker is the hash of the inbound message that triggered the transaction, compared as unsigned 256-bit integers in ascending order.

```
ORDER BY (actor_id ASC, actor_lt ASC, inbound_msg_hash ASC)
```

This ensures that even a buggy or adversarial collator that produces duplicate `actor_lt` values for the same actor cannot create ambiguous merge order. Validators use this tertiary key during replay to verify deterministic equivalence.

### 20.7 Canonical vs Tentative Artifacts

| Artifact | Phase 1 Status | Phase 2 Status |
|----------|---------------|---------------|
| Actor state root | Tentative | Canonical (if committed) |
| Actor budget | Tentative | Canonical (if committed) |
| actor_lt | Tentative | Canonical (if committed) |
| Outbound messages | Tentative (not in queue) | Canonical (materialized into OutMsgQueue) |
| ACTORCLAIM/ACTORRELEASE | Intent (not applied) | Applied to shared_balance (if committed) |
| Account-level lt | Not assigned | Assigned |
| Transaction hash | Not assigned | Assigned |
| Storage fee deduction | Not computed | Computed and applied |

No tentative artifact may be referenced by any external system or proof until it transitions to canonical status via Phase 2 commit.

### 20.8 Canonical Actor Transaction Record (Normative)

After Phase 2 commits a speculative result, the following canonical actor transaction record MUST be constructed. This is the on-chain, provable, externally-visible transaction object for actor-mode transactions.

```
ActorTransaction
 +-- account_addr:bits256          <- account container address
 +-- actor_id:bits256              <- target actor within the container
 +-- actor_lt:uint64               <- actor-local logical time (Phase 1, stable)
 +-- final_lt:uint64               <- account-global logical time (assigned in Phase 2)
 +-- final_lt_end:uint64           <- account-global end logical time
 +-- tx_hash:bits256               <- canonical transaction hash (computed after Phase 2)
 +-- prev_tx_hash:bits256          <- previous transaction hash for this actor
 +-- prev_tx_lt:uint64             <- previous transaction lt for this actor
 +-- execution_status:uint8        <- 0=success, 1=revert, 2=exception
 +-- exit_code:int32               <- VM exit code (0 if success)
 +-- gas_used:uint64               <- gas consumed during Phase 1 compute
 +-- total_fees:CurrencyCollection <- total fees (gas + forwarding)
 +-- state_hash_before:bits256     <- actor state root hash before execution
 +-- state_hash_after:bits256      <- actor state root hash after execution
 +-- budget_before:CurrencyCollection  <- actor budget before execution
 +-- budget_after:CurrencyCollection   <- actor budget after execution
 +-- balance_requests:HashmapE(uint64 -> BalanceRequest)  <- ACTORCLAIM/ACTORRELEASE intents
 +-- in_msg:Maybe<^Message>        <- inbound message that triggered this transaction
 +-- out_msgs:HashmapE(uint15 -> ^Message)  <- outbound messages (materialized in Phase 2)
 +-- out_msg_count:uint15          <- number of outbound messages
```

`BalanceRequest`:

```
balance_request_claim$0 amount:Coins = BalanceRequest;
balance_request_release$1 amount:Coins = BalanceRequest;
```

**Usage by subsystems:**

| Subsystem | Fields consumed |
|-----------|----------------|
| Block explorer | account_addr, actor_id, final_lt, tx_hash, execution_status, gas_used, in_msg, out_msgs |
| Lite-client transaction query | All fields; returned as proof-backed response |
| Validator replay | All fields; compared against re-execution result |
| Merkle proof | tx_hash, state_hash_before/after as proof anchors |
| SDK / wallet | execution_status, budget_before/after, balance_requests, out_msg_count |

This record structure MUST be frozen before V2 implementation begins (see 30A.5).

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

### 21.3 Getter/Opcode Compatibility Matrix

V2 baseline returns sentinel values for forbidden reads unless explicitly marked trap-only. The following table defines the behavior for each relevant TVM instruction when executed in actor-mode Phase 1:

| Instruction | Legacy Behavior | Actor-Mode Phase 1 Behavior | Notes |
|-------------|----------------|----------------------------|-------|
| GETBALANCE | Returns account balance | Returns actor `budget` | Semantic change: actor-local only |
| LTIME | Returns `last_trans_lt` | Returns `actor_lt` | Actor-local logical time |
| TXHASH | Returns last transaction hash | Returns 0x00 (sentinel) | Final hash not yet assigned |
| GETPARAM(5) | Returns account lt | Returns `actor_lt` | Aliased to actor-local |
| GETPARAM(7) | Returns account balance | Returns actor `budget` | Aliased to actor-local |
| GETPARAM(8) | Returns account address | Returns account address (unchanged) | Account-level, not actor-level |
| GETPARAM(18) | N/A (new) | Returns `actor_id` | New c7 tuple slot |
| RANDSEED | Returns random seed | Returns random seed (unchanged) | Deterministic from block seed |
| BLOCKLT | Returns block lt | Returns block lt (unchanged) | Block-level, not account-level |
| NOW | Returns unix timestamp | Returns unix timestamp (unchanged) | Block-level |

Contracts that depend on TXHASH for logic (rare but possible) MUST be rewritten for actor-mode. The sentinel value 0x00 is chosen to be obviously invalid rather than silently wrong.

## 22. Actor Logical Time Model (Normative)

### 22.1 actor_lt

Each Actor maintains its own monotonic `actor_lt` counter, independently of the account-level `last_trans_lt`.

**Phase 1:** The collator reads the current `actor_lt` and increments it to produce a tentative value. This value is stable within Phase 1. If multiple messages target the same Actor in one block, they are serialized per-actor with distinct ascending `actor_lt` values. `actor_lt` is used as the secondary sort key for the deterministic merge: `ORDER BY (actor_id ASC, actor_lt ASC)`.

**Phase 2:** The merge phase iterates results in `(actor_id, actor_lt)` order. For each committed result, Phase 2 assigns a final account-level logical time from the account's global lt counter. The final account-level lt is strictly monotonically increasing across all committed transactions.

The merge engine MUST use account-global final lt only after a speculative result has passed Phase 2 acceptance. No final lt value is assigned to a result that will be rejected; the global lt counter is not advanced for rejected results.

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

Using the 0xFB09-0xFB0F range (currently unoccupied). All gated behind `->require_version(N)` for the protocol upgrade version.

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

The c7 tuple layout for actor-mode is frozen at the following indices:

| Index | Content |
|-------|---------|
| 0-17 | Standard TVM c7 layout (unchanged) |
| 18 | `actor_id:uint256` |

No additional c7 indices are allocated in the V2 baseline. Future extensions MUST use indices >= 19.

The c6 register lifecycle is frozen as follows: c6 is initialized with the actor's `state_root` HashmapE at the start of Phase 1 compute. After compute completes, the c6 value is captured as the tentative post-state. If the transaction is committed in Phase 2, c6 becomes the new canonical `state_root`. If rejected, c6 is discarded.

The new opcodes (0xFB09-0xFB0F) are valid only in actor-mode execution. If a legacy-mode (non-actor) contract attempts to execute any of these opcodes, the VM MUST throw an invalid-opcode exception. This is enforced by the `require_version(N)` gate and additionally by a runtime check that the account is in actor-mode.

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

ACTORSEND failure semantics: if `ACTORSEND` targets an `actor_id` that does not exist within the same account container, the action is recorded in Phase 1 but rejected during Phase 2 action materialization. The entire transaction for the sending actor is rejected (rollback rule applies). Contracts SHOULD verify actor existence via registry lookup before sending.

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

Storage fees in Phase 2 are computed once per account-container finalization, not once per committed actor result. The `apply_storage_fees(account)` call above is executed once after all actor results have been processed, not inside the per-result loop. The pseudocode above is simplified for clarity.

### 24.2 Hybrid Handling

During the V1-to-V2 transition, the collator must support both legacy accounts (serial execution) and actor-mode accounts (two-phase execution) in the same block.

### 24.3 Same-Block Visibility Enforcement

The collator MUST enforce the same-block visibility rule (section 20.5) by partitioning inbound messages into two categories before Phase 1 begins:

1. **Pre-existing messages**: messages that were in the InMsgQueue before this block's processing started. These are eligible for Phase 1 execution.
2. **Newly emitted messages**: messages produced by actor transactions within the current block. These MUST NOT be delivered to any actor in the current block.

The collator achieves this by freezing the set of deliverable messages at the start of block production. Any `ACTORSEND` output produced during Phase 1 is added to the OutMsgQueue for the next block but is not added to the current block's deliverable set.

## 25. Validator Redesign

Validators must be able to replay actor-mode Phase 1 execution and Phase 2 merge, producing identical results. They must verify:

1. `actor_lt` monotonicity per actor
2. Deterministic merge ordering
3. Prefix commit correctness
4. Balance transfer correctness against `shared_balance`
5. `shared_balance` solvency after all operations
6. Same-block visibility rules (no same-block actor message consumption)
7. Canonical transaction outputs match

### 25.1 Replay Equivalence Requirement

A validator's replay of any actor-mode block MUST produce bit-identical canonical state for every committed actor, bit-identical OutMsgQueue entries, and bit-identical account-level fields (shared_balance, last_trans_lt, last_trans_hash). If the validator's replay diverges from the collator's block in any of these fields, the block MUST be rejected.

This requirement implies that the Phase 2 merge algorithm, storage fee computation, and final lt assignment are fully deterministic given the set of Phase 1 results and the pre-block account state. No collator-local randomness, timing, or ordering heuristic may influence the canonical output.

## 26. OutMsgQueue Key Extension

```
Old: workchain(32) | shard_prefix(64) | msg_hash(256)                    = 352 bits
New: workchain(32) | shard_prefix(64) | actor_id(256) | msg_hash(256)    = 608 bits
```

Both `actor_id` and `msg_hash` are kept at full 256 bits. For non-actor messages, `actor_id` is zero-filled to preserve sort order compatibility. This changes the key length constant in `output-queue-merger.h:30` and affects all queue sorting, merging, and routing logic.

The test suite MUST include a golden sort-order test that verifies the following properties:

1. Legacy messages (actor_id = 0x00...00) sort before all actor messages for the same shard prefix.
2. Actor messages sort by actor_id first, then by msg_hash within the same actor_id.
3. The 608-bit key round-trips correctly through pack/unpack.
4. Queue merge across shards produces the same ordering as a single-shard sort of the union.

Key examples:

```
Key A: wc=0 | shard=0x8000 | actor_id=0x00..00 | msg_hash=0xAA..AA  (legacy)
Key B: wc=0 | shard=0x8000 | actor_id=0x00..01 | msg_hash=0x11..11  (actor)
Key C: wc=0 | shard=0x8000 | actor_id=0x00..01 | msg_hash=0xFF..FF  (actor, same actor_id as B)
Key D: wc=0 | shard=0xC000 | actor_id=0x00..00 | msg_hash=0x22..22  (different shard)

Expected order: A < B < C < D
```

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

### 27.1 Actor Proof Query Model

Lite-clients request actor proofs using the `getActorState` query (see Module H). The response includes:

1. A Merkle proof from the block root to the account container.
2. A Merkle proof from the account container to the actor dictionary entry.
3. A Merkle proof from the actor descriptor to the requested state key (if a specific key is requested).

Each proof layer is independently verifiable. A client that already has a verified account container proof can request only the actor-level proof for subsequent queries, reducing bandwidth.

Legacy proof queries (`getAccountState`) continue to work for actor-mode accounts. They return the full account container state (including all actors) as a single proof. This is less efficient but ensures compatibility with clients that have not yet been updated to understand actor-level proofs.

## 28. Execution Paths

Two execution paths, sharing the same state interface (vm::Dictionary / HashmapE):

| Path | For | Performance | Safety |
|------|-----|-------------|--------|
| Native C++ | Built-in/system actors | Fastest | Trusted (ships with node) |
| TVM | User-deployed contracts | Medium | TVM sandbox |

Both execution paths MUST produce semantically equivalent results for the same actor state and inbound message. The Native C++ path is an optimization, not a semantic divergence. Any discrepancy between the two paths for the same input is a consensus-critical bug.

## 29. V2 Risks

1. **Protocol upgrade complexity** — requires coordinated upgrade of all validators, lite-clients, SDKs, and explorers
2. **Two-phase execution correctness** — Phase 1/Phase 2 boundary must be correctly enforced; incorrect isolation breaks consensus
3. **Balance fragmentation** — per-actor budgets may lead to idle capital; need policies for minimum `shared_balance`
4. **Shared balance overdraw** — multiple Actors issuing `ACTORCLAIM` in the same block may collectively overdraw; Phase 2 must reject deterministically
5. **Prefix rejection cascades** — rejecting one speculative result forces rejection of later same-Actor results, reducing throughput in pathological cases
6. **Validation complexity** — validate-query.cpp (7674 lines) needs significant changes; actor-level proofs add new attack surface
7. **State transition** — deployed V1 contracts must transition to V2 containers; requires a transition protocol
8. **Client compatibility** — all wallets, SDKs, and block explorers must upgrade
9. **Behavior binding lock-in** — per-actor `behavior_ref` as baseline means every actor carries its own code reference; if the ecosystem later converges on shared behaviors, transitioning to a behavior registry requires a non-trivial protocol extension and potential state migration of deployed contracts
10. **Transition aliasing** — V1 actors (separate accounts) transitioned into a single V2 container may create address aliasing issues if external systems cache the old per-account addresses; the forwarding shell strategy (section 31.4) mitigates this but does not eliminate it for all cases

## 30. V2 Open Questions

1. **Initial budget allocation:** When an Actor is first created, what is its initial budget? Zero (must ACTORCLAIM first)? Or does the creation message's value seed it?
2. **ACTORCLAIM conflict resolution:** Whole-transaction rejection is recommended over partial claim failure. Is that too restrictive for practical contract patterns?
3. **Minimum shared_balance policy:** Protocol-enforced minimum to cover N blocks of storage fees, or left to contract logic?
4. **Cross-account Actor messages:** `ACTORSEND` is intra-account only. Future `ACTORSENDX` needs design for cross-account / cross-shard delivery.
5. **Actor lifecycle:** Can Actors be destroyed? Remaining `budget` auto-released to `shared_balance`?
6. **V1/V2 coexistence period:** How long do legacy and actor-mode formats run in parallel?
7. **Actor count limits:** Maximum Actors per Account? Storage cost model for actor metadata?
8. **VM forbidden-field enforcement:** Hard-trap vs sentinel when actor-mode code reads Phase-2-only fields?
9. *(Resolved -- see section 17.2: per-actor behavior_ref is the baseline binding model.)*
10. **Transition address alias strategy:** When deployed V1 actors (each with their own account address) are transitioned into a single V2 container, how are the old addresses handled? Options: forwarding shell, protocol-level alias table, or deprecation with grace period. See section 31.4 for the recommended baseline.
11. **Targeted message to unknown actor:** When a message targets a specific actor_id that does not exist, should the message bounce, be absorbed into shared_balance, or trigger auto-creation of a default actor? Current baseline: bounce (see section 19.3).

## 30A. V2 Spec Freeze (Required Before Coding)

This section defines the minimum freeze conditions required before any V2 protocol implementation begins.

V2 coding MUST NOT begin until all items in this section are resolved and marked frozen.

If any descriptive text in Part III conflicts with this section, this section takes precedence.

### 30A.1 Frozen Baseline Decisions

The following baseline decisions are fixed for V2 unless explicitly amended by a later version of this document:

**A. Behavior Binding** — V2 baseline uses **actor-local `behavior_ref`**. This is the canonical V2 behavior model. Account-wide shared code as the only model and behavior registry as the mandatory default are NOT baseline. Behavior registry MAY be introduced later as an optimization layer.

**B. Execution Model** — V2 baseline uses: actor-local Phase 1 tentative execution, account-container Phase 2 deterministic merge, no same-block actor-to-actor re-entry, no protocol-level synchronous actor calls.

**C. Queue Key** — V2 baseline queue key includes: workchain, shard prefix, actor_id, msg_hash.

**D. Storage Fee Rule** — V2 baseline charges storage fees once per account-container finalization, not once per committed actor result.

**E. Container State Model** — V2 actor-mode uses `ContainerStatus` (active/frozen) instead of `AccountState`. Per-actor code/data is carried in `ActorDescriptor.behavior_ref` and `ActorDescriptor.state_root`, not in container-level fields.

### 30A.2 ActorDescriptor Freeze

The ActorDescriptor schema MUST be finalized before coding begins. At minimum, the following fields MUST be frozen:

- `state_root`
- `budget`
- `actor_lt`
- `behavior_ref`
- `actor_flags`

No implementation may treat ActorDescriptor as partially open-ended during execution-layer development.

### 30A.3 ActorAddress Freeze

The following MUST be frozen:

1. binary format
2. text format
3. actor_id size
4. actor_id derivation rule
5. container-level vs actor-level addressing distinction

### 30A.4 VM Context Compatibility Matrix Freeze

Before V2 coding begins, a full compatibility matrix MUST be frozen for: getters, runtime fields, message metadata, account-global values, actor-local values, forbidden fields.

For each item, the matrix MUST specify:

1. legacy behavior
2. V2 Phase 1 behavior
3. V2 canonical behavior
4. trap / sentinel / actor-local remap rule

### 30A.5 Canonical Actor Transaction Freeze

A canonical V2 actor transaction record MUST be frozen before coding begins. At minimum, the record MUST define:

- `account_addr`
- `actor_id`
- `actor_lt`
- `final_lt`
- `tx_hash`
- `execution_status`
- `gas_used`
- `state_before` / `state_after` reference model
- `budget_before` / `budget_after` reference model
- `balance_request_summary`
- `out_msg_refs`

### 30A.6 Merge Ordering Freeze

The V2 merge engine MUST use a frozen deterministic ordering rule. The following MUST be frozen:

1. primary key
2. secondary key
3. tertiary tie-breaker
4. rejection propagation rules
5. prefix commit rules

### 30A.7 Same-Block Visibility Freeze

The following baseline rule is frozen:

> Messages emitted by an Actor during block N are not executable by another Actor until block N+1.

This rule applies to both collator behavior and validator replay.

### 30A.8 Implementation Gating Rule

The following modules MUST NOT begin implementation before this section is fully frozen:

- V2 execution engine
- V2 collator flow
- V2 validator replay
- V2 queue changes
- V2 proof changes
- V2 client actor APIs

### 30A.9 Required Freeze Outputs

Before coding starts, the following artifacts MUST exist:

- frozen TL-B diff
- frozen ActorAddress spec
- frozen VM compatibility matrix
- frozen canonical actor transaction schema
- frozen merge ordering rule
- frozen queue key layout
- frozen storage fee rule
- frozen same-block visibility rule

---

# Part IV — V1 to V2 Transition Path

## 31. Transition Strategy

This section defines how V1 contracts deployed on the live network transition to V2 actor containers once V2 protocol support is implemented. The protocol itself does not need migration -- V2 can be designed in from the start. However, V1 contracts that are already deployed when V2 becomes available will need a transition path to take advantage of protocol-native actor containers.

### 31.1 Transition Mapping

| V1 | V2 |
|----|-----|
| Wallet Actor = independent Account A | Wallet Actor = actor inside Account Container |
| Treasury Actor = independent Account B | Treasury Actor = actor inside same container |
| Recovery Actor = independent Account C | Recovery Actor = actor inside same container |
| Token / App Actors = separate Accounts | Token / App Actors = actors inside containers |

### 31.2 Transition Options

* **Option A: New Accounts Only** — only newly created accounts use actor-mode. Recommended initial strategy.
* **Option B: Opt-In Transition** — deployed V1 actor sets may transition into actor containers via explicit transition procedures.
* **Option C: Full Network Transition** — all accounts eventually move to actor-mode. Long-term goal.

### 31.3 What V1 Concepts Carry Forward

The following from V1 remain valid and should be reused in V2:

* Virtual Account abstraction
* Wallet / Treasury / Recovery / Policy role decomposition
* Session semantics
* Actor-oriented token patterns
* Actor registry semantics
* User-facing one-address UX

Only the **protocol placement** of those concepts changes.

### 31.4 Address Compatibility Strategy

When deployed V1 actors transition from separate accounts into a single V2 container, the old per-account addresses must be handled. Three options:

| Option | Mechanism | Pros | Cons |
|--------|-----------|------|------|
| Forwarding shell | Leave a minimal contract at the old address that forwards all messages to the new ActorAddress inside the container | Inbound compatibility for old addresses; no protocol change needed | Gas overhead per forwarded message; old addresses remain occupied; receiving actors must implement wrapper verification; outbound sender identity NOT preserved (see 31.4.2) |
| Protocol-level alias table | The protocol maintains a mapping from old addresses to new ActorAddresses | Zero-overhead forwarding; clean semantics | Requires additional protocol change; alias table is unbounded |
| Deprecation with grace period | Old addresses stop working after a defined grace period; clients must update | Simplest long-term; no permanent overhead | Breaking change; requires coordinated client update |

**Recommended baseline: forwarding shell.** This requires no additional protocol changes, preserves inbound compatibility for legacy addresses, and can be implemented as a standard V1 contract deployed before or during the transition. The forwarding shell contract stores the target `ActorAddress` and re-routes all inbound messages (including value) to the container.

The gas overhead of forwarding is bounded (one additional message hop per forwarded message) and decreases over time as clients update to the new addresses.

### 31.4.1 On-Chain Message Compatibility Rules (Normative)

When a deployed V1 actor set transitions into a V2 container, the following rules govern message handling for old addresses:

1. **Forwarding shell behavior:** The forwarding shell deployed at the old V1 address MUST: (a) accept all inbound internal and external messages, (b) re-emit each message as an internal message to the corresponding `ActorAddress` inside the V2 container, preserving the original message body and attached value (minus forwarding gas), (c) include the original sender address in a wrapper cell so the target actor can authenticate the true source.

2. **Token contract references:** V1 `TokenBalanceActor` contracts that reference the old Wallet or Treasury address (e.g., for transfer authorization) MUST continue to work through the forwarding shell. The forwarding shell re-routes the authorization message; the actor inside the container sees a message from the forwarding shell address and MUST accept it as equivalent to a message from the original V1 address. This is achieved by having the container-level registry map old V1 addresses to their corresponding actor_ids, enabling the receiving actor to verify provenance.

3. **Third-party app references:** dApps and other contracts that hold the old V1 address as a **destination-only** stored reference (i.e., they send messages to it but do not authenticate it as a sender) will continue to function through forwarding shells without code changes to the third-party contract itself. However, if the third-party contract authenticates the old address as a message sender (callback verification, access control), compatibility requires either wrapper verification on the receiving side or updating the third-party contract to recognize the new container address. See rule 6 below for the full compatibility scope.

4. **Forwarding shell lifecycle:** Forwarding shells SHOULD remain active until monitoring shows that <1% of inbound messages use the old address over a sustained period. The shell may then be frozen or replaced with a permanent redirect bounce message indicating the new address.

5. **Reverse path:** When a transitioned actor inside a V2 container sends a message to an external address, the message originates from the container's account address (not the old V1 address). Recipients MUST be notified of the address change through off-chain channels (SDK updates, explorer annotations, wallet metadata).

6. **Compatibility scope:** Old-address inbound compatibility through forwarding shells is **not pure infrastructure compatibility** — it is **application-protocol compatibility**. The forwarding shell includes the original sender in a wrapper cell, and the receiving actor inside the V2 container must implement shell-wrapper verification to authenticate provenance. Therefore, old-address compatibility is only effective for transitioned actors that have been updated (or were originally written) to understand and verify the wrapper format. Actors that do not implement wrapper verification will see the forwarding shell address as the sender, not the original caller. Transition tooling MUST flag actors that lack wrapper verification as "inbound-compatibility-incomplete."

### 31.4.2 Outbound Identity Compatibility Rule (Normative)

Forwarding shells solve **inbound** compatibility for old V1 addresses, but they do
not automatically preserve **outbound sender identity**. Therefore the protocol and
transition tooling MUST distinguish two compatibility classes:

1. **Inbound-only compatibility**
   Old addresses continue to receive messages through forwarding shells.

2. **Bidirectional identity compatibility**
   External systems not only send to the old address, but also expect replies,
   callbacks, or authorization messages to appear as if they originated from that
   same old address.

The baseline V2 transition guarantee is **inbound-only compatibility**. Full
bidirectional identity preservation is **NOT guaranteed by default**.

The following rules apply:

1. **Canonical sender after transition:** Once an actor is transitioned into a V2 account
   container, its canonical outbound sender is the **container account address**.
   The protocol does not spoof old V1 addresses as native outbound senders.

2. **No protocol-level sender aliasing in baseline V2:** The base protocol MUST NOT
   introduce an implicit alias table that rewrites outbound sender identity from the
   container address back to legacy V1 addresses. Such aliasing, if ever desired,
   requires a separate protocol extension.

3. **Compatibility promise to external integrations:** A transitioned system MAY claim
   "backward compatible" only for integrations that depend on the old address as an
   **inbound destination**. It MUST NOT claim full backward compatibility for
   integrations that authenticate the old address as an **outbound sender**, unless a
   dedicated compatibility adapter is deployed and documented.

4. **Required transition classification:** Before transition, every known dependency on
   a V1 actor address MUST be classified as one of:
   - destination-only reference
   - sender-authenticated reference
   - bidirectional callback reference

5. **Handling sender-authenticated dependencies:** If an external contract, token, or
   application authenticates the old V1 address as the sender, then one of the
   following MUST be chosen explicitly:
   - keep the V1 actor alive and untransitioned
   - retain the V1 address as a permanent compatibility shell with custom outbound
     adapter logic
   - update the dependency itself to recognize the new container address
   - accept a breaking change and schedule it via governance / upgrade coordination

6. **Explorer and SDK disclosure:** Wallets, SDKs, and explorers MUST present the
   transition state of an actor address explicitly:
   - old V1 address still valid for inbound messages
   - canonical outbound identity is now container address X
   - old address preserved only as forwarding shell

7. **Security rule:** A receiving actor inside the V2 container MUST NOT treat a
   message as coming from the old V1 address merely because it arrived through a
   forwarding shell. Provenance must be verified through the wrapper metadata defined
   in §31.4.1, not by trusting `msg.sender` equality.

In short:

> Forwarding shells preserve **where messages can be sent to**.
> They do not, by themselves, preserve **who messages come from**.

### 31.5 Treasury Mapping Rule

When a V1 Treasury Actor (independent Account B) transitions into a V2 container, the following state mapping applies:

* The Treasury Actor's contract balance becomes its initial `budget` in the actor descriptor.
* Outstanding `AllocateBudget` records are preserved in the actor's state.
* The `primary_wallet` backlink is replaced by the container-level `registry_root` lookup for ROLE_PRIMARY.
* If a forwarding shell is deployed at the old Treasury address, it MUST forward `ReturnBudget` messages from V1 actors that have not yet transitioned.

### 31.6 Role/Code/State Transition Rule

For each deployed V1 actor transitioning into a V2 container:

1. **Code**: The V1 contract code becomes the `behavior_ref` in the actor's descriptor. Some contracts may transition without code rewrite if they do not depend on actor-mode opcodes, legacy address identity assumptions, or legacy account-context semantics. Transition tooling MUST perform a compatibility audit before reusing code unchanged. Contracts that wish to use STATEGET/STATESET/STATEDEL must be recompiled for actor-mode.
2. **State**: The V1 contract's `data` Cell is mapped into the actor's `state_root` HashmapE. The mapping strategy depends on the contract's data layout -- flat data Cells are wrapped into a single HashmapE entry keyed by a well-known key (e.g., 0x00); structured HashmapE states are mapped directly.
3. **Role**: The V1 role ID (from the Actor Registry) becomes the key in the container-level `registry_root` mapping to the corresponding V2 `actor_id`.

### 31.6.1 Compatibility Audit (Transition Precondition)

The compatibility audit is a **transition precondition**, not merely a tooling recommendation. No deployed V1 actor may be transitioned into a V2 container until the audit for that actor is complete and all findings are resolved.

Transition tooling MUST verify that the post-transition actor state is functionally equivalent to the pre-transition account state by executing a set of reference transactions against both representations and comparing outputs.

At minimum, the transition audit MUST check the following three categories for each transitioned actor:

1. **Address identity assumptions:** Does the contract logic branch on `my_address` or compare its own address against a stored value? If so, the transitioned actor will observe a different address (the container address + actor_id) and may break. **Resolution:** update address references or deploy an address-translation shim.
2. **Account context assumptions:** Does the contract read account-level fields (balance, code hash, last_trans_lt) that change meaning in actor-mode? If so, the contract must be updated to use actor-local equivalents (budget, behavior_ref hash, actor_lt). **Resolution:** recompile with actor-mode field mappings.
3. **Message source/callback assumptions:** Does the contract authenticate inbound messages by checking `msg.sender` against a stored address, or does it send callback messages expecting the recipient to verify the sender? If the stored address is an old V1 address, the contract must be updated to accept messages via forwarding shell wrapper verification or to use the new container-level address. **Resolution:** implement wrapper verification or update stored addresses.

An actor that fails any of the three audit categories MUST NOT be transitioned until the issue is resolved. The audit result for each actor MUST be recorded and attached to the transition transaction as metadata.

## 31A. Transition Freeze (Normative Before V2 Rollout)

This section is normative for any V1 -> V2 transition planning.

No V2 rollout may begin until the transition rules in this section are frozen.

If any descriptive text in Part IV conflicts with this section, this section takes precedence.

### 31A.1 Transition Baseline

The baseline transition assumption is:

> V1 actor-oriented application architecture already exists. V2 protocol-native actor containers must preserve the semantics of that architecture as closely as possible.

### 31A.2 Address Compatibility Freeze

A V2 rollout MUST freeze one baseline address strategy. One of the following MUST be selected explicitly:

- forwarding shell strategy
- alias mapping strategy
- direct container-address replacement strategy

The chosen strategy MUST define:

1. what existing V1 user-facing addresses continue to mean
2. how old wallet addresses resolve after transition
3. whether users must adopt new visible addresses
4. how explorers and SDKs map old identities to new actor containers

### 31A.3 Treasury Mapping Freeze

The transition of V1 Treasury Actor funds MUST be frozen explicitly. The spec MUST define whether V1 Treasury balances become:

- V2 `shared_balance`
- Treasury Actor budget inside the container
- a split of both

No transition tool may infer this ad hoc.

### 31A.4 Role Transition Freeze

The following mappings MUST be frozen:

- V1 Wallet Actor -> V2 Wallet Actor
- V1 Treasury Actor -> V2 Treasury Actor
- V1 Recovery Actor -> V2 Recovery Actor
- V1 Policy Actor -> V2 Policy Actor
- V1 Token / App Actors -> V2 actor placement rules

### 31A.5 Code and State Transition Freeze

The transition spec MUST define:

1. how V1 contract code maps into V2 `behavior_ref`
2. how V1 persistent state maps into actor-local state
3. how role-specific metadata is preserved
4. how registry information is reconstructed inside the container

### 31A.6 Compatibility Window Freeze

The transition plan MUST define:

- whether legacy and actor-container accounts coexist
- for how long they coexist
- whether transition is opt-in or mandatory
- whether new accounts only may use V2 initially

### 31A.7 Transition Safety Requirements

Any transition tooling MUST preserve at minimum:

- ownership semantics
- recovery semantics
- policy semantics
- treasury semantics
- registry semantics
- token actor linkage where applicable

### 31A.8 Rollout Gating Rule

No V2 public rollout may begin until the following are frozen and tested:

- address compatibility strategy
- treasury mapping rule
- role transition rule
- code/state transition rule
- compatibility window rule

### 31A.9 Required Transition Test Scenarios

At minimum, transition tests MUST cover:

1. V1 wallet actor to V2 wallet actor transition
2. V1 treasury balance transition
3. V1 recovery flow preserved after transition
4. V1 registry semantics preserved after transition
5. old user-facing address resolution after transition
6. mixed legacy + transitioned accounts in the same network

---

# Part V — Implementation Plan

## 32. Module Breakdown

### Module 0: Spec Freeze

**Scope:** Finalize and freeze all V2 normative specifications before any implementation begins.

| Deliverable | Description |
|-------------|-------------|
| Frozen TL-B schemas | Final `ActorDescriptor`, `account_storage_actor`, `ActorAddress` canonical encoding |
| Frozen opcode table | Final 0xFB09-0xFB0F assignments, c6/c7 layout, actor-mode validity gate |
| Frozen merge rules | Final Phase 2 ordering, prefix commit, rollback, tertiary tiebreaker |
| Frozen VM compatibility matrix | Final getter/opcode behavior table (section 21.3) |
| Frozen queue key layout | Final 608-bit key format |
| Frozen proof path | Final block -> shard -> container -> actor -> state -> key path |
| Behavior binding decision | Per-actor `behavior_ref` confirmed as baseline (section 17.2) |
| Reference test vectors | Golden serialization vectors for all frozen schemas |
| V2 Spec Freeze Checklist | All items in Appendix D resolved and signed off |

**Complexity:** MEDIUM | **Estimate:** 2-3 weeks

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
Week 0-2:   Module 0 (Spec Freeze)                    <- must complete before implementation
Week 3-6:   Module A (TL-B & Account)                  <- foundation for all modules
Week 5-7:   Module B (TVM Opcodes)                     <- depends on A
Week 5-7:   Module F (OutMsgQueue Key)                 <- depends on A, parallel with B
Week 6-8:   Module G (Merkle Proofs)                   <- depends on A, parallel
Week 7-10:  Module C (Two-Phase Execution)             <- depends on A+B
Week 9-13:  Module D (Collator Restructuring)          <- depends on A+B+C
Week 11-15: Module E (Validation Logic)                <- depends on A+C+D
Week 12-15: Module H (Lite-Client / SDK)               <- depends on A+G
```

Parallelizable module group: {B, F, G} can be developed simultaneously.

## 34. Effort Estimate

| Layer | Complexity | Effort |
|-------|-----------|--------|
| Spec freeze (Module 0) | Medium | 2-3 weeks |
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

Caveat: these estimates exclude time spent on spec-freeze iteration (Module 0 feedback loops, design review, and revision). Spec freeze may require multiple rounds if open questions (section 30) surface new design constraints. Modules C, D, and E carry the highest implementation risk due to their deep integration with the existing collator/validator codebase and the difficulty of testing concurrent execution correctness.

## 35. Verification

| Module | Method |
|--------|--------|
| 0 | Spec Freeze Checklist (Appendix D) fully resolved; reference test vectors published and reviewed |
| A | Compiles; tlbc generation passes; unpack/pack round-trip tests; golden serialization tests (canonical bit-exact encoding of ActorDescriptor, AccountStorage actor-mode, ActorAddress) |
| B | Unit tests per opcode (normal + exception paths); Fift scripts; VM forbidden-field tests (verify sentinel/trap for TXHASH, account-level lt, shared_balance in actor-mode) |
| C | Phase 1 tentative results correct; Phase 2 merge prefix and rollback rules |
| D | Multi-actor parallel block production; same-block visibility; block limits; mixed legacy+actor-mode block tests (verify blocks containing both legacy serial transactions and actor-mode two-phase transactions produce correct state) |
| E | Validator passes validate-query on blocks produced by D |
| F | Queue merge tests; 608-bit key sort correctness; golden sort-order tests (section 26) |
| G | lite-client getActorState proof verification |
| H | lite-client actor state/list queries return correct results |
| Transition | V1-to-V2 transition test: deploy V1 Virtual Account (Wallet + Treasury + Recovery), execute reference transactions, transition to V2 container, verify post-transition state equivalence and functional equivalence |

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
9. Transition from V1 actor set to one V2 actor container
10. Golden serialization round-trip for ActorDescriptor and actor-mode AccountStorage (bit-exact encoding/decoding)
11. VM forbidden-field enforcement: TXHASH returns sentinel, account-level lt is not accessible, shared_balance is not readable in actor-mode Phase 1
12. Mixed legacy+actor-mode block: a single block containing both legacy serial transactions and actor-mode two-phase transactions produces correct state for both account types
13. Tertiary ordering tiebreaker: two speculative results with the same (actor_id, actor_lt) are ordered deterministically by inbound_msg_hash

## Appendix D: V2 Spec Freeze Checklist

Before V2 coding begins, the following must be frozen:

1. ActorDescriptor schema (including behavior_ref model and final behavior binding choice)
2. AccountContainer schema
3. ActorAddress format
4. actor_lt rules
5. Merge ordering rules
6. Same-block visibility rules
7. VM context compatibility matrix (section 21)
8. Tentative vs canonical transaction structures
9. Queue key layout
10. Proof path format
11. c7 tuple index allocation for actor-mode (indices 18+ frozen)
12. c6 register lifecycle (initialization, capture, commit/discard semantics frozen)

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
| Proof declarations | `crypto/block/check-proof.h` | Actor proof extension |
| Lite-client | `lite-client/lite-client.cpp` | 4723 lines |
| Block-parse | `crypto/block/block-parse.h` | 522-528 |
| Emulator | `emulator/transaction-emulator.h` | Transaction emulation |
| VM core | `crypto/vm/vm.h` | 278-315 (c6 register addition) |
| Continuation | `crypto/vm/continuation.h` | 39 (d[] array extension for c6) |
| Lite API schema | `tl/generate/scheme/lite_api.tl` | getActorState, getActorList |
