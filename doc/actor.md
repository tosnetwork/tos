# Actor Model in TOS — Protocol Proposal (RFC)

**Status:** Draft proposal. Not an incremental patch — this is a hard-fork-level protocol redesign.

**Scope:** This document describes a long-term direction for TOS's execution model.
Implementation requires protocol-level changes to block format, state serialization,
message routing, validation logic, and client tooling.

## 1. Core Idea

Each actor:

- owns its own state
- processes messages independently
- does not rely on shared mutable memory

This gives TOS a natural foundation for parallel execution, fault isolation, and modular system growth.

## 2. Why It Matters for the Node

The C++ node already uses an actor-based runtime through `td::actor`, which means the system naturally maps to:

- isolated workers
- message queues
- asynchronous scheduling
- explicit ownership and lifecycle control

## 3. Why It Matters for the Chain

At the protocol level, the Actor Model supports:

- high throughput through message-oriented execution
- better separation between contracts and services
- cleaner failure boundaries

## 4. Current Architecture (What We Have)

One account = one execution unit:

```
Account (unique address)
 +-- code: Cell         <- one contract
 +-- data: Cell         <- one monolithic state tree
 +-- balance: Coins
 +-- last_trans_lt      <- one timeline -> forced serialization
```

All transactions for the same account are serialized because they share the
same data Cell, balance, logical time, and storage state.

Key code locations:

| Component | File | Lines |
|-----------|------|-------|
| Account struct | `crypto/block/transaction.h` | 262-321 |
| Transaction execution | `validator/impl/collator.cpp` | 3431 (impl_create_ordinary_transaction) |
| Collator state management | `validator/impl/collator.cpp` | 3395, 3743 |
| Validation | `validator/impl/validate-query.cpp` | 7597 lines |
| OutMsgQueue key | `crypto/block/output-queue-merger.h` | 30 |

## 5. Proposed Architecture (Actor Model)

### 5.1 Account Structure

```
Account (unique address)
 +-- code: Cell             <- shared by all Actors
 +-- actors: HashmapE       <- actor_id -> Actor descriptor
 |    +-- actor_0:
 |    |    +-- state: HashmapE   <- independent KV state
 |    |    +-- budget: Coins     <- actor-local working balance
 |    |    +-- actor_lt: uint64  <- independent logical time
 |    +-- actor_1:
 |    |    +-- state: HashmapE
 |    |    +-- budget: Coins
 |    |    +-- actor_lt: uint64
 |    +-- ...
 +-- shared_balance: Coins  <- account-level pool: storage fees, inbound value staging, inter-actor transfers
```

Each actor is identified by a two-level address:
`workchain:account_id:actor_id`. The `actor_id` is
deterministically derived: `actor_id = sha256(account_address || discriminator)`.
`actor_id` is a full 256-bit protocol field everywhere it appears: ActorAddress,
Account storage, transaction records, proofs, and OutMsgQueue keys.

### 5.2 New TVM Instructions

```
// State operations
STATEGET     key_hash:uint256 → value:slice       // wraps Dictionary::lookup
STATESET     key_hash:uint256 value:slice → ()     // wraps Dictionary::set
STATEDEL     key_hash:uint256 → bool               // wraps Dictionary::delete_key

// Messaging
ACTORSEND    actor_id:uint256 body:cell → ()        // intra-account: sends message to another Actor within the SAME account

// Balance operations
BUDGETGET    → amount:coins                         // returns the executing Actor's current budget
ACTORCLAIM   amount:coins → request_id:uint64       // record an intent to pull funds from shared_balance into this Actor's budget
ACTORRELEASE amount:coins → request_id:uint64       // record an intent to return funds from this Actor's budget to shared_balance
```

**ACTORSEND scope limitation:** `ACTORSEND` targets only Actors under the **same
account** as the sender. The `actor_id` operand is sufficient because `workchain`
and `account_id` are implicitly inherited from the executing account context. This
is intentional — cross-account Actor messaging requires the full `ActorAddress`
(`workchain:account_id:actor_id`) and is deferred to a future protocol extension
(see §6.3). A future `ACTORSENDX` instruction may accept a full ActorAddress for
cross-account / cross-shard delivery.

**ACTORCLAIM / ACTORRELEASE:** These two instructions do **not** synchronously move
funds during Phase 1. Instead, they append a **balance-transfer intent** to the
current Actor transaction:

- `ACTORCLAIM(amount)` records "if committed, move `amount` from `shared_balance`
  to this Actor's `budget`"
- `ACTORRELEASE(amount)` records "if committed, move `amount` from this Actor's
  `budget` to `shared_balance`"

The returned `request_id` is only an opaque identifier for tracing / receipts
within the speculative execution result. It is **not** a success indicator.
Success or failure is determined only in Phase 2 during deterministic merge.

Therefore contracts in actor-mode must treat claim/release as **deferred effects**,
not as synchronous conditionals. A contract must not branch on whether the transfer
"already happened" inside the same Phase-1 execution.

State and messaging instructions internally perform lookup/set on the HashmapE in C4.

### 5.3 What This Changes at Protocol Level

**This is a hard fork.** The following protocol components must be upgraded together:

| Component | Change Required |
|-----------|----------------|
| Account state layout | Add `actors` HashmapE (state + budget + actor_lt per actor), replace `balance` with `shared_balance` |
| Account serialization (TL-B) | New schema for actor sub-structure |
| Block format | ActorAddress in transaction records |
| OutMsgQueue key | Extended with actor_id (see 5.6) |
| Transaction execution | Actor-level state isolation |
| Validation logic | Actor-level proof and consistency checks |
| Merkle proofs | Extended proof path: block → shard → account → **actor** → key |
| lite-client | Must understand ActorAddress and new proof format |
| tonlib / SDKs | Must support ActorAddress parsing |
| Block explorers | Must display actor-level transactions |

The Cell/BOC encoding format itself is unchanged (Cells still work the same way),
but the semantic structure stored in those Cells changes.

### 5.4 Hybrid Balance Model

#### 5.4.0 Design Rationale

Current `impl_create_ordinary_transaction` (collator.cpp:3395-3743) modifies
during a single transaction execution:

- `account.balance` (gas deduction, value transfer, storage fees)
- `account.last_trans_lt` / `last_trans_end_lt` / `last_trans_hash`
- `account.storage_stat` (storage fee accounting)
- Block-level accumulators: `last_proc_int_msg_`, block limits, `register_new_msgs()`, `update_max_lt()`, statistics

If two Actors under the same Account shared a single balance and executed in parallel,
they would **concurrently modify the shared balance**, producing a non-deterministic
result. A pure reservation model solves this but adds significant complexity (see
earlier drafts). A fully per-actor balance eliminates contention but fragments
capital and complicates storage fee attribution.

**Solution: hybrid balance model** — each Actor has its own `budget` for gas and
value transfers, while the Account retains a `shared_balance` for storage fees,
inbound value staging, and inter-actor fund movement.

```
Account
 +-- shared_balance: 2 TON          ← storage fees, inbound value, inter-actor pool
 +-- actor_0: { state, budget: 3 TON, actor_lt }
 +-- actor_1: { state, budget: 5 TON, actor_lt }
```

**Why this works for parallel execution:**

- Gas is deducted from the Actor's own `budget` → no cross-actor contention
- Value attached to outbound messages is deducted from the Actor's `budget` → no contention
- `shared_balance` is only mutated by `ACTORCLAIM` / `ACTORRELEASE` and storage
  fee deduction, all of which are deferred to the sequential Phase 2
- TVM compute phase (the expensive part) runs in Phase 1 with **zero shared writes**

**Fields that are actor-local (fully parallel in Phase 1):**
- Actor state (HashmapE)
- Actor budget (gas deduction, value transfer)
- Actor logical time (`actor_lt`)
- TVM compute phase

**Fields that are account-global (sequential in Phase 2):**
- `shared_balance` (ACTORCLAIM / ACTORRELEASE commits, storage fees)
- `last_trans_lt` / `last_trans_hash`
- Outgoing message ordering and materialization
- Block-level statistics

#### 5.4.0.1 Inbound Value Routing

When an external or internal message carrying value arrives at the Account:

1. If the message targets a specific `actor_id`, the value is credited directly
   to that Actor's `budget`.
2. If the message targets the Account without specifying an `actor_id` (legacy
   message format), the value is credited to `shared_balance`.
3. An Actor can later pull funds from `shared_balance` via `ACTORCLAIM`.

This ensures backward compatibility: existing wallets sending to an Account
address still work; the contract code decides how to distribute funds to Actors.

#### 5.4.0.2 Storage Fee Attribution

Storage fees are charged at the **account level**, not per-actor:

- The total Cell tree size (including all Actor states) determines the storage fee.
- Storage fees are deducted from `shared_balance` during Phase 2.
- If `shared_balance` is insufficient, the Account enters the standard
  freeze/deletion path — all Actors are affected.
- Actors are expected to periodically `ACTORRELEASE` surplus budget back to
  `shared_balance` to keep the account solvent. Alternatively, the protocol may
  enforce a minimum `shared_balance` threshold.

### 5.4.1 Phase Boundary: What Happens Where (Normative Draft)

**Phase 1 (parallel, per-actor) produces tentative snapshots only:**
- Post-execution Actor state root (tentative snapshot, not yet committed)
- Compute-phase status: success, revert, exception code
- Gas deducted from Actor `budget` (tentative)
- Value transfers deducted from Actor `budget` (tentative)
- Outbound message list in Actor-local order (tentative — not yet materialized)
- Tentative `ACTORCLAIM` / `ACTORRELEASE` requests (recorded, not yet applied)

**Phase 1 must NOT touch:**
- `shared_balance` (mutated only in Phase 2)
- `last_trans_lt` / `last_trans_end_lt` / `last_trans_hash` (account-global)
- Account storage statistics
- Block-level InMsg / OutMsg descriptors
- Shard OutMsgQueue

**Phase 2 (sequential, single-threaded) finalizes:**
- Apply all `ACTORCLAIM` / `ACTORRELEASE` requests against `shared_balance`
  in deterministic order; reject any that would overdraw
- Deduct storage fees from `shared_balance`
- Assign final logical time and transaction hash per §5.4.3
- Commit the tentative Actor state / Actor budget snapshot only for transactions
  that survive Phase 2 validation
- Materialize outbound messages into block descriptors and queues
- Update block-level accumulators

Because gas and value transfers are computed against the Actor's own tentative
`budget` snapshot in Phase 1, Phase 2 is lighter than in a pure reservation model,
but it is still the only committing phase. No Phase-1 artifact is part of canonical
state until Phase 2 accepts it.

### 5.4.1.1 Rollback Rule (Normative Draft)

If Phase 2 rejects a speculative result for any reason, all of its Phase-1 outputs
must be discarded atomically:

- Tentative Actor state changes are dropped
- Tentative Actor budget changes are dropped
- Tentative outbound messages are dropped
- Tentative claim/release intents are dropped
- Tentative `actor_lt` advancement for that transaction is dropped unless the
  protocol explicitly chooses gap-permitting actor lt (this RFC recommends no gaps;
  see §5.4.3.1)

This is an all-or-nothing rule. There is no partial commit of a speculative result.

### 5.4.2 Speculative VM Context Isolation (Normative Draft)

Phase 1 executes the TVM compute phase speculatively. The VM must be presented with
a **restricted execution context** so that results remain valid after Phase 2 assigns
final account-global values. The following rules define what the VM can and cannot
observe during Phase 1:

**Available to the VM in Phase 1 (stable, will not change after merge):**
- Actor-local state (HashmapE for the executing actor_id)
- Actor `budget` — `BUDGETGET` and `GETBALANCE` both return the Actor's own budget
- Inbound message body, value, and source address
- Account address (`workchain:account_id`)
- Actor id (`actor_id`)
- Current block reference (seqno, shard, workchain)
- Unix timestamp of the block candidate
- Actor-local logical time counter (`actor_lt`, see §5.4.3)

**NOT available to the VM in Phase 1 (returns zero / placeholder):**
- `LTIME` / logical time — returns the actor-local tentative lt, NOT the final
  account-level `last_trans_lt`. The final lt is assigned only in Phase 2.
- Transaction hash — undefined during Phase 1. Any instruction that would return
  the current transaction hash (e.g., for replay protection) must return a
  **sentinel value** (0) or trap. The final hash depends on the merge order.
- Outbound message envelope fields (lt, created_lt) — these are placeholders in
  Phase 1 and are overwritten by Phase 2 when messages are materialized.
- `shared_balance` — not directly readable in Phase 1. The Actor sees only its
  own `budget`. `ACTORCLAIM` / `ACTORRELEASE` are recorded as tentative requests
  and resolved in Phase 2.
- `last_trans_lt` / `last_trans_end_lt` / `last_trans_hash` of the account — these
  are account-global fields updated only in Phase 2.

**Consequence:** Any contract that branches on transaction hash, final lt, or
`shared_balance` will observe different values in Phase 1 vs. a hypothetical serial
execution. This is an intentional trade-off: contracts must be written to depend
only on actor-local state, actor budget, and message content, not on account-global
transaction metadata.

### 5.4.3 Actor Logical Time Model (Normative Draft)

The `actor_lt` stored in each Actor descriptor is a **per-actor monotonic
counter** maintained independently of the account-level `last_trans_lt`.

**Phase 1 behavior:**
- Before executing an Actor transaction, the collator reads the current `actor_lt`
  for the target `actor_id` and increments it to produce a **tentative actor lt**.
- This tentative value is stable within Phase 1 — it does not change during merge.
- If multiple messages target the same Actor in one block, they are serialized
  per-actor and each receives a distinct, ascending `actor_lt`.
- The `actor_lt` is used as the **secondary sort key** when ordering Phase-1 results
  for the deterministic merge: `ORDER BY (actor_id ASC, actor_lt ASC)`.

**Phase 2 behavior:**
- The merge phase iterates results in `(actor_id, actor_lt)` order.
- For each committed result, Phase 2 assigns a **final account-level logical time**
  (`last_trans_lt` / `last_trans_end_lt`) from the account's global lt counter.
- The final account-level lt is strictly monotonically increasing across all
  committed transactions in the block, regardless of which Actor produced them.

**Relationship between the two timelines:**

```
actor_lt (per-actor, Phase 1)     account lt (global, Phase 2)
─────────────────────────────     ──────────────────────────────
actor_0: 100, 101                 → final lt: 5000, 5001
actor_1: 200                      → final lt: 5002
actor_0: 102                      → final lt: 5003
```

- `actor_lt` provides a stable, per-actor ordering that is known before merge.
- Account-level lt provides the global ordering required by the block format and
  external observers (lite-clients, explorers).
- Both are monotonic within their scope; neither is derivable from the other.

### 5.4.3.1 Rejected Transaction and actor_lt Rule (Normative Draft)

This RFC recommends **prefix-only actor_lt commitment with no gaps**:

- A speculative transaction receives a tentative `actor_lt` in Phase 1
- That `actor_lt` becomes canonical only if the transaction is committed in Phase 2
- If the transaction is rejected in Phase 2, the tentative `actor_lt` is discarded
- Therefore the persisted `actor_lt` in account state advances only across committed
  transactions

This avoids confusing gaps in per-actor timelines and keeps replay/audit semantics simple.

### 5.5 Collator Changes

The current collator executes transactions synchronously and updates global state
after each one. This must change to support the two-phase model:

```
Current flow (serial):
  for each message:
    result = impl_create_ordinary_transaction(msg, account)
    update_block_state(result)    // immediately modifies global state

Proposed flow (parallel + merge):
  // Phase 1: parallel execution (per-actor, no shared writes)
  for each message (can be parallel across different actors):
    actor = account.actors[msg.actor_id]
    result[actor_id] = execute_actor_transaction(msg, actor)
    // gas and value applied only to a tentative actor snapshot — no shared contention

  // Phase 2: deterministic merge (single-threaded, lightweight)
  sort results by (actor_id ASC, actor_lt ASC)   // actor_lt is the stable Phase-1 local counter
  for each result in deterministic order:
    // 1. Apply ACTORCLAIM/ACTORRELEASE against shared_balance
    for each claim_request in result.balance_requests:
      if !apply_balance_request(claim_request, account.shared_balance):
        reject_transaction(result); continue
    // 2. Deduct storage fees from shared_balance
    apply_storage_fees(account)
    // 3. Commit tentative actor snapshot, assign final lt, materialize outbound messages
    commit_actor_snapshot(result, account)
    assign_final_lt(result, account)
    materialize_outbound_messages(result, block)
    update_block_state(result)
```

Phase 2 is significantly simpler than in a pure reservation model: it does **not**
recompute gas/value execution, but it still decides whether the speculative result
is committed at all.

### 5.5.0 Prefix Commit Rule for a Single Actor (Normative Draft)

For any fixed `actor_id`, Phase 2 may commit only a **contiguous prefix** of that
Actor's speculative results ordered by `actor_lt`.

Example:

```text
actor_7 speculative results: [lt=11, lt=12, lt=13]
if lt=12 is rejected in Phase 2:
  - lt=11 may commit
  - lt=12 is rejected
  - lt=13 MUST also be rejected without commit
```

Rationale:
- Later speculative results for the same Actor depend on the tentative post-state
  produced by earlier ones
- Rejecting a middle result invalidates all later same-Actor snapshots in the block

Implementation consequence:
- The merge phase tracks a per-actor "prefix still valid" bit
- Once a transaction for `actor_id` is rejected, all later results for the same
  `actor_id` in the current block are discarded automatically

This still requires restructuring the core execution loop in collator.cpp (6707 lines)
and the transaction creation in transaction.cpp (4325 lines), but the merge logic
is less complex.

### 5.5.1 Same-Block Message Visibility Rule (Normative Draft)

The protocol must define whether a message emitted by Actor A during block `N`
can be executed by Actor B in the same block `N`.

**Recommended Phase-1 rule: no same-block re-entry across Actors.**

- Any outbound Actor message created while collating block `N` is considered
  **newly emitted in block N**
- Newly emitted Actor messages are recorded in block `N`, but become executable
  only from block `N+1`
- Therefore Phase 1 parallel execution reads only the pre-block inbound set plus
  deferred messages already admitted into the block candidate before execution starts
- No Actor may observe another Actor's newly emitted same-block message during its own
  Phase-1 execution

This rule intentionally trades latency for determinism:
- It removes same-block cyclic dependencies between Actors
- It avoids merge-order-dependent visibility
- It preserves a clean block boundary: emitted in `N`, consumable in `N+1`

If a future version wants same-block Actor-to-Actor execution, that should be a
separate protocol extension with an explicit topological scheduling rule. It should
not be part of the initial Actor hard fork.

### 5.6 OutMsgQueue Key Change

```
Current: workchain(32) | addr_prefix(64) | msg_hash(256)    = 352 bits
Proposed: workchain(32) | addr_prefix(64) | actor_id(256) | msg_hash(256) = 608 bits
```

Both `actor_id` and `msg_hash` are kept at full 256 bits.

Rationale:
- Address layer, transaction layer, proof layer, and queue layer must use the same
  `actor_id` width to avoid semantic mismatch
- Keeping the full `actor_id` removes collision and truncation ambiguity
- Keeping the full `msg_hash` preserves existing message identity semantics

This changes the key length constant in `output-queue-merger.h:30` and affects
all queue sorting, merging, and routing logic.

### 5.7 Execution Paths

Two execution paths, sharing the same state interface (vm::Dictionary / HashmapE):

| Path | For | Performance | Safety |
|------|-----|-------------|--------|
| Native C++ | Built-in/system actors | Fastest | Trusted (ships with node) |
| TVM | User-deployed contracts | Medium | TVM sandbox |

## 6. Key Design Decisions

### 6.1 Actor Creation Method

- **Recommended: Address derivation** — Actor address deterministically derived from
  `(account_addr, discriminator)`. Predictable, no on-chain registry needed.

### 6.2 Hybrid Balance Model

- **Per-actor `budget`** for gas and value transfers — enables contention-free parallel execution
- **Account-level `shared_balance`** for storage fees, inbound value staging, and inter-actor fund movement
- `ACTORCLAIM` / `ACTORRELEASE` move funds between `shared_balance` and actor `budget` (committed in Phase 2)
- Gas and value transfers computed against actor `budget` in Phase 1 (tentative until Phase 2 commits) — no reservation needed

### 6.3 Sharding Strategy

- All Actors of the same Account stay in the same shard (Phase 1)
- Cross-shard Actor communication deferred to future work

### 6.4 Storage Model

- Cell retained internally, KV Host API exposed externally
- HashmapE / vm::Dictionary already has complete API
- Merkle proof path extended (not replaced)

## 7. Effort Estimate

**This is a hard-fork-level protocol redesign, not a local refactor.**

| Layer | Work | Complexity | Effort |
|-------|------|-----------|--------|
| Account struct + serialization | New TL-B schema (actor descriptor with budget), state migration | High | 3-4 weeks |
| Two-phase execution model | Hybrid balance, lightweight Phase-2 merge | High | 3-4 weeks |
| Collator restructuring | Serial→parallel dispatch, result collection ordering | High | 3-4 weeks |
| TVM new instructions | 7 opcodes (STATEGET/STATESET/STATEDEL/ACTORSEND/BUDGETGET/ACTORCLAIM/ACTORRELEASE) | Medium | 1-2 weeks |
| Message routing | OutMsgQueue key extension, queue merge logic | Medium | 2 weeks |
| Validation logic | Actor-level proof, consistency checks | High | 3-4 weeks |
| Proof/lite-client upgrade | Extended Merkle proof path, new query types | Medium | 2-3 weeks |
| Built-in Token Actors | Native C++ Token Master/Balance/Allowance | Medium | 2 weeks |
| Tola compiler | Solidity-like syntax → Actor semantics → TVM bytecode | High | 6-8 weeks |
| Testing + integration | End-to-end validation, migration testing | High | 4-6 weeks |

**Total: approximately 6-9 months for a small team (2-3 engineers).**

The hardest parts are the collator restructuring and validation logic.
The hybrid balance model significantly reduces two-phase complexity compared
to a pure reservation approach.

## 8. What Stays, What Changes, What's New

### Unchanged (internal implementation)

- Cell data structure encoding
- BOC serialization format
- Consensus protocol (Catchain/Simplex)
- Network transport (ADNL/RLDP/DHT/QUIC)
- Sharding mechanism (address-prefix-based)
- Storage engine (CellDB/RocksDB)
- td::actor runtime framework

### Changed (protocol-level, requires hard fork)

| Before | After |
|--------|-------|
| Account = minimum execution unit | Actor = minimum execution unit |
| One Account, one data Cell | One Account, multiple Actors (each with independent HashmapE) |
| One Account, one lt timeline | Each Actor has independent lt |
| Serial transaction execution | Two-phase: parallel compute (Phase 1) + lightweight merge (Phase 2) |
| Single balance per account | Hybrid: per-actor `budget` + account `shared_balance` |
| OutMsgQueue key: 352 bits | Extended to 608 bits (includes full 256-bit actor_id) |
| Merkle proof: block→account→key | Extended: block→account→**actor**→key |
| lite-client address format | Extended with ActorAddress |

### New

| Component | Purpose |
|-----------|---------|
| `actors: HashmapE` in Account | Actor descriptors: state + budget + actor_lt per Actor |
| `shared_balance` in Account | Account-level pool for storage fees and inter-actor transfers |
| Hybrid balance model | Per-actor budget eliminates balance contention in Phase 1 |
| Lightweight Phase-2 merge | Reconcile shared_balance, assign global lt, materialize messages |
| STATEGET/STATESET/STATEDEL/ACTORSEND/BUDGETGET/ACTORCLAIM/ACTORRELEASE | TVM opcodes for Actor-native programming |
| ActorAddress | Two-level addressing (account_id, actor_id) |
| Built-in Actor Registry | Native C++ Actor execution path |
| Tola language | Solidity-like syntax compiling to TVM |

## 9. Risks

1. **Protocol-level hard fork** — Requires coordinated upgrade of all validators, lite-clients, SDKs, and explorers simultaneously
2. **Two-phase execution model** — Phase 1/Phase 2 boundary must be correctly enforced; incorrect isolation breaks consensus
3. **Balance fragmentation** — Per-actor budgets may lead to idle capital; need policies for minimum `shared_balance` and automatic rebalancing
4. **Shared balance overdraw** — Multiple Actors issuing `ACTORCLAIM` in the same block may collectively overdraw `shared_balance`; Phase 2 must reject excess claims deterministically
5. **Prefix rejection cascades** — Rejecting one speculative result may force rejection of later same-Actor results in the block, reducing throughput in pathological cases
6. **Message visibility semantics** — Same-block Actor messages are consensus-critical; visibility rules must remain simple and deterministic
7. **Validation complexity** — validate-query.cpp (7597 lines) needs significant changes; Actor-level proofs add new attack surface
8. **State migration** — Existing accounts must be migrated to new format; requires migration protocol in the hard fork
9. **Client compatibility** — All wallets, SDKs, and block explorers must upgrade to understand ActorAddress

## 10. Implementation Roadmap

### Phase 1: Design Validation (3-4 months)

1. Formal specification of the hybrid balance model (per-actor budget + shared_balance)
2. Prototype the two-phase execution model (parallel Phase 1 + lightweight Phase 2 merge)
3. Design the Actor-level Merkle proof format
4. Define the state migration protocol
5. Write TL-B schema for new Account structure

### Phase 2: Core Implementation (3-4 months)

1. Implement Account struct changes + serialization
2. Implement two-phase execution in collator
3. Add TVM opcodes (STATEGET/STATESET/STATEDEL/ACTORSEND/BUDGETGET/ACTORCLAIM/ACTORRELEASE)
4. Extend OutMsgQueue with actor_id
5. Update validation logic

### Phase 3: Ecosystem Upgrade (2-3 months)

1. Extend lite-client and tonlib for ActorAddress
2. Update Merkle proof verification
3. Build Actor-level block explorer
4. Implement built-in Token Actors
5. End-to-end integration testing

### Phase 4: Language + Developer Tools (parallel, 2-3 months)

1. Tola compiler (Solidity-like → TVM)
2. Developer documentation and tutorials
3. Test suite for standard Actor patterns

## 11. Built-in Standard Actor Library

### 11.1 Philosophy

> **Users write only the 10% that makes their business unique.**
> **The other 90% (tokens, access control, escrow, AMM) is already built, audited, and running natively.**

Instead of each project copying and redeploying library code, TOS ships standard
actors as **native C++ built-ins compiled into the node binary**:

| | Copy-Deploy Model | TOS Built-in Actors |
|---|---|---|
| Code location | Copied per project | One copy in node binary |
| Deployment cost | Per-project bytecode | Zero — create via message |
| Audit burden | Each fork audited separately | Audited once, all benefit |
| Upgrade | Each project independently | Node upgrade, all validators |
| Performance | VM bytecode interpretation | Native C++ execution |

### 11.2 Standard Actor Inventory

**Token Layer:** TokenMaster, TokenBalance, TokenAllowance, NFTCollection, NFTItem, MultiToken

**Access Control:** Ownable, AccessControl, Multisig, Timelock

**Governance:** Governor, VoteActor

**DeFi:** AMMPool, LiquidityPosition, LendingPool, Escrow, Vesting, PaymentSplitter

**Infrastructure:** Oracle, Proxy

## 12. Open Questions

1. **Initial budget allocation:** When an Actor is first created, what is its initial budget? Zero (must ACTORCLAIM first)? Or does the creation message's value seed it?
2. **ACTORCLAIM conflict resolution:** This RFC now recommends whole-transaction rejection, not partial claim failure. Is that too restrictive for practical contract patterns?
3. **Minimum shared_balance policy:** Should the protocol enforce a minimum `shared_balance` to cover N blocks of storage fees? Or leave it to contract logic?
4. **Cross-account / cross-shard Actor messages:** `ACTORSEND` is scoped to intra-account only (§5.2). A future `ACTORSENDX` with full `ActorAddress` is needed for cross-account delivery. How does this interact with the existing external message routing? Does the message routing protocol need changes beyond OutMsgQueue key?
5. **Actor lifecycle:** Can Actors be destroyed? What happens to remaining `budget` — auto-released to `shared_balance`?
6. **Backward compatibility period:** How long do we run old and new formats in parallel during migration?
7. **Actor count limits:** Maximum number of Actors per Account? Storage cost model for Actor metadata?
8. **Speculative VM forbidden-field enforcement:** Should the VM hard-trap when actor-mode code reads a Phase-2-only field (tx hash, shared_balance, account lt), or silently return a sentinel? Trapping is safer but breaks legacy contract patterns; sentinels are permissive but risk subtle bugs.

## 13. References

- Tola Language design: `./tola.md`
- td::actor framework: `tdactor/td/actor/`
- Collator implementation: `validator/impl/collator.cpp` (6707 lines)
- Account struct: `crypto/block/transaction.h:262-321`
- Transaction execution: `validator/impl/collator.cpp:3431`
- Validation logic: `validator/impl/validate-query.cpp` (7597 lines)
- HashmapE / Dictionary: `crypto/vm/dict.h`
- TVM instruction implementation: `crypto/vm/tosops.cpp`
- OutMsgQueue key: `crypto/block/output-queue-merger.h:30`
- MerkleProof: `crypto/block/check-proof.cpp`
