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
 +-- actors: HashmapE       <- actor_id -> Actor state (Cell dict)
 |    +-- actor_0: HashmapE <- independent KV state
 |    +-- actor_1: HashmapE <- independent KV state
 |    +-- ...
 +-- actor_lt: HashmapE     <- actor_id -> independent logical time
 +-- balance: Coins         <- SHARED — requires reservation model (see 5.4)
```

Each actor is identified by a two-level address:
`workchain:account_id:actor_id`. The `actor_id` is
deterministically derived: `actor_id = sha256(account_address || discriminator)`.
`actor_id` is a full 256-bit protocol field everywhere it appears: ActorAddress,
Account storage, transaction records, proofs, and OutMsgQueue keys.

### 5.2 New TVM Instructions

```
STATEGET   key_hash:uint256 → value:slice       // wraps Dictionary::lookup
STATESET   key_hash:uint256 value:slice → ()     // wraps Dictionary::set
STATEDEL   key_hash:uint256 → bool               // wraps Dictionary::delete_key
ACTORSEND  actor_id:uint256 body:cell → ()        // sends message to another Actor
```

These instructions internally perform lookup/set on the HashmapE in C4.

### 5.3 What This Changes at Protocol Level

**This is a hard fork.** The following protocol components must be upgraded together:

| Component | Change Required |
|-----------|----------------|
| Account state layout | Add `actors` and `actor_lt` HashmapE fields |
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

### 5.4 Shared Balance Problem (Open Design Issue)

**This is the hardest unsolved problem in this proposal.**

Current `impl_create_ordinary_transaction` (collator.cpp:3395-3743) modifies
during a single transaction execution:

- `account.balance` (gas deduction, value transfer, storage fees)
- `account.last_trans_lt` / `last_trans_end_lt` / `last_trans_hash`
- `account.storage_stat` (storage fee accounting)
- Block-level accumulators: `last_proc_int_msg_`, block limits, `register_new_msgs()`, `update_max_lt()`, statistics

If two Actors under the same Account execute in parallel, they will **concurrently
modify the shared balance**, producing a non-deterministic result. This breaks consensus.

**Proposed solution (needs detailed design):**

Two-phase execution model:

1. **Phase 1 — Speculative parallel execution:** Each Actor transaction executes
   independently with a **reserved balance allocation**. The reservation is computed
   before execution (e.g., message value + estimated gas). Actors cannot spend
   more than their reservation.

2. **Phase 2 — Deterministic merge/commit:** After all parallel executions complete,
   a single-threaded merge step:
   - Collects results in a deterministic order (by actor_id)
   - Applies balance changes sequentially
   - Assigns logical timestamps
   - Updates block-level accumulators
   - Rejects transactions that exceeded their reservation

This two-phase model preserves determinism while allowing parallel execution
of the compute-heavy phase.

**Fields that are actor-local (can be parallel):**
- Actor state (HashmapE)
- Actor logical time
- TVM compute phase

**Fields that are account-global (must be sequential in merge phase):**
- Balance
- Storage fees
- last_trans_lt / last_trans_hash
- Outgoing message ordering
- Block-level statistics

### 5.4.1 Speculative Result Boundary (Normative Draft)

To make Phase 1 reviewable, the speculative execution result must be restricted.

**Phase 1 may produce only actor-local tentative outputs:**
- Tentative post-execution Actor state root
- Tentative compute-phase status: success, revert, exception code
- Gas used, gas refund candidate, storage delta estimate
- Tentative outbound message list generated by the Actor, in Actor-local order
- Read/write set summary for the Actor-local state

**Phase 1 must not finalize any account-global outputs:**
- No final balance deduction or refund
- No final `last_trans_lt` / `last_trans_end_lt` / `last_trans_hash`
- No direct mutation of account storage statistics
- No insertion into block-level InMsg / OutMsg descriptors
- No final emission into the shard OutMsgQueue

**Phase 2 is the only committing phase.** It must:
- Re-check the reservation constraint against the finalized account balance state
- Recompute final fees from the already-produced gas/storage usage numbers
- Assign final logical time and transaction hash in deterministic order
- Materialize outbound messages into block descriptors and queues
- Either commit the whole transaction result or discard it as not included in this block

This means speculative execution is closer to "deterministic pre-transaction evaluation"
than to a fully committed transaction. A Phase-1 result is not a transaction yet.

### 5.5 Collator Changes

The current collator executes transactions synchronously and updates global state
after each one. This must change to support the two-phase model:

```
Current flow (serial):
  for each message:
    result = impl_create_ordinary_transaction(msg, account)
    update_block_state(result)    // immediately modifies global state

Proposed flow (parallel + merge):
  // Phase 1: parallel speculative execution
  for each message (can be parallel across actors):
    reservation = compute_balance_reservation(msg)
    result[actor_id] = impl_create_ordinary_transaction(msg, account_readonly, actor_state, reservation)

  // Phase 2: deterministic merge (single-threaded)
  sort results by (actor_id, actor_lt)
  for each result in deterministic order:
    if result.balance_used <= result.reservation:
      apply_to_account(result)
      update_block_state(result)
    else:
      reject_transaction(result)
```

This is **not** a "40 lines of code change." It requires restructuring the core
execution loop in collator.cpp (6707 lines) and the transaction creation in
transaction.cpp (4325 lines).

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

### 6.2 Inter-Actor Balance Model

- **Account-level shared balance with reservation model** (see 5.4)
- Each Actor does not have its own balance
- Balance reservations computed before parallel execution
- Final balance changes applied in deterministic merge phase

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
| Account struct + serialization | New TL-B schema, state migration | High | 3-4 weeks |
| Two-phase execution model | Balance reservation, deterministic merge/commit | **Very High** | 4-6 weeks |
| Collator restructuring | Serial→parallel dispatch, result collection ordering | High | 3-4 weeks |
| TVM new instructions | 4 opcodes (STATEGET/STATESET/STATEDEL/ACTORSEND) | Medium | 1 week |
| Message routing | OutMsgQueue key extension, queue merge logic | Medium | 2 weeks |
| Validation logic | Actor-level proof, consistency checks | High | 3-4 weeks |
| Proof/lite-client upgrade | Extended Merkle proof path, new query types | Medium | 2-3 weeks |
| Built-in Token Actors | Native C++ Token Master/Balance/Allowance | Medium | 2 weeks |
| Tola compiler | Solidity-like syntax → Actor semantics → TVM bytecode | High | 6-8 weeks |
| Testing + integration | End-to-end validation, migration testing | High | 4-6 weeks |

**Total: approximately 6-9 months for a small team (2-3 engineers).**

The hardest parts are the deterministic commit model and collator restructuring.
The TVM opcodes and Tola compiler are comparatively straightforward.

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
| Serial transaction execution | Two-phase: parallel speculative + deterministic merge |
| Single balance per account | Shared balance with reservation model |
| OutMsgQueue key: 352 bits | Extended to 608 bits (includes full 256-bit actor_id) |
| Merkle proof: block→account→key | Extended: block→account→**actor**→key |
| lite-client address format | Extended with ActorAddress |

### New

| Component | Purpose |
|-----------|---------|
| `actors: HashmapE` in Account | Multiple Actor states per Account |
| `actor_lt: HashmapE` in Account | Independent logical time per Actor |
| Balance reservation model | Enable parallel execution with shared balance |
| Deterministic merge/commit phase | Preserve consensus after parallel execution |
| STATEGET/STATESET/STATEDEL/ACTORSEND | TVM opcodes for Actor-native programming |
| ActorAddress | Two-level addressing (account_id, actor_id) |
| Built-in Actor Registry | Native C++ Actor execution path |
| Tola language | Solidity-like syntax compiling to TVM |

## 9. Risks

1. **Protocol-level hard fork** — Requires coordinated upgrade of all validators, lite-clients, SDKs, and explorers simultaneously
2. **Deterministic commit model** — The two-phase execution model is the most complex and novel part; incorrect design breaks consensus
3. **Balance contention** — Reservation model must handle edge cases: insufficient balance after parallel execution, gas refunds, bounce messages
4. **Message visibility semantics** — Same-block Actor messages are consensus-critical; visibility rules must remain simple and deterministic
5. **Validation complexity** — validate-query.cpp (7597 lines) needs significant changes; Actor-level proofs add new attack surface
6. **State migration** — Existing accounts must be migrated to new format; requires migration protocol in the hard fork
7. **Client compatibility** — All wallets, SDKs, and block explorers must upgrade to understand ActorAddress

## 10. Implementation Roadmap

### Phase 1: Design Validation (3-4 months)

1. Formal specification of the two-phase execution model (reservation + merge)
2. Prototype the deterministic commit model in isolation
3. Design the Actor-level Merkle proof format
4. Define the state migration protocol
5. Write TL-B schema for new Account structure

### Phase 2: Core Implementation (3-4 months)

1. Implement Account struct changes + serialization
2. Implement two-phase execution in collator
3. Add TVM opcodes (STATEGET/STATESET/STATEDEL/ACTORSEND)
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

1. **Reservation model details:** How to compute gas reservation before execution? What happens when reservation is insufficient?
2. **Cross-shard Actor messages:** How do Actors in different shards communicate? Does the message routing protocol need changes beyond OutMsgQueue key?
3. **Actor lifecycle:** Can Actors be destroyed? What happens to an Actor's state when its Account is deleted?
4. **Backward compatibility period:** How long do we run old and new formats in parallel during migration?
5. **Actor count limits:** Maximum number of Actors per Account? Storage cost model for Actor metadata?

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
