# Actor Model in TOS

TOS uses the Actor Model as a first-principles design choice.

## Core Idea

Each actor:

- owns its own state
- processes messages independently
- does not rely on shared mutable memory

This gives TOS a natural foundation for parallel execution, fault isolation, and modular system growth.

## Why It Matters for the Node

The C++ node already uses an actor-based runtime through `td::actor`, which means the system naturally maps to:

- isolated workers
- message queues
- asynchronous scheduling
- explicit ownership and lifecycle control

## Why It Matters for the Chain

At the protocol level, the Actor Model supports:

- high throughput through message-oriented execution
- better separation between contracts and services
- cleaner failure boundaries
- a path toward parallel validation and execution

## Practical Consequences

- account and service interactions should be modeled as messages
- blocking synchronous assumptions should be avoided
- system services should expose explicit message contracts
- operator tooling should assume asynchronous progress, not instant global state transitions

## Design Direction

TOS should continue to push toward:

- more explicit actor boundaries in execution and validation
- better queue-aware scheduling
- improved parallelism where correctness boundaries are well defined

## Related Docs

- [README.md](/home/tomi/tos/README.md)
- [smc-guidelines.md](/home/tomi/tos/doc/smc-guidelines.md)

Two inviolable axioms:

1. **Two execution units can run in parallel ⟺ their mutable state is completely disjoint**
2. **Blockchain determinism ⟺ all validators agree on execution order and results**

Conclusion:

> To increase concurrency, an Account's data Cell must be split into multiple
> independent state partitions, each with its own timeline, executing independently
> and communicating via messages.

### 2.1 Storage Model: Cell Retained Internally, KV API Exposed Externally

Cell serves two roles simultaneously:

| Role | Responsibility | Approach |
|------|---------------|----------|
| **Internal storage (Commitment)** | Merkle hash, state proofs, light client verification, consensus, deduplication | **Retain** — Cell's design is elegant, no replacement needed |
| **Programming interface (Data Model)** | Contract developers directly manipulate Cell/Slice/Builder | **Encapsulate** — Hide behind KV Host API |

Cell's problem is not its internal structure, but being exposed as a programming interface.

```
Current (problem): Developer ──direct manipulation──→ Cell/Slice/Builder  (manual bit widths, painful)
Target (solution): Developer ──state_get/put──→ [Host API] ──internal ops──→ Cell  (transparent)
```

**Decision: Cell retained as internal storage structure, KV Host API as external programming interface.**

This means:
- Cell's Merkle proof capability fully preserved, no need to implement SMT from scratch
- BOC encoding fully preserved, block/network/storage formats unchanged
- Developers only see `state_get(key)` / `state_put(key, value)`

Each Actor's KV state is internally stored using TOS's existing HashmapE (Cell-based dictionary).
In C++ this corresponds to `vm::Dictionary` / `vm::AugmentedDictionary` (`crypto/vm/dict.h`).

Host API is a thin wrapper:

```cpp
// state_get: internally performs HashmapE lookup on the Actor's dictionary
td::optional<td::BufferSlice> state_get(td::Slice key) {
    auto key_hash = sha256(key);  // 256-bit key
    auto result = actor_dict.lookup(key_hash, 256);
    if (result.is_null()) return {};
    return result->as_bytes();
}

// state_put: internally performs HashmapE set on the Actor's dictionary
void state_put(td::Slice key, td::Slice value) {
    auto key_hash = sha256(key);
    vm::CellBuilder cb;
    cb.store_bytes(value);
    actor_dict.set(key_hash, 256, cb.as_cellslice_ref());
    // Cell tree auto-updates → Merkle hash auto-updates
}
```

Proof chain holds naturally (every layer is Cell, every layer has Merkle proof):

```
Block root (Cell)
  → ShardState root (Cell)
    → Account (Cell in ShardAccounts HashmapE)
      → Actor data (Cell in Actor HashmapE)   ← new layer added here
        → KV entry (Cell leaf in Actor HashmapE)
```

## 3. Account Model vs Actor Model

| Dimension | Account Model (current) | Actor Model (target) |
|-----------|------------------------|---------------------|
| Minimum unit | Account (one address) | Actor (sub-entity under one address) |
| State | One indivisible Cell tree | Each Actor has independent HashmapE (Cell internal, KV external) |
| Timeline | One `last_trans_lt_` | Each Actor has independent lt |
| Concurrency | N different addresses in parallel | N × M Actors in parallel (M = Actors per contract) |
| Communication | Cross-Account async messages | Cross-Actor async messages (even within same Account) |
| Internal storage | Cell tree | Cell tree (unchanged) |
| Developer interface | Cell/Slice/Builder | state_get/put + actor_send() |

## 4. Concrete Example: Token Contract

### Current (one Account)

```
Token contract (one address)
  data Cell = { total_supply, balances: HashMap<user, amount>, allowances: ... }

  UserA transfer ─┐
  UserB transfer ─┤→ All serial, because all modify the same balances HashMap
  UserC transfer ─┘
```

### After transformation (multiple Actors)

```
Token Master Actor (address/0)
  state = { total_supply, metadata }   ← internally a small HashmapE

Token Balance Actor (address/hash(userA))
  state = { balance: 100 }             ← internally a small HashmapE

Token Balance Actor (address/hash(userB))
  state = { balance: 200 }             ← internally a small HashmapE

UserA transfer → Actor(address/hash(userA))  ─┐
UserC query    → Actor(address/hash(userC))  ─┤ All parallel!
UserB transfer → Actor(address/hash(userB))  ─┘
```

## 5. Three-Layer Transformation

### 5.1 Layer 1: State Model — Introduce Sub-Actor Addressing

**What changes**: `crypto/block/transaction.h` Account struct

Address model extension:

```
Account Address (existing): workchain:account_id
Actor Address (new):        workchain:account_id:actor_id
```

Core change — add Actor index to Account struct:

```cpp
// Current Account (crypto/block/transaction.h:262)
struct Account {
    int status;
    tos::StdSmcAddress addr;
    tos::LogicalTime last_trans_lt_;
    block::CurrencyCollection balance;
    Ref<vm::Cell> code, data, library;   // data = entire contract state
    // ...
};

// After transformation
struct Account {
    int status;
    tos::StdSmcAddress addr;
    tos::LogicalTime last_trans_lt_;     // Account-level lt (retained)
    block::CurrencyCollection balance;
    Ref<vm::Cell> code, library;         // code retained (shared by all Actors)
    vm::Dictionary actors;               // actor_id(256bit) → Actor data Cell
    vm::Dictionary actor_lt;             // actor_id(256bit) → per-Actor lt(64bit)
    // ...
};
```

Each Actor's data is also a HashmapE (`vm::Dictionary`).

State hierarchy (all Cell, all with Merkle proof):

```
ShardState root (Cell)
 └─ ShardAccounts: HashmapE
      └─ Account (Cell)
           ├─ code: Cell (contract code)
           ├─ balance: CurrencyCollection
           ├─ actors: HashmapE (Cell dictionary)
           │    ├─ actor_0 data: HashmapE (Cell dictionary) ← accessed via Host API
           │    ├─ actor_1 data: HashmapE (Cell dictionary) ← accessed via Host API
           │    └─ ...
           └─ actor_lt: HashmapE
                ├─ actor_0 → lt: u64
                └─ actor_1 → lt: u64
```

Light client proof chain (identical to existing Cell MerkleProof mechanism):

```
block_root → shard_state → account → actors → actor_data → key=value
  (every step is a Cell Merkle proof, existing MerkleProof / check_account_proof all reusable)
```

### 5.2 Layer 2: Execution Model — Actor-Level Transactions

**What changes**: `validator/impl/collator.cpp` `impl_create_ordinary_transaction`

Current signature (`collator-impl.h:112`):

```cpp
static td::Result<std::unique_ptr<block::transaction::Transaction>>
impl_create_ordinary_transaction(
    Ref<vm::Cell> msg_root,
    block::Account* acc,           // ← mutable pointer to entire Account
    UnixTime utime, LogicalTime lt,
    block::StoragePhaseConfig* storage_phase_cfg,
    block::ComputePhaseConfig* compute_phase_cfg,
    block::ActionPhaseConfig* action_phase_cfg,
    block::SerializeConfig* serialize_cfg,
    bool external, LogicalTime after_lt,
    CollationStats* stats = nullptr);
```

After transformation:

```cpp
static td::Result<std::unique_ptr<block::transaction::Transaction>>
impl_create_ordinary_transaction(
    Ref<vm::Cell> msg_root,
    const block::Account* acc,     // ← read-only (reads code and balance)
    vm::Dictionary* actor_state,   // ← locks only target Actor's HashmapE
    LogicalTime* actor_lt,         // ← Actor-level timeline
    UnixTime utime, LogicalTime lt,
    // ... rest unchanged
    );
```

TVM-level changes:

- **C4 register**: Instead of loading entire Account `data` Cell, load single Actor's
  HashmapE root Cell. TVM's existing DICTGET/DICTSET instructions work directly.
- **C7 (SmartContractInfo)**: Add `actor_id` field
- **code**: All Actors share the same code Cell
- **Gas / Action / Bounce**: Unchanged

New Host API instructions (as TVM opcodes):

```
STATEGET   key_hash:uint256 → value:slice       // wraps Dictionary::lookup
STATESET   key_hash:uint256 value:slice → ()     // wraps Dictionary::set
STATEDEL   key_hash:uint256 → bool               // wraps Dictionary::delete_key
ACTORSEND  actor_id:uint256 body:cell → ()        // sends message to another Actor
```

These instructions internally perform lookup/set on the HashmapE in C4 — no new data structures introduced.
Implementation location: `crypto/vm/tonops.cpp` (TVM blockchain-specific instruction implementation).

**Contracts can be written in three ways**:

1. **Solidity-like** (primary target, for the wider developer community): Familiar syntax,
   compiles to TVM bytecode using STATEGET/STATESET/ACTORSEND opcodes
2. **FunC/Tolk** (for developers familiar with TOS): Use DICTGET/DICTSET on C4 directly,
   or use the new simplified STATEGET/STATESET
3. **Native C++** (built-in/system contracts only): Ships with the node binary, maximum performance

### 5.3 Layer 3: Scheduling Model — Each On-Chain Actor IS a td::actor::Actor

**What changes**: `validator/impl/collator.cpp`

Core idea: **Each on-chain Actor directly IS a `td::actor::Actor`, receiving messages,
executing, and returning results on its own.** No coordinator + worker pattern needed —
td::actor itself IS an Actor model, no one needs to "assign tasks".

Current Collator executes all transactions synchronously:

```cpp
// Current — collator.cpp:3716 — synchronous serial
auto trans_root = create_ordinary_transaction(msg.msg, msg.metadata, msg.lt, ...);
// blocks until complete, then processes result in-place
```

After transformation, each on-chain Actor is an independent td::actor::Actor:

```cpp
// Each on-chain Actor IS a td::actor::Actor — the minimum execution unit
class OnChainActor : public td::actor::Actor {
    const block::Account* acc_;      // read-only: shared contract code and balance
    vm::Dictionary actor_state_;     // exclusive: this Actor's HashmapE
    LogicalTime actor_lt_;           // exclusive: this Actor's timeline

    void execute(Ref<vm::Cell> msg, td::Promise<Ref<vm::Cell>> promise) {
        auto result = Collator::impl_create_ordinary_transaction(
            msg, acc_, &actor_state_, &actor_lt_, ...);
        promise.set_result(std::move(result));
    }
};
```

Collator's role is unchanged (select messages, enforce block limits, assemble block).
The only change is transaction execution goes from synchronous call to sending a message to the Actor:

```cpp
// Collator's role is unchanged, only the execution method changes
void Collator::process_message(msg) {
    auto actor_addr = get_actor_address(msg);
    auto& actor = get_or_create_actor(actor_addr);

    // Send message directly to Actor (not "assigning a task")
    td::actor::send_closure(actor, &OnChainActor::execute, msg.msg,
        [this](auto result) { collect_transaction_result(result); });
}
```

**Parallelism comes from td::actor Scheduler's natural capability**:
- Different Actors' messages are scheduled in parallel across the thread pool
- Same Actor's messages are serialized by ActorLocker
- No additional concurrency control needed

Message routing also changes:

```
Current: OutMsgQueue key = workchain(32) | addr_prefix(64) | msg_hash(256)
After:   OutMsgQueue key = workchain(32) | addr_prefix(64) | actor_id(64) | msg_hash(192)
```

## 6. Key Design Decisions

### 6.1 Actor Creation Method

- Option A: Explicit in-contract creation — contract code calls `ACTORCREATE`
- Option B: Address derivation — Actor address deterministically derived from `(account_addr, discriminator)`
- **Recommended B** — Deterministic, predictable, no on-chain registry needed

### 6.2 Inter-Actor Balance Model

- Option A: Each Actor has independent balance
- Option B: Shared Account balance, Actors only have state, no balance
- **Recommended B to start** — Simpler, balance management stays at Account level

### 6.3 Execution Engine (Incremental Strategy)

**Two execution paths, sharing the same state interface (vm::Dictionary / HashmapE):**

| Path | For | Performance | Safety | Available |
|------|-----|-------------|--------|-----------|
| **Native C++** | Built-in/system contracts (token standards, governance, etc.) | Fastest | Trusted — ships with node binary | Phase 1 |
| **TVM** | User-deployed contracts (FunC/Tolk/Solidity-like) | Medium | TVM sandbox | Phase 1 |

Both paths operate on the same `vm::Dictionary` (HashmapE). Built-in Actors and
user-deployed Actors can exchange messages freely because state format and message
format are identical.

**Native execution for built-in contracts** leverages the existing `precompiled_contracts_list`
mechanism in the codebase. Currently it only skips TVM with fixed gas accounting;
we extend it to dispatch to native C++ Actor implementations:

```cpp
class BuiltinActorRegistry {
    std::map<uint256, std::unique_ptr<BuiltinActor>> registry_;
    bool has(uint256 code_hash) const;
    td::Result<ExecutionResult> execute(
        uint256 code_hash,
        vm::Dictionary* actor_state,   // same HashmapE API as TVM path
        Ref<vm::Cell> msg);
};
```

Collator selects execution path by code hash:

```cpp
void OnChainActor::execute(Ref<vm::Cell> msg, td::Promise<Ref<vm::Cell>> promise) {
    auto code_hash = acc_->code->get_hash();
    if (builtin_registry.has(code_hash)) {
        // Path 1: built-in → native C++ (fastest)
        auto result = builtin_registry.execute(code_hash, &actor_state_, msg);
        promise.set_result(std::move(result));
    } else {
        // Path 2: user contract (FunC/Tolk/Solidity-like) → TVM sandbox
        auto result = impl_create_ordinary_transaction(msg, acc_, &actor_state_, &actor_lt_, ...);
        promise.set_result(std::move(result));
    }
}
```

**Why native built-in contracts matter:**
- System contracts (token standards, DEX primitives, governance) are the hottest contracts
- Native execution removes TVM overhead for the most critical path
- Built-in Actors serve as reference implementations for user-deployed contracts
- Development order: write built-in Token Actors in native C++ first to validate the entire
  Actor architecture, then open TVM (FunC/Tolk/Solidity-like) to users

**User-deployed contracts cannot run natively** because:
- No sandboxing — native code can read process memory, steal keys, crash the node
- No determinism guarantee — different platforms (x86/ARM), compilers, optimization levels
  may produce different results, breaking validator consensus
- No portability — x86 binary won't run on ARM validators

Incremental timeline:
1. **Short-term**: Native C++ built-in Actors + TVM with STATEGET/STATESET/ACTORSEND opcodes
2. **Mid-term**: Solidity-like language compiling to TVM bytecode — familiar syntax for
   the wider smart contract developer community
3. **Long-term**: Evolve the Solidity-like language based on ecosystem feedback

### 6.4 Shard Boundaries

- **Recommended A to start**: All Actors of the same Account stay in the same shard
- Concurrency improvement is already significant (parallelism within one Account goes from 1 to Actor count)

### 6.5 Storage Model (Decided)

- **Cell retained internally, KV Host API exposed externally**

Rationale:
1. Cell Merkle proof capability fully preserved, no SMT needed
2. HashmapE / vm::Dictionary already has complete API, ready to use
3. BOC / block format / network protocol / storage layer all unchanged
4. MerkleProof code only needs extension, not rewrite
5. FunC/Tolk fully compatible

### 6.6 Serialization Format

- **BOC retained unchanged**

### 6.7 Implementation Language (Decided)

- **C++ (based on ton-c)**

Rationale:
1. Unchanged parts (consensus/network/storage/TVM/validation) have 6 years of production validation
2. td::actor framework naturally supports per-Actor splitting
3. FunC/Tolk compiler, lite-client, tonlib all included
4. Collator per-Actor split costs ~1 extra week, trading for 6 years of code maturity

### 6.8 Smart Contract Language (Decided: Solidity-like as primary target)

**Goal: developers write smart contracts in familiar Solidity-like syntax, compiling to TVM bytecode.**

1. **Short-term**: Extend Tolk with Actor keywords (`stateGet`/`stateSet`/`actorSend`) as a
   stepping stone — validates the new TVM opcodes work correctly (~2 weeks)
2. **Primary target**: Solidity-like frontend compiler (Solidity syntax → Actor semantics → TVM bytecode) (~4-6 weeks)
   - `actor` keyword instead of `contract`
   - `mapping` maps to STATEGET/STATESET
   - `uint64`/`uint128`/`uint256` standard types
   - `other.send()` for async message passing (replaces synchronous `other.call()`)
   - `require()` / `revert()` for error handling
   - No reentrancy by design (messages are queued)
   - Compile target: TVM bytecode (no WASM dependency)
3. **FunC/Tolk remain supported** — existing developers can continue using them with
   the new STATEGET/STATESET/ACTORSEND opcodes directly

Example:

```solidity
actor TokenBalance {
    uint64 balance;

    function credit(uint64 amount) external {
        balance += amount;
    }

    function transfer(uint256 recipient, uint64 amount) external {
        require(balance >= amount, "insufficient");
        balance -= amount;
        recipient.send("credit", abi.encode(amount));
    }
}
```

This compiles to TVM bytecode using STATEGET/STATESET/ACTORSEND — no WASM runtime needed.

## 7. Effort Estimate

Line-level estimates based on actual call site analysis:

| Layer | Specific Changes | Files Involved | Lines Changed | Effort |
|-------|-----------------|----------------|---------------|--------|
| Account struct | Add `actors`/`actor_lt` vm::Dictionary + serialization | `crypto/block/transaction.h` (484 lines), `transaction.cpp` (4325 lines), `block.cpp` | ~200 lines | 1-2 weeks |
| Execution model | `impl_create_ordinary_transaction` signature + C4/C7 Actor-level | `validator/impl/collator.cpp:3431` | ~40 lines | 3-5 days |
| OnChainActor + async | New `OnChainActor` class + 5 sync call sites → `send_closure` | `validator/impl/collator.cpp` (3716, 4083, 4312, 3565, 2381) | ~200 lines | 1-1.5 weeks |
| TVM new instructions | STATEGET/STATESET/STATEDEL/ACTORSEND — four opcodes | `crypto/vm/tonops.cpp` (2565 lines) | ~150 lines | 3-5 days |
| Message routing | OutMsgQueue key extension with actor_id | `crypto/block/output-queue-merger.*` (323 lines) | ~180 lines | 1-1.5 weeks |
| Validation logic | Account/transaction/OutMsg validation adapted for Actor sub-structure | `validator/impl/validate-query.cpp` (7597 lines) | ~200 lines | 1-2 weeks |
| Built-in Actor registry | Extend precompiled mechanism + BuiltinActorRegistry | `validator/impl/collator.cpp`, new header | ~100 lines | 3-5 days |
| Built-in Token Actors | Native C++ Token Master/Balance/Allowance (reference Tako examples) | New source files | ~300 lines | 1 week |
| Solidity-like compiler | Solidity syntax → Actor semantics → TVM bytecode | New compiler project | ~3000-5000 lines | 4-6 weeks |

**Total: approximately 10-16 weeks for one person**, split into two deliverables:
- **Actor infrastructure (Phases 1-3)**: ~6-10 weeks, ~1400 lines of node changes
- **Solidity-like compiler (Phase 4)**: ~4-6 weeks, ~3000-5000 lines — independent project, can be parallelized

Why the effort is small:
- Cell/BOC/block format all unchanged → serialization layer mostly unaffected
- Each on-chain Actor directly IS a `td::actor::Actor` → no additional scheduling framework needed
- Only 5 synchronous call sites in Collator need async conversion → not a full rewrite
- TVM new instructions are just wrappers around existing `vm::Dictionary` API → no new concepts
- Most of validate-query's 7597 lines are unrelated to Actor changes → only Account-structure-related parts change
- Built-in Actor registry extends the existing `precompiled_contracts_list` mechanism → framework already exists
- Built-in Token Actors closely follow Tako's proven examples (`../old_rtos/crates/tosnetwork/tako/src/builtin/application/token/`)

## 8. What Stays, What Changes, What's New

### Unchanged

- **Cell data structure** — retained internally, all Merkle proof capability intact
- **BOC encoding** — block/network/storage serialization format unchanged
- **Block format** — Block/Transaction/Message Cell encoding unchanged
- **MerkleProof** — existing `check_proof()` etc. reusable
- **Network protocol** — ADNL/RLDP/DHT/QUIC transport unchanged
- **Consensus layer** — Catchain/Simplex unaffected
- **Sharding architecture** — address-prefix-based sharding unchanged
- **td::actor framework** — continues in use, OnChainActor is a new Actor type
- **Scheduling semantics** — multi-phase dispatch queue, fairness, backpressure
- **Execution phases** — storage → credit → compute → action → bounce
- **FunC/Tolk** — existing contract languages continue working
- **lite-client / tonlib** — client tools continue working
- **Storage layer** — CellDB / RocksDB unchanged

### Changed

| Before | After | Reason |
|--------|-------|--------|
| Account = minimum execution unit | Actor = minimum execution unit | Increase concurrency |
| One Account, one data Cell | One Account, multiple Actors (each with independent HashmapE) | State isolation |
| One Account, one lt timeline | Each Actor has independent lt | Enable parallelism |
| Collator executes all transactions synchronously | Collator sends messages to OnChainActor, Actor executes autonomously | Parallel execution |
| `impl_create_ordinary_transaction(acc*)` | `impl_create_ordinary_transaction(acc*, actor_state*, actor_lt*)` | Actor-level locking |
| TVM C4 = Account data Cell | C4 = Actor data HashmapE root Cell | Actor-level state |
| OutMsgQueue key without actor_id | Key includes actor_id | Actor-level message routing |

### New

| Component | Purpose | Implementation Location |
|-----------|---------|------------------------|
| `actors: vm::Dictionary` in Account | Manage multiple Actors under one Account | `crypto/block/transaction.h` |
| `actor_lt: vm::Dictionary` in Account | Independent logical time per Actor | `crypto/block/transaction.h` |
| `OnChainActor : td::actor::Actor` | On-chain Actor = td::actor, minimum execution unit | `validator/impl/collator.cpp` |
| STATEGET/STATESET/STATEDEL opcodes | KV-style access to Actor's HashmapE | `crypto/vm/tonops.cpp` |
| ACTORSEND opcode | Inter-Actor message sending | `crypto/vm/tonops.cpp` |
| ActorAddress type | (AccountId, ActorId) two-level addressing | `crypto/block/block.h` |
| BuiltinActorRegistry | Dispatch to native C++ Actors by code hash | `validator/impl/collator.cpp` |
| Built-in Token Actors | Native C++ Token Master/Balance/Allowance | New source files (reference Tako examples) |

## 9. Risks

1. **On-chain data format change** — Adding actors/actor_lt to Account means a hard fork
2. **Validation logic consistency** — `validate-query.cpp` at 7597 lines is the most error-prone area
3. **Balance contention** — Multiple OnChainActors sharing Account balance, parallel gas deduction needs atomic operations
4. **State bloat** — Per-Actor lt and HashmapE metadata increase Cell storage overhead
5. **Collator async conversion** — Changing from sync calls to send_closure + Promise callbacks across 6707-line collator.cpp requires careful result collection ordering
6. **td::actor scheduling pressure** — Large numbers of OnChainActors may increase Scheduler overhead; consider keeping synchronous path optimization for small Accounts (single Actor)

## 10. Incremental Implementation Roadmap

### Phase 1: Actor State Isolation + Built-in Actors (Goal: validate the architecture)

1. Add `actors` and `actor_lt` (`vm::Dictionary`) to Account struct
2. Change `impl_create_ordinary_transaction` signature to Actor granularity
3. Change TVM C4 to load Actor HashmapE
4. Add STATEGET/STATESET/STATEDEL/ACTORSEND TVM instructions
5. Extend `precompiled_contracts_list` into BuiltinActorRegistry for native C++ execution
6. Implement built-in Token Actors in native C++ (Master/Balance/Allowance — reference Tako examples)
7. **Validate entire Actor architecture end-to-end with built-in Token before opening to users**

### Phase 2: Per-Actor Parallel Execution (Goal: concurrency improvement)

1. Add `OnChainActor : td::actor::Actor` — each on-chain Actor IS a td::actor
2. Change Collator's `create_ordinary_transaction` from sync call to `send_closure` message to Actor
3. Different Actors under same Account naturally scheduled in parallel by Scheduler
4. Results collected via `Promise` callbacks, block assembly remains in Collator
5. Built-in Actors also run as td::actor instances, benefiting from same parallelism

### Phase 3: Message Routing Extension (Goal: Actor-to-Actor communication)

1. Add actor_id to OutMsgQueue key
2. Extend message destination to ActorAddress
3. Adapt `validate-query.cpp` for Actor-level validation

### Phase 4: Solidity-Like Language (Goal: familiar developer experience)

1. Build Solidity-subset compiler with Actor extensions (`actor` keyword, `send()` for async)
2. Compile target: TVM bytecode — `mapping` compiles to STATEGET/STATESET, `send()` compiles to ACTORSEND
3. No reentrancy by design — all cross-Actor calls are async messages
4. Developers learn one new concept: calling others = sending messages, no synchronous return values
5. FunC/Tolk/built-in contracts continue working alongside Solidity-like contracts

## 11. Built-in Standard Actor Library (OpenZeppelin for TOS)

### 11.1 Philosophy

Ethereum's OpenZeppelin library proved that **standardized, audited building blocks**
are the single most impactful developer tool in a smart contract ecosystem. Over 10 years,
the pattern is clear: 90% of on-chain applications are compositions of a few standard
primitives (tokens, access control, governance, escrow).

TOS takes this further. Instead of each project copying and redeploying the same library
code (Ethereum's model), TOS ships standard actors as **native C++ built-ins compiled
into the node binary**:

| | Ethereum + OpenZeppelin | TOS Built-in Actors |
|---|---|---|
| Code location | Copied into each project, deployed per-project | One copy in node binary, shared by all |
| Deployment cost | ~1M gas per ERC20 deployment | Zero — create Actor instance via message |
| Audit burden | Each fork audited separately | Audited once, all users benefit |
| Fragmentation | Thousands of ERC20 variants with subtle differences | One canonical implementation, identical behavior |
| Upgrade path | Each project upgrades independently (or doesn't) | Node upgrade updates all validators simultaneously |
| Performance | EVM bytecode interpretation | Native C++ execution (fastest path) |

### 11.2 Standard Actor Library

Extracted from 10 years of Ethereum/OpenZeppelin/DeFi ecosystem experience:

**Token Layer (Phase 1 — ships with Actor launch)**

| Actor Type | OpenZeppelin Equivalent | Purpose |
|-----------|------------------------|---------|
| TokenMaster | ERC20 (admin) | Mint, burn, metadata, total supply |
| TokenBalance | ERC20 (per-user) | Hold balance, transfer, credit |
| TokenAllowance | ERC20 (approval) | Approve, transferFrom |
| NFTCollection | ERC721 (collection) | Mint, metadata, enumeration |
| NFTItem | ERC721 (per-item) | Owner, transfer, approve |
| MultiToken | ERC1155 | Multiple token types in one contract |

**Access Control Layer**

| Actor Type | OpenZeppelin Equivalent | Purpose |
|-----------|------------------------|---------|
| Ownable | OZ Ownable | Single-owner access control |
| AccessControl | OZ AccessControl | Role-based permission management |
| Multisig | Gnosis Safe | Multi-signature approval |
| Timelock | OZ TimelockController | Delayed execution |

**Governance Layer**

| Actor Type | OpenZeppelin Equivalent | Purpose |
|-----------|------------------------|---------|
| Governor | OZ Governor | Proposal, voting, execution |
| VoteActor | OZ Votes | Voting power snapshot, delegation |

**DeFi Layer**

| Actor Type | Equivalent | Purpose |
|-----------|-----------|---------|
| AMMPool | Uniswap V2 Pair | Reserve management, swap, LP |
| LiquidityPosition | Uniswap V3 Position | Concentrated liquidity |
| LendingPool | Aave/Compound | Borrow, lend, interest, liquidation |
| Escrow | OZ Escrow | Custody, release (Tako example exists) |
| Vesting | OZ VestingWallet | Token vesting schedule |
| PaymentSplitter | OZ PaymentSplitter | Revenue splitting |

**Infrastructure Layer**

| Actor Type | Equivalent | Purpose |
|-----------|-----------|---------|
| Oracle | Chainlink Feed | Price feed interface |
| Proxy | OZ Proxy | Upgradeable actor pattern |

### 11.3 How Users Build with Standard Actors

**Scenario 1: Launch a token (zero code)**

User sends one message — no contract writing, no deployment, no audit needed:

```
User → System: "create TokenMaster, name=MyToken, symbol=MTK, supply=1000000"
  → System auto-creates: TokenMaster Actor + TokenBalance Actor (holding initial supply)
```

**Scenario 2: Build a DEX (only write routing logic)**

```tola
// User only writes the business-specific routing logic.
// AMM math, token transfers, LP accounting — all handled by built-in Actors.
actor DEXRouter {
    function swap(ActorId pool, ActorId userBalance, uint64 amountIn) external {
        pool.send("swap", abi.encode(userBalance, amountIn));
    }

    function addLiquidity(ActorId pool, uint64 amountA, uint64 amountB) external {
        pool.send("add_liquidity", abi.encode(msg.sender, amountA, amountB));
    }
}
```

**Scenario 3: Build an NFT marketplace (compose standard Actors)**

```tola
actor Marketplace {
    function list(ActorId nftActor, uint64 price) external {
        nftActor.send("transfer", abi.encode(self));   // NFT → escrow
        stateSet("listing", abi.encode(msg.sender, price));
    }

    function buy(ActorId nftActor) external payable {
        (ActorId seller, uint64 price) = abi.decode(stateGet("listing"));
        require(msg.value >= price, "insufficient payment");
        nftActor.send("transfer", abi.encode(msg.sender));   // NFT → buyer
        seller.send("credit", abi.encode(price));              // payment → seller
    }
}
```

### 11.4 Design Principle

> **Users write only the 10% that makes their business unique.**
> **The other 90% (tokens, access control, escrow, AMM) is already built, audited, and running natively.**

This is the core value proposition: the TOS built-in Actor library extracts a decade
of Ethereum smart contract patterns into zero-deployment, zero-audit, native-performance
standard components that any Tola contract can call with a single `.send()`.

## 12. References

- Tola Language Whitepaper: `./tola.md`
- td::actor framework: `tdactor/td/actor/`
  - Actor base class: `tdactor/td/actor/core/Actor.h`
  - ActorMailbox: `tdactor/td/actor/core/ActorMailbox.h`
  - ActorExecutor: `tdactor/td/actor/core/ActorExecutor.h`
  - Scheduler: `tdactor/td/actor/core/Scheduler.h`
  - create_actor / send_closure: `tdactor/td/actor/actor.h`
- Collator Actor: `validator/impl/collator-impl.h:46`
- Collator implementation: `validator/impl/collator.cpp` (6707 lines)
- Account struct: `crypto/block/transaction.h:262-321`
- Transaction execution: `validator/impl/collator.cpp:3431` (impl_create_ordinary_transaction)
- Validation logic: `validator/impl/validate-query.cpp` (7597 lines)
- HashmapE / Dictionary: `crypto/vm/dict.h`
- TVM instruction implementation: `crypto/vm/tonops.cpp`
- MerkleProof: `crypto/block/check-proof.cpp`
