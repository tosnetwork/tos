# TOS EVM Workchain Feasibility

Version: v0.1

## Purpose

This document evaluates the feasibility of adding an `evm-workchain` to TOS by embedding `revm` as the execution engine for a new workchain.

The target outcome is not "full Ethereum node parity on day one". The target outcome is a staged path that makes the `evm-workchain` look Ethereum-compatible at the wallet and API surface from the first implementation wave, while keeping the internal execution scope intentionally narrow.

This document is intentionally pragmatic. It is written to answer:

- what an initial `evm-workchain` can realistically support
- what should be deferred
- where the current TOS architecture already provides integration points
- which parts `revm` can solve directly
- which parts remain TOS-specific and must be implemented locally

## Executive Summary

Embedding `revm` into TOS is feasible, but the main difficulty is not the VM itself.

The hard part is bridging:

- TOS account and message semantics
- TOS transaction lifecycle
- TOS fee accounting
- TOS block context
- TOS state storage layout

to:

- EVM account state
- EVM call/create execution
- EVM gas rules
- EVM receipts and logs

This means:

- plugging in `revm` is a moderate engineering task
- turning it into a wallet- and tooling-compatible `evm-workchain` is a large systems task

The recommended path is:

1. make address format, signing model, and core RPC surface Ethereum-compatible from the start
2. keep the execution scope intentionally narrow
3. prove end-to-end execution first
4. expand compatibility only after the first wallet-facing path is stable

## Recommendation

The most practical delivery path is:

### 1. First build an `evm-workchain` prototype that is Ethereum-compatible at the wallet and API surface, and supports only:

- Ethereum-compatible `0x` 20-byte account addresses
- secp256k1 EOAs and Ethereum transaction signing
- a minimal wallet-facing `eth_*` RPC surface
- EOAs
- simple `CALL`
- simple `CREATE`
- native balance
- basic gas

### 2. Explicitly do not build yet:

- full Ethereum node parity or complete `eth_*` RPC coverage
- cross-workchain contract messaging
- full precompile coverage
- full logs and tracing compatibility

### 3. After the execution pipeline works:

- add broader compatibility layers incrementally
- add richer wallet and developer tooling support
- add wider RPC compatibility where justified

This is the right order because wallet compatibility without execution correctness is hollow, and execution correctness without a wallet-facing compatibility surface does not solve ecosystem onboarding.

## Why Workchain Is the Right Integration Boundary

TOS already models workchains as separate execution/state domains.

Each workchain has its own descriptor in `ConfigParam 12`, including:

- active flag
- message acceptance policy
- zerostate hashes
- `vm_version`
- `vm_mode`

This means the protocol model already has a place where different execution environments can be attached without pretending that all contracts must use the same VM.

Relevant repository evidence:

- `doc/ConfigParam.md`
- `crypto/block/block.tlb`
- `tosctl/src/block/src/config_params.rs`

That does not mean an EVM workchain is already implemented. It means the architectural boundary is already present.

## What `revm` Gives Us

Using `revm` reduces the amount of EVM-specific work we must build ourselves.

`revm` can provide:

- EVM bytecode execution
- `CALL` and `CREATE` semantics
- gas accounting inside the EVM interpreter
- storage updates and account mutation logic
- fork-specific EVM rules if configured
- optional precompile and inspector support

If `reth` is locally available, it also provides examples of:

- EVM configuration factories
- state database adapters
- executor wiring
- custom EVM environments

This is valuable because it avoids implementing a fresh EVM from scratch.

## Silkworm-Based Implementation Path

If the implementation direction is C++-first, `~/silkworm` is a viable foundation for the `evm-workchain`.

The role of Silkworm in this design should be:

- provide reusable Ethereum execution components
- provide reusable Ethereum transaction, receipt, and RPC semantics
- reduce the amount of fresh EVM client logic that must be implemented inside TOS

The role of Silkworm should not be:

- replace the TOS node
- replace TOS workchain routing or finalization
- become a second independent chain coordinator inside the same node

In other words, the intended model is:

- TOS owns the chain
- Silkworm-backed components help implement the EVM workchain inside that chain

### Recommended Reuse From Silkworm

The following areas are strong candidates for reuse or adaptation:

- EVM execution path
- Ethereum transaction decoding and validation
- sender recovery and secp256k1-related transaction semantics
- gas and intrinsic gas calculations
- receipt building and Ethereum-style execution results
- Ethereum JSON-RPC method handling for the wallet-facing surface
- chain configuration concepts where useful for the EVM workchain

Relevant local code areas include:

- `~/silkworm/silkworm/execution`
- `~/silkworm/silkworm/core`
- `~/silkworm/silkworm/rpc`
- `~/silkworm/third_party/evmone`

### What Must Still Be Implemented In TOS

Even with Silkworm reuse, the following remain TOS-specific engineering tasks:

- workchain definition and config activation
- zerostate definition for the new workchain
- workchain-aware routing and dispatch from the TOS transaction pipeline
- mapping TOS chain lifecycle and block context into the EVM execution context
- defining the dedicated EVM state boundary inside the TOS node
- building the storage adapter between TOS-managed EVM state and the Silkworm execution/state interfaces
- deciding how TOS fee accounting and EVM gas accounting meet
- replay, sandbox, and validator/collator integration under TOS rules
- explicit handling of cross-workchain non-goals in the MVP

These are not generic Ethereum client concerns. They are TOS integration concerns and must be owned locally.

### Recommended Integration Shape

The recommended integration shape is:

1. keep TOS as the outer coordinator
2. isolate the EVM workchain state behind its own storage boundary
3. use Silkworm-derived execution and RPC modules only for the EVM workchain
4. keep the interface between TOS and Silkworm-derived modules narrow and explicit

That interface should ideally pass:

- workchain-scoped block context
- EVM transaction payloads
- account/state access requests against the dedicated EVM state store
- execution results, receipts, gas usage, and state diffs

It should avoid sharing:

- raw TOS-internal object graphs
- TVM account representations
- mixed TVM/EVM state abstractions

### Reuse Strategy

The implementation should prefer selective extraction and adaptation over wholesale embedding.

Recommended strategy:

- reuse execution-oriented modules
- reuse RPC surface logic where it cleanly maps to the wallet-facing API
- adapt state access through a TOS-owned storage adapter
- avoid adopting Silkworm's full node, sync, or storage stack as-is

This keeps the architecture aligned with the TOS workchain model instead of trying to host two different blockchain nodes inside one process.

## What `revm` Does Not Solve

`revm` does not solve the TOS-side integration model.

The following remain TOS engineering work:

- defining the new workchain and its zerostate
- deciding the address model for EVM accounts in that workchain
- mapping TOS inbound messages to EVM transactions
- mapping EVM results back into TOS transaction phases
- integrating TOS fee rules with EVM gas usage
- deciding how balances are represented and charged
- defining what state layout is canonical for EVM accounts on TOS
- deciding what is visible through JSON-RPC and SDKs

This is why the project is feasible but still substantial.

## Current TOS Integration Points

The current repository already has several useful boundaries:

### 1. Workchain Format Configuration

Workchain descriptors already contain `vm_version` and `vm_mode`.

That means we can define a new workchain format without pretending it is identical to the existing basechain.

### 2. Transaction Execution Pipeline

TOS already has a transaction execution pipeline that separates:

- compute phase
- action phase
- fee handling
- state updates

This is useful because an EVM executor can be introduced as an alternative compute path for one workchain, rather than replacing global execution logic.

Relevant repository areas:

- `crypto/block/transaction.cpp`
- `tosctl/src/executor`
- `tosctl/src/sandbox`

### 3. Message and Address Routing

TOS already routes messages using:

- workchain
- address length / address payload
- workchain acceptance rules

This means new workchain-specific routing policy can be introduced without redefining the whole chain.

## Main Architectural Decision

The key decision is:

> Should `evm-workchain` be modeled as a workchain-specific execution environment with TOS-native envelopes, or as an Ethereum-compatible subsystem with TOS merely hosting it?

For the first implementation wave, the answer should be:

> Ethereum-compatible external surface with TOS-hosted EVM execution inside.

That means:

- TOS remains the outer chain model
- EVM is the compute engine for one workchain
- the wallet-facing address and API surface is Ethereum-compatible from the first milestone
- deeper node parity is added progressively, not assumed from the first commit

This gives the project a practical ecosystem entry point without forcing the first milestone to reproduce a full Ethereum client.

## State Storage Boundary

The `evm-workchain` should not be implemented as a completely separate blockchain database stack. It should be implemented as a separate execution-state domain within the TOS node.

In practice, this means:

- chain-level metadata remains under the TOS node
- block production, routing, finalization, and workchain coordination remain under the TOS node
- the EVM workchain gets its own state storage boundary
- the EVM workchain state should use its own schema, namespace, or dedicated database

This separation is strongly recommended because the TOS-native TVM/account-cell state model and the EVM account/storage-slot model are structurally different.

The first implementation should therefore prefer:

- shared chain metadata
- isolated TVM state
- isolated EVM state

over:

- a fully separate chain stack
- or a single mixed storage format for both TVM and EVM accounts

The design goal is logical and operational separation, even if some lower-level storage infrastructure is shared.

## External Compatibility Goal

The first implementation wave should make the `evm-workchain` look like a normal EVM chain to existing wallets and standard client libraries.

At minimum, this means:

- account addresses are standard Ethereum-style `0x` 20-byte addresses
- EOAs use secp256k1 keys and Ethereum-compatible signing and sender recovery
- transactions use Ethereum-compatible transaction encoding and nonce semantics
- the node exposes a minimal but standard `eth_*` JSON-RPC surface
- the network is identified by an EVM `chainId`

The project should explicitly target compatibility with:

- standard EVM wallet connection flows
- WalletConnect-compatible wallets
- common EVM libraries such as `ethers` and `viem`

This does not require full Ethereum node parity in the first milestone. It does require that a wallet can recognize the chain, derive the correct account, sign transactions, submit them, and read back basic execution results without learning TOS-native account or address formats.

## MVP Scope

The initial `evm-workchain` prototype should support only the minimum features required to prove that:

- accounts can exist in the new workchain
- transactions can execute through `revm`
- state can persist correctly
- gas can be charged in a simple and deterministic way
- existing EVM wallets can connect using Ethereum-style addresses and APIs

### MVP Features

#### 0. Ethereum-Compatible External Surface

Before discussing execution depth, the first milestone must freeze the external compatibility surface.

For the MVP:

- use standard Ethereum `0x` 20-byte account addresses
- use secp256k1 EOAs
- use Ethereum-compatible transaction signing and sender recovery
- assign an EVM `chainId`
- expose the minimum JSON-RPC set required for wallet connectivity

The minimum RPC set should include:

- `eth_chainId`
- `eth_blockNumber`
- `eth_getBalance`
- `eth_getTransactionCount`
- `eth_call`
- `eth_estimateGas`
- `eth_gasPrice` or the minimal fee-equivalent method set
- `eth_sendRawTransaction`
- `eth_getTransactionReceipt`
- `eth_getCode`

#### 1. EOAs

Support externally controlled accounts that can:

- hold native balance
- submit signed transactions
- pay gas

For the MVP:

- use secp256k1 signatures
- support only a simple Ethereum-like nonce model
- do not add account abstraction
- do not attempt contract-wallet support
- make the EOA account and signing flow indistinguishable from a normal EVM chain from the wallet point of view

#### 2. Simple `CALL`

Support a transaction that:

- identifies a sender EOA
- identifies a destination account
- carries value
- optionally carries calldata
- executes one EVM call

The MVP should support:

- value transfer
- contract call
- revert / success result

#### 3. Simple `CREATE`

Support contract deployment via:

- initcode
- sender nonce
- deterministic address derivation for the chosen model

For the MVP:

- support only standard `CREATE`
- defer `CREATE2`

#### 4. Native Balance

Support a single native asset balance for the EVM workchain.

For the MVP:

- represent balance as the workchain-native gas/value currency
- do not implement ERC-20 bridging
- do not attempt multi-currency semantics

#### 5. Basic Gas

Support:

- intrinsic transaction gas
- execution gas consumed by `revm`
- simple gas price
- sender balance debit

For the MVP:

- keep gas policy intentionally simple
- avoid advanced fee market mechanics
- do not attempt full Ethereum mempool economics

## Explicitly Out of Scope for the MVP

The initial prototype should explicitly not implement the following:

### 1. Full `eth_*` RPC Compatibility

Do not try to reach full Ethereum client parity immediately.

For the MVP:

- the wallet-facing minimum RPC set is required from the beginning
- broad `eth_*` coverage beyond wallet-critical methods is deferred
- advanced debug, trace, filter, and infra-oriented methods are deferred

### 2. Cross-Workchain Contract Messaging

Do not attempt contract-to-contract messaging between:

- `evm-workchain`
- basechain / TVM contracts
- masterchain system contracts

For the MVP:

- keep execution local to the new workchain
- treat the EVM workchain as self-contained

### 3. Full Precompile Coverage

Do not attempt all Ethereum precompiles from day one.

For the MVP:

- start with the minimal set needed for simple contract execution
- or even ship with a reduced set if test contracts do not require more

### 4. Full Logs / Tracing / Tracer Compatibility

Do not try to reproduce:

- `debug_traceTransaction`
- full parity/geth tracer semantics
- complete receipt/log indexing guarantees

For the MVP:

- record execution success/failure
- record gas used
- optionally record raw EVM logs internally
- defer full compatibility surfaces

## Proposed Architecture

### High-Level Architecture

```text
                            +------------------------------+
                            |          TOS Node            |
                            | validator / collator / block |
                            | routing / finalization       |
                            +---------------+--------------+
                                            |
                 +--------------------------+--------------------------+
                 |                                                     |
                 v                                                     v
     +---------------------------+                       +---------------------------+
     |   Shared Chain Metadata   |                       |   Workchain Dispatcher    |
     | blocks / shards / config  |                       | route by workchain id     |
     | receipts index / routing  |                       | and execution mode        |
     +-------------+-------------+                       +-------------+-------------+
                   |                                                     |
                   |                                                     |
         +---------+---------+                               +-----------+-----------+
         |                   |                               |                       |
         v                   v                               v                       v
+------------------+  +------------------+        +------------------+    +------------------+
| TVM Workchains   |  | EVM Workchain    |        | TVM Executor     |    | EVM Executor     |
| state boundary   |  | state boundary   |        | existing TVM     |    | revm / silkworm  |
| cells / accounts |  | nonce/balance/   |        | path             |    | compatible path  |
| / message state  |  | code/storage     |        +------------------+    +------------------+
+------------------+  +------------------+                  |                       |
         |                   |                               |                       |
         v                   v                               v                       v
+------------------+  +------------------+        +------------------+    +------------------+
| TVM State Store  |  | EVM State Store  |        | TVM-facing APIs   |    | Ethereum-facing  |
| existing schema  |  | dedicated schema |        | native TOS APIs   |    | RPC / wallets    |
| or namespace     |  | / namespace / DB |        +------------------+    +------------------+
+------------------+  +------------------+
```

This architecture has three intended properties:

- one TOS node remains responsible for chain ownership and workchain coordination
- TVM and EVM execution remain isolated from each other at the state layer
- the EVM workchain can expose Ethereum-compatible wallet and RPC surfaces without forcing TVM workchains to adopt EVM semantics

### Layer 1. Workchain Definition

Add a new workchain descriptor with:

- a dedicated workchain id
- a dedicated zerostate
- `vm_version` / `vm_mode` values reserved for EVM execution

This workchain must be:

- explicitly activated in config
- self-consistent in zerostate
- routable by existing address and shard logic
- externally identified by an EVM `chainId`

This layer should not create a second independent chain coordinator. It should register an additional workchain under the existing TOS chain coordinator.

### Layer 2. EVM Account State Model

Define a TOS-side state representation for EVM accounts that can store:

- nonce
- balance
- code hash or code cell reference
- storage root or equivalent storage handle

The external address format for these accounts should still be standard EVM:

- 20-byte Ethereum-style address for EOAs and contracts

Internally, TOS may keep additional routing or workchain metadata, but this must not leak into the wallet-facing address format.

The most important design constraint:

- the state model must be stable enough to survive beyond the prototype

If possible, the prototype should avoid a throwaway format that must later be rewritten completely.

This state should live behind a dedicated EVM state boundary:

- separate schema
- separate namespace or column family
- or a separate physical database if that produces cleaner operational isolation

The important point is not the exact storage technology. The important point is that EVM state must not be mixed into the TVM state model as if they were the same execution domain.

### Layer 3. `revm` Database Adapter

Implement a database adapter that maps the EVM workchain state storage into the `revm` database interface.

This adapter is one of the highest-value components because it isolates:

- TOS EVM-state storage semantics
- `revm` execution semantics

The adapter should support at least:

- account lookup
- balance / nonce / code retrieval
- storage slot read
- commit of state changes after execution

This adapter should target the EVM state boundary directly, not the TVM state store.

### Layer 4. Workchain-Specific Compute Executor

Add a branch in the compute path:

- if destination account belongs to standard TVM workchain: existing path
- if destination account belongs to `evm-workchain`: route to `revm`

The first version can be narrow:

- one account family
- one transaction envelope type
- one execution path

### Layer 5. Result Projection Back Into TOS

After `revm` execution, project results back into the TOS transaction lifecycle:

- success / failure
- gas charged
- new state
- transfers generated internally within the workchain

This layer is where execution semantics meet TOS accounting and finalization logic.

State commits from this layer should update:

- shared chain metadata where required by the TOS node
- the dedicated EVM state store for EVM account/storage changes

They should not directly mutate TVM state representations.

### Layer 6. Ethereum-Compatible RPC Facade

Add a wallet-facing JSON-RPC facade for the `evm-workchain`.

The first version should focus only on the methods needed by wallets and standard client libraries:

- chain identification
- balance queries
- nonce queries
- code queries
- raw transaction submission
- call / estimate gas
- transaction receipt retrieval

This layer is not optional if the first milestone aims to support existing EVM wallets.

## Feasibility by Component

### Feasible Now

- defining a new workchain
- exposing an Ethereum-compatible address and signing model
- embedding `revm`
- building a minimal account/state adapter
- running `CALL` / `CREATE`
- charging simple gas
- storing native balance and nonce
- exposing a small wallet-facing `eth_*` RPC subset

### Feasible Later

- richer precompile coverage
- EVM logs exposure
- richer wallet tooling
- indexer support
- broader `eth_*` RPC compatibility

### High-Risk / Expensive

- full Ethereum JSON-RPC compatibility
- deep compatibility with every wallet and infrastructure edge case
- cross-workchain contract calls
- production-grade tracing
- exact reproduction of Ethereum node edge cases

## Suggested Implementation Phases

## Phase 0. Design Freeze

Deliverables:

- workchain id choice
- EVM `chainId` choice
- account state schema
- external address model
- transaction envelope definition
- gas accounting policy
- address derivation policy for EOAs and contracts
- minimum wallet-facing JSON-RPC method set

Exit criteria:

- no unresolved foundational format questions

## Phase 1. Minimal Execution Prototype

Deliverables:

- new workchain definition
- zerostate entry
- `revm` integration
- account database adapter
- Ethereum-compatible address derivation and transaction signing path
- minimum wallet-facing JSON-RPC surface
- EOA transaction submission path
- simple `CALL`
- simple `CREATE`
- native balance
- basic gas charge

Exit criteria:

- an existing EVM wallet can connect using the declared `chainId`
- an existing EVM wallet can see balance and nonce for an EOA
- a signed raw Ethereum transaction can be submitted successfully
- deploy simple contract
- call simple contract
- transfer native value
- persist state across multiple transactions

## Phase 2. Stabilize Internal Semantics

Deliverables:

- deterministic state commit rules
- stable error mapping
- simple receipts
- basic test harness
- sandbox coverage
- wallet compatibility validation with at least one standard EVM wallet

Exit criteria:

- repeated execution is deterministic
- replay behavior is clear
- account state is inspectable

## Phase 3. Add Compatibility Layers

Deliverables:

- broader `eth_*` read methods
- optional EVM logs exposure
- broader precompile support
- toolchain adapters
- developer documentation

Exit criteria:

- external developers can interact without learning internal node-only APIs

## Phase 4. Evaluate Advanced Features

Candidates:

- contract wallets
- account abstraction
- richer receipts
- tracing
- cross-workchain messaging
- bridging surfaces

These should come only after the execution path is already reliable.

## Proposed Acceptance Criteria for the Prototype

The first prototype is successful if all of the following are true:

1. A new workchain can be activated and recognized by the node.
2. The workchain exposes a valid EVM `chainId` and Ethereum-compatible `0x` addresses.
3. An existing EVM wallet can derive and display an EOA account correctly.
4. An EOA can submit a signed Ethereum-compatible transaction into that workchain.
5. The node can execute a simple contract deployment via `CREATE`.
6. The node can execute a simple contract call via `CALL`.
7. Native balance changes are correctly persisted.
8. Gas is charged deterministically.
9. The resulting state can be reloaded and used in subsequent transactions.
10. The implementation does not break existing TVM workchains.

## Recommended Repository Work Split

### TOS-Side Work

- workchain config and zerostate wiring
- account state format
- transaction envelope mapping
- fee and balance rules
- execution-path branching
- node/API exposure for testing

Likely repository areas:

- `crypto/block`
- `validator-engine`
- `tosctl/src/block`
- `tosctl/src/executor`
- `tosctl/src/sandbox`

### `revm` / `reth` Reuse

- EVM execution
- gas accounting internals
- fork rules where relevant
- database interface patterns
- executor wiring patterns

The recommended approach is reuse, not vendoring the entire `reth` architecture into TOS.

## Main Risks

### 1. Outer-Model Mismatch

TOS is message-driven and TVM-oriented. EVM execution assumes an Ethereum account-and-transaction model.

Risk:

- too much glue code accumulates around `revm`

Mitigation:

- keep the first envelope model narrow
- do not overgeneralize before the prototype works

### 2. Fee Model Confusion

If TOS fee accounting and EVM gas accounting are mixed too early, the implementation may become hard to reason about.

Mitigation:

- start with a simplified gas model
- keep workchain-local fee rules explicit

### 3. Compatibility Scope Creep

Trying to be "Ethereum-compatible" too early can collapse the project under wallet, RPC, tracing, and tooling expectations.

Mitigation:

- declare MVP scope publicly
- defer compatibility layers intentionally

### 4. State Model Throwaway Risk

If the prototype uses a temporary state schema, later migration may be expensive.

Mitigation:

- design the account state model carefully before coding

## Bottom-Line Assessment

Embedding `revm` into TOS for a new `evm-workchain` is feasible.

It is not a trivial patch, but it is also not blocked by any obvious architectural impossibility in the current repository.

The most important discipline is scope control:

- build execution first
- keep the prototype local to one workchain
- defer compatibility claims
- add external-facing surfaces only after the compute and state path is stable

That is the highest-probability path to a working result.
