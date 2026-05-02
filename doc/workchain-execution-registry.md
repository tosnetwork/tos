# Workchain Execution Registry and Config-Driven Dispatch

Status: design proposal
Date: 2026-05-02

## Purpose

TOS currently supports multiple execution domains under one masterchain-rooted
consensus: native TVM on `wc=0`, EVM on `wc=1`, and Uno on `wc=2`.
The product direction is correct: a workchain is an execution domain with its
own state transition rules, while the masterchain provides shared consensus,
configuration, validator rotation, and global time.

The current implementation is intentionally direct: `crypto/block/transaction.cpp`
checks concrete workchain ids and calls the EVM or Uno dispatcher. This was a
reasonable integration path for the first two non-TVM workchains, but it should
not be the long-term architecture. The transaction engine should not know that
`wc=1` means EVM or that `wc=2` means Uno. That mapping is chain configuration,
not C++ control flow.

This document defines the target architecture: a config-driven workchain
execution registry.

## Current Shape

The current consensus execution path has these properties:

- `Transaction::prepare_compute_phase()` routes `account.workchain == 1` to
  `evm_workchain_dispatch::invoke_evm_compute(...)`.
- The same method routes `account.workchain == 2` to
  `uno_workchain_dispatch::invoke_uno_compute(...)`.
- Both custom workchains use a singleton executor account at
  `0x0000...0001`.
- EVM and Uno register handlers at validator startup from their own modules.
- State changes still commit into TOS cells through `cp.new_data`, so this is
  not a sidecar architecture.

The important limitation is not the existence of a dispatch hook. Dispatch is
necessary. The limitation is that dispatch is keyed by hardcoded workchain ids
inside the generic transaction engine instead of being derived from
masterchain configuration.

## First Principles

### 1. Consensus selects the state transition function

For any accepted block, every validator must run the same state transition
function for every transaction. That function is not a local preference. It is
part of consensus.

Therefore, the selected execution engine for a workchain must be derived from
masterchain state, primarily `ConfigParam 12` workchain descriptors. Local
binary code may decide whether the node is capable of participating, but it
must not silently reinterpret a configured workchain.

The descriptor used for dispatch must come from the same masterchain config
snapshot that the block transition is already using for fees, limits, validator
rules, and global version. It must not be read from process-global latest state,
RPC-visible head state, environment variables, or a mutable local cache. For a
given block candidate, collation, validation, replay, archive import, and
catch-up must all resolve workchain execution from the same config snapshot.

### 2. A workchain id is not an engine id

`workchain_id` identifies an address space, shard namespace, zerostate, and
message-routing domain. It should not be the only way to select an execution
engine.

The same engine family may be deployed at a different workchain id on a testnet
or future network. Conversely, a future `wc=3` may use an engine that does not
exist today. Dispatch should be based on the workchain descriptor's execution
format, not on a switch over known ids.

Engine modules may still reject descriptors for ids that are part of their
cryptographic domain separation. For example, Uno can require `workchain_id=2`
for the public network if that id is committed into addresses, transcripts, or
genesis allocation semantics. That rule belongs to Uno descriptor validation,
not to generic transaction dispatch.

### 3. Unknown engine is a node capability failure, not a transaction reject

If a workchain is active in masterchain configuration and a validator assigned
to that shard does not have the required engine implementation, the node cannot
validate or collate that shard. It must fail closed.

It must not convert every transaction into a deterministic reject. That would
let an under-upgraded validator produce a different block from upgraded
validators while appearing to execute normally.

Fail-closed alone is not enough for network liveness. Activating a new engine
is a coordinated network capability event: validator eligibility, advertised
capabilities, minimum global version or binary capability, and activation height
must be explicit before a workchain becomes active or before an existing
workchain moves to a new execution format. A validator set must not be assigned
to a shard it cannot execute.

### 4. Engine-specific state must still be cell-native

The registry changes how an executor is selected. It does not change the state
commitment model.

Each engine must consume the current account state cell, the inbound message,
and consensus context, then produce a deterministic compute result. Any new
state committed by the engine must still enter the ordinary TOS account and
shard state tree.

An engine must also be byte-compatible across validators for a fixed descriptor.
A binary update must not change consensus output for the same
`WorkchainDescr`, global version, input state, message, and context. Any EVM
hardfork rule, Uno proof rule, state layout, fee rule, bug-compatibility change,
or validation rule change that can affect compute output must be gated by
on-chain descriptor/config fields or by an existing consensus global version.

### 5. The generic transaction engine owns the transaction envelope

Workchain engines should not own shared transaction mechanics such as storage
fee collection, account activation semantics, bounce behavior, block ordering,
or shard state commitment. They own only the workchain-specific compute phase.

The generic host code should translate between TOS transaction machinery and a
small workchain-execution interface.

### 6. RPC and indexing are not consensus dispatch

JSON-RPC namespaces, subscriptions, cache DB writes, explorer records, and
post-accept notifications are downstream surfaces. They may be registered by
the same engine module, but they must not affect consensus execution.

Consensus compute must be a pure function of chain state, message data, and
consensus context. Non-consensus side effects must be staged and applied only
after a block is accepted.

## Target Model

The target model has three layers:

1. `WorkchainDescr` in masterchain config declares the execution format.
2. A local `WorkchainExecutionRegistry` maps supported execution formats to
   compiled engine modules.
3. The transaction engine asks the registry for the executor for the current
   workchain and invokes it through a generic interface.

In this model, `transaction.cpp` no longer has branches like:

```cpp
if (account.workchain == 1) invoke_evm_compute(...);
if (account.workchain == 2) invoke_uno_compute(...);
```

Instead, it does:

```cpp
auto plan = workchain_execution_registry().resolve(cfg.workchain_descr);
auto result = plan.executor->run_compute(input, context);
```

The descriptor, not the source file, decides which engine is active.

## Descriptor Surface

TOS already has a protocol hook for this: `ConfigParam 12` workchain
descriptions. The existing documentation defines a `format` field with
`wfmt_basic` / `wfmt_ext`, and for `wfmt_basic` the subfields include:

- `vm_version`
- `vm_mode`

The first production version of this architecture should use those fields
instead of introducing a new config parameter.

Recommended mapping:

| Engine | `vm_version` | `vm_mode` |
|---|---:|---|
| TVM | `0x00000000` | TVM mode flags |
| EVM | `0x0045564d` (`"EVM"`) | EVM chain id |
| Uno v1 | `0x554e4f31` (`"UNO1"`) | Uno chain/suite mode |

`workchain_id` remains part of the descriptor key and address namespace. It is
not the engine selector by itself.

Future `wfmt_ext` can carry a richer parameters cell if an engine needs more
consensus-critical configuration than fits in `vm_mode`. Until that is
necessary, `vm_version` plus `vm_mode` is enough to remove hardcoded dispatch.

The engine selector is the descriptor format plus `vm_version`, not
`vm_version` alone. `vm_mode` and any future parameter cell are then validated
by the selected engine and may select sub-rules inside that engine. This avoids
collisions between future descriptor formats that reuse a numeric `vm_version`
with different semantics.

### Descriptor Changes and Migration

Changing the descriptor of an active workchain is a consensus upgrade, not a
local refactor.

The default rule is:

- changing non-semantic fields such as monitoring depth follows normal
  ConfigParam governance;
- changing engine parameters inside the same engine family is allowed only if
  the engine explicitly validates the transition and gates all changed behavior
  by descriptor/config fields;
- changing `(format, vm_version)` for an existing active workchain is forbidden
  unless the old engine and the new engine define a deterministic migration
  boundary and state transformation;
- any state migration must be committed in chain state, replayable from the
  pre-upgrade state, and identical for collation, validation, archive import,
  and catch-up.

For EVM and Uno v1, there is no implicit state reinterpretation contract. A
future descriptor that changes their state layout or engine family must either
define an explicit migration transaction/block rule or activate as a new
workchain with its own zerostate.

## Workchain Execution Descriptor

The runtime should decode `WorkchainDescr` into a normalized internal view:

```cpp
struct WorkchainExecutionDescriptor {
  tos::WorkchainId workchain_id;
  uint32_t enabled_since;
  bool active;
  bool accept_msgs;

  WorkchainFormat format;
  uint32_t descriptor_version;
  uint32_t vm_version;
  uint64_t vm_mode;

  uint8_t min_split;
  uint8_t max_split;
  td::Bits256 zerostate_root_hash;
  td::Bits256 zerostate_file_hash;

  td::Ref<vm::Cell> raw_descriptor_cell;
};
```

This type is a host-side view, not necessarily a new TL-B schema. It gives the
registry a stable input while keeping the canonical format in `block.tlb`.

Each engine can further parse `vm_mode` or an optional future parameters cell
into its own config type:

- EVM: chain id, hardfork schedule, precompile set, block gas rules.
- Uno: scheme id set, fee constants, proof limits, mining mode if applicable.
- TVM: VM version and mode flags.

## Registry

The registry is a process-local table of compiled engine implementations. It is
not consensus state. It answers one question: "Can this binary execute the
engine declared by this descriptor?"

```cpp
enum class WorkchainFormat {
  Basic,
  Extended
};

struct WorkchainEngineKey {
  WorkchainFormat format;
  uint32_t vm_version;
};

class WorkchainExecutionRegistry {
 public:
  void register_engine(std::unique_ptr<WorkchainEngine> engine);

  td::Result<ResolvedWorkchainExecution> resolve(
      const WorkchainExecutionDescriptor& descriptor) const;

  td::Status validate_active_workchains(
      const block::WorkchainSet& workchains) const;
};
```

`register_engine(...)` is called from module initialization:

- TVM registers the default engine.
- EVM registers an engine for key `{Basic, "EVM"}`.
- Uno registers an engine for key `{Basic, "UNO1"}`.

The registry is keyed by `(format, vm_version)`, not by a fixed workchain id.
`vm_mode`, descriptor version, and any future parameter cell are validated after
the engine family is selected.

## Engine Interface

The long-term interface should avoid passing a mutable `block::ComputePhase&`
directly into workchain modules. Engines should return a compute result, and
host code should translate that result into the existing transaction structure.

Initial migration can keep a compatibility adapter around `ComputePhase`, but
the target interface should look like this:

```cpp
struct WorkchainComputeContext {
  tos::WorkchainId workchain_id;
  tos::ShardIdFull shard;
  tos::BlockSeqno block_seqno;
  uint64_t now;

  uint32_t global_version;
  std::array<uint8_t, 32> rand_seed;
  std::array<uint8_t, 32> parent_block_hash;

  const WorkchainExecutionDescriptor* descriptor;
  const block::Config* block_transition_config;
};

struct WorkchainComputeInput {
  tos::StdSmcAddress account_addr;
  td::Ref<vm::Cell> current_code;
  td::Ref<vm::Cell> current_data;
  vm::CellSlice inbound_body;
  uint64_t gas_limit;
};

struct WorkchainComputeOutput {
  bool completed;
  bool accepted;
  bool success;

  uint64_t gas_used;
  td::RefInt256 gas_fees;

  td::Ref<vm::Cell> new_data;
  td::Ref<vm::Cell> new_code_marker;

  std::string vm_log;
  std::unique_ptr<WorkchainSideEffects> side_effects;
};

class WorkchainEngine {
 public:
  virtual WorkchainEngineKey engine_key() const = 0;

  virtual td::Status validate_descriptor(
      const WorkchainExecutionDescriptor& descriptor) const = 0;

  virtual AccountExecutionPolicy account_policy(
      const WorkchainExecutionDescriptor& descriptor) const = 0;

  virtual td::Result<WorkchainComputeOutput> run_compute(
      const WorkchainComputeInput& input,
      const WorkchainComputeContext& context) = 0;
};
```

The exact names can change during implementation. The important boundary is
that engines receive a normalized context and return a result. They should not
reach back into global mutable chain state during compute.

## Account Execution Policy

The executor-account gate should also move out of `transaction.cpp`.

Current EVM and Uno both use singleton executor account
`0x0000...0001`. That is a valid engine policy, but it should be declared by
the engine. The policy must cover every host-level rule that is currently
hardcoded around custom workchain dispatch:

```cpp
enum class AccountExecutionPolicyKind {
  AnyAccount,
  SingletonExecutor,
  ShardLocalExecutor,
  EngineDefined
};

struct AccountExecutionPolicy {
  AccountExecutionPolicyKind kind;
  tos::StdSmcAddress singleton_address;

  bool accepts_external_inbound;
  bool accepts_internal_inbound;
  bool may_activate_uninitialized_account;

  td::Ref<vm::Cell> code_marker;
};
```

Examples:

- TVM: `AnyAccount`.
- EVM v1: `SingletonExecutor(0x0000...0001)`.
- Uno v1: `SingletonExecutor(0x0000...0001)`.
- A future parallel EVM design: `ShardLocalExecutor`.
- A future native custom VM: `AnyAccount` or `EngineDefined`.

If a message targets an address forbidden by the active engine policy, the host
returns the same deterministic skip behavior that EVM and Uno currently use
for non-executor addresses. The rule is generic; the address value is not.

The host still owns the transaction envelope: storage fees, account status
transitions, import fee rules, bounce semantics, and state commitment remain in
generic transaction code. The engine policy only declares which account/message
shapes may enter the engine and which canonical marker cell should be installed
when a custom executor activates an account.

## Fail-Closed Rules

Dispatch must distinguish three cases:

### 1. Workchain absent or inactive

If the workchain is not present or inactive in `ConfigParam 12`, the existing
chain rules for inactive workchains apply. The registry should not invent an
engine.

### 2. Workchain active, descriptor valid, engine locally available

The transaction engine invokes the resolved engine.

### 3. Workchain active, descriptor valid, engine locally unavailable

The node is not capable of validating or collating this shard. This is a local
capability failure. It must abort collation/validation for that shard and emit a
clear operator error.

It must not silently fall back to TVM. It must not deterministically reject all
transactions. It must not accept a block by pretending the workchain is unknown.

This rule is the main safety property of the architecture.

## Activation and Capability Coordination

A new workchain engine or engine-breaking descriptor update must be activated
like any other consensus feature.

The activation flow should include:

1. a descriptor or global-version proposal that declares the new execution
   format and activation point;
2. a validator capability signal showing which validators can execute that
   format;
3. scheduler/election rules that do not assign incapable validators to shards
   requiring that format after activation;
4. node startup and config-update preflight that refuses unsupported active
   workchains before collation or validation begins;
5. operator-facing errors that identify the missing engine key and descriptor.

The exact capability advertisement mechanism can reuse existing validator
version/capability fields or introduce a dedicated engine capability set. The
architectural requirement is that unsupported engines are handled before block
production, not discovered transaction-by-transaction.

## Descriptor Validation

Each engine owns validation of its descriptor:

- TVM validates TVM `vm_version` and mode flags.
- EVM validates chain id, supported hardfork schedule, precompile profile, and
  any descriptor version constraints.
- Uno validates workchain id if required by domain separation, scheme ids,
  proof limits, and config compatibility.

Generic validation owns only generic shape:

- descriptor cell parses correctly
- workchain is active only after `enabled_since`
- split depths and zerostate hashes are well-formed
- `(format, vm_version)` maps to exactly one registered engine

The registry should expose a startup/config-update preflight:

```cpp
td::Status validate_active_workchains(const block::WorkchainSet& workchains);
```

This lets `validator-engine` refuse unsafe operation before it starts collating
or serving public RPC for a workchain it cannot execute.

## RPC Registration

RPC should use the same module boundary but not the same consensus interface.

An engine may optionally register non-consensus services:

```cpp
class WorkchainRuntimeServices {
 public:
  virtual void register_rpc(JsonRpcRouter& router);
  virtual void register_metrics(PrometheusExporter& exporter);
  virtual void apply_post_accept_side_effects(
      const AcceptedBlockContext& context,
      WorkchainSideEffects&& side_effects);
};
```

This keeps `eth_*` and `uno_*` close to their engines without letting RPC shape
leak into compute dispatch.

## Side Effects

Side effects such as EVM receipts, log indexes, subscription notifications, and
Uno filters are not consensus state unless they are explicitly committed into
cells.

The compute path may produce side-effect records, but they must be staged under
accepted-block context and applied only after BFT acceptance. The side-effect
key must include concrete accepted-block identity to prevent stale candidate
data from being published after a competing candidate wins.

Minimum side-effect identity:

- engine key `(format, vm_version)`;
- workchain id and shard id;
- accepted block seqno;
- accepted block root hash or file hash;
- transaction index or logical transaction id inside the accepted block;
- engine-specific transaction hash if the engine has one, such as EVM tx hash
  or Uno transfer hash.

This preserves the current safety direction of EVM cache handling while making
it engine-generic.

## Migration Plan

### Phase 0 - Document and pin behavior

Add tests around the current behavior before refactoring:

- `wc=1` dispatches only to EVM.
- `wc=2` dispatches only to Uno.
- non-executor account targets are rejected consistently.
- missing handler does not fall through into a successful custom execution.

### Phase 1 - Add generic registry with compatibility adapters

Introduce:

- `crypto/block/workchain-execution-dispatch.h`
- `crypto/block/workchain-execution-dispatch.cpp`
- `WorkchainExecutionRegistry`
- `WorkchainEngine`

Register EVM and Uno through adapters that call the current handlers. Keep the
old EVM/Uno dispatcher headers temporarily.

At the end of Phase 1, behavior should be byte-identical.

### Phase 2 - Resolve from `WorkchainDescr`

Thread the active workchain descriptor into compute-phase configuration, likely
through `ComputePhaseConfig`.

Replace hardcoded workchain-id branches with:

1. read the descriptor for `account.workchain` from the authoritative config
   snapshot for the current block transition;
2. resolve engine by `(format, vm_version)`;
3. validate `vm_mode`, descriptor version, and engine parameters;
4. ask engine for account policy;
5. invoke engine through the generic interface.

At this phase, `workchain_id` is still part of context, but not the dispatch
selector.

### Phase 3 - Move descriptor validation to startup and config updates

When `validator-engine` loads or observes masterchain config, it validates that
all locally relevant active workchains can be executed by this binary.

Nodes that are not compiled with a required engine fail closed before they
attempt to validate or collate the corresponding shard.

Capability coordination for active workchains lands in this phase: validator
assignment must not place incapable validators on shards that require an engine
they do not support.

### Phase 4 - Retire per-engine dispatch headers

Remove or shrink:

- `crypto/block/evm-workchain-dispatch.*`
- `crypto/block/uno-workchain-dispatch.*`

Engine modules should register directly with the generic registry.

### Phase 5 - Extend to future engines

The next non-TVM engine should not touch `transaction.cpp`. It should add:

- its engine module
- descriptor builder/validator
- registry registration
- tests
- optional RPC/runtime services

If `transaction.cpp` must be edited for a new engine, this architecture has
failed its main goal.

## Test Strategy

Required tests:

- descriptor parsing and normalization for TVM, EVM, and Uno
- registry lookup by `(format, vm_version)`
- unknown engine key fails closed
- active workchain with missing local engine fails preflight
- EVM and Uno singleton executor policies preserve current behavior
- descriptor-driven dispatch produces the same compute result as current
  hardcoded dispatch
- collator and validator paths use the same resolved engine
- config update that changes an engine descriptor is rejected unless all
  descriptor validation passes
- descriptor lookup uses the block's authoritative config snapshot, not latest
  masterchain state
- changing consensus semantics without changing descriptor/config/global
  version is forbidden by tests or review gates
- changing `(format, vm_version)` for an active workchain is rejected unless an
  explicit migration rule is present
- validator assignment/capability tests prove incapable validators are not
  assigned to shards requiring unsupported engines
- side-effect staging keys include accepted block identity and cannot publish
  losing-candidate receipts/logs/filters
- no RPC handler is required for consensus execution

Negative tests are as important as positive tests:

- no silent TVM fallback for configured EVM/Uno workchains
- no local environment variable can override consensus-critical descriptor
  fields
- no process-global mutable engine state can change compute output between
  replay and live validation

## Design Constraints

### No local override of consensus-critical engine parameters

Runtime environment variables and command-line flags may enable logging,
metrics, local cache behavior, or RPC profile choices. They must not change the
engine selected for a workchain or consensus-critical parameters inside that
engine.

If an operator wants a different EVM chain id or Uno proof suite, that belongs
in a different zerostate or governance-approved config update, not in a local
flag.

### No mandatory sidecar for execution

The registry is in-process. A future optimization may offload proving,
indexing, or read-only RPC to helper processes, but consensus execution remains
inside the validator binary or an equivalently deterministic, locally verified
execution component.

### No dynamic plugin loading in consensus path

The first version should use statically linked engines. Dynamic loading creates
deployment and audit complexity at the worst possible boundary. A registry does
not require runtime shared-object plugins.

### No schema churn unless `vm_version` / `vm_mode` are insufficient

`ConfigParam 12` already exists for workchain descriptors. Use it. Introduce a
new TL-B shape only when a future engine needs descriptor data that cannot be
represented safely in the current format.

## Expected End State

The long-term end state is:

- `transaction.cpp` is engine-agnostic.
- `ConfigParam 12` determines the execution format for each active workchain.
- engine modules register capabilities with a local registry.
- unsupported active workchains fail closed at node capability boundaries.
- EVM and Uno remain first-class consensus workchains, not sidecars.
- adding `wc=3` does not require editing generic transaction execution logic.

This aligns TOS with the original workchain idea: the masterchain defines which
workchains exist and what execution format they use; validators run the matching
state transition function; the generic chain engine does not hardcode every
execution domain that the network may ever support.
