# Workchain Execution Registry and Config-Driven Dispatch

Status: implemented architecture baseline
Date: 2026-05-04

Deployment assumption: TOS has not launched mainnet. The migration therefore
does not need to preserve byte-compatibility with pre-mainnet devnet behavior,
old zerostates, old testnet descriptors, process-local defaults, or hardcoded
`wc=1` / `wc=2` dispatch behavior. Where the existing implementation conflicts
with the clean workchain abstraction or intended EVM semantics, this document
chooses the target semantics directly instead of adding a legacy
global-version gate.

## Purpose

TOS currently supports multiple execution domains under one masterchain-rooted
consensus: native TVM on `wc=0`, EVM on `wc=1`, and Uno on `wc=2`.
The product direction is correct: a workchain is an execution domain with its
own state transition rules, while the masterchain provides shared consensus,
configuration, validator rotation, and global time.

The original implementation was intentionally direct:
`crypto/block/transaction.cpp` checked concrete workchain ids and called the
EVM or Uno dispatcher. That was a reasonable integration path for the first two
non-TVM workchains, but it is not the long-term architecture. The transaction
engine must not know that `wc=1` means EVM or that `wc=2` means Uno. That
mapping is chain configuration, not C++ control flow.

This document defines the architecture now used by the implementation baseline:
a config-driven workchain execution registry.

## Pre-Mainnet Compatibility Policy

Because the project has not launched mainnet, this design is allowed to break
pre-mainnet development behavior in order to reach the clean architecture
directly.

Implementation rules:

- Do not add consensus code solely to preserve pre-registry devnet behavior.
- Do not add fallback dispatch from workchain id to engine id when ConfigParam
  12 or the registry context is missing; fail closed instead.
- Do not source consensus-critical EVM parameters from process-local defaults
  when the descriptor should provide them.
- Do not preserve old EVM revert behavior if it conflicts with the intended
  state model. EVM reverts should commit nonce/gas/receipt state while exposing
  engine failure through receipt/status semantics.
- Use global-version gates for future post-mainnet upgrades. Before mainnet,
  prefer clean genesis/config regeneration over compatibility shims.
- Legacy helpers may remain only for tests, tooling, or explicitly
  non-consensus paths, and must be labelled as such.

## Current Shape

The current consensus execution path has these properties:

- `Transaction::prepare_compute_phase()` resolves `account.workchain` through
  the active `ConfigParam 12` descriptor and the local
  `WorkchainExecutionRegistry`.
- EVM and Uno register `WorkchainEngine` implementations at validator startup
  from their own modules.
- EVM v1 and Uno v1 declare a singleton executor account at `0x0000...0001`
  through engine policy, not through generic transaction dispatch.
- State changes still commit into TOS cells through `cp.new_data`, so this is
  not a sidecar architecture.

The important property is that dispatch is now keyed by the descriptor
`(format, selector)` and validated engine config, not by hardcoded workchain ids
inside the generic transaction engine.

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

Engine modules may still reject descriptors for ids only if that id is truly
part of their cryptographic domain separation, such as being committed into
addresses, transcripts, or genesis allocation semantics. Such a rule belongs to
engine descriptor validation, not to generic transaction dispatch.

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

An engine must also be deterministic across validators for a fixed descriptor.
A binary update must not change consensus output for the same
`WorkchainDescr`, global version, input state, message, and context. Any EVM
hardfork rule, Uno proof rule, state layout, fee rule, bug fix, or validation
rule change that can affect compute output must be represented by on-chain
descriptor/config fields or by an existing consensus global version.

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
// registry is injected into the block-transition pipeline, not a global singleton
TRY_RESULT(plan, registry.resolve(cfg.workchain_descr, cfg.block_transition_config));
TRY_RESULT(result, plan.executor->run_compute(input, context));
```

The descriptor, not the source file, decides which engine is active.

The registry applies to ordinary workchains described by `ConfigParam 12`.
Masterchain execution (`wc=-1`) is not represented in `ConfigParam 12` and
remains TVM by protocol. Keeping a direct masterchain TVM path in
`transaction.cpp` is not a violation of this design; the masterchain is not a
governance-configured execution domain in the same sense as basechain, EVM, Uno,
or future workchains.

## Descriptor Surface

TOS already has a protocol hook for this: `ConfigParam 12` workchain
descriptions. The canonical TL-B defines a `format` field with two shapes:

- `wfmt_basic`: carries `vm_version:int32` and `vm_mode:uint64`.
- `wfmt_ext`: carries address-length bounds and
  `workchain_type_id:uint32`.

The first production version of this architecture should use those fields
instead of introducing a new config parameter.

Recommended mapping:

| Engine | Format | Selector | Mode / parameters |
|---|---|---:|---|
| TVM | `wfmt_basic` | `vm_version = -1` (`0xFFFFFFFF`) | `vm_mode = 0` |
| EVM | `wfmt_basic` | `vm_version = 0x0045564d` (`"EVM"`) | `vm_mode = EVM chain id` |
| Uno v1 | `wfmt_basic` | `vm_version = 0x554e4f31` (`"UNO1"`) | `vm_mode = 0` today; Uno suite parameters live in Uno config |

The TVM value `-1` matches the TOS zerostates produced by this repository:
`crypto/fift/lib/Workchain.fif::add-std-workchain` stores `vm_version = -1`
for `wc=0`. The registry must use `-1`, not `0`, to dispatch TVM. Using `0`
would leave `wc=0` without a registered engine and fail every TVM transaction
at startup preflight.

For EVM, `vm_mode = 0` is a legacy sentinel and is not a valid production
descriptor. Production EVM descriptors must be built with
`evm_workchain::build_evm_workchain_descr()` so `vm_mode` carries the actual
chain id. The Fift helper `add-evm-workchain` in `crypto/fift/lib/Workchain.fif`
currently emits `vm_mode = 0`; that helper is suitable only as a legacy/devnet
stub until it is updated, and a registry-based EVM engine must reject it through
`validate_and_resolve_config`.

`workchain_id` remains part of the descriptor key and address namespace. It is
not the engine selector by itself.

For `wfmt_basic`, the engine selector is `vm_version`. For `wfmt_ext`, the
engine selector is `workchain_type_id`. `vm_mode` and any engine-specific
ConfigParam are validated only after the engine family is selected. Current
`wfmt_ext` does not contain a parameter cell; if a future engine needs richer
consensus-critical parameters, they should live in a dedicated ConfigParam
keyed by workchain id, or in a deliberate TL-B schema upgrade.

Implementation requirement: the registry normalizer must preserve all selector
fields from the canonical `WorkchainDescr` cell. The current
`block::WorkchainInfo` helper exposes `vm_version` and `vm_mode` for
`wfmt_basic`, but it does not expose `workchain_type_id` for `wfmt_ext`. Phase 1
must either extend `block::WorkchainInfo` with `workchain_type_id` populated from
`wfmt_ext`, or parse the raw descriptor cell directly before registry lookup.
Until that exists, every extended-format workchain would normalize to
`{Extended, 0}` and extended engines would collide or fail closed.

The registry key is therefore `(format, selector)`, not `workchain_id` and not
`vm_version` alone. This avoids collisions between descriptor formats that reuse
numeric selector values with different semantics.

### Descriptor Changes and Migration

Changing the descriptor of an active workchain is a consensus upgrade, not a
local refactor.

The default rule is:

- changing non-semantic fields such as monitoring depth follows normal
  ConfigParam governance;
- changing engine parameters inside the same engine family is allowed only if
  the engine explicitly validates the transition and gates all changed behavior
  by descriptor/config fields;
- changing `(format, selector)` for an existing active workchain is forbidden
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
enum class WorkchainFormat {
  Basic,
  Extended
};

struct WorkchainExecutionDescriptor {
  tos::WorkchainId workchain_id;
  uint32_t enabled_since;
  bool active;
  bool accept_msgs;

  WorkchainFormat format;
  uint32_t version;       // WorkchainDescr.version from the protocol
  int32_t vm_version;     // valid only for wfmt_basic; TL-B int32
  uint64_t vm_mode;       // valid only for wfmt_basic
  uint32_t workchain_type_id;  // valid only for wfmt_ext; 0 otherwise

  uint8_t min_split;
  uint8_t max_split;
  uint16_t min_addr_len;
  uint16_t max_addr_len;
  uint16_t addr_len_step;
  td::Bits256 zerostate_root_hash;
  td::Bits256 zerostate_file_hash;

  td::Ref<vm::Cell> raw_descriptor_cell;
};
```

This type is a host-side view, not necessarily a new TL-B schema. It gives the
registry a stable input while keeping the canonical format in `block.tlb`.

Each engine can further parse `vm_mode` (for `wfmt_basic`) and any
engine-specific ConfigParam into its own config type:

- EVM: chain id, hardfork schedule, precompile set, block gas rules.
- Uno: scheme id set, fee constants, proof limits, mining mode if applicable.
- TVM: VM version and mode flags.

## Registry

The registry is a process-local table of compiled engine implementations. It is
not consensus state. It answers one question: "Can this binary execute the
engine declared by this descriptor?"

```cpp
struct WorkchainEngineKey {
  WorkchainFormat format;
  // For Basic this is vm_version:int32 sign-extended to int64_t.
  // For Extended this is workchain_type_id:uint32.
  int64_t selector;
};

// Opaque side-effect bundle produced by compute and consumed by
// WorkchainRuntimeServices::apply_post_accept_side_effects.
// Each engine defines its own concrete subtype.
struct WorkchainSideEffects {
  virtual ~WorkchainSideEffects() = default;
};

// Immutable engine-specific config parsed from the same block-transition
// Config snapshot as the WorkchainDescr. Each engine defines its own concrete
// subtype, e.g. EVM hardfork/precompile rules or Uno proof parameters.
struct WorkchainEngineConfig {
  virtual ~WorkchainEngineConfig() = default;
};

// Returned by resolve(). The registry owns the engine; the pointer
// is valid for the lifetime of the registry.
struct ResolvedWorkchainExecution {
  const WorkchainEngine* executor;
  WorkchainExecutionDescriptor descriptor;
  std::shared_ptr<const WorkchainEngineConfig> engine_config;
};

struct LocalWorkchainRoleSet {
  // Workchains this process is expected to collate, validate, or serve through
  // trusted execution-dependent RPC. A node may still sync or relay metadata for
  // other active workchains without being capable of executing them locally.
  bool requires_local_execution(tos::WorkchainId workchain_id) const;
};

class WorkchainExecutionRegistry {
 public:
  // Registers an engine. Startup fails if the same (format, selector)
  // key is registered twice -- this is a programming error, not a runtime
  // condition. The registry is not a global singleton; it is owned by the
  // validator engine and injected into the block-transition pipeline.
  void register_engine(std::unique_ptr<WorkchainEngine> engine);

  td::Result<ResolvedWorkchainExecution> resolve(
      const WorkchainExecutionDescriptor& descriptor,
      const block::Config& block_transition_config) const;

  td::Status validate_required_workchains(
      const block::WorkchainSet& workchains,
      const block::Config& block_transition_config,
      const LocalWorkchainRoleSet& local_roles) const;
};
```

`register_engine(...)` is called from module initialization:

- TVM registers an engine for key `{Basic, -1}`.
- EVM registers an engine for key `{Basic, 0x0045564d}`.
- Uno registers an engine for key `{Basic, 0x554e4f31}`.

The registry is keyed by `(format, selector)`, not by a fixed workchain id.
After the engine family is selected, the engine validates `vm_mode`, `version`,
and any engine-specific ConfigParam against the same `block::Config` snapshot
used for the block transition.

`resolve()` internally calls the engine's descriptor/config validator and returns
a resolved immutable `engine_config`. Callers must resolve once per workchain per
block-transition config snapshot and reuse the resulting
`ResolvedWorkchainExecution` for all transactions in that block targeting the
same workchain. Calling `resolve()` per-transaction would re-parse and revalidate
engine config on every message, which is not the intended performance contract.

If an implementation caches `ResolvedWorkchainExecution` outside a single block
transition object, the cache key must include the workchain id and an identity
for the exact config snapshot, such as the config root hash or block id that
owns it. A cache keyed only by workchain id would reuse stale engine config
across key blocks or config-update blocks and is forbidden.

## Engine Interface

The generic transaction engine does not pass a mutable
`block::ComputePhase&` directly into its dispatch logic. It calls the resolved
engine through `WorkchainEngine::run_compute`, receives a compute result, and
translates that result into the existing transaction structure. EVM and Uno may
still bridge to their internal historical handlers behind the engine boundary,
but that bridge is private to the engine module and is not a transaction
dispatch rule.

```cpp
struct WorkchainComputeContext {
  tos::WorkchainId workchain_id;
  tos::ShardIdFull shard;
  uint64_t block_seqno;
  tos::LogicalTime block_lt;   // start LT of this block; TVM needs it to assign trans_lt
  uint64_t now;

  uint32_t global_version;
  std::array<uint8_t, 32> rand_seed;          // randomness source; maps to EVM PREVRANDAO
  std::array<uint8_t, 32> parent_block_hash;  // parent context for EVM BLOCKHASH / EIP-2935

  WorkchainExecutionDescriptor descriptor;  // value copy; all fields are cheaply copyable
  std::shared_ptr<const WorkchainEngineConfig> engine_config;  // resolved once per config snapshot
  const block::Config* block_transition_config;  // immutable block-transition snapshot; never null
};

struct WorkchainComputeInput {
  tos::StdSmcAddress account_addr;
  td::Ref<vm::Cell> current_code;  // may be null for acc_uninit
  td::Ref<vm::Cell> current_data;
  block::CurrencyCollection account_balance;  // needed for EVM value transfer
  td::Ref<vm::Cell> inbound_message;          // full message cell, not just body
  td::Ref<vm::CellSlice> inbound_body;         // decoded body slice for engines that need it
  tos::LogicalTime msg_lt;    // LT of the inbound message; TVM needs it for outbound LT ordering
  uint64_t gas_limit;
};

// `current_code` is the account code visible immediately before workchain
// compute. It may be null for an uninitialized account. The host must not
// pre-populate it from AccountExecutionPolicy.activation_code before calling
// run_compute; activation_code is applied only after the engine commits.
// Engines must document whether they accept null code. EVM and Uno v1 ignore
// the code cell and use their state cell; TVM treats null code as the ordinary
// "no executable code" case unless existing message-state rules provide code
// before compute.

struct WorkchainComputeOutput {
  // Invariants (must hold for all engines):
  //   !completed -> !accepted, !committed
  //   committed  -> accepted
  //   gas_fees   is never null; zero when !completed
  // `committed` is the host-chain state-commit decision: if true, host code
  // may apply new_data/new_code and run the action phase if action_list is set.
  // `engine_success` is the engine-visible outcome for receipts/status.
  // The two are intentionally separate: in the target EVM semantics, a revert
  // has committed=true (nonce/gas/receipt state still commits) and
  // engine_success=false.
  // For TVM: committed = accepted && TVM committed; engine_success = committed.
  // For Uno: committed = engine_success for valid state transitions.
  int skip_reason;
  bool completed;
  bool accepted;
  bool committed;
  bool engine_success;
  bool msg_state_used;
  bool account_activated;
  bool out_of_gas;
  int mode;
  int32_t exit_code;
  int32_t exit_arg;
  int vm_steps;
  tos::Bits256 vm_init_state_hash;
  tos::Bits256 vm_final_state_hash;

  uint64_t gas_used;
  td::RefInt256 gas_fees;   // always non-null; zero when !completed

  td::Ref<vm::Cell> new_data;
  td::Ref<vm::Cell> new_code;   // updated code cell; null means unchanged

  // Standard TOS action list produced by compute. TVM populates this from c5;
  // the host action phase interprets it and remains responsible for forward
  // fees, SENDRAWMSG modes, reserve actions, set_code, state-limit rollback,
  // and action result codes. Null means no action phase.
  td::Ref<vm::Cell> action_list;

  std::string vm_log;
  std::unique_ptr<WorkchainSideEffects> side_effects;
};

class WorkchainEngine {
 public:
  virtual ~WorkchainEngine() = default;

  virtual WorkchainEngineKey engine_key() const = 0;

  virtual td::Result<std::shared_ptr<const WorkchainEngineConfig>>
  validate_and_resolve_config(
      const WorkchainExecutionDescriptor& descriptor,
      const block::Config& block_transition_config) const = 0;

  virtual AccountExecutionPolicy account_policy(
      const WorkchainExecutionDescriptor& descriptor,
      const WorkchainEngineConfig& engine_config) const = 0;

  // Must be pure and deterministic: same inputs -> same output on every
  // validator. No mutable engine state may affect the result.
  virtual td::Result<WorkchainComputeOutput> run_compute(
      const WorkchainComputeInput& input,
      const WorkchainComputeContext& context) const = 0;
};
```

The exact names can change during implementation. The important boundary is
that engines receive a normalized context and return a result. They should not
reach back into global mutable chain state during compute.

Mapping this output back into the existing `block::ComputePhase` must preserve
the `committed` / `engine_success` distinction. In particular, a reverted EVM
transaction is an engine-level failure but not a host state-commit failure:
nonce/gas/receipt state still commits while the EVM receipt status remains
failed. Because TOS is pre-mainnet, the registry migration should implement
this target semantic directly instead of preserving the older
`cp.success=false => do not commit cp.new_data` behavior.

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
  // Only valid when kind == SingletonExecutor; meaningless otherwise.
  std::optional<tos::StdSmcAddress> singleton_address;

  bool accepts_external_inbound;
  bool accepts_internal_inbound;
  bool may_activate_uninitialized_account;

  // Code cell installed on the executor account at first activation.
  // E.g. the 0x45 'E' marker for EVM or 0x55 'U' for Uno.
  td::Ref<vm::Cell> activation_code;
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
generic transaction code. The engine policy declares which account/message
shapes may enter the engine and what `new_code` cell should be installed when a
custom executor activates an account (for example, the `0x45 'E'` marker for EVM
or `0x55 'U'` for Uno). When `new_code` in `WorkchainComputeOutput` is null, the
host leaves the existing code cell unchanged.

`ShardLocalExecutor` is reserved for future parallel-execution designs where
each shard maintains its own executor account. Its assignment semantics across
shard splits are not defined in this version and must be specified before
implementation.

## Scope Boundary: Registry vs EVM State Topology

This proposal fixes the dispatch abstraction. It does not, by itself, migrate
the EVM workchain away from the current singleton executor account model.

For EVM v1, the expected behavior after Phases 1-4 intentionally keeps the
same state topology while adopting the target descriptor-driven semantics:

- the EVM workchain uses the EVM engine selected from `ConfigParam 12`;
- the EVM engine still declares `SingletonExecutor(0x0000...0001)`;
- the current EVM state layout remains committed under that executor account;
- EVM receipts, logs, nonce changes, gas accounting, and revert semantics must
  follow the descriptor-selected EVM engine, including committing nonce/gas
  state on EVM revert.

That is not a failure of the registry design. It is the correct separation of
concerns. The registry removes hardcoded engine selection from generic
transaction code. It can expose account topology as an engine policy, but it
does not magically turn singleton EVM state into account-native or shard-local
EVM state.

A future EVM topology change must be specified as a separate consensus upgrade.
It must not be hidden behind the same descriptor semantics. The upgrade needs an
explicit descriptor/config change or a new workchain zerostate, plus rules for:

- state layout: singleton world-state cell, shard-local executor cells, or
  account-native EVM account cells;
- ordering semantics: whether EVM transactions remain globally serial within the
  workchain, serial per shard, or ordered by an explicit merge rule;
- receipt and log ordering: how `transactionIndex`, `logIndex`, bloom filters,
  subscriptions, and archive queries remain deterministic across shard splits and
  merges;
- cross-shard account access: whether synchronous reads/writes are forbidden,
  mediated through messages, or constrained by an access-list/partition rule;
- migration boundary: how old state is transformed, where the migration is
  committed, and how archive replay derives the same post-migration state.

The safest long-term path is to treat this as "EVM v2" rather than as a cleanup
inside the registry refactor. EVM v2 can reuse the same registry interface, but
it needs either a new `(format, selector)` value, a descriptor version/mode that
the EVM engine validates as a hardfork boundary, or a new workchain id with its
own zerostate. Reusing the EVM v1 descriptor while changing state topology would
violate the core rule that the same descriptor/config/input must produce the
same compute output.

## Admission and Mempool

External-message admission, mempool filters, fee estimation, and RPC prechecks
must use the same registry and descriptor normalization code as consensus
compute, but they are not authoritative. They may reject malformed or obviously
unsupported messages early, but they must not be the only place that enforces a
consensus rule.

Admission must be conservative around config transitions:

- if the node cannot resolve the workchain descriptor from a stable config
  snapshot, admission returns "temporarily unavailable" rather than guessing;
- if the workchain is active but the local engine is missing or rejects the
  descriptor, admission rejects with a capability/configuration error;
- if admission accepted a message under an older config, the consensus compute
  path still re-resolves the descriptor from the block-transition snapshot and
  may reject or process differently according to that authoritative snapshot.

This prevents RPC or mempool state from becoming a hidden consensus input.

## Fail-Closed Rules

Dispatch must distinguish four cases:

### 1. Workchain absent or inactive

If the workchain is not present or inactive in `ConfigParam 12`, the existing
chain rules for inactive workchains apply. The registry should not invent an
engine.

### 2. Workchain active, descriptor structurally valid, engine locally available and engine validation passes

The transaction engine invokes the resolved engine.

### 3. Workchain active, descriptor structurally valid, engine locally unavailable

The node is not capable of validating or collating this shard. This is a local
capability failure. It must abort collation/validation for that shard and emit a
clear operator error identifying the missing engine key.

It must not silently fall back to TVM. It must not deterministically reject all
transactions. It must not accept a block by pretending the workchain is unknown.

This rule is the main safety property of the architecture.

### 4. Workchain active, descriptor structurally valid, engine registered, but `validate_and_resolve_config` fails

The engine is present in the binary but rejects the descriptor -- for example,
EVM `chain_id == 0`, an unsupported hardfork level, or an Uno scheme id unknown
to this binary version.

This is distinct from Case 3: the node *has* the engine but the descriptor
requests a configuration the engine cannot execute. The node must also fail
closed here. It must abort collation/validation for that shard and emit a clear
operator error identifying the engine and the rejection reason returned by
`validate_and_resolve_config`.

It must not fall back to TVM, reject transactions deterministically, or silently
proceed with a partially-matching configuration. The error message must
distinguish this case from Case 3 so operators can diagnose whether the problem
is an absent engine or an incompatible descriptor revision.

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

Each engine owns validation of its descriptor plus any engine-specific
ConfigParam read from the block-transition config snapshot:

- TVM validates TVM `vm_version` and mode flags.
- EVM validates chain id, supported hardfork schedule, precompile profile, and
  any descriptor version constraints.
- Uno validates workchain id if required by domain separation, scheme ids,
  proof limits, and config constraints.

Generic validation owns only generic shape:

- descriptor cell parses correctly
- workchain is active only after `enabled_since`
- split depths and zerostate hashes are well-formed
- `(format, selector)` maps to exactly one registered engine

The registry's `validate_required_workchains` method serves as a
startup/config-update preflight. It lets `validator-engine` refuse unsafe
operation before it starts collating, validating, or serving trusted
execution-dependent RPC for a workchain it cannot execute. A node may still
sync headers, relay metadata, or serve explicitly-unavailable responses for
workchains outside its local role set.

## RPC Registration

RPC should use the same module boundary but not the same consensus interface.

An engine may optionally register non-consensus services:

```cpp
class WorkchainRuntimeServices {
 public:
  virtual ~WorkchainRuntimeServices() = default;

  virtual void register_rpc(JsonRpcRouter& router) {}
  virtual void register_metrics(PrometheusExporter& exporter) {}
  virtual void apply_post_accept_side_effects(
      const AcceptedBlockContext& context,
      std::unique_ptr<WorkchainSideEffects> side_effects) {}
};
```

Engines that implement non-consensus services should expose a
`WorkchainRuntimeServices*` alongside their `WorkchainEngine`. The validator
engine calls `register_rpc` and `register_metrics` once at startup after all
engines are registered, and calls `apply_post_accept_side_effects` once per
accepted block (never during candidate collation or validation). The default
empty implementations mean engines with no side effects require no extra code.

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

- engine key `(format, selector)`;
- workchain id and shard id;
- accepted block seqno;
- accepted block root hash or file hash;
- transaction index or logical transaction id inside the accepted block;
- engine-specific transaction hash if the engine has one, such as EVM tx hash
  or Uno transfer hash.

This preserves the current safety direction of EVM cache handling while making
it engine-generic.

## Implementation Progress

Legend:

- ✅ Complete for the current pre-mainnet registry baseline.
- 🟡 Partially complete; the safe core exists, but broader integration or
  operator/capability plumbing remains.
- ⬜ Not started or intentionally deferred to a future workchain/topology
  upgrade.

Last updated: 2026-05-04.

| Area | Status | Current state | Remaining work |
|---|---:|---|---|
| Phase 0 - target behavior | ✅ | Target behavior is pinned in this document, including the pre-mainnet no-compatibility policy. | Keep future changes reflected here before coding. |
| Phase 1 - registry and adapters | ✅ | `crypto/block/workchain-execution-dispatch.*` exists; TVM/EVM/Uno engines register through the registry; `WorkchainInfo` preserves `wfmt_ext.workchain_type_id`. | Keep per-engine dispatch headers narrow until Phase 4 is fully retired. |
| Phase 2 - descriptor-driven compute | ✅ | `transaction.cpp` resolves custom workchain execution from ConfigParam 12 through `ComputePhaseConfig`; EVM chain id comes from descriptor `vm_mode`; EVM/Uno singleton executor addresses are engine policy. | Add more regression tests around config transitions and new-engine extensibility. |
| RPC/admission registry use | ✅ | `eth_sendRawTransaction`, `uno_sendMineUno`, and `uno_sendTransfer` resolve the active workchain from ConfigParam 12 before building external messages. | Future RPC namespaces can move behind engine runtime-service registration. |
| Custom workchain gas/fee boundary | ✅ | Registry compute path preserves engine-returned `gas_fees`; host TVM gas pricing no longer overwrites custom-engine fees. | Engine-specific fee tests should be expanded when EVM/Uno fee models stabilize. |
| Phase 3 - startup/config-update preflight | 🟡 | `validate_required_workchains` and `LocalWorkchainRoleSet` exist; collator/validator block paths require the local shard workchain; validator-engine now preflights each observed top masterchain state using local shard roles; active execution descriptor key/version/`vm_mode` changes are rejected without a migration rule. | Add validator capability advertisement / assignment rules. |
| Phase 4 - dispatch bridge retirement | 🟡 | `evm-workchain-dispatch.*` and `uno-workchain-dispatch.*` are now narrow registration/handler bridges; `transaction.cpp` no longer selects EVM/Uno by workchain id. | Move remaining bridge surface into engine modules when link boundaries allow it. |
| Phase 5 - future engines | ⬜ | The design supports adding a future engine without editing generic transaction dispatch. | Prove this with the next engine or a dedicated dummy-engine integration test. |
| EVM v2 shard-local/account-native topology | ⬜ | Explicitly out of scope for the registry baseline. | Requires a separate consensus migration with state layout, ordering, logs/receipts, and cross-shard rules. |

## Migration Plan

### Phase 0 - Document and pin target behavior ✅

Add tests around the intended descriptor-driven behavior before refactoring:

- ✅ EVM dispatch is selected by `ConfigParam 12` descriptor key
  `{Basic, 0x0045564d}`, not by a bare `wc=1` branch.
- ✅ Uno dispatch is selected by `{Basic, 0x554e4f31}`, not by a bare `wc=2`
  branch.
- ✅ non-executor account targets are rejected consistently.
- ✅ missing handler does not fall through into a successful custom execution.

### Phase 1 - Add generic registry and engine adapters ✅

Introduce:

- ✅ `crypto/block/workchain-execution-dispatch.h`
- ✅ `crypto/block/workchain-execution-dispatch.cpp`
- ✅ `WorkchainExecutionRegistry`
- ✅ `WorkchainEngine`

✅ Phase 1 prerequisite: the descriptor normalizer must preserve
`wfmt_ext.workchain_type_id`. The preferred implementation is to extend
`block::WorkchainInfo` with `uint32_t workchain_type_id = 0` and populate it in
`WorkchainInfo::unpack()` when `format` is `wfmt_ext`; alternatively, parse the
raw descriptor cell directly in the normalizer. Do not introduce registry lookup
for extended-format descriptors while this value is being dropped.

✅ Register EVM and Uno as `WorkchainEngine` implementations. It is acceptable for
those engine implementations to call existing internal handlers, but
transaction dispatch must see only `WorkchainEngine::run_compute`; it must not
contain EVM/Uno-specific workchain-id or selector branches. Any adapter is a
private engine-module implementation detail, not a compatibility contract, and
must not reintroduce workchain-id fallback dispatch.

### Phase 2 - Resolve from `WorkchainDescr` ✅

✅ Thread the active workchain descriptor into compute-phase configuration, likely
through `ComputePhaseConfig`.

Replace hardcoded workchain-id branches with:

1. ✅ read the descriptor for `account.workchain` from the authoritative config
   snapshot for the current block transition;
2. ✅ resolve engine by `(format, selector)` against that same config snapshot;
3. ✅ validate `vm_mode`, `version`, and engine-specific parameters from that
   snapshot and cache the immutable resolved engine config;
4. ✅ ask engine for account policy using the descriptor plus resolved engine
   config;
5. ✅ invoke engine through `WorkchainEngine::run_compute`.

At this phase, `workchain_id` is still part of context, but not the dispatch
selector.

✅ EVM-specific Phase 2 requirement: `validate_and_resolve_config` must extract
the EVM chain id from the on-chain descriptor's `vm_mode` and store it in
`EvmEngineConfig`. Consensus compute must read the chain id from
`WorkchainComputeContext.engine_config`, not from `evm_chain_config()` or
`current_evm_chain_id()`, because those are process-local singleton paths.
The singleton path may remain for tests, genesis tooling, or non-consensus
metrics, but not for CHAINID, EIP-155 replay protection, transaction hashing,
block execution, receipt construction, or `eth_sendRawTransaction` admission.

### Phase 3 - Move descriptor validation to startup and config updates 🟡

✅ When `validator-engine` loads or observes masterchain config, it validates that
all workchains required by this node's local roles can be executed by this
binary. "Required" means the node is assigned or configured to collate,
validate, or serve trusted execution-dependent RPC for that workchain; it does
not mean every active workchain in the network.

✅ Nodes that are not compiled with a required engine fail closed before they
attempt to validate or collate the corresponding shard.

✅ Active workchains cannot change execution key, descriptor version, or
`vm_mode` without an explicit migration rule. The current pre-mainnet baseline
has no descriptor migration rule, so such config updates are rejected.

⬜ Capability coordination for active workchains lands in this phase: validator
assignment must not place incapable validators on shards that require an engine
they do not support.

### Phase 4 - Retire or shrink per-engine dispatch headers 🟡

Remove or shrink:

- 🟡 `crypto/block/evm-workchain-dispatch.*`
- 🟡 `crypto/block/uno-workchain-dispatch.*`

🟡 Engine modules should register directly with the generic registry. Any
remaining `evm-workchain-dispatch.*` or `uno-workchain-dispatch.*` surface
should be a narrow registration/handler bridge, not something
`transaction.cpp` uses for engine selection.

### Phase 5 - Extend to future engines ⬜

The next non-TVM engine should not touch `transaction.cpp`. It should add:

- ⬜ its engine module
- ⬜ descriptor builder/validator
- ⬜ registry registration
- ⬜ tests
- ⬜ optional RPC/runtime services

If `transaction.cpp` must be edited for a new engine, this architecture has
failed its main goal.

## Test Strategy

Required tests:

- ✅ descriptor parsing and normalization for TVM, EVM, and Uno
- ✅ extended-format descriptor parsing preserves `workchain_type_id` and does not
  normalize every `wfmt_ext` descriptor to `{Extended, 0}`
- ✅ registry lookup by `(format, selector)`
- ✅ unknown engine key fails closed
- ✅ required workchain with missing local engine fails preflight
- ✅ EVM and Uno singleton executor policies are enforced by engine policy
- 🟡 EVM v1 registry refactor does not change singleton state layout, receipt/log
  ordering, or the target revert-state commitment semantics
- ✅ EVM chain id used by consensus compute comes from descriptor `vm_mode` through
  `EvmEngineConfig`, not from `evm_chain_config()` or `current_evm_chain_id()`
- ✅ EVM descriptors with legacy `vm_mode = 0` fail engine config validation
- ✅ descriptor-driven dispatch produces deterministic compute results without
  falling back to hardcoded workchain-id dispatch
- 🟡 collator and validator paths use the same resolved engine
- ✅ config update that changes an active engine descriptor is rejected unless descriptor
  transition validation and any required migration rule pass
- ✅ descriptor lookup uses the block's authoritative config snapshot, not latest
  masterchain state
- 🟡 resolved engine caches cannot be reused across config snapshots when
  ConfigParam 12 or engine-specific ConfigParams change
- 🟡 changing consensus semantics without changing descriptor/config/global
  version is forbidden by tests or review gates
- ✅ changing `(format, selector)` for an active workchain is rejected unless an
  explicit migration rule is present
- ⬜ validator assignment/capability tests prove incapable validators are not
  assigned to shards requiring unsupported engines
- 🟡 side-effect staging keys include accepted block identity and cannot publish
  losing-candidate receipts/logs/filters
- 🟡 admission and mempool tests prove RPC prechecks are conservative and
  consensus compute re-resolves descriptors from the authoritative block
  snapshot
- 🟡 EVM revert tests prove `committed` and `engine_success` are distinct and that
  revert nonce/gas/receipt state commits under the pre-mainnet target
  semantics
- ⬜ any future EVM shard-local or account-native topology fails activation unless
  an explicit descriptor/config migration rule is present and tested for state,
  ordering, receipts/logs, and cross-shard access
- 🟡 uninitialized account tests cover null `current_code` and prove
  `activation_code` is not applied before `run_compute`
- ✅ masterchain transactions continue through the protocol-defined TVM path
  outside ConfigParam 12 registry dispatch
- ✅ no RPC handler is required for consensus execution

Negative tests are as important as positive tests:

- ✅ no silent TVM fallback for configured EVM/Uno workchains
- ✅ no local environment variable can override consensus-critical descriptor
  fields
- 🟡 no process-global mutable engine state can change compute output between
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

### No schema churn unless ConfigParam 12 is insufficient

`ConfigParam 12` already exists for workchain descriptors. Use it. Introduce a
new TL-B shape only when a future engine needs descriptor data that cannot be
represented safely by `wfmt_basic`, `wfmt_ext`, or a dedicated engine-specific
ConfigParam keyed by workchain id.

## Expected End State

The long-term end state is:

- `transaction.cpp` has no hardcoded engine branches for ConfigParam 12
  workchains.
- `ConfigParam 12` determines the execution format for each active workchain.
- masterchain (`wc=-1`) remains the protocol-defined TVM path outside
  `ConfigParam 12`.
- engine modules register capabilities with a local registry.
- unsupported active workchains fail closed at node capability boundaries.
- EVM and Uno remain first-class consensus workchains, not sidecars.
- EVM v1 singleton execution is declared by engine policy instead of hidden in
  `transaction.cpp`; any shard-local or account-native EVM model is a separate
  consensus migration.
- adding `wc=3` does not require editing generic transaction execution logic.

This aligns TOS with the original workchain idea: the masterchain defines which
workchains exist and what execution format they use; validators run the matching
state transition function; the generic chain engine does not hardcode every
execution domain that the network may ever support.
