# tosctl Migration Audit

**Scope:** `src/node-control/*` in the TOS fork  
**Goal:** classify which parts of the imported TON Rust `nodectl` stack can be kept as-is, which require only naming cleanup, which require protocol adaptation for TOS, and which are high-risk because they embed TON election assumptions.

---

## 1. Executive Summary

The imported `node-control` stack is a good starting point for a future `tosctl`, but it is **not** yet TOS-native.

Current state:

- The **operations framework** is reusable:
  - CLI layering
  - config loading and persistence
  - vault integration
  - ADNL control client structure
  - background service model
  - REST API / auth / snapshot machinery
- The **protocol-facing business logic** is still TON-oriented:
  - `ton_http_api` naming and RPC assumptions
  - Elector wrapper
  - single nominator pool wrapper
  - validator set parsing from config params `15/34/36`
  - wallet defaults and deployment flows built around TON wallet semantics

Recommended migration rule:

> Preserve the framework, replace the chain-specific assumptions.

---

## 2. Classification

### 2.1 Keep As-Is

These modules are structural and can remain largely unchanged in the first TOS migration phase.

#### `common`

- `log.rs`
- `os_signals.rs`
- `password.rs`
- `task_cancellation.rs`
- `time_format.rs`
- `clap_utils.rs`
- `serde_utils.rs`

Reason:

- generic process/service infrastructure
- no deep TON-specific protocol coupling

#### `service`

- `auth/*`
- `http/*`
- `task/*`
- `runtime_config.rs`
- `service_main_task.rs`

Reason:

- generic service container, auth, JWT, hot-reload, task scheduling
- only the task payloads and exposed labels need chain adaptation

#### `commands`

- output formatting
- auth/key/service wiring
- most command dispatch logic

Reason:

- the CLI tree and dispatch pattern are reusable even if subcommand names evolve

#### `control-client`

- overall shape of `ClientAPI`
- ADNL control server client architecture

Reason:

- if TOS validator control server remains TON-compatible or near-compatible, this layer is a strong reuse candidate

---

### 2.2 Rename Only

These parts are mostly valid but still carry TON-facing names or docs.

#### User-facing names

- binary name: `nodectl` -> `tosctl`
- default config: `nodectl-config.json` -> `tosctl-config.json`
- default log file: `nodectl.log` -> `tosctl.log`

Status:

- already started in this repo

#### Documentation and examples

- `README.md`
- `Makefile`
- local config examples
- setup guides under `docs/`

Required changes:

- rename operator-facing examples to `tosctl`
- refer to TOS nodes / TOS testnet instead of TON nodes
- clearly mark temporary internal TON naming where still present

#### Module names that can stay temporarily but should eventually be renamed

- `commands::nodectl::*`
- `ton_http_api`
- `TonHttpApiConfig`
- `TonWalletVersion`
- `ton_utils`

Reason:

- not immediate blockers for functionality
- but they create cognitive debt if left indefinitely

---

### 2.3 Needs TOS Protocol Adaptation

These modules are not just naming issues. They encode protocol and RPC assumptions.

#### A. Chain RPC layer

Files:

- `common/src/app_config.rs`
- `commands/src/commands/nodectl/config_ton_http_api_cmd.rs`
- `contracts/src/provider.rs`
- `chain-rpc-client/*`

Current assumption:

- chain access happens through TON-style JSON-RPC / JSON-RPC compatible interfaces
- config field is explicitly `ton_http_api`
- default endpoint is `http://127.0.0.1:3301/`

Risk:

- if TOS exposes different RPC endpoints, auth, methods, or response shapes, this layer must be adapted before higher-level contract tooling works

Migration target:

- abstract this into a TOS chain RPC provider
- keep a compatibility adapter if TOS initially reuses TON-style JSON-RPC

#### B. Wallet layer

Files:

- `common/src/wallet_version.rs`
- `contracts/src/wallet/*`

Current assumption:

- TON wallet versions `V1R3`, `V3R2`, `V4R2`, `V5R1`
- known TON wallet code cells are embedded directly in code
- deploy/send flows are derived from TON wallet message layout

Risk:

- if TOS keeps TON wallet contracts, this can remain mostly valid
- if TOS has diverged wallet code or address derivation, this becomes incorrect quickly

Migration target:

- explicitly define which wallet contracts are canonical in TOS
- if unchanged, document them as TOS-supported wallet profiles
- if changed, replace embedded code/constants and deployment logic

#### C. Config param parsing

Files:

- `control-client/src/config_params.rs`

Current assumption:

- validator/election logic is derived from TON config params:
  - `15`
  - `34`
  - `36`
- JSON structure of those params is TON-specific

Risk:

- if TOS config params differ in numbering or shape, elections and validator snapshots break silently or semantically

Migration target:

- freeze TOS config param compatibility policy:
  - exact compatibility
  - compatibility adapter
  - fully different param parser

#### D. Contract wrapper provider semantics

Files:

- `contracts/src/provider.rs`

Current assumption:

- `run_get_method` RPC exists and returns TON-style TVM stack entries
- account balance lookup is TON-style

Risk:

- if TOS RPC is not stack-compatible, all wrappers break

Migration target:

- add a TOS provider trait and keep the current provider as a TON-compatible implementation

---

### 2.4 High-Risk Election Assumptions

These are the most protocol-sensitive parts and should be treated as a dedicated migration track.

#### A. Elector contract wrapper

Files:

- `contracts/src/elector/elector_impl.rs`

Hard-coded assumptions:

- elector address is fixed to:
  - `-1:3333333333333333333333333333333333333333333333333333333333333333`
- getter names:
  - `active_election_id`
  - `participates_in`
  - `compute_returned_stake`
  - `participant_list_extended`
  - `past_elections`
- stack parsing logic follows TON elector return layouts exactly

Risk:

- even small TOS divergence in elector ABI breaks this module

Required action:

- verify TOS elector address and getter ABI
- if TOS cloned TON unchanged, keep wrapper and document compatibility
- otherwise create a TOS elector wrapper and parser

#### B. Single nominator pool wrapper

Files:

- `contracts/src/nominator/single_nominator.rs`

Hard-coded assumptions:

- embedded TON single-nominator contract code
- TON workchain default:
  - `NOMINATOR_POOL_WORKCHAIN = -1`
- `get_roles` / `get_pool_data` stack layout is fixed

Risk:

- if TOS keeps this exact pool contract, the wrapper is reusable
- if pool code or role layout changed, deployment and monitoring become invalid

Required action:

- decide whether TOS standardizes the TON single-nominator contract unchanged

#### C. Election runner

Files:

- `elections/src/election_task.rs`
- `elections/src/runner.rs`
- `elections/src/providers/*`

Current assumption:

- validator participation model is:
  - poll chain state
  - derive election window
  - generate validator keys
  - submit stake via wallet or pool
  - infer acceptance via elector and validator-set params

Risk:

- any divergence in TOS validator lifecycle, key registration, or staking workflow affects this entire module

Required action:

- perform a dedicated TOS election compatibility audit before enabling this in production

#### D. Snapshot and status labels

Files:

- `common/src/snapshot.rs`

Current assumption:

- status lifecycle is:
  - `Idle -> Participating -> Submitted -> Accepted -> Elected -> Validating`
- `p34` and `p36` semantics are used directly

Risk:

- if TOS validator lifecycle differs, REST API semantics become misleading even if the code still runs

Required action:

- rename or redefine statuses only after TOS validator lifecycle is confirmed

---

## 3. Recommended Migration Order

### Phase 1 — Operations Facade

Goal:

- finish user-facing migration to `tosctl`

Tasks:

- rename remaining README/docs/examples
- rename package references in scripts
- rename service/config examples

### Phase 2 — RPC Abstraction

Goal:

- stop hard-coding TON RPC vocabulary as the only chain access path

Tasks:

- introduce TOS-facing naming in config and command layer
- decide whether TOS chain RPC remains TON JSON-RPC compatible
- adapt `chain-rpc-client` or wrap it

### Phase 3 — Protocol Compatibility Audit

Goal:

- validate whether TOS reuses TON contracts and config params unchanged

Tasks:

- verify:
  - elector ABI
  - nominator contract ABI/code
  - wallet compatibility
  - config params `15/34/36`
  - control server compatibility

### Phase 4 — TOS-Specific Business Logic

Goal:

- replace only the parts where TOS diverges

Tasks:

- add TOS-specific wrappers/parsers where TON compatibility is broken
- keep generic service/CLI/auth/vault infrastructure unchanged

---

## 4. Immediate Next Engineering Tasks

1. Finish user-facing renames in `src/node-control/docs/*`
2. Rename `ton_http_api` config/CLI surfaces to a neutral TOS-facing name while preserving backward compatibility
3. Write a compatibility checklist for:
   - Elector
   - Single nominator pool
   - Wallet contracts
   - Config params `15/34/36`
   - ADNL control server methods
4. Add a top-level compatibility mode decision:
   - `TON-compatible TOS`
   - or `TOS-native with adapters`

---

## 5. Bottom Line

The imported framework is worth keeping.

What should remain:

- CLI/service/auth/vault/control framework
- most of the operator UX structure

What must be verified before real TOS use:

- chain RPC assumptions
- elector ABI
- nominator pool ABI/code
- validator config param semantics
- wallet contract compatibility

That is the correct foundation for turning `nodectl` into `tosctl` without throwing away mature tooling.
