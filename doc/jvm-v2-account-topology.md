# JVM v2 Account-Native Topology

Reference for the wc=3 (Avata JVM) workchain after the v2 pivot. Audience:
validator/full-node implementers and JVM contract toolchain authors. All cell
shapes, magics, and field orders are consensus-stable.

Engine selector remains `vm_version = 0x4a564d31` ("JVM1") in ConfigParam 12.
The wire-level pivot is the per-account state envelope (`JvmContractAccountState`,
JVAC) and the per-contract account-creation flow; ConfigParam 85 itself is
bumped to `schema_version=2` (see [ConfigParam.md §85](ConfigParam.md#configparam-85--jvm-workchain-chain-config)).

## 1. Overview / Topology

- Each Java contract is a real wc=3 account at a deterministic 256-bit address.
- No singleton executor; no shared class store; no shared storage namespace.
  The v1 SingletonExecutor at `0x0000…0001` is no longer seeded
  (`jvm/core/zerostate.h:15`).
- The wc=3 ShardAccounts dict is **empty by default at genesis**; contracts
  materialize later via the host `action_create_account` action emitted by
  an authorized wc=3 sender (`jvm/core/zerostate.cpp:5`). Network operators
  who want a non-empty genesis (the canonical way to break the wc=3
  bootstrap deadlock — see §Genesis seeding) can pre-seed wc=3 wallet
  accounts at zerostate via the Fift word `jvm-zerostate-from-alloc`.
- Account state is split exactly as TVM accounts already are:
  `account.code` is the activation marker (single byte `0x4a` = `'J'`,
  `jvm/core/dispatch-engine.cpp:33-37`) and `account.data` is the encoded
  `JvmContractAccountState` cell.
- `class_hash`, `class_bytes`, and `manifest_root` are pinned at deploy time.
  `run_compute` only rewrites `storage_root`
  (`jvm/core/avata-execution.cpp:310-321`).

## 2. Address Derivation

Per-contract wc=3 address — five-input nested formula
(`derive_jvm_contract_address_from_state` at
`jvm/core/deploy-abi.cpp:215-232`):

```
class_hash         = sha256(class_bytes)                         // 32B
address_commit     = sha256(
    deployer_addr.bits256                                        // 32B — wc=3 sender of the deploy action
 || salt                                                         // 32B — caller-chosen
 || init_args_cell.get_hash().bits256                            // 32B — cell hash, consensus-stable
)                                                                // 32B
manifest_root_hash = manifest_root_cell.get_hash().bits256       // 32B (or 32B zero if manifest is null)

addr_bytes := sha256(
    "TOS-JVM-CONTRACT-v2"
 || deployer_addr.bits256                                        // 32B
 || address_commit                                               // 32B — collapses (salt, init_args) into one bits256
 || class_hash                                                   // 32B
 || manifest_root_hash                                           // 32B — binds the dispatchable method set into the address
)
```

The `address_commit` indirection lets the engine authenticate the
first-activation message source (`msg.src.addr == state.deployer`)
without breaking the (salt, init_args) commitment; binding
`manifest_root_hash` into the address prevents an attacker from
redirecting `method_id → method dispatch` post-deploy.  Both
commitments are stored verbatim inside the JVAC state and re-verified
on every `run_compute` by the address-binding gate at
`jvm/core/dispatch-engine.cpp:370-402`.

`tos::StdSmcAddress` is flat 256 bits (`tos/tos-types.h:46`) — there are
no reserved bit ranges, so the full sha256 output is the address. Workchain
id 3 is implicit; the full account address is `StdAddress{workchain=3,
addr=addr_bytes}`.

The address is determined entirely by the deploy descriptor; consensus
recomputes it during admission and rejects any deploy whose
`derive_jvm_contract_address` does not match the destination of the
synthesized `action_create_account`.

## 3. Per-Account State Cell — `JvmContractAccountState`

Magic `0x4a564143` "JVAC", `schema_version=2`. Codec in
`jvm/core/cell-codec.{h,cpp}`:

```
jvm_contract_account#4a564143
  schema_version:uint8 (=2)
  stdlib_hash:bits256
  class_hash:bits256
  class_bytes:^Cell
  storage_root:(Maybe ^Cell)
  manifest_root:(Maybe ^Cell)
  = JvmContractAccountState;
```

Field semantics:

| Field | Source | Notes |
|---|---|---|
| `stdlib_hash` | ConfigParam 85 at deploy time | Compute-time check: `state.stdlib_hash == cfg.stdlib_hash` (`jvm/core/dispatch-engine.cpp:144-148`). Mismatch fails closed with `sk_bad_state`. |
| `class_hash` | `compute_jvm_class_hash(class_bytes)` | Pinned at deploy. Decoder rejects all-zero (`jvm/core/cell-codec.cpp:114-119`). |
| `class_bytes` | Cell ref to JVM storage-value envelope | Held as `^Cell` so the underlying Cell DB physically deduplicates contracts that share identical bytecode — `CellStorer::set` keys the KV by `cell->get_hash()` with refcount accounting (`crypto/vm/db/CellStorage.cpp:267`). Same class deployed at two distinct salts shares one DB row. |
| `storage_root` | Maybe ref into a JVM storage trie | Only field rewritten by `run_compute`. Validated through `validate_jvm_storage_root` on decode. |
| `manifest_root` | Maybe ref to a `JvmMethodManifest` cell | Per-account method registry (§4). |

Encoder rejects: wrong schema, null `class_bytes`, zero `class_hash`
(`jvm/core/cell-codec.cpp:50-72`).
Decoder rejects: special cells, wrong magic, wrong schema, malformed
`Maybe ^Cell`, trailing bits/refs, zero `class_hash`, null `class_bytes`,
or invalid storage root (`jvm/core/cell-codec.cpp:74-131`).

`encode_jvm_state_init_cell` (`jvm/core/cell-codec.cpp:133-169`) wraps a
state into a canonical TLB `StateInit{code=^marker, data=^state, library=ϵ}`
cell suitable for `action_create_account.state_init`.

## 4. Per-Account Method Manifest

Magic `0x4a564d32` "JVM2", `schema_version=1`. Codec in
`jvm/core/class-manifest.{h,cpp}`.

Linked-list spine (mirrors v1 string-cell helpers so audit tooling can be
reused):

```
jvm_method_manifest#4a564d32
  schema_version:uint8 (=1)
  count:uint16
  entries:^(JvmMethodManifestEntryNode chain)?
  = JvmMethodManifest;

jvm_method_manifest_entry
  method_id:uint32
  has_next:bit
  next:^(JvmMethodManifestEntryNode)?
  class_name:^StringCell
  method_name:^StringCell
  method_spec:^StringCell
  = JvmMethodManifestEntry;
```

The destination wc=3 address already names the contract, so the manifest
entry no longer carries `contract_id` (compare to v1's `JvmClassMethodManifest`).
Per-contract manifest size cap: `kJvmMethodManifestMaxEntries = 1024`
(`jvm/core/class-manifest.h:29`). Per-string cap:
`kJvmAvataManifestStringMaxBytes = 512`.

`encode_jvm_method_manifest` rejects duplicate `method_id` values at encode
time; `parse_jvm_method_manifest` rejects them at parse time. Lookup is
linear via `find_jvm_method_manifest_entry`.

## 5. Inbound Call Descriptor

Magic `0x4a564932` "JVI2", `schema_version=2`. Codec in
`jvm/core/message-abi.{h,cpp}`.

```
jvm_call#4a564932
  schema_version:uint8 (=2)
  method_id:uint32
  args:^Cell
  = JvmCallDescriptor;
```

`contract_id` is no longer carried (the destination wc=3 address already
names the contract, removing 32 bytes from every inbound call).
`args` is either:

- a typed `JvmArgs` cell, magic `0x4a564d41` "JVMA",
  `schema_version=1`, up to `kJvmArgsMaxCount = 64` typed values
  (`jvm/core/message-abi.h:25-51`); or
- the canonical empty cell for parameterless `()V` calls
  (`kJvmStaticVoidMethodSpec = "()V"`).

Validation helpers `validate_jvm_typed_call_args` /
`validate_jvm_static_void_call_args` enforce that the args cell matches the
manifest entry's `method_spec` before `JvmComputeRuntime::run_contract` is
invoked.

## 6. Deploy Flow

1. Caller (any wc=3 contract or an external admission gateway invoking
   `jvm_deployContract` JSON-RPC) builds a `JvmDeployDescriptor` and computes
   `contract_address = derive_jvm_contract_address(descriptor)`.
2. Caller emits an `action_create_account#4a435241` from its own wc=3
   transaction (TLB definition in `crypto/block/block.tlb:420-424`):

   ```
   action_create_account#4a435241 mode:(## 8)
     dest_addr:bits256
     state_init:^StateInit
     value:Tomis
     body:(Maybe ^Cell) = OutAction;
   ```

   with:

   - `dest_addr = contract_address`
   - `state_init = encode_jvm_state_init_cell(initial_state)` —
     `StateInit{code=^marker(0x4a), data=^JvmContractAccountState}`
   - `value = ...` (initial balance)
   - `body = optional first call descriptor` (Maybe ^Cell)

3. The host action phase
   (`crypto/block/transaction.cpp::Transaction::try_action_create_account`,
   `transaction.cpp:2601-`) gates on
   `admits_engine_create_account_actions` and only honors the action when
   the source workchain is addressable as `addr_std` (int8 wc id range).
   It then synthesizes an internal `MessageRelaxed{init, body}` with
   `src=addr_none$00` (filled in by `check_replace_src_addr`) and reuses
   `try_action_send_msg`, so all fee, validation, and outbound-queue logic
   is shared with normal sends.
4. The receiving account materializes via the existing TVM
   `acc_uninit → acc_active` path when the synthesized message arrives.
5. Synchronicity: account materialization is visible to the next transaction
   in the same block; method invocation on the new account is async via the
   message queue (the deploy emitter's transaction completes before the
   contract executes).

**Bootstrap note (first wc=3 account).** Step 3 requires the sender to
live on wc=3 — `Transaction::try_action_create_account` rejects
`action_create_account` whose source is not wc=3
(`crypto/block/transaction.cpp:2812-2823`). On an empty-default wc=3
genesis there is no wc=3 sender at block 0, so the first contract is
not deployable through this flow. The only currently-supported
bootstrap path is the **genesis seed**: pre-install one or more
Ed25519 wallet accounts via `jvm-zerostate-from-alloc` (see §Genesis
seeding below) so the chain has working wc=3 senders from block 0,
and the deploy flow above can then proceed normally for every
subsequent contract. Cross-reference: `jvm/core/zerostate.h` (the
parameterized vs. empty zerostate builders) and
`jvm/core/genesis-wallet.{h,cpp}` (per-wallet materialization).

## Genesis seeding (Phase F option)

Network operators can pre-seed wc=3 with Ed25519 wallet accounts at
zerostate.  The Fift word `jvm-zerostate-from-alloc`
(`crypto/block/create-state.cpp:648`, registered at line 1083)
accepts a tuple of `(owner_pubkey:32B, salt:32B, balance:int)`
triples; each triple becomes a fully-active wc=3 account whose
`storage_root` is pre-populated as if `Wallet.init(ownerPubKey)` had
already run.  This breaks the chicken-and-egg of an empty genesis:
pre-seeded wallets can immediately emit `action_create_account` to
deploy further wc=3 contracts (the standard `try_action_create_account`
gate only requires that the source account live on wc=3, which a
genesis-seeded wallet does by construction).

Fift stack signature:

```
( T class_bytes stdlib_hash -- accounts_cell )
where T is a tuple of 3-tuples (owner_pubkey:32B, salt:32B, balance:int).
```

Each seeded account is materialized as:

- `account.code` = single-byte `0x4a` activation marker.
- `account.data` = `JvmContractAccountState` (JVAC, schema=2) with
  `class_hash = sha256(class_bytes)`, `class_bytes` carrying the
  canonical compiled `java.lang.Wallet.class`, `storage_root`
  pre-populated with the three slots `keccak256("Wallet.ownerPubKey")
  → owner_pubkey`, `keccak256("Wallet.nonce") → Uint256.ZERO`,
  `keccak256("Wallet.initFlag") → 0x01`, and `manifest_root` carrying
  `init`/`execute`/`getNonce`.
- Account state is `account_active$1`, so the account does not need a
  first-activation message to come alive.
- Address is derived through `derive_jvm_contract_address_from_state`
  — the same formula the dispatch engine recomputes on every call,
  so the address-binding gate accepts the genesis account without
  any new code path. Sentinel deployer is all-zero
  (`kJvmGenesisDeployer`, `jvm/core/genesis-wallet.h:75`), signalling
  "seeded at zerostate" — the genesis account is `acc_active` from
  block 0 and never traverses the first-activation gate that would
  have rejected an all-zero deployer.

See `jvm/core/genesis-wallet.{h,cpp}` for the per-wallet builder and
the five `JvmWorkchainCore` tests under
`crypto/test/test-workchain-execution-registry.cpp` that pin the
consensus invariants:

- `GenesisWalletBuildIsDeterministic` — same inputs → byte-identical
  Account cells (so a genesis script is reproducible across
  validator hosts).
- `GenesisWalletAddressBindingMatchesDispatchGate` — re-derives the
  address from the encoded JVAC the way `dispatch-engine.cpp:370`
  does; verifies the seeded address satisfies the address-binding
  gate so wc=3 transactions against the wallet pass without
  `sk_bad_state`.
- `GenesisWalletStorageSlotsMatchWalletInit` — the seeded storage
  contains exactly the three slots `Wallet.init` would have written.
- `GenesisWalletDifferentSaltProducesDifferentAddresses` — salt
  disambiguation: one owner can hold multiple distinct wallet
  addresses.
- `GenesisZerostateAccountsCellEmbedsAllWallets` — the parameterized
  zerostate builder produces a dict whose entries iterate exactly
  the supplied wallets, keyed on derived addresses; build twice →
  identical hash.

Empty-default semantics still hold: `build_jvm_zerostate_accounts_cell()`
with no arguments returns the canonical `hme_empty$0` cell, so a
chain that bootstraps purely via `action_create_account` from an
external sender remains supported.  The choice between empty and
seeded genesis is per-network and is made at zerostate-build time.

## 7. `run_compute` Flow on a Per-Contract Account

`JvmNativeEngine::run_compute` (`jvm/core/dispatch-engine.cpp:112-154`) runs
on the destination account. Pseudocode:

```
JvmNativeEngine::run_compute(input, context):
  cfg := dynamic_cast<JvmEngineConfig>(context.engine_config)
  require(cfg.config.chain_id != 0)                                      // sk_bad_state
  require(input.inbound_body.not_null())                                 // sk_bad_state
  require(0 < input.gas_limit <= cfg.config.max_gas_per_tx)              // sk_no_gas (out_of_gas)
  require(runtime_ != nullptr)                                           // sk_bad_state

  parse_jvm_call_descriptor(input.inbound_body) → JvmCallDescriptor      // sk_bad_state on err
      { method_id, args }

  decode_jvm_contract_account_state(input.current_data) → state          // sk_bad_state on err
  require(state.stdlib_hash == cfg.config.stdlib_hash)                   // sk_bad_state

  invocation := runtime_->run_contract(input, context, cfg.config, state)
      // runtime resolves method_id via state.manifest_root → (class_name,
      // method_name, method_spec); validates args against method_spec;
      // loads bytecode from state.class_bytes (cache key = state.class_hash);
      // runs execute_jvm_avata_transaction with JvmStorageCellHost(state.storage_root).

  return build_jvm_workchain_output(cfg.config, state, gas_limit, invocation)
```

`build_jvm_workchain_output` (`jvm/core/avata-execution.cpp:243-329`):

```
next_state := state with
    storage_root := invocation.storage_root           // only mutable field
    // class_hash, class_bytes, manifest_root, stdlib_hash unchanged
out.new_data    = encode_jvm_contract_account_state(next_state)
out.action_list = invocation.action_list ?? empty_jvm_action_list()
out.gas_used    = invocation.gas_used
out.gas_fees    = jvm_gas_fees(config, gas_used)
```

Failure modes (rollback): on `!invocation.success` the builder returns an
`engine_success=false`, `committed=false` output with no `new_data` —
storage does not advance and the contract account remains at its
pre-call state.

## 8. Engine Identity

| Field | Value | Source |
|---|---|---|
| Workchain ID | `wc=3` | ConfigParam 12 entry |
| ConfigParam 12 format | `wfmt_basic` | `build_jvm_workchain_descr` (`jvm/core/config-param.cpp:155-179`) |
| `vm_version` (engine selector) | `0x4a564d31` ("JVM1") | `jvm/core/dispatch-engine.h:32` |
| `vm_mode` | 0 | required by `validate_and_resolve_config` (`dispatch-engine.cpp:80-82`) |
| Activation code marker | `0x4a` ('J') | `jvm/core/dispatch-engine.h:35`, `dispatch-engine.cpp:33-37` |
| Account policy | `EngineDefined` + `admits_engine_create_account_actions=true` | `jvm/core/dispatch-engine.cpp:92-110` |
| ConfigParam | 85 (`schema_version=2`) | `jvm/core/dispatch-engine.h:38`, `jvm/core/config-param.h:26` |
| Capability flag | `kTosNodeCapabilityWorkchainJvm` | set by `register_jvm_workchain_engine` |

The policy is `EngineDefined` (not `SingletonExecutor`): the host accepts
any address in wc=3 and lets the engine emit `action_create_account` to
materialize new contract accounts. Both `accepts_external_inbound` and
`accepts_internal_inbound` are true; `may_activate_uninitialized_account`
is true so that the inbound deploy message can drive the
`acc_uninit → acc_active` transition.

## 9. Invariants

- Immutability: `class_hash`, `class_bytes`, `manifest_root`, and
  `stdlib_hash` are pinned at deploy and never rewritten by `run_compute`.
  `build_jvm_workchain_output` copies them verbatim from `previous_state`
  into `next_state`.
- Storage isolation: two contracts deployed with the same class but
  different salts have different addresses (`salt` and `init_args` enter
  the sha256 through `address_commit`, which is itself one of the five
  inputs to the final address hash) and therefore disjoint `storage_root`
  trees.  No cross-contract storage namespace exists.
- Manifest binding: `manifest_root_hash` is one of the five address-derivation
  inputs, so the dispatchable method set is committed into the address.
  Swapping `method_id → method` mapping post-deploy would change the
  account's address; consensus rejects any mismatch through the
  address-binding gate.
- Address space is flat: the wc=3 256-bit address space has no reserved
  ranges (`tos::StdSmcAddress = Bits256`, `tos/tos-types.h:46`).
- Re-deploy is idempotent: a second deploy with the same
  `(deployer, class_hash, salt, init_args)` produces the same address;
  the host fails the second `action_create_account` because the destination
  account is already `acc_active` (the standard TVM rejection of an inbound
  msg with `state_init` against a live account). No special-case "already
  exists" code path in the JVM engine — this is shared TVM admission logic.
- Bytecode dedup is a Cell DB property, not a consensus rule. Two contracts
  sharing identical `class_bytes` resolve to the same physical row in
  `CellStorage` (`crypto/vm/db/CellStorage.cpp:267`); their
  `JvmContractAccountState` cells are still distinct because their address,
  storage, and manifest differ.
- Schema versions are independent: `JvmContractAccountState.schema_version=2`,
  `JvmMethodManifest.schema_version=1`, `JvmCallDescriptor.schema_version=2`,
  `JvmConfig.schema_version=2`. Bumping any one is a chain-config breaking
  change in its own right.

## 10. RPC Surface

Source: `jvm/core/rpc.{h,cpp}` (request parsing, validation, encoders) and
`validator-engine/json-rpc-server-jvm.cpp` (full-node integration with live
state lookup and method routing).

| Method | Request | Response |
|---|---|---|
| `jvm_deployContract` | `classBytes:hex`, `className:str`, `deployer:bits256-hex`, `salt:bits256-hex`, optional `initArgsBoc:hex` | `{ contractAddress:hex, deployDescriptorBoc:hex }` (`jvm/core/rpc.cpp:291`) |
| `jvm_callContract` | `contractAddress:hex` (legacy alias `contractId` accepted), `methodId:uint32`, `argsBoc:hex` (optional, defaults to canonical empty), `gasLimit:uint64`, optional `accountStateBoc:hex` (legacy alias `executorStateBoc` accepted) | `{ callDescriptorBoc:hex, contractAddress:hex, [localResult: { gasUsed, success, vmLog, newStateBoc }] }`. `localResult` is only emitted when a runtime is wired and `accountStateBoc` (or its alias) is provided (`jvm/core/rpc.cpp:453-477`). |
| `jvm_getContractState` | `contractAddress:hex` (alias `contractId` accepted), `accountStateBoc:hex` (alias `executorStateBoc` accepted) | `{ contractAddress:hex, storage: {...} }` decoded view (`jvm/core/rpc.cpp:557-578`) |
| `jvm_getReceipts` | `contractAddress:hex`, `fromBlock`, `toBlock` | event log entries scanned over the requested block range (`jvm/core/rpc.cpp:613` and `validator-engine/json-rpc-server-jvm.cpp:298+`) |

Aliasing rules: each request parser first looks up the v2 canonical key
(`contractAddress`, `accountStateBoc`); if absent it falls through to the
v1 alias (`contractId`, `executorStateBoc`). This is a one-shot
backward-compat shim for existing tooling — emit the v2 names from new
clients (`jvm/core/rpc.cpp:306-311, 344-348, 467-477, 576-578`).

Admission contract: `jvm_deployContract` pre-validates class bytes against
the Java 8 verifier profile and ConfigParam 85 limits as a developer
convenience. Consensus re-validates on execution and never trusts the
result of the RPC admission check (`jvm/core/rpc.h:17-20`).

Live-state routing (`validator-engine/json-rpc-server-jvm.cpp:46-92`):
when `jvm_callContract` or `jvm_getContractState` is invoked without an
explicit `accountStateBoc` / `executorStateBoc` parameter, the full-node
loads the per-account state from the live wc=3 ShardAccounts dict using
the supplied `contractAddress`.

## 11. Test Coverage Index

Canonical tests live in `crypto/test/test-workchain-execution-registry.cpp`:

### Codec & address derivation (`JvmWorkchainCore` suite)

- `ContractAccountStateCodecRoundTripsClassBytesAndStorage` — JVAC encode/decode
  preserves all fields, including the class-bytes ref under DB hash dedup.
- `EncodeJvmStateInitCellPassesTlbValidation` — generated `StateInit{code, data}`
  cell passes `block::gen::t_StateInit.validate_ref`, i.e. is consensus-valid
  for `action_create_account`.
- `MessageAbiCallDescriptorRoundTripsAndOmitsContractId` — JVI2 codec round-trip;
  asserts `contract_id` is no longer carried in the descriptor body.
- `DeriveJvmContractAddressIsDeterministicAndSensitive` — address formula is
  deterministic and sensitive to each input (deployer, class_hash, salt,
  init_args hash).
- `MethodManifestRoundTripsAndRejectsDuplicates` — JVM2 manifest codec; both
  encoder and parser reject duplicate `method_id`.
- `ConfigParam85CodecRoundTripsGasTables` — opcode/helper gas tables survive
  encode/parse on `schema_version=2`.
- `JvmActivationConfigBuildsAndRoundTrips` — `JvmConfig::default_activation`
  → `build_jvm_config_cell` → `parse_jvm_config_cell` is identity.
- `JvmConfigCellRejectsV1Schema` — `parse_jvm_config_cell` fails closed when
  fed a v1 ConfigParam 85 cell (regression for the v1→v2 wire-break).
- `JvmConfigDefaultActivationV2` — `default_activation` emits
  `schema_version=2` and omits `max_total_class_bytes`.
- `DeriveJvmContractAddressFormulaMatchesSpec` — exercises the exact byte
  layout of the address pre-image against the spec in §2.
- `WorkchainDescriptorUsesJvmV1Selector` — ConfigParam 12 descriptor for wc=3
  uses `vm_version=0x4a564d31`, `vm_mode=0`, basic format.
- `GasBridgeInstallsConfigParam85Tables` — Avata gas bridge applies parsed
  ConfigParam 85 opcode/helper tables before invocation.
- `StorageCellHostRoundTripAndTransactions` /
  `StorageHostCallbackKeepsEmptyValueDistinctFromMissing` — JvmStorageCellHost
  semantics under transaction commit/rollback.
- `AvataTransactionCommitsSuccessfulStorageWrites` /
  `AvataTransactionRollsBackFailedInvocation` /
  `AvataTransactionClassifiesOutOfGasAndFailsClosed` — execute_jvm_avata_transaction
  commit/rollback/out-of-gas semantics.
- `EventPayloadAndActionListCodec` — JVM event encoding round-trip.
- `ZerostateAccountsCellIsEmpty` — wc=3 genesis ShardAccounts is `hme_empty$0`
  with zero entries; build is deterministic across calls.

### Engine policy & dispatch (`WorkchainExecutionRegistry` suite)

- `EngineDefinedPolicyValidates` — host accepts the new `EngineDefined`
  variant (with and without `admits_engine_create_account_actions`); other
  unimplemented kinds (e.g. `ShardLocalExecutor`) still fail closed.
- `JvmEngineAccountPolicyIsEngineDefined` — JVM engine declares
  `EngineDefined`, no `singleton_address`, `admits_engine_create_account_actions`,
  `may_activate_uninitialized_account`, both inbound directions enabled,
  activation_code present.
- `JvmEngineDispatchesAccountStateToRuntime` — engine decodes JVAC from
  `current_data` and dispatches to `JvmComputeRuntime::run_contract`; output
  re-encodes JVAC with new `storage_root` and pinned `class_hash` /
  `class_bytes` / `manifest_root`.
- `JvmEngineRejectsMalformedAccountState` — malformed JVAC triggers
  fail-closed `sk_bad_state`.
- `JvmEndToEndDeployCallSequence` — engine + mock runtime e2e: deploy →
  call (storage carries forward) → failed call (rollback).
- `JvmDeterminismReplay` — replaying the same descriptor + state on a
  fresh registry produces identical `new_data` / gas accounting.
- `EvmAndUnoDescriptorEnginesValidateConfig` — ConfigParam 12 routing for
  EVM/Uno/JVM engines including JVM `vm_mode != 0` and missing
  ConfigParam 85 fail-closed cases.

### RPC (`JvmWorkchainCore` suite)

- `RpcIsJvmMethod` — `is_jvm_rpc_method` recognizes the four jvm_* methods.
- `RpcDeployContractParsesAndValidates` — request parser accepts well-formed
  inputs; validates Java 8 class profile.
- `RpcDeployContractAdmissionChecksClassSize` — admission rejects oversize
  class bytes against ConfigParam 85's `max_class_bytes`.
- `RpcDeployContractReturnsContractAddress` — response carries the derived
  per-contract wc=3 address and the deploy-descriptor BOC.
- `RpcDispatcherRoutesJvmMethods` / `RpcDispatcherPropagatesRealResults` —
  `handle_jvm_rpc` dispatcher routing and result propagation.
- `RpcCallContractAcceptsAddressNotContractId` — v2 canonical
  `contractAddress` parses; legacy `contractId` alias still parses.
- `RpcGetContractStateFetchesPerAccount` — `jvm_getContractState` returns
  the storage view for the requested per-contract wc=3 account.

### Per-contract topology (`JvmWorkchainCore` suite)

- `AvataResolverFindsMethodInPerAccountManifest` —
  `find_jvm_method_manifest_entry` resolves `method_id` against the
  per-account manifest_root.
- `AvataResolverRejectsUnknownMethodId` — unknown `method_id` is a
  consensus error, not silently dispatched.
- `AvataClassCacheKeyedOnClassHash` — class loader cache uses
  `state.class_hash` as its key, so two contracts sharing identical
  bytecode share the loaded class.
- `MultiContractIsolatedStorageWithSharedClass` — two contracts with the
  same `class_bytes` but different salts have disjoint storage roots.

When auditing this list, scan
`crypto/test/test-workchain-execution-registry.cpp` for
`TEST(JvmWorkchainCore, ...)` and `TEST(WorkchainExecutionRegistry, ...Jvm...)`
to confirm; additional tests may have been added since this doc was written.

## Related docs

- [ConfigParam.md §85](ConfigParam.md#configparam-85--jvm-workchain-chain-config) — `schema_version=2` ConfigParam 85 layout and migration.
- [jvm-roadmap.md](jvm-roadmap.md) — phased roadmap and out-of-scope items.
- [block.tlb](../crypto/block/block.tlb) — canonical TLB schema, including
  `action_create_account#4a435241` at line 420.
