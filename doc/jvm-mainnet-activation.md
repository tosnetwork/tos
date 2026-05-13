# Mainnet Activation Runbook — wc=3 (Avata JVM)

Status: code-complete; awaiting operational pinning decisions.

This document is the step-by-step procedure for activating wc=3 on
the TOS mainnet.  Audience: network operators / governance.  All
referenced code is on `origin/main` as of the document date; line
numbers are accurate but may shift as the tree evolves.

For background see [`jvm-roadmap.md`](jvm-roadmap.md) (phase
breakdown, design rationale) and
[`jvm-v2-account-topology.md`](jvm-v2-account-topology.md) (state
shape, address derivation, deploy flow).

Activation is a one-way governance event: once ConfigParam 12 is
updated to `active=true` on wc=3, validators with the JVM capability
bit start producing wc=3 blocks.  Pre-activation pinning decisions
(steps 1–2) are irreversible in the sense that any wc=3 account
created against a given `stdlib_hash` / `class_bytes` is bound to
those bytes forever (the address itself is derived from them).

## 1. Build rt.jar and pin `stdlib_hash`

ConfigParam 85 carries a 32-byte `stdlib_hash` field; each JVAC's
`stdlib_hash` is checked against this value at every `run_compute`
(`jvm/core/dispatch-engine.cpp:144-148`).  Today
`JvmConfig::default_activation()` returns `stdlib_hash = 0`
(`jvm/core/config-param.cpp:286` — "stdlib_hash stays zero-initialized
until the stdlib archive is locked in"), which means the check is
trivially passed by any deploy with `stdlib_hash=0`.

**Before activation:**

1. Build the canonical `rt.jar` from `jvm/avata/rt/java/lang/` at a
   pinned tree revision.  `make -C jvm/avata` plus `rt/check-profile.sh`
   and `rt/check-native-profile.sh` gate against profile regressions
   (see roadmap §Phase 3).
2. Compute `stdlib_hash = sha256(rt.jar)`.
3. Use `JvmConfig::default_activation_with_stdlib(rt_jar_bytes)`
   (`jvm/core/config-param.cpp:328`) — or the Fift word
   `jvm-config-param-cell-with-stdlib`
   (`crypto/block/create-state.cpp:788, 1137`) — to embed that hash
   into the ConfigParam 85 cell.
4. Pin the rt.jar artifact + its sha256 in the network's release
   manifest so every validator boots against the same bytes.

Files to read: `jvm/core/config-param.{h,cpp}`,
`crypto/block/create-state.cpp:776-820`.

## 2. Choose the initial genesis wallet set

The empty-default wc=3 ShardAccounts dict has no sender that can emit
`action_create_account`, so the first contract on wc=3 is
undeployable without pre-seeded wallet accounts (see
`jvm-v2-account-topology.md §Genesis seeding (Phase F option)`).

Governance decision: pick **N ≥ 1** Ed25519 keypairs (typically the
network's foundation / treasury / initial validators), and for each
keypair choose:

- A 32-byte salt (sha256 of a human-readable name works well).
- An initial TOMIS balance (must be non-negative and fit in 120
  bits — `crypto/block/create-state.cpp:736-739`).

These keypairs become the bootstrap accounts: they hold pre-seeded
funds and can send messages via `Wallet.execute(...)`.  **Wallets
cannot themselves deploy new contracts** — `java.lang.Wallet`
exposes only `System.sendMessage`, not `System.createAccount`.
Runtime deployment of further wc=3 contracts requires at least one
*Deployer* account at genesis as well (see §3 below); without one,
the chain can move funds but never grow its contract surface.

Loss of all N private keys (wallets + deployers) before further
accounts are deployed means the chain cannot grow its wc=3 surface
— at least one Deployer-owner key must be held by an entity with
operational continuity.

For the canonical wallet contract see [`jvm-wallet.md`](jvm-wallet.md).

Files to read: `jvm/core/genesis-wallet.h`, `jvm/avata/rt/java/lang/Wallet.java`,
`jvm/avata/rt/java/lang/Deployer.java`.

## 3. Build the wc=3 ShardAccounts cell

A chain that wants both pre-funded user wallets AND runtime contract
deployment from block 0 should use the combined seed word
(`crypto/block/create-state.cpp`,
`interpret_jvm_zerostate_with_deployers_from_alloc`):

```
( wallet_alloc wallet_class_bytes deployer_alloc deployer_class_bytes
  stdlib_hash -- accounts_cell )
  jvm-zerostate-with-deployers-from-alloc
```

where:

- `wallet_alloc` / `deployer_alloc` are Fift tuples of 3-tuples
  `(owner_pubkey:32B, salt:32B, balance:int)`.  Either may be empty.
- `wallet_class_bytes` is the canonical `Wallet.class` bytecode.
- `deployer_class_bytes` is the canonical `Deployer.class` bytecode.
  These must be the same `.class` blobs admitted by the contract
  profile header — the genesis seeder hashes each into `class_hash`
  and into every derived address, so mismatch with the on-chain
  admitted bytes would produce accounts the dispatch engine rejects.
- `stdlib_hash` is the 32-byte sha256 from step 1.

A Wallet and a Deployer with identical `(owner_pubkey, salt)` derive
to *different* wc=3 addresses (the address-binding gate hashes
`manifest_root_hash` in, and the two manifests differ).  Mixing both
seed types in one dict therefore cannot collide.

The combined wallet+deployer count is capped at
`kJvmGenesisWalletCountMax` (256 at the time of writing).  All
length validation runs before any cells are materialized, so
malformed declarations surface as a clear `fift::IntError`.

**Backward-compat path — wallets only:** for tests or for a chain
that has no use case for runtime contract deployment, the older
single-tuple word remains available:

```
( wallet_alloc class_bytes stdlib_hash -- accounts_cell ) jvm-zerostate-from-alloc
```

This is functionally a special case of the combined word with the
deployer tuple empty.  A chain seeded with this word can move funds
between pre-existing wallets but cannot deploy any further wc=3
contract — the bootstrap deadlock described in §1 reappears.

To keep an empty wc=3 zerostate (no bootstrap accounts at all —
only valid if you have an alternate plan for getting a wc=3
sender, such as a future masterchain-bound mechanism), use
`jvm-zerostate-accounts-cell` which returns the canonical
`hme_empty$0`.

Files to read: `crypto/block/create-state.cpp:640-756`,
`jvm/core/zerostate.{h,cpp}`, `jvm/core/genesis-wallet.{h,cpp}`.

## 4. Add ConfigParam 12 entry for wc=3

The wc=3 descriptor is built by
`jvm_workchain::build_jvm_workchain_descr`
(`jvm/core/config-param.cpp` / `.h:82`).  Engine selector is
`vm_version = 0x4a564d31` ("JVM1"); format is `wfmt_basic`;
account policy is `EngineDefined` with
`admits_engine_create_account_actions=true`.

In Fift the binding is `add-jvm-workchain`
(`crypto/fift/lib/Workchain.fif`), which mirrors `add-evm-workchain`
/ `add-uno-workchain`:

```
( root-hash file-hash enable-utime actual-min-split min-split max-split workchain-id -- )
  add-jvm-workchain
```

The descriptor must be inserted into ConfigParam 12 at the wc=3 slot
with `active=false` until step 7.  `enabled_since` records activation
metadata but is **not** an automatic delayed-height trigger in the
current dispatch path — the active-flag flip in step 7 is what
actually opens the workchain.

The wc=3 ShardState itself is built either with `3 mkemptyShardState`
(empty accounts — fine while bootstrapping, but no contract can ever
deploy from this state without a Deployer seed; see §1 deadlock note)
or with `accounts_cell 3 mkShardStateWithAccounts` where
`accounts_cell` is the output of
`jvm-zerostate-with-deployers-from-alloc` from step 3.  Both Fift
words live in `crypto/fift/lib/Workchain.fif`.

The canonical genesis script (`crypto/smartcont/gen-zerostate.fif`)
ships with the empty-accounts variant gated behind a TODO comment;
launch operators replace it with the seeded form before generating
the production zerostate.

Files to read: `jvm/core/config-param.cpp:155-179`,
`jvm/core/dispatch-engine.cpp:80-110`,
`doc/ConfigParam.md` (ConfigParam 12 layout),
`crypto/fift/lib/Workchain.fif` (`add-jvm-workchain`,
`mkShardStateWithAccounts`),
`crypto/smartcont/gen-zerostate.fif` (wc=3 block).

## 5. Add ConfigParam 85

Use `jvm-config-param-cell-with-stdlib`
(`crypto/block/create-state.cpp:788, 1137`) to build a ConfigParam
85 cell that includes the `stdlib_hash` from step 1.  The Fift word
calls `JvmConfig::default_activation_with_stdlib(stdlib_bytes)`
internally, so the gas schedule, max-class-bytes (64 KiB),
max-gas-per-tx (1 M), max-heap-bytes (4 MiB), max-storage-cells
(65 536), and the 23-entry helper-gas table all come from the
canonical defaults
(`jvm/core/config-param.cpp:275-326`).

If governance wants to deviate from the defaults (e.g. raise
`max_gas_per_tx`, adjust opcode costs), build the `JvmConfig` struct
directly and serialize via `build_jvm_config_cell` — but the table
can also be adjusted post-activation via a regular ConfigParam
update, so deviating at genesis is not necessary.

Files to read: `jvm/core/config-param.cpp:275-341`,
`crypto/block/create-state.cpp:758-820`,
`jvm/avata/include/avata/gas_schedule.h` (the canonical opcode +
helper cost names + indices).

## 6. Validator capability flag

Every validator assigned to wc=3 must advertise the JVM capability
bit.  The bit is defined as
`kTosNodeCapabilityWorkchainJvm = 1u << 2`
(`crypto/block/workchain-execution-dispatch.h:66`) and is added to
`workchain_execution_capability_flags()` only when the JVM engine is
linked into the binary
(`crypto/block/workchain-execution-dispatch.cpp:310`).

Action: ensure every validator node that will be assigned to wc=3 is
running a binary built with the JVM workchain enabled
(`init_jvm_workchain()` called at startup — see
`validator-engine/validator-engine.cpp` for the wiring), and that
`validate_required_workchains` covers wc=3 before activation.  Nodes
that do not advertise the bit cannot be assigned to wc=3 (see
`doc/workchain-execution-registry.md §Activation and Capability
Coordination`).

Files to read: `crypto/block/workchain-execution-dispatch.{h,cpp}`,
`jvm/core/init.{h,cpp}`,
`doc/workchain-execution-registry.md`.

## 7. Activation

Submit a ConfigParam 12 update that flips the wc=3 descriptor's
`active` flag to `true`.  The activation point is the masterchain
block where this update becomes active, with ConfigParam 85 already
present in the same config snapshot (step 5 must land at or before
this height).

From this block onward:

- Validators advertising `kTosNodeCapabilityWorkchainJvm` can be
  assigned to wc=3 shards.
- The genesis-seeded wallets are live at their derived addresses
  and can immediately emit `execute(...)` calls.
- `jvm_*` JSON-RPC endpoints
  (`jvm_deployContract` / `jvm_callContract` / `jvm_getContractState`
  / `jvm_getReceipts`) become functional through full-nodes.
- `action_create_account` from any wc=3 sender starts materializing
  new wc=3 contract accounts.

Files to read: `crypto/block/transaction.cpp` (action-phase
gating), `validator-engine/json-rpc-server-jvm.cpp` (RPC routing).

## 8. Post-activation smoke tests

The following exercises should run successfully against the live
chain within the first masterchain rotation after activation:

1. **Wallet sanity**.  Call `getNonce()` against each genesis-seeded
   wallet via `jvm_callContract` and verify the resulting
   `WalletNonce(uint256)` event surfaces through `jvm_getReceipts`
   with `nonce=0`.
2. **First contract deploy**.  Build a trivial no-op contract (one
   `@ContractEntry void noop()` method), submit
   `jvm_deployContract` to a full-node, sign the resulting deploy
   descriptor with a genesis wallet's private key, and broadcast the
   `execute(...)` containing the wallet's outbound
   `action_create_account` (via the body / send-message path).
   Confirm the derived contract address materializes as
   `acc_active` in the next wc=3 block.
3. **First contract call**.  Submit a call to the noop entry via
   another wallet `execute`.  Confirm the transaction commits and
   the storage_root field rewrites are limited to the noop
   contract's own account state.
4. **Determinism replay**.  Take a wc=3 block from the smoke-test
   suite, re-import it on a second validator, and assert byte-
   identical block hash.  The replay tests under
   `crypto/test/test-workchain-execution-registry.cpp`
   (`JvmDeterminismReplay`) cover the in-process variant of this
   check.
5. **Capability gate**.  Confirm that a node *without* the JVM
   capability bit cannot be assigned to wc=3 and that its
   liteserver returns an explicit capability error for `jvm_*` RPC.

Files to read: `validator-engine/json-rpc-server-jvm.cpp`,
`crypto/test/test-workchain-execution-registry.cpp` (test scaffold
to clone from for smoke runs).

## 9. Rollback considerations

ConfigParam 12 supports `active=false`, but flipping wc=3 inactive
after live accounts exist would freeze every wc=3 account in place
(no new transactions can commit).  This is a stop-the-world action,
not a rollback — the accounts and their balances remain on chain.
There is no consensus-supported way to delete or rewrite a wc=3
account's history.

For an emergency stop, ConfigParam 85 fields can be adjusted via a
regular config update to make new transactions unattractive (e.g.
gas_price=very_high, max_gas_per_tx=very_low).  This is the
preferred lever over toggling `active=false`.

Any rollback that requires altering wc=3 history is a hard fork.
