# EVM Workchain Transaction Admission and Permanent Resolution via Single-Executor Account

Version: v2.0 — rewritten after Phase A–D proof test `a6631a16` showed the per-account mirror design is not merely sub-optimal but structurally rejected by TOS's `validate-query` AccountBlock invariant.

## Revision history

- **v1.0** (pre-Phase-A): framed the problem as "outer TOS balance admission rejects EVM ext-messages". This framing was wrong in two ways: (a) those admission gates had already been bypassed via `is_evm_workchain()` branches in `crypto/block/transaction.cpp:988/1443/1862`; (b) the deeper issue was not admission but **consensus-state persistence**. The v1.0 conclusion ("single-executor account") turned out correct, but the route to that conclusion was wrong. Much of v1.0's supporting argument was built on top of the wrong framing.
- **v2.0** (this doc): rewritten against the evidence from shipped Phase A/B/C/D (commits `c9751b42` → `a6631a16`) and the reproducible proof test at `test/evm-workchain/proof-mirror-not-canonical.sh`. The single-executor verdict stands; the reasoning is now grounded in TOS's actual `validate-query` enforcement rules rather than in architectural preference.

## Purpose

Document the design decision to move wc=1 EVM execution from a per-EVM-account ShardAccount mirror (Phase A) to a single-executor ShardAccount model. Provide the evidence that per-account mirror is structurally blocked, not just slow or ugly, and describe the minimal implementation delta.

This document supersedes all v1.0 content. It also supersedes the relevant "Phase B" (hydrate from canonical) and "Phase D.2" (embed bytecode in StateInit.code) designs in `cozy-snacking-bear.md`, because both of those designs assumed the per-account mirror could carry mutations into accepted canonical state.

## Executive summary

On Phase C–D the EVM workchain looked functional at the RPC layer: `eth_sendRawTransaction` minted, `eth_getBalance` and `eth_getTransactionCount` reflected the post-execution state, contracts deployed. None of that correctness survived a validator restart. The reproducible test `proof-mirror-not-canonical.sh`:

```
  sender nonce:    pre=0x0 post-tx=0x1 post-restart=0x0
  recipient bal:   pre=0x21e19…2400000 post-tx=0x222e6…170000 post-restart=0x21e19…2400000
```

Root cause is not a race, not a persistence glitch, and not the in-memory `g_evm_state` singleton being "stale". It is that TOS `validate-query` enforces "every `ShardAccounts` delta must have a matching `AccountBlock`" (`validator/impl/validate-query.cpp:3064–3125`). A normal EVM transaction produces exactly one `AccountBlock` — for the ext-in-msg destination, which Phase A routed to the sender's outer account. Any additional mutations the Phase A post-loop merge tries to write (recipient balance, contract code, touched storage roots, etc.) have no matching `AccountBlock` and are filtered out of any block candidate that survives consensus. The accepted canonical state therefore retains at most one outer-account change per EVM tx — specifically, the sender's outer account with `cp.new_data = "EVM magic + Maybe ^CellEvmState root + bits256 stateRoot"` (see `crypto/block/evm-workchain/evm-compute-phase.cpp:118–141`). Phase B's hydration reads `StateInit.data` only as an `EvmAccountData` cell and skips this `cp.new_data` format, so the sender's nonce reverts to the zerostate value and every downstream account (recipient, contract, anything touched only indirectly) reverts to genesis.

The permanent resolution is to stop trying to carry multi-account mutations across TOS's AccountBlock invariant at all. Instead: designate one fixed wc=1 outer TOS address (the *executor*), route every EVM ext-in-msg to it, make its `StateInit.data` hold the entire cell-native EVM world, and produce exactly one `AccountBlock` per EVM transaction. TOS's invariants are satisfied by construction. Validators, collators, proof generators, and the sharding / rent / augmentation machinery all keep working with no special-case hooks — they just see a single account update per block.

The critical observation that makes this design nearly zero-cost to adopt: `cp.new_data` in `evm-compute-phase.cpp:118–141` already embeds the entire `^CellEvmState root` on the sender's outer account. This is functionally the single-executor design already, but with the carrier address *varying per transaction*. All that needs to change is: (1) route ext-in-msg to a fixed executor address instead of the sender, and (2) teach hydration to look up that fixed address. The compute phase, silkworm dispatch, cell encoder, MPT proof generator, JSON-RPC layer, and subscription layer all remain untouched.

## What Phase A–D actually shipped

For honesty, the current behavior on the `evm-workchain` branch at commit `a6631a16`:

| Commit | Phase | Behavior |
|--------|-------|----------|
| `c9751b42` | Phase A bootstrap | collator accepts wc=1; fixes tear_down crash; ext-msg pool skips TVM account-fetch for wc=1 |
| `d5b8a0cf` | Phase A mirror | per-EVM-account ShardAccount wrapper; post-loop merge attempts to land multi-account changes |
| `5714a7fe` | Phase A receipt | `store_receipt` first-write-wins to survive validate-query replay |
| `d2f67434` | Phase A block-num | `block.number` = wc=1 shard seqno instead of logical time |
| `a02b8368` | Phase B | hydrate `g_evm_state` from canonical `ShardAccounts` at first wc=1 block load; delete `evm-state.boc` sidecar path |
| `1abec8e4` | Phase C | move pre-fund of 10 test EOAs into Fift zerostate (visible in `WorkchainDescr.zerostate_root_hash`) |
| `c9751b42` → `ad8075a4` | Phase D | dead-code cleanup; bytecode codec + `StateInit.code` enrichment |
| `a6631a16` | Proof test | reproducible script that exits 2 today, should exit 0 after this doc's design ships |

RPC-visible behavior on the running testnet is correct **while the node is alive** because `g_evm_state` (in-RAM `CellEvmState`) is updated by silkworm on every tx. It becomes incorrect the moment the process is restarted, because the canonical `ShardAccounts` it hydrates from does not contain any of the mutations the mirror attempted to write.

## Root cause

### TOS enforces an AccountBlock-per-account invariant in consensus

`validator/impl/validate-query.cpp::precheck_one_account_update` (lines 3059–3125) iterates every differing key between the old and new `ShardAccounts` of the candidate block. For each differing key it requires:

1. A matching `AccountBlock` exists in the block's `ShardAccountBlocks` for that key.
2. The `AccountBlock`'s `HASH_UPDATE` structure (`old_hash`, `new_hash`) matches `hash(old_ShardAccount.Account)` and `hash(new_ShardAccount.Account)`.

If either fails, the block is rejected:

```
"the state of account <addr> changed in the new state with respect to the old
 state, but the block contains no AccountBlock for this account"
```

This rule holds for every workchain, including wc=1. The rule is what TOS uses to detect collators silently rewriting account state outside the transaction machinery. It is not a per-workchain knob.

### EVM external messages generate exactly one AccountBlock

`crypto/block/evm-workchain/evm-external-message.cpp::build_evm_external_message` (line 40+) constructs an `ext_in_msg_info$10` where the destination `dest:MsgAddressInt` is the **sender's own EVM address padded to 256 bits**. There is no other ext-in-msg destination in the current design.

When the collator consumes this ext-msg, `Collator::process_external_message` (`validator/impl/collator.cpp:4416`) looks up the destination account and runs exactly one ordinary transaction for that one destination via `create_ordinary_transaction`. That produces exactly one `AccountBlock`, keyed by the sender's address.

### Phase A's post-loop merge tries to write N accounts

`validator/impl/collator.cpp:3208–3241` (the Phase A wc=1 merge) iterates `evm_state_mirror_dict_`, which is populated by `CellEvmState::sync_to_dict` and contains every EVM account silkworm has ever touched in this process (sender, recipient, freshly-created contracts, etc.). For each of these it calls `account_dict->set_builder(key, ShardAccount_cell, Replace)`.

This write succeeds on the local collator's in-memory `AugmentedDictionary` — confirmed by a `DEBUG_MERGE` probe that reads the same key back out and recovers the just-written nonce. But only ONE of the keys the merge touches (the sender) has a matching `AccountBlock` in the block candidate. Every other key fails the validate-query check.

### What the chain actually accepts

Because the chain keeps producing blocks, some candidate is clearly being accepted every round. Given validate-query's check, the accepted candidate cannot contain multi-account EVM mutations. Two possibilities:

- (a) the winning collator's candidate does not include the Phase A merge (e.g., the merge is skipped on non-leader paths, or the merge write is reverted between `set_builder` and the final `append_dict_to_bool`), or
- (b) the winning collator's candidate includes the merge for the *one* sender account only, because that's the only mutation with a matching `AccountBlock`.

Either way, accepted canonical `ShardAccounts` contains exactly the sender's outer account updated with whatever `Transaction::compute_state()` produced. And what `compute_state()` produces for wc=1 is the EVM dispatch's `cp.new_data` — the cell at `evm-compute-phase.cpp:118–141`:

```
evm_compute_new_data#45564D
  has_state_root:(## 1)
  state_root:(Maybe ^Cell)       // CellEvmState root — entire EVM world
  eth_state_root:bits256         // Ethereum MPT root (for eth_getProof)
```

This cell is stored as the sender's `StateInit.data` via `Transaction::prepare_compute_phase` at `crypto/block/transaction.cpp:1914`.

### Phase B hydration cannot see these values

`crypto/block/evm-workchain/evm-init.cpp::populate_state_from_shard_accounts` (lines 139+) walks `ShardAccounts`, extracts `StateInit.data` as a cell, and attempts to decode it as `EvmAccountData` via `decode_evm_account_data`. That decoder checks the first 24 bits for magic `0x45564D` (matches) and then expects `nonce:uint64 balance:uint256 code_hash:bits256 storage:Maybe ^Cell`. The `cp.new_data` cell has magic but the following bits are `has_state_root:1 [^state_root] eth_state_root:bits256` — entirely different layout. The decode fails (or worse, decodes garbage), and hydration skips the entry. The sender's RAM nonce ends up at whatever `seed_test_accounts` put there (0 for all ten test EOAs).

### Summary

- RPC sees correct values because silkworm updates `g_evm_state` in-RAM.
- Consensus-accepted canonical state contains exactly the sender's outer account with `cp.new_data` (EVM-workchain-specific format).
- Phase B hydration does not understand this format, so restart wipes back to zerostate.
- Phase A's per-account mirror writes are not part of accepted canonical state because `validate-query` filters them out.

The proof is reproducible via `bash test/evm-workchain/proof-mirror-not-canonical.sh` and exits 2 on the current codebase.

## cp.new_data is already half the single-executor design

This is the observation that makes the fix small.

`crypto/block/evm-workchain/evm-compute-phase.cpp:118–141` already:

1. Takes the full `CellEvmState.account_dict_root()` — a cell tree containing every EVM account's `EvmAccountData` — and stores it as a ref inside `cp.new_data`.
2. Stores the Ethereum MPT root separately (for `eth_getProof`).

So on every EVM transaction, there is already a cell that holds the entire EVM world state, and that cell already lands in canonical `ShardAccounts` on exactly one account — whichever account the ext-in-msg was routed to.

The only thing wrong is: **the carrier account varies per transaction**. Transaction N goes to sender A, transaction N+1 goes to sender B. Restart hydration does not know where to look. The whole EVM world is present in canonical state somewhere, but there's no stable lookup key.

Single-executor is just: fix the carrier to a well-known address (the executor), so every EVM transaction deposits the updated world state onto the same account, and hydration knows exactly where to read from.

## Design: single-executor account

### Executor account

- **Address**: `0x0000000000000000000000000000000000000001` at wc=1. Fixed in `crypto/block/evm-workchain/evm-workchain.h` as `kEvmExecutorAddress`.
- **Code**: `kEvmCodeMarker` (the existing single-byte `0x45` cell from `evm_workchain_dispatch::get_evm_code_marker_cell`). Deduplicated across the whole chain by CellDb.
- **Outer balance**: zero. Permanently. The EVM world's total balance lives entirely inside `StateInit.data → EvmAccountData.balance` for the per-address entries. This avoids any double-count against the TOS monetary base via `compute_total_balance()`.
- **StateInit.data**: a cell in the `cp.new_data` format above. On every block, updated to reflect the post-execution `CellEvmState`.

### Ext-in-msg routing

`crypto/block/evm-workchain/evm-external-message.cpp::build_evm_external_message` changes one line:

```
// before:
cb.store_bits(eth_addr_to_internal(sender_addr).as_bitslice());

// after:
cb.store_bits(kEvmExecutorAddress.as_bitslice());  // fixed
```

The ext-msg body (the RLP-signed EVM tx) is unchanged. Every EVM tx regardless of sender routes to the same executor account.

### Compute phase

No change beyond what already exists. `Transaction::prepare_compute_phase` at `transaction.cpp:1886–1931` already dispatches on `workchain == 1` to `invoke_evm_compute`, which populates `cp.new_data` with the full `^CellEvmState root + bits256 eth_state_root`. This already lands as `StateInit.data` of whatever account the ext-msg was routed to — which is now always the executor.

### Collator post-loop merge

**Removed.** The whole `if (workchain() == evm_workchain::kWorkchainId && evm_state_mirror_dict_)` block in `combine_account_transactions` (`collator.cpp:3193–3241`) is deleted. The per-account mirror was never landing in accepted state; removing it costs nothing. It also deletes the symmetric code in `validator/impl/validate-query.cpp:1122–1129` and `1140–1143`.

### Validate-query

No special case for wc=1 in `precheck_one_account_update` anymore. The existing general-case check works, because every EVM tx now produces exactly one `AccountBlock` (for the executor) and exactly one `ShardAccounts` delta (for the executor). The Phase A "bootstrap acceptance" branch has already been removed in D.1.

### Hydration

`populate_state_from_shard_accounts` in `evm-init.cpp:139+` changes from "walk all wc=1 ShardAccounts and decode each as EvmAccountData" to:

```
1. Look up the executor account (kEvmExecutorAddress) in shard_accounts.
2. Extract its Account → AccountStorage → AccountState (active) → StateInit.data cell.
3. Parse that cell as cp.new_data format (24-bit magic + Maybe ^state_root + bits256 eth_root).
4. Load the ^state_root into g_evm_state via CellEvmState::load_from_cell().
```

The per-account for_each_extra loop in the current hydration is replaced with a single dictionary lookup.

### Zerostate

`crypto/block/evm-workchain/evm-init.cpp::build_evm_zerostate_accounts_cell` (Phase C) changes from "build ShardAccounts containing 10 EOAs as per-account entries" to "build ShardAccounts containing one executor account, whose `StateInit.data` is a `cp.new_data`-shaped cell wrapping a `CellEvmState` preloaded with the 10 test EOAs". The 10 EOAs move inside the executor's world state. From TOS's perspective, wc=1 zerostate has exactly one account.

### `build_evm_shard_account_cell`

Simplifies. It no longer has a `code_cell` parameter (since contract bytecode lives *inside* the executor's world state, not in the outer ShardAccount's `StateInit.code`). It produces a ShardAccount cell for the executor only.

### `lookup_and_encode_evm_bytecode`

**Deleted** entirely. Bytecode lives in `CellEvmState.code_`, which is serialized as part of the world state root embedded in `cp.new_data`. There's no need to pluck it out and re-embed in a separate cell.

### Phase D.2 bytecode roundtrip helpers (`encode_evm_bytecode` / `decode_evm_bytecode`)

Kept as utility code (they're sound and unit-tested), but no longer called from the merge path. They may be useful later if `CellEvmState`'s storage layout changes to embed bytecode inline rather than via an adjacent map.

## Why this is consensus-compatible

### TOS AccountBlock invariant

Every ShardAccounts delta has a matching AccountBlock: ✓. Every EVM tx produces one AccountBlock (for the executor), and its `HASH_UPDATE.new_hash` matches the new executor account cell hash that the compute phase produced via `cp.new_data`.

### Sharding

wc=1 cannot shard-split (the executor address is fixed at a specific shard prefix). Not a regression — per-account mirror in Phase A didn't enable sharding either (the `kEvmWorkchainShard` was a single `0x8000...` shard in practice). The TOS multi-workchain design does not require every workchain to shard; workchains are allowed to be single-shard forever. See `WorkchainDescr.{min_split, max_split}` which are both permitted to be equal.

### AugmentedDictionary / depth-balance

Executor outer balance is 0. AugmentedDictionary's `aug_ShardAccounts.eval_leaf` (which does `t_Account.skip_copy_depth_balance`) sees 0 and rolls up 0 into the subtree. EVM balances stay inside `StateInit.data` and do not participate in `compute_total_balance` / masterchain's `total_balance`. No double-count.

### eth_getProof

Two-part proof that was already contemplated in `crypto/block/evm-workchain/evm-mpt-prover.h`:

1. Outer: standard TOS `ShardAccounts` Merkle proof from wc=1 shard state root down to the executor account's `Account` cell.
2. Inner: the Ethereum MPT proof (`evm-mpt-prover.cpp::generate_mpt_proof`) built against the `bits256 eth_state_root` embedded in `cp.new_data`.

Both pieces exist in the codebase today. They compose naturally under single-executor.

### Cross-validator determinism

silkworm's `execute_transaction` is byte-deterministic given byte-identical input state. All validators receive the same ext-in-msg (routed to the same executor address now) and load the same input `CellEvmState` (from the executor's previous-block `StateInit.data`). They produce identical `cp.new_data` cells. `HASH_UPDATE.new_hash` is the same on every validator.

### TOS global balance

The executor's outer balance contributes 0 to masterchain's global `total_balance`. The global balance invariant is preserved.

## Final state layout

```
masterchain ConfigParam 12
└── wc=1 WorkchainDescr
    ├── zerostate_root_hash   — hash of wc=1 zerostate (below)
    └── zerostate_file_hash   — BoC file hash of wc=1 zerostate

wc=1 zerostate / latest ShardState
└── ShardAccounts (HashmapAugE 256 ShardAccount)
    └── 0x0000…0001 (executor)
        └── ShardAccount
            ├── last_trans_hash / last_trans_lt
            └── ^Account
                ├── addr: addr_std$10 wc=1 0x0000…0001
                ├── storage_stat: StorageInfo
                └── storage: AccountStorage
                    ├── last_trans_lt
                    ├── balance: CurrencyCollection{Tomis=0}
                    └── state: account_active$1 StateInit
                        ├── split_depth: nothing
                        ├── special: nothing
                        ├── code: ^kEvmCodeMarker
                        ├── data: ^cp.new_data_cell
                        │   └── evm_magic:24 has_root:1 ^CellEvmState_root bits256:eth_state_root
                        │       └── CellEvmState root
                        │           └── HashmapE 256 ^EvmAccountData
                        │               ├── 0xf39F… → EvmAccountData{nonce, balance, code_hash, storage}
                        │               ├── 0x7099… → EvmAccountData{…}
                        │               └── …
                        └── library: nothing
```

The wc=1 `accounts:^ShardAccounts` dictionary has exactly **one** entry forever — the executor.

## Operational flow

### Zerostate generation

Fift script (extended via `create-state.cpp`):

1. Build `CellEvmState` seeded with the 10 Hardhat/Anvil test EOAs (nonce=0, balance=10,000,000 eTOS wei each — dev/test eTOS supply 100 M total). eTOS is the wc=1-native token, independent of TOS on wc=0; no on-chain bridge between them.
2. Serialize into a `cp.new_data`-shaped cell: magic + `^account_dict_root` + 256-bit Ethereum MPT root.
3. Build an executor `Account` cell whose `StateInit.data` is the cell above and whose `StateInit.code` is the marker.
4. Wrap into `ShardAccount`; insert at key `kEvmExecutorAddress` into an `AugmentedDictionary{256, aug_ShardAccounts}`.
5. Produce the wc=1 zerostate `ShardState` cell with this dict as its `accounts:^ShardAccounts`.

Result: `evmstate1.boc` and its hashes bake the initial EVM world into the masterchain `WorkchainDescr`. Any validator with a different executor layout (wrong address, wrong kTestAccounts, wrong encoding) computes a different `zerostate_root_hash` and cannot join the chain — loud failure at chain init, not silent fork at block 1.

### External message submission

`eth_sendRawTransaction` → JsonRpcServer → `build_evm_external_message` (now routing to executor) → ext-msg pool → collator selects → `create_ordinary_transaction(executor_addr)`.

### Compute phase

`Transaction::prepare_compute_phase` dispatches to `invoke_evm_compute` as today. silkworm runs against a `CellEvmState` loaded from the executor's current `StateInit.data` (decoded from the `cp.new_data` cell of the previous block). The transaction modifies whichever EVM accounts it likes inside that `CellEvmState`. Compute phase writes the new `cp.new_data` back.

### Commit

`Transaction::compute_state()` produces the new executor `Account` cell. The per-account-loop in `combine_account_transactions` serializes this into the new `account_dict`. `AccountBlock` is generated for the executor, `HASH_UPDATE` matches. `append_dict_to_bool` writes the new `ShardAccounts` root into the new `ShardState`. CellDb commits atomically.

### Validate-query

Sees one ShardAccounts key changed (executor), sees one AccountBlock (for executor), `HASH_UPDATE` matches. Accepts.

### Hydration after restart

`Collator::fetch_config_params` on a fresh process, wc=1 branch: look up `kEvmExecutorAddress` in the input `account_dict`. Extract `StateInit.data` → parse as `cp.new_data` → load `^state_root` into `g_evm_state`. Process continues with silkworm seeing the correct post-latest-block world state.

### RPC

All `eth_*` handlers read `g_evm_state` as today. No handler changes.

## Fee accounting

Outer balance of the executor is **always zero**. EVM wei balances stay inside `EvmAccountData.balance` entries in the inner world-state tree. The TOS monetary base (masterchain `total_balance`) is unaware of EVM balances; this is fine for Phase E and is the same behavior Phase A's wrapper already implemented.

If and when EVM balances need to participate in cross-workchain value flows, that belongs in a separate bridge design (explicit TOS ↔ EVM conversion contract), not in the single-executor internal accounting.

Gas fees: charged inside silkworm against inner EVM balances; outer executor account's balance does not move.

## Why per-account mirror cannot work (evidence)

### The `validate-query` rule is not negotiable

`precheck_one_account_update` runs on every validator, for every block, for every differing ShardAccounts key. There is no wc=1 bypass because `validate-query` is part of consensus — a bypass would be exploitable by any validator to write arbitrary state.

### Per-account mirror writes N accounts per EVM tx

Every EVM transfer touches at least sender + recipient. Every contract creation touches at least sender + coinbase + contract. Internal calls touch more. Single-AccountBlock-per-tx is not compatible with any of these.

### Proof test

`test/evm-workchain/proof-mirror-not-canonical.sh` exits 2 on the current codebase. After the single-executor implementation it must exit 0. The test is a drop-in acceptance criterion.

### What mirror would need to start working

Synthesize a full `AccountBlock` + `HASH_UPDATE` for each touched EVM account. This is a complete re-implementation of TOS native transaction machinery inside the EVM workchain, and it introduces N AccountBlocks per tx, O(N) validate-query work per tx, O(N) cell allocation per tx, O(N) `AccountBlocks` dict growth per tx, etc. It also changes the meaning of per-workchain block gas accounting. This is weeks of work with no clear upside over single-executor, which works today by construction.

## Implementation plan (delta against commit `a6631a16`)

| # | File | Change |
|---|------|--------|
| 1 | `crypto/block/evm-workchain/evm-workchain.h` | Add `kEvmExecutorAddress` constant (`td::Bits256`, value `0x0000…0001`) |
| 2 | `crypto/block/evm-workchain/evm-external-message.cpp` | `build_evm_external_message` routes `dest` to `kEvmExecutorAddress` instead of `eth_addr_to_internal(sender_addr)` |
| 3 | `crypto/block/evm-workchain/evm-init.{h,cpp}` | Replace `build_evm_zerostate_accounts_cell` with `build_evm_zerostate_executor_account_cell` that produces a `ShardAccounts` cell with exactly one entry (the executor) whose `StateInit.data` is a `cp.new_data`-shaped cell wrapping a `CellEvmState` preloaded with `kTestAccounts`. |
| 4 | `crypto/block/evm-workchain/evm-init.{h,cpp}` | Replace `populate_state_from_shard_accounts` body: look up `kEvmExecutorAddress`, decode `StateInit.data` as `cp.new_data`, call `CellEvmState::load_from_cell(^state_root)`. |
| 5 | `crypto/block/evm-workchain/evm-init.{h,cpp}` | Delete `lookup_and_encode_evm_bytecode`. |
| 6 | `crypto/block/evm-workchain/evm-cell-state.{h,cpp}` | Simplify `build_evm_shard_account_cell` signature: drop `code_cell` parameter. Body builds the executor account only. Drop the helper if no external caller remains. |
| 7 | `validator/impl/collator.cpp` | Delete the `wc==1 && evm_state_mirror_dict_` post-loop merge block (lines ~3193–3241). Delete the `evm_state_mirror_dict_` allocation and the `compute_phase_cfg_.evm_shard_accounts = …` assignment. |
| 8 | `validator/impl/collator-impl.h` | Delete `std::unique_ptr<vm::Dictionary> evm_state_mirror_dict_;` member. |
| 9 | `validator/impl/validate-query.cpp` | Delete the symmetric `evm_state_mirror_dict_` setup and any remaining wc=1-specific bootstrap logic. (Most of it was already removed in Phase D.1.) |
| 10 | `validator/impl/validate-query.hpp` | Delete `std::unique_ptr<vm::Dictionary> evm_state_mirror_dict_;` member. |
| 11 | `crypto/block/transaction.h` | Delete `ComputePhaseConfig::evm_shard_accounts` field (no longer passed from collator). |
| 12 | `crypto/block/transaction.cpp` | In the wc=1 dispatch at line 1896, drop the `cfg.evm_shard_accounts` argument from `invoke_evm_compute`. |
| 13 | `crypto/block/evm-workchain-dispatch.{h,cpp}` | Drop `shard_accounts` parameter from `EvmComputeHandler` and `invoke_evm_compute`. |
| 14 | `crypto/block/evm-workchain/evm-compute-phase.{h,cpp}` | Drop `shard_accounts` parameter from `run_evm_compute_phase`. Delete the `cs->sync_to_dict(*shard_accounts)` block. `cp.new_data` assembly at lines 118–141 stays unchanged — this is the load-bearing piece that makes the whole design work. |
| 15 | `crypto/block/evm-workchain/evm-cell-state.{h,cpp}` | Delete `sync_to_dict`. It was only used by the mirror merge. |
| 16 | `test/tostester/src/tostester/zerostate.py` | `evm-zerostate-accounts-cell` → `evm-zerostate-executor-account-cell`. Fift glue unchanged in shape (still splicing one ref into the ShardState); only the content is different. |
| 17 | `crypto/block/create-state.cpp` | Update the Fift-exposed word to call the new executor builder. |
| 18 | `crypto/block/evm-workchain/test-evm-executor.cpp` | Retire `test_sync_to_dict`, `test_aug_shard_accounts_with_evm_entry`, `test_bytecode_marker_distinguished` (the last one is testing code that's no longer in the hot path). Add `test_executor_zerostate_roundtrip` (encode executor zerostate → extract `^state_root` → decode → verify kTestAccounts present) and `test_single_executor_hydration` (build a ShardAccounts dict with just an executor, call `populate_state_from_shard_accounts`, verify silkworm sees the inner world). |

Net diff: net **negative** lines. The mirror path and all its plumbing is far more code than the executor path needs.

## Acceptance criteria

Phase E is complete when:

1. `bash test/evm-workchain/proof-mirror-not-canonical.sh` exits 0 (currently 2).
2. All existing 41 unit tests still pass (new tests replace deleted ones one-for-one).
3. On a fresh testnet after `setup-testnet.sh --clean`:
   - `eth_getBalance` for any test EOA returns 10,000,000 eTOS **before the first wc=1 block is produced** (because zerostate already carries the executor with the inner world pre-populated, and hydration reads it on first collator wake).
   - Send a transfer; `eth_sendRawTransaction` returns a tx hash; receipt arrives within 30s; balances move as expected.
   - `kill -9` validator@1; restart; within 60s the validator rejoins consensus and its `eth_getBalance` / `eth_getTransactionCount` / `eth_getCode` all return post-tx values correctly.
4. Deploy a contract; `eth_getCode(contractAddress)` returns the bytecode; restart; `eth_getCode(contractAddress)` still returns the same bytecode.
5. Replay equivalence across all 4 validators: query `eth_getStorageAt` / `eth_getBalance` for the same addresses on ports 8011/8012/8013/8014; all must match for every block.
6. Cell-level consensus check: the `zerostate_root_hash` in `WorkchainDescr` for wc=1 matches on every validator (sanity check that all binaries agree on the executor's initial world).

Criteria 3, 4, 5, 6 were all already broken on `a6631a16`. The design above is how they become correct.

## Known risks

### Single-shard forever

wc=1 cannot shard-split. Scalability cap is one shard's throughput. This is acceptable for Ethereum-compatibility at current mainnet throughput levels (15–30 tx/s); if it ever becomes binding, the escape hatch is multiple executor accounts at fixed prefixes (each holding a disjoint partition of EVM address space) — which is its own design problem and not one we need to solve today.

### Executor account's cell size grows unbounded

The executor's `StateInit.data` holds the whole EVM world. At 1M EVM accounts each with a 300-byte `EvmAccountData` cell, that's ~300 MB of cells — which CellDb handles fine (CellDb is designed for multi-GB state), but storage rent on the executor account grows linearly with inner world size. Since outer balance is always 0, TOS's storage rent collection on the executor would fail (no balance to debit). Options:

1. Special-case wc=1: masterchain config exempts the executor from storage rent.
2. Set a nonzero executor balance at zerostate funded from somewhere (e.g., a system mint at genesis) and let it pay rent like a normal account.

The first is simpler and matches the "EVM is its own accounting world" philosophy. Decide before mainnet; not a blocker for testnet.

### Executor account hash explodes on every block

Every EVM tx changes the executor's `StateInit.data` (via the world-state root it references). That propagates up to a new Account cell hash and a new ShardAccount hash. CellDb dedupes unchanged cells at every level of the tree, so the actual stored cost is only what changed in the inner world state. But the executor's outer cell hash is different every block, which inflates the `ShardAccounts` augmentation recomputation by one entry per block. That's fine — `aug_ShardAccounts.eval_leaf` is cheap.

### `IncrementalTrieCalculator` (Ethereum MPT root) lifecycle

Computed per tx via the existing `evm-incremental-trie.{h,cpp}`. Embedded in `cp.new_data`. Used by `eth_getProof` only, not consensus-checked. Single-executor doesn't change this. Good.

### Receipts / transactions / blocks / logs cache

Still RAM-only, bounded LRU inside `g_evm_state`. Lost on restart. This is Phase F territory (extract `EvmRpcCache` from `g_evm_state`, potentially persist as a sidecar that doesn't affect consensus). Not a single-executor concern.

## What v1.0 proposed that v2.0 keeps

- Single-executor account architecture — verdict unchanged.
- Final state layout figure (updated to reflect the actual `cp.new_data` format).
- Operational flow framing.

## What v1.0 proposed that v2.0 rejects or corrects

- v1.0's problem statement blamed TOS admission gates (import-fee, gas-from-outer-balance). Those were already bypassed. Rewritten above.
- v1.0's "dual state" framing was right in spirit but too vague. Rewritten above with specific code paths.
- v1.0's fee accounting suggested "outer balance = sum of inner balances". This double-counts wei in masterchain `total_balance`. Rewritten to "outer balance = 0 forever; EVM value stays inside".
- v1.0's "why mirror isn't best" was worded as a design preference. Rewritten as a hard consensus rule (validate-query enforces it).
- v1.0's implementation plan was written assuming many collator-path changes; with the `cp.new_data` insight the actual changes are concentrated in ext-msg routing + hydration + dead-code removal.
