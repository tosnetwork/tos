# EVM Workchain — Cell-Native State Architecture

Version: v1.1 — Cell-native EVM state with collator dispatch hook

## Motivation

The original EVM workchain implementation stored EVM state (accounts, storage, code, receipts) in a dedicated RocksDB instance at `{db_root}/evm-state/`, separate from TOS's CellDb at `{db_root}/cells/`. This was the obvious-but-wrong choice.

### The Atomicity Problem

A TOS block contains state updates that must be committed atomically. With two independent RocksDB instances:

```
Block N execution flow (BROKEN):
  1. EVM executes → writes to evm-state/ RocksDB
  2. TOS commits ShardState → writes to cells/ RocksDB
  3. CRASH between (1) and (2): EVM has new state, TOS thinks block N never happened
  4. CRASH between (2) and (1): TOS has block N committed, EVM is missing the writes
```

No coordination scheme bridges this gap. Write-ahead logs, two-phase commits, replay-on-recovery — all are patches that close *most* of the window, not all of it. Different validators might recover differently, causing consensus divergence.

### First-Principles Resolution

In TOS, **all canonical state is cells in the CellDb**, committed atomically per block via `rocksdb::WriteBatch`. This is not a convention — it is the architectural foundation. masterchain (workchain -1) and basechain (workchain 0) both follow this rule. The EVM workchain must follow it too.

The fix is not to add coordination between two stores. The fix is to remove the second store. EVM state becomes cells, stored in CellDb, committed by the same WriteBatch that commits the TOS ShardState. Atomicity is then a property of the construction, not of careful runtime coordination.

## Design

### Storage Hierarchy

```
TOS CellDb (single source of truth)
└── ShardState (per workchain, per shard)
    ├── shard_id: ShardIdent { workchain=1, shard=0x8000... }
    ├── accounts: ^ShardAccounts (HashmapAugE 256 ShardAccount)
    │   └── EVM Account (e.g., 0x1234...)
    │       └── ShardAccount cell
    │           └── ^Account
    │               └── AccountStorage
    │                   └── AccountState (account_active$1)
    │                       └── StateInit
    │                           ├── code: ^Cell
    │                           │   └── EVM bytecode (raw bytes in cell)
    │                           └── data: ^Cell
    │                               └── EvmAccountData cell
    │                                   ├── magic: 0x45564D
    │                                   ├── nonce: uint64
    │                                   ├── balance: uint256
    │                                   ├── code_hash: bits256
    │                                   └── storage: HashmapE 256 ^EvmStorageEntry
    │                                       └── slot_hash → value cell
    └── ... other workchain metadata ...
```

### TLB Schema (Documented, Not Modified)

`block.tlb` is **not** modified. The existing `data:(Maybe ^Cell)` field in StateInit accepts arbitrary cells — TOS treats it as opaque. We define the cell format via convention:

```tlb
// Cell stored inside StateInit.data for EVM workchain (wc=1) accounts
evm_account_data#45564d
  nonce:uint64
  balance:uint256
  code_hash:bits256
  storage:(HashmapE 256 ^EvmStorageEntry)
  = EvmAccountData;

evm_storage_entry#_ value:bits256 = EvmStorageEntry;
```

The `0x45564D` magic ("EVM" in ASCII) lets validators identify EVM accounts when scanning ShardAccounts.

### silkworm::State Adapter

A new class `CellEvmState : silkworm::State` bridges silkworm's account-and-storage interface to TOS cells:

```cpp
class CellEvmState : public silkworm::State {
 public:
  // Constructed with a mutable reference to the collator's ShardAccounts dict.
  CellEvmState(vm::AugmentedDictionary& account_dict);

  // silkworm::State interface (reads):
  std::optional<silkworm::Account> read_account(const evmc::address&) const noexcept override;
  silkworm::ByteView read_code(const evmc::address&, const evmc::bytes32& code_hash) const noexcept override;
  evmc::bytes32 read_storage(const evmc::address&, uint64_t inc, const evmc::bytes32& loc) const noexcept override;

  // silkworm::State interface (writes — only called from IntraBlockState::write_to_db):
  void update_account(const evmc::address&, std::optional<silkworm::Account> initial,
                      std::optional<silkworm::Account> current) override;
  void update_account_code(const evmc::address&, uint64_t inc, const evmc::bytes32& code_hash,
                           silkworm::ByteView code) override;
  void update_storage(const evmc::address&, uint64_t inc, const evmc::bytes32& loc,
                      const evmc::bytes32& initial, const evmc::bytes32& current) override;

  // ...other State methods (mostly no-ops for our use case)...

 private:
  vm::AugmentedDictionary& account_dict_;        // Owned by collator
  mutable AccountCache hot_accounts_;            // In-memory cache
  mutable StorageCache hot_storage_;             // In-memory cache
  CodeCache code_cache_;                         // code_hash → Bytes
};
```

### Read Path

```
read_account(addr):
  1. Check hot_accounts_ cache → return if hit
  2. Build 256-bit address key (left-pad 20-byte EVM address to 32 bytes)
  3. account_dict_.lookup_extra(key, 256) → CellSlice for ShardAccount
  4. Parse to silkworm::Account (StateInit.data → EvmAccountData cell → fields)
  5. Insert into cache, return

read_storage(addr, inc, loc):
  1. Check hot_storage_ cache → return if hit
  2. Read account → get storage_dict cell reference
  3. vm::Dictionary storage(storage_root, 256)
  4. storage.lookup(loc, 256) → CellSlice for value
  5. Parse to bytes32, cache, return

read_code(addr, code_hash):
  1. Check code_cache_ → return if hit
  2. Read account → get StateInit.code cell
  3. Extract bytes from cell, cache by code_hash, return
```

### Write Path

```
update_account(addr, initial, current):
  1. If current is null → account deleted → account_dict_.lookup_delete(addr)
  2. Else build new ShardAccount cell with EvmAccountData encoded:
     - Build EvmAccountData cell: magic + nonce + balance + code_hash + storage_dict_ref
     - Wrap in StateInit { code: bytecode_cell, data: evm_account_data }
     - Wrap in AccountStorage, Account, ShardAccount
     - account_dict_.set_builder(addr, cb, SetMode::Set)
  3. Update hot_accounts_ cache

update_storage(addr, inc, loc, initial, current):
  1. Load current storage dict cell from account
  2. vm::Dictionary storage(root, 256)
  3. If current is zero → storage.lookup_delete(loc, 256)
  4. Else storage.set_builder(loc, builder_with_value, SetMode::Set)
  5. Update account's storage_root reference (triggers update_account)
  6. Update hot_storage_ cache

update_account_code(addr, inc, code_hash, code):
  1. Build cell containing the bytecode bytes
  2. Cache by code_hash for fast lookup
  3. Will be assigned to StateInit.code on next update_account
```

### Atomicity Guarantee

Block commit is atomic by construction:

```
Block N execution flow (CORRECT):
  1. Collator builds ShardState_N as in-memory cells (account_dict_ mutations)
  2. EVM execution runs against CellEvmState wrapping account_dict_
  3. EVM writes go into account_dict_ (cells, in-memory)
  4. Collator finalizes ShardState_N → root cell
  5. Single rocksdb::WriteBatch commits ALL cells (TOS + EVM together)
  6. CellDb atomic write → block N is fully committed or not at all
```

There is no separate EVM commit. There is no second database. There is no recovery scan. The entire EVM state mutation is part of the same WriteBatch as the TOS state.

If a crash occurs at any point before step 6, no part of block N is persisted. After step 6, all of block N is persisted. Different validators recovering from a crash will all reach the same state because there is only one consistent state to recover from.

### Caching Strategy

EVM execution does many SLOAD/SSTORE operations per transaction. Cell traversal for every operation would be slow (a HashmapE 256 lookup is ~3-4 cell reads for typical contracts). The fix is in-memory caching:

- `hot_accounts_`: LRU cache, address → silkworm::Account, default 10K entries
- `hot_storage_`: LRU cache, (address, slot) → bytes32, default 100K entries
- `code_cache_`: code_hash → Bytes (already content-addressed)

Cache populated on first read, evicted by LRU at capacity. Writes update both cache and underlying dict (for the dict, only on `write_to_db` at block end — within a tx, `IntraBlockState` already maintains its own journal).

The cache is **not** persistent state. It's purely a read accelerator. Restarting reloads from cells. Two validators with different cache states still produce identical block hashes because the canonical state is the cells.

### Performance Characteristics

| Operation | KV-based (old) | Cell-based (new) | Notes |
|-----------|---------------|------------------|-------|
| Cold SLOAD | 1 RocksDB get | ~3-4 cell reads | Cache hit reduces to O(1) |
| Hot SLOAD | 1 RocksDB get | 1 cache hit | Comparable |
| Cold SSTORE | 1 RocksDB put | log256(N) cell rebuilds | CellDb batches efficiently |
| Block commit | 2 separate batches | 1 unified batch | **Atomic** |
| Read account | 1 get | 1 dict lookup | Cached after first |
| Crash recovery | Complex coordination | None needed | Same as TOS |

Realistic workloads (ERC-20 transfers, simple swaps) hit the cache for >90% of accesses, making per-transaction cost comparable to the KV approach. Cold accesses are slightly slower but committed reads dominate uncommitted ones.

### Migration

Old data in `{db_root}/evm-state/` is abandoned. Any chain using the old architecture must be reset and replayed under the new one. Production deployment has not occurred, so this is a clean migration. The directory itself is no longer created.

## Consensus Implications

### TOS state_hash Now Commits to EVM State

Previously the TOS state_hash committed only to the "TOS shell" of EVM accounts — empty code/data cells, gas balance changes. EVM-specific state lived elsewhere and was not cryptographically committed.

With cell-native state, the EVM account data (nonce, balance, storage) is encoded into the StateInit data cell, which is part of the ShardState cell tree, whose root hash is the state_hash. Therefore:

- Different validators executing the same block produce identical ShardState cell trees and identical state_hash
- An incorrect EVM execution (bug, malicious behavior) produces a different cell tree and different state_hash → caught by consensus
- No "deterministic execution" assumption needed; consensus is enforced by hash equality

### Ethereum stateRoot Becomes RPC-Only

The Ethereum-format stateRoot (Merkle Patricia Trie over keccak256-hashed accounts and RLP-encoded values) is computed by `IncrementalTrieCalculator` and exposed via `eth_getBlockByNumber.stateRoot`. It serves wallet/explorer compatibility but is **not** used for TOS consensus. TOS uses the cell-based state_hash; Ethereum tools see the MPT stateRoot.

Both roots commit to the same underlying state — they differ only in encoding.

## Collator Integration Hook

The dispatch interface (`evm-workchain-dispatch.h`) accepts an optional
`vm::Dictionary* shard_accounts` parameter. When supplied by the collator,
`run_evm_compute_phase()` calls `CellEvmState::sync_to_dict()` after EVM
execution, replicating every EVM account's `EvmAccountData` cell into the
target dict. The collator then commits the unified dict (TOS + EVM data)
to CellDb in a single atomic WriteBatch.

When `shard_accounts == nullptr` (test paths, RPC sync path), the EVM
state is still embedded into `cp.new_data` so that the per-transaction
account StateInit cell carries a reference to the full EVM state root.
Either path produces the same first-principles guarantee: the TOS state_hash
transitively includes the EVM state cell tree.

## Affected Components

### New

- `crypto/block/evm-workchain/evm-cell-codec.h/.cpp` — encode/decode EvmAccountData cells
- `crypto/block/evm-workchain/evm-cell-state.h/.cpp` — `CellEvmState : silkworm::State`

### Modified

- `crypto/block/evm-workchain/evm-state.h/.cpp` — wraps CellEvmState; remove InMemoryState/PersistentEvmState branches
- `crypto/block/evm-workchain/evm-init.cpp` — initializes CellEvmState; no separate DB path
- `crypto/block/evm-workchain/evm-incremental-trie.cpp` — iterates accounts via the cell dict
- `crypto/block/evm-workchain/evm-compute-phase.cpp` — uses CellEvmState constructed from collator's account_dict
- `crypto/block/evm-workchain-dispatch.h/.cpp` — dispatch signature carries account_dict reference
- `crypto/block/transaction.cpp` — EVM dispatch passes collator's account_dict
- `crypto/block/evm-workchain/test-evm-executor.cpp` — adds cell-codec, atomicity, state_hash tests

### Deleted

- `crypto/block/evm-workchain/evm-persistent-state.h/.cpp` — separate RocksDB no longer needed
- The `{db_root}/evm-state/` directory is no longer created at runtime

## Verification

### Build

```bash
cd build && make -j$(nproc) test-evm-executor validator-engine
```

Both binaries must compile without warnings introduced by these changes.

### Functional Tests

```bash
./crypto/block/evm-workchain/test-evm-executor
```

All existing tests must continue to pass. New tests added:

- `test_cell_codec_roundtrip` — encode/decode an Account cell, verify all fields preserved
- `test_storage_dict_persistence` — SSTORE → cell update → SLOAD returns same value
- `test_state_hash_includes_evm_state` — modifying EVM state changes the ShardState cell hash
- `test_no_separate_evm_db` — runtime check that no `evm-state/` directory is created

### Atomicity Verification (Manual)

```bash
# Start node, send transaction, kill -9 mid-block
./validator-engine ... &
PID=$!
curl -X POST -d '{"method":"eth_sendRawTransaction",...}' http://localhost:8545
kill -9 $PID  # crash before block commits

# Restart and verify state is consistent
./validator-engine ...
curl -X POST -d '{"method":"eth_getBalance",...}' http://localhost:8545
# Result: balance is either pre-transaction (block didn't commit)
#         or post-transaction (block fully committed)
# Never: a partial state where some changes applied and others didn't
```

## References

- TOS block TLB schema: `crypto/block/block.tlb`
- Cell-based dictionary patterns: `crypto/vm/dict.h`, `crypto/vm/dict.cpp`
- Collator account dictionary usage: `validator/impl/collator.cpp` (lines 2860, 3107-3147, 5864)
- silkworm::State interface: `third-party/silkworm/core/state/state.hpp`
- Reference implementation pattern: `silkworm::InMemoryState` (`third-party/silkworm/core/state/in_memory_state.hpp`)
