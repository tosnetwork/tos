# EVM Workchain — RPC Cache Persistence (Phase F)

Version: v0.1 — Design + scaffold for receipts/transactions/blocks/logs survival across validator restart.

Owner: EVM workchain. Status: design accepted, scaffold landed,
live wiring deferred. Blocks Gate P row P-5 (`doc/evm-workchain-test-plan.md`).

## Problem

`g_evm_state` keeps `receipts_`, `transactions_`, `blocks_`, `block_logs_`
as RAM `unordered_map` / `map` containers (see `crypto/block/evm-workchain/evm-state.h:197-201`).
They are populated only as a side effect of the live execution path
(`evm-compute-phase.cpp:80-97`: `store_receipt` / `store_transaction` /
`store_logs`; `evm-compute-phase.cpp:196`: `store_block`). After a
validator process restart the containers are empty; an
`eth_getTransactionReceipt(hash)` call for a tx mined before the
restart returns `null`. The same is true for `eth_getTransactionByHash`,
`eth_getBlockByHash`, `eth_getLogs`. This is the only remaining blocker
for Gate P row P-5 ("Receipts / tx / logs survive validator restart").

The data is **not consensus state** — receipts, tx envelopes, and log
indexes are derived locally from the block's compute-phase output
and are recomputable in principle from canonical state + the original
RLP. But recomputation requires the original signed transactions,
which are themselves only kept as part of `StoredTransaction.raw_rlp`
in the same lost map. So in practice, after restart, this data is
gone forever for blocks the node missed re-executing.

## Three options

### Option A — embed receipts inside `EvmAccountData`

Per-tx records ride inside the account dict that already lives under
`cp.new_data`. Simplest delta to the existing cell tree.

| Aspect | A — embed in EvmAccountData |
|---|---|
| Atomicity | Trivially atomic: same WriteBatch as the rest of the block. |
| Consensus impact | **Receipts contribute to `state_hash`**. Any non-determinism in receipt ordering / log indexing diverges consensus. |
| Schema change | Extend `EvmAccountData` (or add a sibling field) — needs versioning. |
| Retention | Unbounded growth: every receipt sticks around forever via the account that produced it. |
| Restart hydration | Free: rides existing `populate_state_from_shard_accounts`. |
| Risk | High: any bug in receipt encoding becomes a fork. |

### Option B — sibling cell tree under `cp.new_data`

`cp.new_data` already encodes `magic + Maybe ^state_root + bits256 eth_state_root`.
Bump it to `magic + Maybe ^state_root + bits256 eth_state_root + Maybe ^rpc_cache_root`.
The new ref points at a separate cell tree holding receipts / tx /
blocks / logs.

| Aspect | B — sibling under cp.new_data |
|---|---|
| Atomicity | Trivially atomic: same WriteBatch as state_root. |
| Consensus impact | **Yes** — `cp.new_data` is a `StateInit.data` cell. Its hash feeds the executor account hash, which feeds `ShardAccounts`, which feeds `state_hash`. Validators that disagree on receipt encoding (cumulative_gas_used ordering, log_index ordering, etc.) fork. |
| Schema change | Versioned migration of `cp.new_data` decoder + zerostate generator. |
| Retention | Pruning needs the same WriteBatch hook — unclear if CellDb pruning understands "drop ^rpc_cache_root branches older than block N". |
| Restart hydration | Free: rides existing `populate_state_from_shard_accounts`. |
| Risk | Same fork risk as A; plus the schema-bump migration has to land everywhere (zerostate generator, hydration decoder, RPC writer). |

### Option C — side-channel CellDb namespace, written in the same WriteBatch but NOT referenced from `state_hash`

Each receipt/tx/block/log record is encoded as a cell, written to
CellDb under a stable lookup key (kept in a small "rpc cache pointer"
cell that *is* referenced from `cp.new_data`, so we know where to
look on restart). The lookup key is a flat dict keyed by tx hash /
block hash / block number — separate from `account_dict`. The cells
live in CellDb forever (same as any other persisted cell), but
their hashes are not transitively reachable from `state_hash`, so
disagreement between validators on receipt encoding is **not** a
consensus fault.

| Aspect | C — side-channel cell tree, separate root |
|---|---|
| Atomicity | Trivially atomic: cells go in the same WriteBatch as `ShardAccounts`. CellDb either commits both or neither. |
| Consensus impact | **None**. The pointer cell *is* under `cp.new_data` (so the chain knows where the cache lives), but its CONTENTS — the actual receipt cells — are ref'd by a non-consensus dictionary. Validators with bugs in the encoder produce different receipt cells but the same `state_hash`. |
| Schema change | One extra `Maybe ^Cell` field on `cp.new_data` (the pointer to the cache root). Versioned but trivial. |
| Retention | Pruning is opt-in: a background sweep can rewrite the rpc cache root cell to drop entries below `block_number - N`. The pruned cells become unreachable from any new state and CellDb's existing GC reclaims them. The dropped data does not affect any consensus invariant. |
| Restart hydration | One extra cell read on startup: open the rpc cache root from `cp.new_data`, lazily fall through to it on RPC cache miss. No bulk re-population needed. |
| Risk | Low: receipts being absent or wrong only affects RPC clients, not block production. |

## Recommendation: Option C

**Rationale.** The problem space (RPC cache for indexer-style
queries) is operational, not consensus. Polluting `state_hash` with
receipts (Options A and B) is the wrong abstraction for two reasons:

1. **Fork surface area.** The receipt encoding has 30+ subtle fields
   (cumulative_gas_used ordering, log_index across all txs in a
   block, bloom filter computation, etc.). Every subtle ordering
   bug becomes a consensus divergence under A or B; under C it
   becomes an RPC bug visible only on the buggy validator and
   fixable without a hardfork.

2. **Retention policy.** Geth and erigon both prune receipts /
   transactions outside an indexer window (default ~90 days), and
   bridges / archive nodes opt in to longer retention. If receipts
   are part of `state_hash` (A or B), every full node has to keep
   every receipt forever, blowing up cell storage on a chain with
   any meaningful tx volume. C lets us configure retention per
   operator without a hardfork.

C also matches what every other Ethereum implementation does:
receipts and tx envelopes live in a separate "blocks" CF in
RocksDB, alongside but not inside the state trie. We are
implementing the same separation — just in CellDb's terms, so
atomicity is still free.

The minor complexity of C (one extra `Maybe ^Cell` ref under
`cp.new_data`, plus a flat lookup dict) is far outweighed by the
removed fork surface and the retention flexibility.

## Detailed design (Option C)

### TLB schema

```tlb
// Extension to cp.new_data (compute-phase output cell, see
// crypto/block/evm-workchain/evm-compute-phase.cpp:118-141).
//
// v1 (current):
//   evm_compute_new_data#45564d
//     has_state_root:(## 1)
//     state_root:(Maybe ^Cell)
//     eth_state_root:bits256
//     = EvmComputeNewData;
//
// v2 (Phase F): adds rpc_cache_root.
//   evm_compute_new_data_v2#45564d
//     has_state_root:(## 1)
//     state_root:(Maybe ^Cell)
//     eth_state_root:bits256
//     rpc_cache_root:(Maybe ^EvmRpcCacheRoot)
//     = EvmComputeNewData;
//
// Decoder is backward-compatible: if the trailing Maybe bit is
// missing (legacy v1 cell), treat as `nothing`.

evm_rpc_cache_root#52504343  // "RPCC"
  receipts:(Maybe ^Cell)         // HashmapE 256 ^PersistedReceipt, key = tx_hash
  transactions:(Maybe ^Cell)     // HashmapE 256 ^PersistedTransaction, key = tx_hash
  blocks_by_number:(Maybe ^Cell) // HashmapE 64 ^PersistedBlock, key = block_number
  blocks_by_hash:(Maybe ^Cell)   // HashmapE 256 ^PersistedBlock, key = block_hash
  logs_by_block:(Maybe ^Cell)    // HashmapE 64 ^PersistedLogList, key = block_number
  retention_floor:uint64         // lowest block_number still indexed (pruning watermark)
  = EvmRpcCacheRoot;

// PersistedReceipt mirrors StoredReceipt 1:1 (evm-state.h:40-51).
persisted_receipt#52455054     // "REPT"
  success:Bool
  gas_used:uint64
  cumulative_gas_used:uint64
  block_number:uint64
  tx_index:uint32
  from:bits160                  // evmc::address — 20 bytes
  to_kind:(## 2)                // 0=none, 1=address
  to:to_kind?bits160
  contract_kind:(## 2)
  contract_address:contract_kind?bits160
  return_data:(Maybe ^Cell)     // chunked bytes (reuse encode_evm_bytecode chain)
  logs:^PersistedLogList
  = PersistedReceipt;

persisted_log_list#_ {n:#}
  count:(## 16) { count <= n }
  logs:(count * ^PersistedLog)  // outer cells, one per log entry
  = PersistedLogList;

persisted_log#4c4f4720          // "LOG "
  address:bits160
  topic_count:(## 4)            // 0..4
  topics:(Maybe ^TopicArray)    // outer ref: 4×bits256 = 1024 bits would
                                // overflow a single cell with the magic+addr
                                // header, so topics live in a sibling cell
  data:(Maybe ^Cell)            // chunked bytes for arbitrary-length log data
  = PersistedLog;

// Topics live in a parent cell whose refs each point at a 32-byte leaf
// cell. Per-topic-ref (rather than inline) is forced by the per-cell
// 1023-bit limit: 4 × 256 = 1024 bits would not fit a single cell.
topic_array#_ {n:#} entries:(n * ^TopicLeaf) { n <= 4 } = TopicArray;
topic_leaf#_ topic:bits256 = TopicLeaf;

// PersistedTransaction mirrors StoredTransaction 1:1 (evm-state.h:54-65).
persisted_transaction#54585845   // "TXNE"
  from:bits160
  to_kind:(## 2)
  to:to_kind?bits160
  value:bits256                 // intx::uint256, big-endian
  data:(Maybe ^Cell)            // chunked
  nonce:uint64
  gas_limit:uint64
  gas_price:bits256
  block_number:uint64
  tx_index:uint32
  raw_rlp:^Cell                 // chunked, always present
  = PersistedTransaction;

// PersistedBlock mirrors StoredBlock 1:1 (evm-state.h:68-83).
persisted_block#424c4b48         // "BLKH"
  number:uint64
  hash:bits256
  parent_hash:bits256
  timestamp:uint64
  gas_limit:uint64
  gas_used:uint64
  miner:bits160
  base_fee_per_gas:bits256
  state_root:bits256
  transactions_root:bits256
  receipts_root:bits256
  logs_bloom:^Cell              // 256 bytes inline = 2048 bits, fits one cell
  tx_hashes:(Maybe ^Cell)       // HashmapE 16 bits256, key = tx_index
  = PersistedBlock;
```

The `chunked bytes` cell type is the existing `EvmBytecodeChunk`
chain from `evm-cell-codec.h:80-94` (`encode_evm_bytecode` /
`decode_evm_bytecode`) — already proven, already unit-tested, and
deterministic. Reuse instead of inventing a new chunk format.

### Write path

In `evm-compute-phase.cpp::run_evm_compute_phase`, after each existing
`state.store_receipt(...) / store_transaction(...) / store_logs(...)`
and `state.store_block(...)`:

```cpp
// Existing live-RAM write (kept for fast path on the same process):
state.store_receipt(tx_hash, std::move(receipt));

// New persistent write — same WriteBatch, no separate commit:
auto receipt_cell = encode_persisted_receipt(receipt);
g_evm_rpc_cache.put_receipt(tx_hash, std::move(receipt_cell));
```

`g_evm_rpc_cache` is a thin singleton holding the in-memory dicts
(`receipts_dict_`, `transactions_dict_`, `blocks_dict_`,
`logs_dict_`). At end-of-block, the collator hooks the cache's
serialized root cell into `cp.new_data` as `rpc_cache_root`. CellDb
commits the augmented root atomically with the rest of the block.

The dicts are HashmapE keyed by tx_hash / block_hash / block_number;
no balance augmentation is needed (we're not summing anything).

### Read path

`evm-rpc.cpp` handlers fall through to the persisted store on RAM
cache miss:

```cpp
auto receipt = global_evm_state().get_receipt_copy(tx_hash);
if (!receipt) {
    // RAM miss (e.g., after restart). Fall through to the
    // persisted cache — at most one CellDb cell read.
    auto persisted_cell = g_evm_rpc_cache.get_receipt_cell(tx_hash);
    if (persisted_cell.not_null()) {
        StoredReceipt rebuilt;
        if (decode_persisted_receipt(persisted_cell, rebuilt)) {
            receipt = std::move(rebuilt);
        }
    }
}
if (!receipt) return null_response;  // genuinely never seen
```

Same fall-through pattern for `get_transaction_copy`,
`get_block_copy`, `get_block_by_hash_copy`, and `get_logs`. RPC
handlers are unchanged in shape; the fallback is wrapped inside the
existing `EvmState::get_*_copy` methods so callers don't have to
know.

### Restart hydration

In `evm-init.cpp::populate_state_from_shard_accounts`, after the
existing `state_root` extraction, also extract `rpc_cache_root` from
the same `cp.new_data` cell. Hand it to `g_evm_rpc_cache` which
constructs lazy-loadable dict references (no bulk in-memory
hydration; entries are decoded on first read).

```cpp
td::Ref<vm::Cell> state_root, rpc_cache_root;
if (!decode_cp_new_data_v2(cp_new_data_cell, state_root, eth_state_root, rpc_cache_root))
    return 0;
g_evm_rpc_cache.attach(rpc_cache_root);   // O(1), parses the root cell only
```

Cost on startup: O(1). A 1M-receipt cache costs the same to attach
as a 100-receipt one — we only fetch entries on demand.

### Retention / pruning

Configurable via `ConfigParam` (the EVM-workchain config slot):

- `rpc_cache_retention_blocks` (default `0`, meaning "unlimited").
- When non-zero, at the end of every block N the writer also walks
  any entry whose `block_number < N - retention_blocks` and removes
  it from the dict. The pruned cells become unreachable from any
  future cell tree; CellDb's existing GC reclaims them.
- A `retention_floor` field in `EvmRpcCacheRoot` records the lowest
  block still indexed. RPC handlers consult this and return
  `null` / `not found` for queries below the floor (matching geth's
  "tx pruned" behavior).

Recommended default once Phase F lands and stabilizes: `0`
(unlimited) for testnet, `90 days × ~12s/block ≈ 648000 blocks`
for archive node operators, `~256 blocks` for "indexer not needed"
operators (parity with Ethereum's BLOCKHASH window).

## Acceptance test plan

`test/evm-workchain/proof-receipt-survives-restart.sh` — a 4th
proof script following the structure of
`proof-bytecode-survives-restart.sh`:

```
Stage 1: clean testnet
Stage 2: send a value transfer tx
Stage 3: wait for receipt, capture tx_hash + receipt JSON
Stage 4: assert eth_getTransactionReceipt(tx_hash) returns the receipt
         eth_getTransactionByHash(tx_hash) returns the tx
         eth_getBlockByHash(blockHash) returns the block
         eth_getLogs(filter for tx_hash's address) returns 1 log
Stage 5: systemctl restart tos-validator@1
Stage 6: wait for hydration
Stage 7: re-issue the same four queries; require byte-for-byte
         equality with the Stage 4 captures.

Exit codes:
  0 = receipt + tx + block + logs all survived
  1 = setup error
  2 = at least one survived check failed
```

Plus a unit test landing alongside the codec (Deliverable 2) that
proves the encoder round-trips byte-equal in isolation.

## References

- `crypto/block/evm-workchain/evm-state.h` — RAM containers and
  capacity constants
- `crypto/block/evm-workchain/evm-state.cpp` — current store/get
  implementation
- `crypto/block/evm-workchain/evm-init.cpp:139-238` —
  `populate_state_from_shard_accounts` and `decode_cp_new_data`
- `crypto/block/evm-workchain/evm-compute-phase.cpp:78-200` — the
  live store hooks where the persistent write would attach
- `crypto/block/evm-workchain/evm-cell-codec.h` — chunked-bytes
  encoder we reuse for `data` / `raw_rlp` / `return_data`
- `doc/evm-workchain-cell-native-state.md` — the cell-native state
  pattern this design follows
- `doc/evm-workchain-transaction-admission-and-single-executor.md` —
  the executor-account architecture that gives us a fixed carrier
  for `cp.new_data`
- `doc/evm-workchain-test-plan.md` Gate P row P-5 — the requirement
  this unblocks
