/*
    EVM Workchain — post-accept side-effects application.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm/core/post-accept.h"
#include "evm/core/post-accept-bridge.h"

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/transaction.h"
#include "evm/core/compute-phase.h"
#include "evm/core/init.h"
#include "evm/core/native-commitment.h"
#include "evm/core/transaction.h"
#include "evm/core/workchain.h"
#include "evm/rpc/cache-codec.h"
#include "evm/rpc/cache-db.h"
#include "evm/rpc/subscriptions.h"

#include "td/utils/logging.h"

#include "vm/cells/Cell.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/dict.h"
#include "vm/excno.hpp"

#include <ethash/keccak.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/transaction.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace evm_workchain {

namespace {

std::atomic<uint64_t> g_missing_side_effects{0};
std::atomic<uint64_t> g_replayed_side_effects{0};
std::atomic<uint64_t> g_replay_failures{0};
std::atomic<uint64_t> g_malformed_messages{0};
std::atomic<uint64_t> g_malformed_special_cell_messages{0};
std::atomic<uint64_t> g_strict_root_failures{0};
std::atomic<uint64_t> g_pruned_incomplete_markers{0};

constexpr size_t kMaxIncompleteIndexedTransactions = 10'000;
constexpr size_t kMaxIncompleteIndexedBlocks = 10'000;
constexpr uint64_t kIncompleteMarkerTtlSeconds = 24 * 60 * 60;

struct Bytes32Hasher {
    size_t operator()(const evmc::bytes32& v) const noexcept {
        uint64_t a = 0;
        uint64_t b = 0;
        std::memcpy(&a, v.bytes, sizeof(a));
        std::memcpy(&b, v.bytes + 24, sizeof(b));
        return static_cast<size_t>(a ^ (b + 0x9e3779b97f4a7c15ULL + (a << 6) + (a >> 2)));
    }
};

struct IncompleteIndex {
    std::mutex mu;
    std::unordered_set<evmc::bytes32, Bytes32Hasher> txs;
    std::deque<evmc::bytes32> order;
};

struct IncompleteBlockIndex {
    std::mutex mu;
    std::unordered_set<uint64_t> blocks;
    std::deque<uint64_t> order;
};

IncompleteIndex& g_incomplete_index() {
    static IncompleteIndex idx;
    return idx;
}

IncompleteBlockIndex& g_incomplete_block_index() {
    static IncompleteBlockIndex idx;
    return idx;
}

td::Bits256 bytes32_to_bits(const evmc::bytes32& value) {
    td::Bits256 bits;
    std::memcpy(bits.data(), value.bytes, 32);
    return bits;
}

void compact_incomplete_order_locked(IncompleteIndex& idx) {
    if (idx.order.size() <= kMaxIncompleteIndexedTransactions * 2) {
        return;
    }
    std::unordered_set<evmc::bytes32, Bytes32Hasher> seen;
    std::deque<evmc::bytes32> compacted;
    for (const auto& tx_hash : idx.order) {
        if (idx.txs.find(tx_hash) != idx.txs.end() &&
            seen.insert(tx_hash).second) {
            compacted.push_back(tx_hash);
        }
    }
    idx.order.swap(compacted);
}

void mark_rpc_indexing_incomplete_memory(const evmc::bytes32& tx_hash) noexcept {
    auto& idx = g_incomplete_index();
    std::lock_guard<std::mutex> lock(idx.mu);
    if (idx.txs.insert(tx_hash).second) {
        idx.order.push_back(tx_hash);
    }
    while (idx.txs.size() > kMaxIncompleteIndexedTransactions && !idx.order.empty()) {
        auto oldest = idx.order.front();
        idx.order.pop_front();
        idx.txs.erase(oldest);
    }
    compact_incomplete_order_locked(idx);
}

void mark_rpc_indexing_incomplete(const evmc::bytes32& tx_hash) noexcept {
    mark_rpc_indexing_incomplete_memory(tx_hash);
    if (auto* cache = evm_rpc_cache_db()) {
        auto status = cache->put_incomplete_transaction(bytes32_to_bits(tx_hash));
        if (status.is_error()) {
            LOG(WARNING) << "evm-rpc-cache: put incomplete tx marker failed: "
                         << status.message();
        }
    }
}

void clear_rpc_indexing_incomplete_memory(const evmc::bytes32& tx_hash) noexcept {
    auto& idx = g_incomplete_index();
    std::lock_guard<std::mutex> lock(idx.mu);
    if (idx.txs.erase(tx_hash) == 0) {
        return;
    }
    std::deque<evmc::bytes32> filtered;
    for (const auto& existing : idx.order) {
        if (existing != tx_hash) {
            filtered.push_back(existing);
        }
    }
    idx.order.swap(filtered);
    compact_incomplete_order_locked(idx);
}

void clear_rpc_indexing_incomplete(const evmc::bytes32& tx_hash) noexcept {
    clear_rpc_indexing_incomplete_memory(tx_hash);
    if (auto* cache = evm_rpc_cache_db()) {
        auto status = cache->delete_incomplete_transaction(bytes32_to_bits(tx_hash));
        if (status.is_error()) {
            LOG(WARNING) << "evm-rpc-cache: delete incomplete tx marker failed: "
                         << status.message();
        }
    }
}

uint64_t incomplete_indexed_transaction_count() noexcept {
    auto& idx = g_incomplete_index();
    std::lock_guard<std::mutex> lock(idx.mu);
    return idx.txs.size();
}

void clear_all_rpc_indexing_incomplete() noexcept {
    auto& idx = g_incomplete_index();
    std::lock_guard<std::mutex> lock(idx.mu);
    idx.txs.clear();
    idx.order.clear();
}

void compact_incomplete_block_order_locked(IncompleteBlockIndex& idx) {
    if (idx.order.size() <= kMaxIncompleteIndexedBlocks * 2) {
        return;
    }
    std::unordered_set<uint64_t> seen;
    std::deque<uint64_t> compacted;
    for (uint64_t block_number : idx.order) {
        if (idx.blocks.find(block_number) != idx.blocks.end() &&
            seen.insert(block_number).second) {
            compacted.push_back(block_number);
        }
    }
    idx.order.swap(compacted);
}

void mark_rpc_block_indexing_incomplete_memory(uint64_t block_number) noexcept {
    auto& idx = g_incomplete_block_index();
    std::lock_guard<std::mutex> lock(idx.mu);
    if (idx.blocks.insert(block_number).second) {
        idx.order.push_back(block_number);
    }
    while (idx.blocks.size() > kMaxIncompleteIndexedBlocks && !idx.order.empty()) {
        uint64_t oldest = idx.order.front();
        idx.order.pop_front();
        idx.blocks.erase(oldest);
    }
    compact_incomplete_block_order_locked(idx);
}

void mark_rpc_block_indexing_incomplete(uint64_t block_number) noexcept {
    mark_rpc_block_indexing_incomplete_memory(block_number);
    if (auto* cache = evm_rpc_cache_db()) {
        auto status = cache->put_incomplete_block(block_number);
        if (status.is_error()) {
            LOG(WARNING) << "evm-rpc-cache: put incomplete block marker failed: "
                         << status.message();
        }
    }
}

void clear_rpc_block_indexing_incomplete_memory(uint64_t block_number) noexcept {
    auto& idx = g_incomplete_block_index();
    std::lock_guard<std::mutex> lock(idx.mu);
    if (idx.blocks.erase(block_number) == 0) {
        return;
    }
    std::deque<uint64_t> filtered;
    for (uint64_t existing : idx.order) {
        if (existing != block_number) {
            filtered.push_back(existing);
        }
    }
    idx.order.swap(filtered);
    compact_incomplete_block_order_locked(idx);
}

void clear_rpc_block_indexing_incomplete(uint64_t block_number) noexcept {
    clear_rpc_block_indexing_incomplete_memory(block_number);
    if (auto* cache = evm_rpc_cache_db()) {
        auto status = cache->delete_incomplete_block(block_number);
        if (status.is_error()) {
            LOG(WARNING) << "evm-rpc-cache: delete incomplete block marker failed: "
                         << status.message();
        }
    }
}

uint64_t incomplete_indexed_block_count() noexcept {
    auto& idx = g_incomplete_block_index();
    std::lock_guard<std::mutex> lock(idx.mu);
    return idx.blocks.size();
}

void clear_all_rpc_block_indexing_incomplete() noexcept {
    auto& idx = g_incomplete_block_index();
    std::lock_guard<std::mutex> lock(idx.mu);
    idx.blocks.clear();
    idx.order.clear();
}

}  // namespace

void apply_block_side_effects(const EvmBlockSideEffects& fx) {
    auto& state = global_evm_state();

    // Round 87 MEDIUM fix: when this side-effect record carries a
    // block summary (fx.has_block) and the currently-stored block
    // at this height has a DIFFERENT hash, we are re-running the
    // post-accept path for a same-height rewrite.  The orthogonal
    // per-block logs index would otherwise have stale entries from
    // the prior rewrite — `store_block` erases the hash → number
    // mapping but `store_logs` (called BEFORE `store_block` in
    // this function) would simply append the new logs on top.
    // Drop the stale logs for that height before re-processing.
    // The block_logs_[N] vector is rebuilt as the rewrite's
    // subsequent txs land via store_logs, and `apply_stashed_side_
    // effects_for_messages` applies a block's txs in tx-index
    // order so the has_block tx is processed first.
    if (fx.has_block) {
        auto existing_block = state.get_block_copy(fx.block.number);
        // get_block_copy returns a default-constructed StoredBlock
        // (hash=0) when missing.  Treat the all-zero hash as "no
        // prior block at this height" rather than a rewrite.
        if (existing_block.hash != evmc::bytes32{} &&
            existing_block.hash != fx.block.hash) {
            state.reset_block_logs(fx.block.number);
        }
    }

    // Idempotency dedupe: a node that runs both collator and validator
    // roles for the same block reaches this seam twice (once per role).
    // Snapshot compute is pure, so the second apply would write
    // bitwise-identical records — but the receipt-insertion-order vector
    // is bounded and pushing dups would burn cache slots, and per-tx log
    // store appends per call. Bail early when this (block, tx_hash) is
    // already stored. Cheap (one hash-map lookup).
    //
    // Security hardening round 1 (M-02): the dedup key MUST include block context
    // (here: `block_number`). A bare-`tx_hash` key would silently keep
    // the first receipt observed even when the same Ethereum tx later
    // lands in a different accepted block (reorg / fork-import path) —
    // leaving RPC `eth_getTransactionReceipt` pointing at a no-longer-
    // canonical block. Compare existing.block_number against the
    // incoming receipt and fall through to overwrite on mismatch.
    // `store_receipt` / `store_transaction` are last-write-wins, so the
    // records refresh cleanly; per-tx logs from the prior block remain
    // attributed to that historical block_number — correct for RPC
    // consumers that explicitly query the old number.
    if (auto existing = state.get_receipt_copy(fx.tx_hash);
        existing.has_value() &&
        existing->block_number == fx.receipt.block_number) {
        // Round 87 MEDIUM fix: extend the dedup gate so a same-
        // height rewrite (same tx_hash, same block_number, but
        // different block hash) falls through to re-run the
        // block-installation path.  Pre-fix this branch returned
        // before `state.store_block(fx.block)` at line 379, so
        // `eth_getBlockByNumber(N)` kept serving the OLD hash and
        // `eth_getBlockByHash(new_hash)` returned null even though
        // consensus had accepted the rewrite.  When fx carries a
        // block (fx.has_block == true) compare against the
        // currently-stored block at that height; only skip when
        // the hash is identical.  Mid-block txs (no block context
        // in fx) keep the prior idempotent skip semantics.
        bool block_hash_matches = true;
        if (fx.has_block) {
            auto existing_block = state.get_block_copy(fx.block.number);
            // get_block_copy returns a default-constructed
            // StoredBlock (hash=0) when missing, which compares
            // unequal to any real fx.block.hash and correctly
            // forces the fall-through.
            block_hash_matches = (existing_block.hash == fx.block.hash);
        }
        if (block_hash_matches) {
            clear_rpc_indexing_incomplete(fx.tx_hash);
            return;
        }
        // Fall through: same-height rewrite needs the receipt /
        // transaction / block records refreshed under the new
        // hash so the round-86 erase-old-hash path runs.
    }
    // Round 92 MEDIUM fix: do NOT clear the tx incomplete marker
    // here.  Pre-fix the marker was cleared before
    // `cache->put_receipt` / `cache->put_transaction` ran, and a
    // disk-full / read-only failure left the durable cache without
    // the record while the marker was already gone — RPC
    // consumers then saw silent null instead of the contractual
    // -32010.  The marker is now cleared at the end of this
    // function ONLY when both writes succeeded (or no cache DB is
    // configured).
    bool tx_cache_writes_ok = true;

    // Per-block canonical-identity stamp. Every cache entry produced for
    // this block (receipt, transaction, logs, block-by-number,
    // block-by-hash) carries the same stamp so an RPC reader can decide
    // whether the cached record still matches the canonical chain at the
    // referenced (block_number, block_hash) — and skip stale entries after
    // a reorg without reaching back to consensus state. The receipt-only
    // sidecar slots (logs_commitment / receipts_commitment) let canonical-
    // state hydration recompute log/receipt summaries without re-reading
    // the full RAM containers.
    //
    // For mid-block txs (fx.has_block == false) the block summary fields
    // are filled from the receipt's block_number; block_hash and
    // native_state_commitment are unavailable until the block's first tx
    // lands, so they remain zero — readers gate on the matching block-
    // record stamp before consuming, which is the legacy behavior.
    EvmCacheRecordStamp stamp{};
    stamp.workchain_id = kEvmCacheWorkchainId;
    stamp.schema_version = kEvmCacheCodecSchemaVersion;
    stamp.block_seqno = static_cast<uint32_t>(
        fx.has_block ? fx.block.number : fx.receipt.block_number);
    stamp.block_hash = fx.has_block ? fx.block.hash : evmc::bytes32{};
    stamp.native_state_commitment =
        fx.has_block ? fx.block.state_root : evmc::bytes32{};
    stamp.logs_commitment =
        compute_native_log_list_commitment(fx.receipt.logs);
    stamp.receipts_commitment = compute_native_receipt_list_commitment(
        std::vector<StoredReceipt>{fx.receipt});

    // Receipt: store in RAM, persist to cache DB.
    {
        StoredReceipt r = fx.receipt;
        state.store_receipt(fx.tx_hash, std::move(r));
    }
    if (auto* cache = evm_rpc_cache_db()) {
        td::Bits256 tx_hash_bits = bytes32_to_bits(fx.tx_hash);
        auto cell = encode_persisted_receipt(fx.receipt, stamp);
        auto put_status = cache->put_receipt(tx_hash_bits, cell);
        if (put_status.is_error()) {
            LOG(WARNING) << "evm-rpc-cache: put_receipt failed for "
                         << tx_hash_bits.to_hex() << ": "
                         << put_status.message();
            tx_cache_writes_ok = false;
        }
    }

    // Transaction record.
    {
        StoredTransaction t = fx.transaction;
        state.store_transaction(fx.tx_hash, std::move(t));
    }
    if (auto* cache = evm_rpc_cache_db()) {
        td::Bits256 tx_hash_bits = bytes32_to_bits(fx.tx_hash);
        auto cell = encode_persisted_transaction(fx.transaction, stamp);
        auto put_status = cache->put_transaction(tx_hash_bits, cell);
        if (put_status.is_error()) {
            LOG(WARNING) << "evm-rpc-cache: put_transaction failed for "
                         << tx_hash_bits.to_hex() << ": "
                         << put_status.message();
            tx_cache_writes_ok = false;
        }
    }

    // Per-tx logs. block_number / tx_hash / tx_index are all in the
    // captured records; store_logs derives `log_index` from the existing
    // vector size, so a re-apply for the same tx would re-append. The
    // EvmState owns the dedup contract — see receipt store path; logs
    // re-apply is a no-op of equivalent records, not a true duplication.
    if (!fx.logs.empty()) {
        state.store_logs(fx.receipt.block_number, fx.tx_hash, fx.logs,
                         fx.receipt.tx_index);

        if (auto* cache = evm_rpc_cache_db()) {
            auto block_logs =
                state.get_logs_for_block_copy(fx.receipt.block_number);
            auto cell = encode_persisted_logs_for_block(block_logs, stamp);
            auto put_status =
                cache->put_logs_for_block(fx.receipt.block_number, cell);
            if (put_status.is_error()) {
                LOG(WARNING) << "evm-rpc-cache: put_logs_for_block failed for #"
                             << fx.receipt.block_number << ": "
                             << put_status.message();
                // Round 93 MEDIUM fix: gate the tx marker clear on
                // log persistence too.  Pre-fix a put_logs_for_block
                // failure left the per-block log batch absent (so
                // restart hydration produced `[]`), but the marker
                // was still cleared, and `eth_getLogs` /
                // `is_logs_for_block_canonical` treated the
                // empty cell as canonical — log loss masquerading
                // as "no logs in this block".
                tx_cache_writes_ok = false;
            }
        }
    }

    // Block summary (only the block's first tx carries this). The persisted
    // block cell already binds the block's TOS-native state commitment via
    // StoredBlock.state_root (see W1-A: compute_native_evm_state_commitment),
    // so a reader can detect a stale entry by comparing the cached value
    // against the current native commitment for that block_number.
    if (fx.has_block) {
        // Round 92 MEDIUM fix: defer the block-marker clear until
        // after cache writes succeed.  Pre-fix the marker was
        // cleared before any cache write ran; a disk-full /
        // read-only failure left the durable cache without the
        // block record while the marker was already gone —
        // restart hydration would then expose the partial state
        // as `silent null` / `[]` instead of the contractual
        // -32010.
        bool block_cache_writes_ok = true;
        state.store_block(fx.block);
        {
            std::unique_lock lock(state.mutex());
            state.state().canonize_block(fx.block.number, fx.block.hash);
        }

        if (auto* cache = evm_rpc_cache_db()) {
            auto cell = encode_persisted_block(fx.block);
            auto put_n_status =
                cache->put_block_by_number(fx.block.number, cell);
            if (put_n_status.is_error()) {
                LOG(WARNING) << "evm-rpc-cache: put_block_by_number failed for #"
                             << fx.block.number << ": "
                             << put_n_status.message();
                block_cache_writes_ok = false;
            }
            td::Bits256 hash_bits = bytes32_to_bits(fx.block.hash);
            auto put_h_status = cache->put_block_by_hash(hash_bits, cell);
            if (put_h_status.is_error()) {
                LOG(WARNING) << "evm-rpc-cache: put_block_by_hash failed for "
                             << hash_bits.to_hex() << ": "
                             << put_h_status.message();
                block_cache_writes_ok = false;
            }
        }
        // Round 92 MEDIUM fix: clear the block incomplete marker
        // ONLY when the block cache writes succeeded (or no cache
        // DB is configured).  Otherwise leave the marker in place
        // so subsequent reads surface -32010.
        //
        // Round 95 HIGH fix: also leave the marker in place when
        // ANY earlier tx in the same block was marked incomplete.
        // The has_block tx may be the last in the block's
        // apply-side-effects sequence, so an earlier failed tx
        // already raised the block marker; clearing it now would
        // erase the partial-commit signal even though the block's
        // tx index is incomplete.  Sweep blk.transaction_hashes
        // (already populated when fx.has_block) and keep the
        // marker if any tx is still marked incomplete.
        bool any_prior_tx_incomplete = false;
        if (block_cache_writes_ok) {
            for (const auto& th : fx.block.transaction_hashes) {
                if (th == fx.tx_hash) continue;
                if (is_evm_rpc_indexing_incomplete(th)) {
                    any_prior_tx_incomplete = true;
                    break;
                }
            }
        }
        if (block_cache_writes_ok && !any_prior_tx_incomplete) {
            clear_rpc_block_indexing_incomplete(fx.block.number);
        } else {
            // Round 93 MEDIUM fix: when there was no pre-existing
            // block marker (the normal post-accept happy path),
            // failing cache writes left no marker for subsequent
            // reads to surface -32010 with.  Create one explicitly
            // so the contractual guarantee survives a partial
            // commit.
            mark_rpc_block_indexing_incomplete(fx.block.number);
        }

        // Round 95 MEDIUM fix: skip subscription notifications
        // when the block carries an incomplete marker (either
        // pre-existing or newly created above).  Pre-fix
        // notify_new_head / notify_logs fired even on partial
        // commits, so subscription consumers received header /
        // log events for a block whose ordinary RPC returns
        // -32010.  Drop the deliveries so live subscribers see
        // the same canonicality contract as poll-based RPC.
        const bool block_index_complete =
            block_cache_writes_ok && !any_prior_tx_incomplete &&
            tx_cache_writes_ok;
        if (block_index_complete) {
            auto& sub_mgr = global_subscription_manager();
            sub_mgr.notify_new_head(fx.block);
            sub_mgr.notify_new_pending_transaction(fx.tx_hash);
            if (!fx.logs.empty()) {
                sub_mgr.notify_logs(fx.block.number, fx.tx_hash, fx.logs,
                                    fx.block.hash);
            }
        }
    } else if (!fx.logs.empty() && tx_cache_writes_ok) {
        // Round 95 MEDIUM fix: same-canonicality gate for mid-
        // block tx subscription notifications.  Skip the log
        // delivery when this tx's cache writes failed — the
        // logs index for the block is partial and ordinary RPC
        // will surface -32010.
        // Mid-block tx with logs but no block summary still notifies
        // log subscribers; mirrors legacy behaviour where
        // notify_logs fired on every store_logs invocation.
        auto& sub_mgr = global_subscription_manager();
        sub_mgr.notify_logs(fx.receipt.block_number, fx.tx_hash, fx.logs,
                            evmc::bytes32{});
    }
    // Round 92 MEDIUM fix: clear the tx incomplete marker only after
    // tx cache writes succeeded.  When writes failed the marker
    // stays so RPC consumers see -32010 instead of a stale partial
    // record on the next read or after restart.
    //
    // Round 93 MEDIUM fix: when there was no pre-existing tx
    // marker (the normal happy path) and cache writes failed,
    // create a fresh marker so the -32010 contract survives.
    if (tx_cache_writes_ok) {
        clear_rpc_indexing_incomplete(fx.tx_hash);
    } else {
        mark_rpc_indexing_incomplete(fx.tx_hash);
        // Round 94 HIGH fix: a tx/receipt/log cache failure leaves
        // the per-block index partial too — by-block handlers
        // (eth_getBlockByNumber, eth_getBlockReceipts, eth_getLogs,
        // by-index tx lookups) need a block marker to surface
        // -32010 instead of serving the gappy block.  Pre-fix only
        // the per-tx marker was set, so the round-93 happy-path
        // block-marker checks couldn't fire for this case.
        mark_rpc_block_indexing_incomplete(fx.receipt.block_number);
    }
}

// ---------------------------------------------------------------------------
// Deferred-apply queue.
// ---------------------------------------------------------------------------

namespace {

constexpr size_t kMaxStashedSideEffects = 4096;
constexpr size_t kMaxPendingSideEffects = 8192;
constexpr uint64_t kPendingSideEffectsKeepBlocks = 8;

// Audit #4 (2026-04-26): bind tx_hash to candidate block context. A tx hash
// alone is not enough because rejected candidates may contain the same EVM tx
// under different timestamp / rand seed / parent context.
struct EvmStashKey {
    uint64_t seqno{};
    uint64_t timestamp{};
    evmc::bytes32 rand_seed{};
    evmc::bytes32 parent_hash{};
    evmc::bytes32 v{};
    bool operator==(const EvmStashKey& o) const noexcept {
        return seqno == o.seqno &&
               timestamp == o.timestamp &&
               std::memcmp(rand_seed.bytes, o.rand_seed.bytes, 32) == 0 &&
               std::memcmp(parent_hash.bytes, o.parent_hash.bytes, 32) == 0 &&
               std::memcmp(v.bytes, o.v.bytes, 32) == 0;
    }
};

struct EvmStashKeyHasher {
    size_t operator()(const EvmStashKey& k) const noexcept {
        size_t h = 0;
        std::memcpy(&h, k.v.bytes, sizeof(h));
        auto mix = [&h](uint64_t x) {
            h ^= (x + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2));
        };
        mix(k.seqno);
        mix(k.timestamp);
        uint64_t r0 = 0;
        uint64_t p0 = 0;
        std::memcpy(&r0, k.rand_seed.bytes, sizeof(r0));
        std::memcpy(&p0, k.parent_hash.bytes, sizeof(p0));
        mix(r0);
        mix(p0);
        return h;
    }
};

struct StashedEntry {
    EvmBlockSideEffects fx;
    uint64_t inserted_at_us{};
};

struct IndexedSideEffects {
    uint32_t tx_index{};
    EvmBlockSideEffects fx;
};

struct StashedCache {
    std::mutex mu;
    std::unordered_map<EvmStashKey, StashedEntry, EvmStashKeyHasher> map;

    static uint64_t now_us() noexcept {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    void evict_oldest_locked() {
        if (map.empty()) return;
        auto oldest = map.begin();
        uint64_t oldest_t = oldest->second.inserted_at_us;
        for (auto it = std::next(map.begin()); it != map.end(); ++it) {
            if (it->second.inserted_at_us < oldest_t) {
                oldest = it;
                oldest_t = it->second.inserted_at_us;
            }
        }
        map.erase(oldest);
    }
};

StashedCache& g_stashed_cache() {
    static StashedCache c;
    return c;
}

EvmStashKey make_stash_key(uint64_t block_seqno,
                           uint64_t timestamp,
                           const uint8_t rand_seed[32],
                           const uint8_t parent_block_hash[32],
                           const evmc::bytes32& tx_hash) {
    EvmStashKey key{};
    key.seqno = block_seqno;
    key.timestamp = timestamp;
    std::memcpy(key.rand_seed.bytes, rand_seed, 32);
    std::memcpy(key.parent_hash.bytes, parent_block_hash, 32);
    key.v = tx_hash;
    return key;
}

td::Ref<vm::Cell> encode_pending_side_effects(const EvmBlockSideEffects& fx) {
    constexpr uint32_t kPendingSideEffectsMagic = 0x46585331;  // "FXS1"
    // Build a stamp from the side-effects record. The pending blob is a
    // private restart-recovery store keyed by (block_seqno, timestamp,
    // rand_seed, parent_hash, tx_hash); freshness is enforced by the key
    // match in take_pending_side_effects, not the stamp. Populate the
    // sidecar commitments so that when the recovered record gets re-published
    // through apply_block_side_effects, the encoder seeded by that path will
    // recompute identical stamps (deterministic).
    EvmCacheRecordStamp stamp{};
    stamp.workchain_id = kEvmCacheWorkchainId;
    stamp.schema_version = kEvmCacheCodecSchemaVersion;
    stamp.block_seqno = static_cast<uint32_t>(
        fx.has_block ? fx.block.number : fx.receipt.block_number);
    stamp.block_hash = fx.has_block ? fx.block.hash : evmc::bytes32{};
    stamp.native_state_commitment =
        fx.has_block ? fx.block.state_root : evmc::bytes32{};
    stamp.logs_commitment =
        compute_native_log_list_commitment(fx.receipt.logs);
    stamp.receipts_commitment = compute_native_receipt_list_commitment(
        std::vector<StoredReceipt>{fx.receipt});

    vm::CellBuilder cb;
    cb.store_long(kPendingSideEffectsMagic, 32);
    cb.store_bytes(fx.tx_hash.bytes, 32);
    cb.store_bytes(fx.rand_seed.bytes, 32);
    cb.store_long(fx.has_block ? 1 : 0, 1);
    cb.store_ref(encode_persisted_receipt(fx.receipt, stamp));
    cb.store_ref(encode_persisted_transaction(fx.transaction, stamp));
    if (fx.has_block) {
        cb.store_ref(encode_persisted_block(fx.block));
    }
    return cb.finalize();
}

bool decode_pending_side_effects(td::Ref<vm::Cell> cell, EvmBlockSideEffects& out) {
    constexpr uint32_t kPendingSideEffectsMagic = 0x46585331;  // "FXS1"
    out = {};
    try {
        if (cell.is_null()) return false;
        bool special = false;
        auto cs = vm::load_cell_slice_special(cell, special);
        if (special) return false;
        if (cs.size() < 32 + 256 + 256 + 1) return false;
        auto magic = cs.fetch_ulong(32);
        if (magic != kPendingSideEffectsMagic) return false;
        if (!cs.fetch_bytes(out.tx_hash.bytes, 32)) return false;
        if (!cs.fetch_bytes(out.rand_seed.bytes, 32)) return false;
        out.has_block = cs.fetch_ulong(1) != 0;
        if (cs.size() != 0) return false;
        const unsigned expected_refs = out.has_block ? 3 : 2;
        if (cs.size_refs() != expected_refs) return false;
        // Stamps are recomputed on re-publish, so we don't enforce them here.
        EvmCacheRecordStamp receipt_stamp;
        EvmCacheRecordStamp tx_stamp;
        EvmCacheRecordStamp block_stamp;
        (void)receipt_stamp;
        (void)tx_stamp;
        (void)block_stamp;
        if (!decode_persisted_receipt(cs.fetch_ref(), out.receipt, receipt_stamp)) return false;
        if (!decode_persisted_transaction(cs.fetch_ref(), out.transaction, tx_stamp)) return false;
        out.logs = out.receipt.logs;
        if (out.has_block &&
            !decode_persisted_block(cs.fetch_ref(), out.block, block_stamp)) {
            return false;
        }
        return true;
    } catch (vm::VmError&) {
        return false;
    } catch (vm::VmVirtError&) {
        return false;
    } catch (std::exception&) {
        return false;
    } catch (...) {
        return false;
    }
}

void persist_pending_side_effects(uint64_t block_seqno,
                                  uint64_t timestamp,
                                  const EvmStashKey& key,
                                  const EvmBlockSideEffects& fx) {
    auto* cache = evm_rpc_cache_db();
    if (!cache) return;
    const uint64_t keep_from =
        block_seqno > kPendingSideEffectsKeepBlocks
            ? block_seqno - kPendingSideEffectsKeepBlocks
            : 0;
    auto prune_status = cache->prune_pending_side_effects(
        keep_from, kMaxPendingSideEffects - 1);
    if (prune_status.is_error()) {
        LOG(WARNING) << "evm-rpc-cache: prune_pending_side_effects failed: "
                     << prune_status.message();
    }
    auto cell = encode_pending_side_effects(fx);
    auto status = cache->put_pending_side_effects(
        block_seqno, timestamp, bytes32_to_bits(key.rand_seed),
        bytes32_to_bits(key.parent_hash), bytes32_to_bits(key.v), cell);
    if (status.is_error()) {
        LOG(WARNING) << "evm-rpc-cache: put_pending_side_effects failed for tx "
                     << bytes32_to_bits(key.v).to_hex() << ": "
                     << status.message();
    }
}

void delete_pending_side_effects(uint64_t block_seqno,
                                 uint64_t timestamp,
                                 const EvmStashKey& key) {
    auto* cache = evm_rpc_cache_db();
    if (!cache) return;
    auto status = cache->delete_pending_side_effects(
        block_seqno, timestamp, bytes32_to_bits(key.rand_seed),
        bytes32_to_bits(key.parent_hash), bytes32_to_bits(key.v));
    if (status.is_error()) {
        LOG(WARNING) << "evm-rpc-cache: delete_pending_side_effects failed for tx "
                     << bytes32_to_bits(key.v).to_hex() << ": "
                     << status.message();
    }
}

std::optional<EvmBlockSideEffects> load_pending_side_effects(
    uint64_t block_seqno,
    uint64_t timestamp,
    const EvmStashKey& key) {
    auto* cache = evm_rpc_cache_db();
    if (!cache) return std::nullopt;
    auto cell_r = cache->get_pending_side_effects(
        block_seqno, timestamp, bytes32_to_bits(key.rand_seed),
        bytes32_to_bits(key.parent_hash), bytes32_to_bits(key.v));
    if (cell_r.is_error()) {
        LOG(WARNING) << "evm-rpc-cache: get_pending_side_effects failed for tx "
                     << bytes32_to_bits(key.v).to_hex() << ": "
                     << cell_r.error().message();
        return std::nullopt;
    }
    auto cell = cell_r.move_as_ok();
    if (cell.is_null()) return std::nullopt;
    EvmBlockSideEffects fx;
    if (!decode_pending_side_effects(cell, fx)) {
        LOG(WARNING) << "evm-rpc-cache: corrupt pending side effects for tx "
                     << bytes32_to_bits(key.v).to_hex();
        delete_pending_side_effects(block_seqno, timestamp, key);
        return std::nullopt;
    }
    delete_pending_side_effects(block_seqno, timestamp, key);
    return fx;
}

void add_to_bloom(uint8_t bloom[256], const uint8_t* data, size_t len) {
    auto h = ethash::keccak256(data, len);
    for (int i = 0; i < 6; i += 2) {
        uint16_t bit = (static_cast<uint16_t>(h.bytes[i]) << 8 | h.bytes[i + 1]) & 0x7FF;
        bloom[bit / 8] |= (1 << (bit % 8));
    }
}

void recompute_block_hash(StoredBlock& block) {
    // The block_hash is the keccak of the silkworm BlockHeader RLP. The
    // header carries 32-byte fields named state_root / transactions_root /
    // receipts_root for Ethereum JSON-RPC wire compatibility — but the
    // values are TOS-native commitments (see W1-A native-commitment.h), not
    // Ethereum MPT roots. The hash function does not care: it just RLPs
    // 32-byte values, so the computed block_hash is a deterministic,
    // collision-resistant identity for the block.
    silkworm::BlockHeader hdr{};
    std::memcpy(hdr.parent_hash.bytes, block.parent_hash.bytes, 32);
    hdr.ommers_hash = silkworm::kEmptyListHash;
    std::memcpy(hdr.state_root.bytes, block.state_root.bytes, 32);
    std::memcpy(hdr.transactions_root.bytes, block.transactions_root.bytes, 32);
    std::memcpy(hdr.receipts_root.bytes, block.receipts_root.bytes, 32);
    std::memcpy(hdr.logs_bloom.data(), block.logs_bloom, 256);
    hdr.difficulty = 0;
    hdr.number = block.number;
    hdr.gas_limit = block.gas_limit;
    hdr.gas_used = block.gas_used;
    hdr.timestamp = block.timestamp;
    const std::string client_id = "evm-workchain/0.1.0";
    hdr.extra_data.assign(client_id.begin(), client_id.end());
    hdr.base_fee_per_gas = block.base_fee_per_gas;
    hdr.withdrawals_root = silkworm::kEmptyRoot;
    hdr.blob_gas_used = 0;
    hdr.excess_blob_gas = 0;
    hdr.parent_beacon_block_root = evmc::bytes32{};
    {
        evmc::bytes32 rh{};
        static const uint8_t kSha256Empty[32] = {
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
        std::memcpy(rh.bytes, kSha256Empty, 32);
        hdr.requests_hash = rh;
    }
    const auto eth_hash = hdr.hash();
    std::memcpy(block.hash.bytes, eth_hash.bytes, 32);
}

bool finalize_block_side_effects(std::vector<IndexedSideEffects>& fxs,
                                 uint64_t accepted_block_seqno,
                                 uint64_t accepted_timestamp) {
    if (fxs.empty()) return true;

    std::vector<StoredTransaction> txs;
    std::vector<StoredReceipt> receipts;
    txs.reserve(fxs.size());
    receipts.reserve(fxs.size());

    StoredBlock block = fxs.back().fx.block;
    block.number = accepted_block_seqno;
    block.timestamp = accepted_timestamp;
    block.state_root = fxs.back().fx.block.state_root;
    block.transaction_hashes.clear();
    block.gas_used = 0;
    std::memset(block.logs_bloom, 0, sizeof(block.logs_bloom));

    for (auto& indexed : fxs) {
        auto& fx = indexed.fx;
        fx.receipt.block_number = accepted_block_seqno;
        fx.receipt.tx_index = indexed.tx_index;
        fx.transaction.block_number = accepted_block_seqno;
        fx.transaction.tx_index = indexed.tx_index;

        if (fx.receipt.gas_used > block.gas_limit ||
            block.gas_used > block.gas_limit - fx.receipt.gas_used) {
            g_strict_root_failures.fetch_add(1, std::memory_order_relaxed);
            for (const auto& pending : fxs) {
                mark_rpc_indexing_incomplete(pending.fx.tx_hash);
            }
            mark_rpc_block_indexing_incomplete(accepted_block_seqno);
            LOG(WARNING) << "evm post-accept: refusing block #"
                         << accepted_block_seqno
                         << " side effects because gas_used would exceed "
                         << "block gas limit or overflow (current="
                         << block.gas_used << ", tx="
                         << fx.receipt.gas_used << ", limit="
                         << block.gas_limit << ")";
            fxs.clear();
            return false;
        }
        block.gas_used += fx.receipt.gas_used;
        fx.receipt.cumulative_gas_used = block.gas_used;

        txs.push_back(fx.transaction);
        receipts.push_back(fx.receipt);
        block.transaction_hashes.push_back(fx.tx_hash);

        for (const auto& log : fx.logs) {
            add_to_bloom(block.logs_bloom, log.address.bytes, 20);
            for (const auto& topic : log.topics) {
                add_to_bloom(block.logs_bloom, topic.bytes, 32);
            }
        }
        fx.has_block = false;
    }

    // Per plan §9: a canonical-rebuildable cache demands raw_rlp on every
    // transaction. The native commitment can technically commit empty
    // records, but doing so would leave receipts/logs un-rebuildable from
    // canonical state if the cache were wiped. Withhold the block's RPC
    // index when raw_rlp is missing so that property is preserved.
    for (const auto& tx : txs) {
        if (tx.raw_rlp.empty()) {
            g_strict_root_failures.fetch_add(1, std::memory_order_relaxed);
            for (const auto& indexed : fxs) {
                mark_rpc_indexing_incomplete(indexed.fx.tx_hash);
            }
            mark_rpc_block_indexing_incomplete(accepted_block_seqno);
            LOG(WARNING) << "evm post-accept: cannot finalize block #"
                         << accepted_block_seqno
                         << " because at least one accepted tx lacks raw signed RLP";
            fxs.clear();
            return false;
        }
    }
    // StoredBlock.{transactions_root,receipts_root} carry TOS-native list
    // commitments (keccak over a length-prefixed canonical record stream),
    // not Ethereum MPT roots. The field name is preserved so the wire
    // format and Ethereum JSON-RPC surface stay byte-stable.
    block.transactions_root = compute_native_tx_list_commitment(txs);
    block.receipts_root = compute_native_receipt_list_commitment(receipts);
    recompute_block_hash(block);

    fxs.back().fx.has_block = true;
    fxs.back().fx.block = block;
    return true;
}

}  // namespace

void stash_side_effects(uint64_t block_seqno,
                        uint64_t timestamp,
                        const uint8_t rand_seed[32],
                        const uint8_t parent_block_hash[32],
                        const evmc::bytes32& tx_hash,
                        EvmBlockSideEffects fx) {
    EvmStashKey key = make_stash_key(block_seqno, timestamp, rand_seed,
                                     parent_block_hash, tx_hash);
    persist_pending_side_effects(block_seqno, timestamp, key, fx);

    auto& c = g_stashed_cache();
    std::lock_guard<std::mutex> lock(c.mu);
    auto it = c.map.find(key);
    if (it != c.map.end()) {
        // Same candidate context re-run. Snapshot compute is deterministic
        // for identical inputs; replacement refreshes eviction age.
        it->second.fx = std::move(fx);
        it->second.inserted_at_us = StashedCache::now_us();
        return;
    }
    if (c.map.size() >= kMaxStashedSideEffects) {
        c.evict_oldest_locked();
    }
    c.map.emplace(key, StashedEntry{std::move(fx), StashedCache::now_us()});
}

std::optional<EvmBlockSideEffects>
take_side_effects(uint64_t block_seqno,
                  uint64_t timestamp,
                  const uint8_t rand_seed[32],
                  const uint8_t parent_block_hash[32],
                  const evmc::bytes32& tx_hash) {
    auto key = make_stash_key(block_seqno, timestamp, rand_seed,
                              parent_block_hash, tx_hash);
    std::optional<EvmBlockSideEffects> in_memory;
    {
        auto& c = g_stashed_cache();
        std::lock_guard<std::mutex> lock(c.mu);
        auto it = c.map.find(key);
        if (it != c.map.end()) {
            in_memory = std::move(it->second.fx);
            c.map.erase(it);
        }
    }
    if (in_memory) {
        delete_pending_side_effects(block_seqno, timestamp, key);
        return in_memory;
    }
    return load_pending_side_effects(block_seqno, timestamp, key);
}

size_t stashed_side_effects_count() noexcept {
    auto& c = g_stashed_cache();
    std::lock_guard<std::mutex> lock(c.mu);
    return c.map.size();
}

void clear_stashed_side_effects_for_tests() noexcept {
    auto& c = g_stashed_cache();
    std::lock_guard<std::mutex> lock(c.mu);
    c.map.clear();
}

EvmPostAcceptHealth evm_post_accept_health() noexcept {
    return EvmPostAcceptHealth{
        .missing_side_effects = g_missing_side_effects.load(std::memory_order_relaxed),
        .replayed_side_effects = g_replayed_side_effects.load(std::memory_order_relaxed),
        .replay_failures = g_replay_failures.load(std::memory_order_relaxed),
        .malformed_messages = g_malformed_messages.load(std::memory_order_relaxed),
        .malformed_special_cell_messages = g_malformed_special_cell_messages.load(std::memory_order_relaxed),
        .strict_root_failures = g_strict_root_failures.load(std::memory_order_relaxed),
        .incomplete_indexed_transactions = incomplete_indexed_transaction_count(),
        .incomplete_indexed_blocks = incomplete_indexed_block_count(),
        .pruned_incomplete_markers = g_pruned_incomplete_markers.load(std::memory_order_relaxed),
    };
}

void reset_evm_post_accept_health_for_tests() noexcept {
    g_missing_side_effects.store(0, std::memory_order_relaxed);
    g_replayed_side_effects.store(0, std::memory_order_relaxed);
    g_replay_failures.store(0, std::memory_order_relaxed);
    g_malformed_messages.store(0, std::memory_order_relaxed);
    g_malformed_special_cell_messages.store(0, std::memory_order_relaxed);
    g_strict_root_failures.store(0, std::memory_order_relaxed);
    g_pruned_incomplete_markers.store(0, std::memory_order_relaxed);
    clear_all_rpc_indexing_incomplete();
    clear_all_rpc_block_indexing_incomplete();
}

void hydrate_evm_rpc_incomplete_indexes_from_cache() noexcept {
    auto* cache = evm_rpc_cache_db();
    if (!cache) {
        return;
    }

    auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    IncompleteMarkerPruneStats prune_stats;
    auto prune_status = cache->prune_incomplete_markers(
        now, kIncompleteMarkerTtlSeconds,
        kMaxIncompleteIndexedTransactions,
        kMaxIncompleteIndexedBlocks,
        &prune_stats);
    if (prune_status.is_error()) {
        LOG(WARNING) << "evm-rpc-cache: incomplete marker prune failed: "
                     << prune_status.message();
    } else {
        uint64_t pruned =
            prune_stats.expired_transactions +
            prune_stats.overflow_transactions +
            prune_stats.expired_blocks +
            prune_stats.overflow_blocks;
        if (pruned != 0) {
            g_pruned_incomplete_markers.fetch_add(pruned, std::memory_order_relaxed);
            LOG(WARNING) << "evm-rpc-cache: pruned " << pruned
                         << " stale/overflow incomplete marker(s)";
        }
    }

    size_t txs = 0;
    auto tx_status = cache->for_each_incomplete_transaction(
        [&txs](const td::Bits256& tx_hash_bits) -> td::Status {
            evmc::bytes32 tx_hash{};
            std::memcpy(tx_hash.bytes, tx_hash_bits.data(), 32);
            mark_rpc_indexing_incomplete_memory(tx_hash);
            ++txs;
            return td::Status::OK();
        });
    if (tx_status.is_error()) {
        LOG(WARNING) << "evm-rpc-cache: incomplete tx marker hydration failed: "
                     << tx_status.message();
    }

    size_t blocks = 0;
    auto block_status = cache->for_each_incomplete_block(
        [&blocks](uint64_t block_number) -> td::Status {
            mark_rpc_block_indexing_incomplete_memory(block_number);
            ++blocks;
            return td::Status::OK();
        });
    if (block_status.is_error()) {
        LOG(WARNING) << "evm-rpc-cache: incomplete block marker hydration failed: "
                     << block_status.message();
    }

    LOG(WARNING) << "evm-workchain: hydrated " << txs
                 << " incomplete tx marker(s) and " << blocks
                 << " incomplete block marker(s) from rpc cache db";
}

bool is_evm_rpc_indexing_incomplete(const evmc::bytes32& tx_hash) noexcept {
    auto& idx = g_incomplete_index();
    {
        std::lock_guard<std::mutex> lock(idx.mu);
        if (idx.txs.find(tx_hash) != idx.txs.end()) {
            return true;
        }
    }
    if (auto* cache = evm_rpc_cache_db()) {
        auto r = cache->has_incomplete_transaction(bytes32_to_bits(tx_hash));
        if (r.is_ok() && r.ok()) {
            mark_rpc_indexing_incomplete_memory(tx_hash);
            return true;
        }
        if (r.is_error()) {
            LOG(WARNING) << "evm-rpc-cache: has incomplete tx marker failed: "
                         << r.error().message();
        }
    }
    return false;
}

bool is_evm_rpc_block_indexing_incomplete(uint64_t block_number) noexcept {
    auto& idx = g_incomplete_block_index();
    {
        std::lock_guard<std::mutex> lock(idx.mu);
        if (idx.blocks.find(block_number) != idx.blocks.end()) {
            return true;
        }
    }
    if (auto* cache = evm_rpc_cache_db()) {
        auto r = cache->has_incomplete_block(block_number);
        if (r.is_ok() && r.ok()) {
            mark_rpc_block_indexing_incomplete_memory(block_number);
            return true;
        }
        if (r.is_error()) {
            LOG(WARNING) << "evm-rpc-cache: has incomplete block marker failed: "
                         << r.error().message();
        }
    }
    return false;
}

RpcCacheRebuildStats rebuild_rpc_cache_from_global_state(
    uint64_t from_block,
    uint64_t to_block) noexcept {
    RpcCacheRebuildStats stats;
    stats.from_block = from_block;
    stats.to_block = to_block;

    auto* cache = evm_rpc_cache_db();
    if (!cache) {
        stats.errors = 1;
        stats.last_error = "rpc cache db is not open";
        return stats;
    }
    if (to_block < from_block) {
        stats.errors = 1;
        stats.last_error = "invalid block range";
        return stats;
    }

    auto& state = global_evm_state();
    for (uint64_t block_number = from_block; block_number <= to_block;
         ++block_number) {
        if (!state.has_block(block_number)) {
            if (block_number == UINT64_MAX) break;
            continue;
        }
        auto block = state.get_block_copy(block_number);
        ++stats.blocks_seen;

        std::vector<StoredTransaction> txs;
        std::vector<StoredReceipt> receipts;
        txs.reserve(block.transaction_hashes.size());
        receipts.reserve(block.transaction_hashes.size());

        bool block_ok = true;
        for (const auto& tx_hash : block.transaction_hashes) {
            auto tx = state.get_transaction_copy(tx_hash);
            if (!tx || tx->raw_rlp.empty()) {
                block_ok = false;
                ++stats.errors;
                stats.last_error = "missing transaction or raw signed RLP";
                break;
            }
            auto receipt = state.get_receipt_copy(tx_hash);
            if (!receipt) {
                block_ok = false;
                ++stats.errors;
                stats.last_error = "missing receipt";
                break;
            }
            txs.push_back(std::move(*tx));
            receipts.push_back(std::move(*receipt));
        }
        if (!block_ok) {
            if (block_number == UINT64_MAX) break;
            continue;
        }

        // Both fields carry TOS-native list commitments; recompute and
        // compare to detect a corrupt or stale stored block summary before
        // we publish derived records.
        bool tx_rlp_ok = true;
        for (const auto& tx : txs) {
            if (tx.raw_rlp.empty()) { tx_rlp_ok = false; break; }
        }
        if (!tx_rlp_ok) {
            ++stats.errors;
            stats.last_error = "missing raw signed RLP for transactions root rebuild";
            if (block_number == UINT64_MAX) break;
            continue;
        }
        auto tx_root = compute_native_tx_list_commitment(txs);
        if (tx_root != block.transactions_root) {
            ++stats.errors;
            stats.last_error = "transactionsRoot mismatch";
            if (block_number == UINT64_MAX) break;
            continue;
        }
        auto receipts_root = compute_native_receipt_list_commitment(receipts);
        if (receipts_root != block.receipts_root) {
            ++stats.errors;
            stats.last_error = "receiptsRoot mismatch";
            if (block_number == UINT64_MAX) break;
            continue;
        }

        // Per-block stamp shared by every record written below. Receipt-
        // record stamps in apply_block_side_effects bind logs/receipts
        // commitments to the single tx; in the rebuild path we re-publish
        // the canonical block-level commitments so RPC readers can re-verify
        // the cached records against the current canonical chain. The
        // per-record receipt-only sidecar slots (logs/receipts commitments
        // for a single tx) are recomputed below per-tx so they match the
        // values the live apply path would have produced.
        EvmCacheRecordStamp block_stamp{};
        block_stamp.workchain_id = kEvmCacheWorkchainId;
        block_stamp.schema_version = kEvmCacheCodecSchemaVersion;
        block_stamp.block_seqno = static_cast<uint32_t>(block.number);
        block_stamp.block_hash = block.hash;
        block_stamp.native_state_commitment = block.state_root;

        for (size_t i = 0; i < block.transaction_hashes.size(); ++i) {
            auto tx_hash_bits = bytes32_to_bits(block.transaction_hashes[i]);

            EvmCacheRecordStamp record_stamp = block_stamp;
            record_stamp.logs_commitment =
                compute_native_log_list_commitment(receipts[i].logs);
            record_stamp.receipts_commitment =
                compute_native_receipt_list_commitment(
                    std::vector<StoredReceipt>{receipts[i]});

            auto tx_status = cache->put_transaction(
                tx_hash_bits,
                encode_persisted_transaction(txs[i], record_stamp));
            if (tx_status.is_error()) {
                ++stats.errors;
                stats.last_error = tx_status.message().str();
                block_ok = false;
                break;
            }
            ++stats.transactions_written;

            auto receipt_status = cache->put_receipt(
                tx_hash_bits,
                encode_persisted_receipt(receipts[i], record_stamp));
            if (receipt_status.is_error()) {
                ++stats.errors;
                stats.last_error = receipt_status.message().str();
                block_ok = false;
                break;
            }
            ++stats.receipts_written;
        }
        if (!block_ok) {
            if (block_number == UINT64_MAX) break;
            continue;
        }

        auto block_cell = encode_persisted_block(block);
        auto block_n_status =
            cache->put_block_by_number(block.number, block_cell);
        if (block_n_status.is_error()) {
            ++stats.errors;
            stats.last_error = block_n_status.message().str();
            if (block_number == UINT64_MAX) break;
            continue;
        }
        auto block_h_status =
            cache->put_block_by_hash(bytes32_to_bits(block.hash), block_cell);
        if (block_h_status.is_error()) {
            ++stats.errors;
            stats.last_error = block_h_status.message().str();
            if (block_number == UINT64_MAX) break;
            continue;
        }
        ++stats.blocks_written;

        auto logs = state.get_logs_for_block_copy(block.number);
        auto logs_status = cache->put_logs_for_block(
            block.number,
            encode_persisted_logs_for_block(logs, block_stamp));
        if (logs_status.is_error()) {
            ++stats.errors;
            stats.last_error = logs_status.message().str();
            if (block_number == UINT64_MAX) break;
            continue;
        }
        ++stats.log_blocks_written;

        // Round 94 MEDIUM fix: clear durable incomplete markers
        // for the repaired block + its txs.  Pre-fix the rebuild
        // path rewrote every cache record but never cleared the
        // markers post-write, so a previously-failed cache write
        // left the block / tx returning -32010 even after a
        // successful rebuild.  Clear only after every record
        // for this block succeeded.
        clear_rpc_block_indexing_incomplete(block.number);
        for (const auto& tx_hash : block.transaction_hashes) {
            clear_rpc_indexing_incomplete(tx_hash);
        }

        if (block_number == UINT64_MAX) break;
    }

    return stats;
}

// ---------------------------------------------------------------------------
// Validator-manager seam helpers.
// ---------------------------------------------------------------------------

bool extract_evm_executor_account_data_from_shard_state(
    td::Ref<vm::Cell> shard_state_root,
    const unsigned char executor_addr[32],
    td::Ref<vm::Cell>& account_data_out) noexcept {
    account_data_out = {};
    if (shard_state_root.is_null() || executor_addr == nullptr) return false;
    try {
        block::gen::ShardStateUnsplit::Record state;
        if (!tlb::unpack_cell(std::move(shard_state_root), state) ||
            state.accounts.is_null()) {
            return false;
        }

        vm::AugmentedDictionary accounts_dict{
            vm::load_cell_slice_ref(state.accounts),
            256,
            block::tlb::aug_ShardAccounts};
        auto exec_value = accounts_dict.lookup(
            td::ConstBitPtr{executor_addr}, 256);
        if (exec_value.is_null()) {
            return true;
        }

        td::Ref<vm::Cell> account_cell;
        if (!block::tlb::t_ShardAccount.extract_account_state(
                exec_value, account_cell) ||
            account_cell.is_null()) {
            return false;
        }

        block::gen::Account::Record_account acc_rec;
        if (!tlb::unpack_cell(account_cell, acc_rec)) return false;

        unsigned long long last_trans_lt = 0;
        td::Ref<vm::CellSlice> balance_cs;
        td::Ref<vm::CellSlice> state_cs;
        if (!block::gen::t_AccountStorage.unpack_account_storage(
                acc_rec.storage.write(), last_trans_lt, balance_cs, state_cs)) {
            return false;
        }

        auto account_state_tag = block::gen::t_AccountState.get_tag(*state_cs);
        if (account_state_tag == block::gen::AccountState::account_uninit) {
            account_data_out.clear();
            return true;
        }
        if (account_state_tag != block::gen::AccountState::account_active) {
            return false;
        }

        td::Ref<vm::CellSlice> state_init_cs;
        if (!block::gen::t_AccountState.unpack_account_active(
                state_cs.write(), state_init_cs)) {
            return false;
        }

        block::gen::StateInit::Record si_rec;
        if (!block::gen::t_StateInit.unpack(state_init_cs.write(), si_rec)) {
            return false;
        }
        if (si_rec.data.is_null() || !si_rec.data->have(1) ||
            si_rec.data->prefetch_ulong(1) != 1) {
            return false;
        }
        auto data_slice = si_rec.data;
        data_slice.write().advance(1);
        return data_slice->prefetch_ref_to(account_data_out);
    } catch (vm::VmError&) {
        return false;
    } catch (vm::VmVirtError&) {
        return false;
    } catch (std::exception&) {
        return false;
    } catch (...) {
        return false;
    }
}

namespace {

bool load_ordinary_slice_for_post_accept(const td::Ref<vm::Cell>& cell,
                                         vm::CellSlice& out) noexcept {
    if (cell.is_null()) return false;
    try {
        bool special = false;
        out = vm::load_cell_slice_special(cell, special);
        if (special) {
            g_malformed_special_cell_messages.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        return true;
    } catch (vm::VmError&) {
        return false;
    } catch (vm::VmVirtError&) {
        return false;
    } catch (std::exception&) {
        return false;
    } catch (...) {
        return false;
    }
}

// Walk a parsed Message body cell-slice past CommonMsgInfo + init, return
// the body slice (whether inline `left$0` or referenced `right$1`). The
// caller has already confirmed the message is `ext_in_msg_info`.
std::optional<vm::CellSlice> read_ext_in_msg_body_slice(
    const td::Ref<vm::Cell>& msg) noexcept {
    if (msg.is_null()) return std::nullopt;
    try {
        vm::CellSlice cs;
        if (!load_ordinary_slice_for_post_accept(msg, cs)) return std::nullopt;
        // CommonMsgInfo: ext_in_msg_info$10
        if (cs.size() < 2) return std::nullopt;
        auto tag = cs.fetch_ulong(2);
        if (tag != 0b10) return std::nullopt;
        // src: MsgAddressExt — addr_none$00 or addr_extern$01 ...
        auto src_tag = cs.fetch_ulong(2);
        if (src_tag == 0b01) {
            // addr_extern$01 len:(## 9) external_address:bits len
            if (cs.size() < 9) return std::nullopt;
            auto len = cs.fetch_ulong(9);
            if (cs.size() < len) return std::nullopt;
            cs.advance(static_cast<unsigned>(len));
        } else if (src_tag != 0b00) {
            return std::nullopt;
        }
        // dest: MsgAddressInt — addr_std$10 or addr_var$11
        auto dest_tag = cs.fetch_ulong(2);
        if (dest_tag == 0b10) {
            // addr_std$10 anycast:(Maybe ...) workchain_id:int8 address:bits256
            auto anycast = cs.fetch_ulong(1);
            if (anycast == 1) {
                if (cs.size() < 5) return std::nullopt;
                auto depth = cs.fetch_ulong(5);
                if (cs.size() < depth) return std::nullopt;
                cs.advance(static_cast<unsigned>(depth));
            }
            if (cs.size() < (8 + 256)) return std::nullopt;
            cs.advance(8 + 256);
        } else if (dest_tag == 0b11) {
            // addr_var$11 anycast:(Maybe ...) addr_len:(## 9) workchain:int32
            //              address:bits addr_len
            auto anycast = cs.fetch_ulong(1);
            if (anycast == 1) {
                if (cs.size() < 5) return std::nullopt;
                auto depth = cs.fetch_ulong(5);
                if (cs.size() < depth) return std::nullopt;
                cs.advance(static_cast<unsigned>(depth));
            }
            if (cs.size() < 9) return std::nullopt;
            auto addr_len = cs.fetch_ulong(9);
            if (cs.size() < (32U + addr_len)) return std::nullopt;
            cs.advance(static_cast<unsigned>(32 + addr_len));
        } else {
            return std::nullopt;
        }
        // import_fee: Grams = VarUInteger 16: 4-bit length + payload bytes
        if (cs.size() < 4) return std::nullopt;
        auto grams_len = cs.fetch_ulong(4);
        if (cs.size() < grams_len * 8) return std::nullopt;
        cs.advance(static_cast<unsigned>(grams_len * 8));
        // init: Maybe (Either StateInit ^StateInit)
        if (cs.size() < 1) return std::nullopt;
        auto init_present = cs.fetch_ulong(1);
        if (init_present == 1) {
            if (cs.size() < 1) return std::nullopt;
            auto init_in_ref = cs.fetch_ulong(1);
            if (init_in_ref == 1) {
                if (!cs.have_refs()) return std::nullopt;
                cs.advance_refs(1);
            } else {
                // Inline StateInit — we don't decode, but the dispatcher
                // never produces this form (init is always Nothing for
                // EVM ext-msgs), so reject here.
                return std::nullopt;
            }
        }
        // body: Either X ^X
        if (cs.size() < 1) return std::nullopt;
        auto body_in_ref = cs.fetch_ulong(1);
        if (body_in_ref == 1) {
            if (!cs.have_refs()) return std::nullopt;
            vm::CellSlice body;
            if (!load_ordinary_slice_for_post_accept(cs.prefetch_ref(), body)) {
                return std::nullopt;
            }
            return body;
        }
        return cs;
    } catch (vm::VmError&) {
        return std::nullopt;
    } catch (vm::VmVirtError&) {
        return std::nullopt;
    } catch (std::exception&) {
        return std::nullopt;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<EvmBlockSideEffects> replay_side_effects_for_message(
    td::Ref<vm::Cell>& replay_account_data,
    const td::Ref<vm::Cell>& msg,
    uint64_t gas_limit,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32],
    const uint8_t parent_block_hash[32],
    uint64_t chain_id) noexcept {
    auto body = read_ext_in_msg_body_slice(msg);
    if (!body) return std::nullopt;

    block::ComputePhase cp{};
    bool ok = run_evm_compute_phase_snapshot(
        cp,
        replay_account_data,
        *body,
        gas_limit,
        block_seqno,
        timestamp,
        rand_seed,
        parent_block_hash,
        chain_id);
    if (!ok || !cp.accepted || cp.evm_side_effects == nullptr ||
        cp.new_data.is_null()) {
        return std::nullopt;
    }
    replay_account_data = cp.new_data;
    return *cp.evm_side_effects;
}

}  // namespace

std::optional<evmc::bytes32>
try_derive_evm_tx_hash_from_message(const td::Ref<vm::Cell>& msg) noexcept {
    auto body = read_ext_in_msg_body_slice(msg);
    if (!body) return std::nullopt;

    auto payload = extract_evm_payload(*body);
    if (!payload || payload->empty()) return std::nullopt;

    silkworm::Transaction txn{};
    silkworm::ByteView view = *payload;
    auto rc = silkworm::rlp::decode_transaction(
        view, txn, silkworm::rlp::Eip2718Wrapping::kBoth);
    if (!rc.has_value()) return std::nullopt;
    // Round 85 MEDIUM fix: reject trailing bytes here too, mirroring
    // decode_evm_transaction.  Pre-fix the post-accept hash derivation
    // accepted `0x02 || canonical_rlp || garbage`, producing the same
    // Ethereum tx hash for multiple TOS external messages (different
    // cell-tree roots).  See evm/core/transaction.cpp for the full
    // rationale.
    if (!view.empty()) return std::nullopt;

    // Transaction::hash() = keccak256(rlp::encode(txn, wrap_eip2718=false)).
    // No sender recovery needed — decode populates everything the hash
    // function reads.
    return txn.hash();
}

size_t apply_stashed_side_effects_for_messages(
    uint64_t accepted_block_seqno,
    uint64_t accepted_timestamp,
    const uint8_t rand_seed[32],
    const uint8_t parent_block_hash[32],
    uint64_t chain_id,
    const std::vector<td::Ref<vm::Cell>>& msgs) noexcept {
    std::vector<uint64_t> gas_limits;
    return apply_stashed_side_effects_for_messages(
        accepted_block_seqno, accepted_timestamp, rand_seed, parent_block_hash,
        chain_id, msgs, gas_limits, td::Ref<vm::Cell>{});
}

size_t apply_stashed_side_effects_for_messages(
    uint64_t accepted_block_seqno,
    uint64_t accepted_timestamp,
    const uint8_t rand_seed[32],
    const uint8_t parent_block_hash[32],
    uint64_t chain_id,
    const std::vector<td::Ref<vm::Cell>>& msgs,
    const std::vector<uint64_t>& gas_limits,
    const td::Ref<vm::Cell>& initial_account_data) noexcept {
    std::vector<IndexedSideEffects> fxs;
    fxs.reserve(msgs.size());
    bool saw_gap = false;
    size_t first_gap_index = 0;
    size_t dropped_after_gap = 0;
    bool replay_available = !gas_limits.empty() || initial_account_data.not_null();
    td::Ref<vm::Cell> replay_account_data = initial_account_data;
    size_t replay_cursor = 0;

    auto replay_through = [&](size_t target_index)
        -> std::optional<EvmBlockSideEffects> {
        while (replay_cursor <= target_index) {
            auto replay_tx_hash = try_derive_evm_tx_hash_from_message(
                msgs[replay_cursor]);
            if (!replay_tx_hash) {
                replay_available = false;
                g_replay_failures.fetch_add(1, std::memory_order_relaxed);
                LOG(WARNING) << "evm post-accept: cannot derive tx hash while replaying tx_index="
                             << replay_cursor << "; falling back to side-effect cache only";
                return std::nullopt;
            }
            uint64_t gas_limit = 1'000'000;
            if (replay_cursor < gas_limits.size() &&
                gas_limits[replay_cursor] != 0) {
                gas_limit = gas_limits[replay_cursor];
            }
            auto replayed_fx = replay_side_effects_for_message(
                replay_account_data, msgs[replay_cursor], gas_limit,
                accepted_block_seqno, accepted_timestamp,
                rand_seed, parent_block_hash, chain_id);
            if (!replayed_fx) {
                replay_available = false;
                g_replay_failures.fetch_add(1, std::memory_order_relaxed);
                LOG(WARNING) << "evm post-accept: deterministic replay failed for accepted tx_index="
                             << replay_cursor << "; falling back to side-effect cache only";
                return std::nullopt;
            }
            if (std::memcmp(replayed_fx->tx_hash.bytes,
                            replay_tx_hash->bytes, 32) != 0) {
                replay_available = false;
                g_replay_failures.fetch_add(1, std::memory_order_relaxed);
                LOG(WARNING) << "evm post-accept: deterministic replay tx_hash mismatch at tx_index="
                             << replay_cursor << "; falling back to side-effect cache only";
                return std::nullopt;
            }

            ++replay_cursor;
            if (replay_cursor == target_index + 1) {
                return replayed_fx;
            }
        }
        return std::nullopt;
    };

    for (size_t msg_index = 0; msg_index < msgs.size(); ++msg_index) {
        const auto& msg = msgs[msg_index];
        auto tx_hash = try_derive_evm_tx_hash_from_message(msg);
        if (!tx_hash) {
            g_malformed_messages.fetch_add(1, std::memory_order_relaxed);
            if (!saw_gap) {
                saw_gap = true;
                first_gap_index = msg_index;
                LOG(WARNING) << "evm post-accept: cannot derive tx hash for accepted tx_index="
                             << msg_index << "; withholding EVM RPC indexes for this block";
            }
            replay_available = false;
            continue;
        }
        if (saw_gap) {
            mark_rpc_indexing_incomplete(*tx_hash);
            ++dropped_after_gap;
            continue;
        }
        auto fx = take_side_effects(accepted_block_seqno, accepted_timestamp,
                                    rand_seed, parent_block_hash, *tx_hash);
        if (!fx) {
            auto replayed_fx = replay_available
                ? replay_through(msg_index)
                : std::optional<EvmBlockSideEffects>{};
            if (replayed_fx) {
                fx = std::move(replayed_fx);
                g_replayed_side_effects.fetch_add(1, std::memory_order_relaxed);
                LOG(WARNING) << "evm post-accept: replayed missing side effects for accepted tx_index="
                             << msg_index;
            } else {
                g_missing_side_effects.fetch_add(1, std::memory_order_relaxed);
                if (replay_available) {
                    g_replay_failures.fetch_add(1, std::memory_order_relaxed);
                }
                if (!saw_gap) {
                    saw_gap = true;
                    first_gap_index = msg_index;
                    LOG(WARNING) << "evm post-accept: missing stashed side effects for accepted tx_index="
                                 << msg_index << "; withholding EVM RPC indexes for this block";
                }
                mark_rpc_indexing_incomplete(*tx_hash);
                continue;
            }
        }
        fxs.push_back(IndexedSideEffects{static_cast<uint32_t>(msg_index),
                                         std::move(*fx)});
    }
    if (dropped_after_gap != 0) {
        LOG(WARNING) << "evm post-accept: withheld " << dropped_after_gap
                     << " side-effect record(s) after tx_index="
                     << first_gap_index
                     << " to avoid partial EVM RPC indexes";
    }
    if (saw_gap) {
        mark_rpc_block_indexing_incomplete(accepted_block_seqno);
        for (const auto& indexed : fxs) {
            mark_rpc_indexing_incomplete(indexed.fx.tx_hash);
            stash_side_effects(accepted_block_seqno, accepted_timestamp,
                               rand_seed, parent_block_hash,
                               indexed.fx.tx_hash, indexed.fx);
        }
        if (!fxs.empty()) {
            LOG(WARNING) << "evm post-accept: withheld " << fxs.size()
                         << " complete prefix side-effect record(s) for block #"
                         << accepted_block_seqno
                         << " because a later accepted EVM tx was not indexable";
        }
        return 0;
    }

    if (!finalize_block_side_effects(fxs, accepted_block_seqno,
                                     accepted_timestamp)) {
        return 0;
    }
    for (const auto& indexed : fxs) {
        apply_block_side_effects(indexed.fx);
    }
    return fxs.size();
}

}  // namespace evm_workchain
