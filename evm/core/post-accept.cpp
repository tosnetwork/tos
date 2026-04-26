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
#include "evm/core/state-root.h"
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
#include <cstring>
#include <mutex>
#include <unordered_map>

namespace evm_workchain {

namespace {

std::atomic<uint64_t> g_missing_side_effects{0};
std::atomic<uint64_t> g_replayed_side_effects{0};
std::atomic<uint64_t> g_replay_failures{0};
std::atomic<uint64_t> g_malformed_messages{0};
std::atomic<uint64_t> g_strict_root_failures{0};

td::Bits256 bytes32_to_bits(const evmc::bytes32& value) {
    td::Bits256 bits;
    std::memcpy(bits.data(), value.bytes, 32);
    return bits;
}

}  // namespace

void apply_block_side_effects(const EvmBlockSideEffects& fx) {
    auto& state = global_evm_state();

    // Idempotency dedupe: a node that runs both collator and validator
    // roles for the same block reaches this seam twice (once per role).
    // Snapshot compute is pure, so the second apply would write
    // bitwise-identical records — but the receipt-insertion-order vector
    // is bounded and pushing dups would burn cache slots, and per-tx log
    // store appends per call. Bail early when this (block, tx_hash) is
    // already stored. Cheap (one hash-map lookup).
    if (state.get_receipt_copy(fx.tx_hash).has_value()) {
        return;
    }

    // Receipt: store in RAM, persist to cache DB.
    {
        StoredReceipt r = fx.receipt;
        state.store_receipt(fx.tx_hash, std::move(r));
    }
    if (auto* cache = evm_rpc_cache_db()) {
        td::Bits256 tx_hash_bits = bytes32_to_bits(fx.tx_hash);
        auto cell = encode_persisted_receipt(fx.receipt);
        auto put_status = cache->put_receipt(tx_hash_bits, cell);
        if (put_status.is_error()) {
            LOG(WARNING) << "evm-rpc-cache: put_receipt failed for "
                         << tx_hash_bits.to_hex() << ": "
                         << put_status.message();
        }
    }

    // Transaction record.
    {
        StoredTransaction t = fx.transaction;
        state.store_transaction(fx.tx_hash, std::move(t));
    }
    if (auto* cache = evm_rpc_cache_db()) {
        td::Bits256 tx_hash_bits = bytes32_to_bits(fx.tx_hash);
        auto cell = encode_persisted_transaction(fx.transaction);
        auto put_status = cache->put_transaction(tx_hash_bits, cell);
        if (put_status.is_error()) {
            LOG(WARNING) << "evm-rpc-cache: put_transaction failed for "
                         << tx_hash_bits.to_hex() << ": "
                         << put_status.message();
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
            auto cell = encode_persisted_logs_for_block(block_logs);
            auto put_status =
                cache->put_logs_for_block(fx.receipt.block_number, cell);
            if (put_status.is_error()) {
                LOG(WARNING) << "evm-rpc-cache: put_logs_for_block failed for #"
                             << fx.receipt.block_number << ": "
                             << put_status.message();
            }
        }
    }

    // Block summary (only the block's first tx carries this).
    if (fx.has_block) {
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
            }
            td::Bits256 hash_bits = bytes32_to_bits(fx.block.hash);
            auto put_h_status = cache->put_block_by_hash(hash_bits, cell);
            if (put_h_status.is_error()) {
                LOG(WARNING) << "evm-rpc-cache: put_block_by_hash failed for "
                             << hash_bits.to_hex() << ": "
                             << put_h_status.message();
            }
        }

        auto& sub_mgr = global_subscription_manager();
        sub_mgr.notify_new_head(fx.block);
        sub_mgr.notify_new_pending_transaction(fx.tx_hash);
        if (!fx.logs.empty()) {
            sub_mgr.notify_logs(fx.block.number, fx.tx_hash, fx.logs,
                                fx.block.hash);
        }
    } else if (!fx.logs.empty()) {
        // Mid-block tx with logs but no block summary still notifies
        // log subscribers; mirrors legacy behaviour where
        // notify_logs fired on every store_logs invocation.
        auto& sub_mgr = global_subscription_manager();
        sub_mgr.notify_logs(fx.receipt.block_number, fx.tx_hash, fx.logs,
                            evmc::bytes32{});
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
    vm::CellBuilder cb;
    cb.store_long(kPendingSideEffectsMagic, 32);
    cb.store_bytes(fx.tx_hash.bytes, 32);
    cb.store_bytes(fx.rand_seed.bytes, 32);
    cb.store_long(fx.has_block ? 1 : 0, 1);
    cb.store_ref(encode_persisted_receipt(fx.receipt));
    cb.store_ref(encode_persisted_transaction(fx.transaction));
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
        if (!decode_persisted_receipt(cs.fetch_ref(), out.receipt)) return false;
        if (!decode_persisted_transaction(cs.fetch_ref(), out.transaction)) return false;
        out.logs = out.receipt.logs;
        if (out.has_block &&
            !decode_persisted_block(cs.fetch_ref(), out.block)) {
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

    auto transactions_root = try_compute_transactions_root_from_records(txs);
    if (!transactions_root) {
        g_strict_root_failures.fetch_add(1, std::memory_order_relaxed);
        LOG(WARNING) << "evm post-accept: cannot finalize block #"
                     << accepted_block_seqno
                     << " because at least one accepted tx lacks raw signed RLP";
        fxs.clear();
        return false;
    }
    block.transactions_root = *transactions_root;
    block.receipts_root = compute_receipts_root_from_records(receipts);
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
        .strict_root_failures = g_strict_root_failures.load(std::memory_order_relaxed),
    };
}

void reset_evm_post_accept_health_for_tests() noexcept {
    g_missing_side_effects.store(0, std::memory_order_relaxed);
    g_replayed_side_effects.store(0, std::memory_order_relaxed);
    g_replay_failures.store(0, std::memory_order_relaxed);
    g_malformed_messages.store(0, std::memory_order_relaxed);
    g_strict_root_failures.store(0, std::memory_order_relaxed);
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

        auto tx_root = try_compute_transactions_root_from_records(txs);
        if (!tx_root || *tx_root != block.transactions_root) {
            ++stats.errors;
            stats.last_error = "transactionsRoot mismatch";
            if (block_number == UINT64_MAX) break;
            continue;
        }
        auto receipts_root = compute_receipts_root_from_records(receipts);
        if (receipts_root != block.receipts_root) {
            ++stats.errors;
            stats.last_error = "receiptsRoot mismatch";
            if (block_number == UINT64_MAX) break;
            continue;
        }

        for (size_t i = 0; i < block.transaction_hashes.size(); ++i) {
            auto tx_hash_bits = bytes32_to_bits(block.transaction_hashes[i]);
            auto tx_status = cache->put_transaction(
                tx_hash_bits, encode_persisted_transaction(txs[i]));
            if (tx_status.is_error()) {
                ++stats.errors;
                stats.last_error = tx_status.message().str();
                block_ok = false;
                break;
            }
            ++stats.transactions_written;

            auto receipt_status = cache->put_receipt(
                tx_hash_bits, encode_persisted_receipt(receipts[i]));
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
            block.number, encode_persisted_logs_for_block(logs));
        if (logs_status.is_error()) {
            ++stats.errors;
            stats.last_error = logs_status.message().str();
            if (block_number == UINT64_MAX) break;
            continue;
        }
        ++stats.log_blocks_written;

        if (block_number == UINT64_MAX) break;
    }

    return stats;
}

// ---------------------------------------------------------------------------
// Validator-manager seam helpers.
// ---------------------------------------------------------------------------

bool is_evm_executor_address(const unsigned char addr[32]) noexcept {
    return std::memcmp(addr, kEvmExecutorAddressBytes, 32) == 0;
}

bool extract_evm_executor_account_data_from_shard_state(
    td::Ref<vm::Cell> shard_state_root,
    td::Ref<vm::Cell>& account_data_out) noexcept {
    account_data_out = {};
    if (shard_state_root.is_null()) return false;
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
            td::ConstBitPtr{kEvmExecutorAddressBytes}, 256);
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

// Walk a parsed Message body cell-slice past CommonMsgInfo + init, return
// the body slice (whether inline `left$0` or referenced `right$1`). The
// caller has already confirmed the message is `ext_in_msg_info`.
std::optional<vm::CellSlice> read_ext_in_msg_body_slice(
    const td::Ref<vm::Cell>& msg) noexcept {
    if (msg.is_null()) return std::nullopt;
    try {
        vm::CellSlice cs = vm::load_cell_slice(msg);
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
            return vm::load_cell_slice(cs.prefetch_ref());
        }
        return cs;
    } catch (vm::VmError&) {
        return std::nullopt;
    } catch (vm::VmVirtError&) {
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
    const uint8_t parent_block_hash[32]) noexcept {
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
        parent_block_hash);
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
    const std::vector<td::Ref<vm::Cell>>& msgs) noexcept {
    std::vector<uint64_t> gas_limits;
    return apply_stashed_side_effects_for_messages(
        accepted_block_seqno, accepted_timestamp, rand_seed, parent_block_hash,
        msgs, gas_limits, td::Ref<vm::Cell>{});
}

size_t apply_stashed_side_effects_for_messages(
    uint64_t accepted_block_seqno,
    uint64_t accepted_timestamp,
    const uint8_t rand_seed[32],
    const uint8_t parent_block_hash[32],
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
                rand_seed, parent_block_hash);
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
                             << msg_index << "; publishing only complete prefix";
            }
            replay_available = false;
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
                                 << msg_index << "; publishing only complete prefix";
                }
                continue;
            }
        }
        if (saw_gap) {
            ++dropped_after_gap;
            continue;
        }
        fxs.push_back(IndexedSideEffects{static_cast<uint32_t>(msg_index),
                                         std::move(*fx)});
    }
    if (dropped_after_gap != 0) {
        LOG(WARNING) << "evm post-accept: discarded " << dropped_after_gap
                     << " stashed side-effect record(s) after tx_index="
                     << first_gap_index
                     << " to avoid wrong tx_index/cumulativeGasUsed";
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
