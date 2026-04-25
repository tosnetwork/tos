/*
    EVM Workchain — post-accept side-effects application.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm/core/post-accept.h"
#include "evm/core/post-accept-bridge.h"

#include "evm/core/init.h"
#include "evm/core/transaction.h"
#include "evm/core/workchain.h"
#include "evm/rpc/cache-codec.h"
#include "evm/rpc/cache-db.h"
#include "evm/rpc/subscriptions.h"

#include "td/utils/logging.h"

#include "vm/cells/Cell.h"
#include "vm/cells/CellSlice.h"
#include "vm/excno.hpp"

#include <ethash/keccak.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/types/transaction.hpp>

#include <chrono>
#include <cstring>
#include <mutex>
#include <unordered_map>

namespace evm_workchain {

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
        td::Bits256 tx_hash_bits;
        std::memcpy(tx_hash_bits.data(), fx.tx_hash.bytes, 32);
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
        td::Bits256 tx_hash_bits;
        std::memcpy(tx_hash_bits.data(), fx.tx_hash.bytes, 32);
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

        if (auto* cache = evm_rpc_cache_db()) {
            auto cell = encode_persisted_block(fx.block);
            auto put_n_status =
                cache->put_block_by_number(fx.block.number, cell);
            if (put_n_status.is_error()) {
                LOG(WARNING) << "evm-rpc-cache: put_block_by_number failed for #"
                             << fx.block.number << ": "
                             << put_n_status.message();
            }
            td::Bits256 hash_bits;
            std::memcpy(hash_bits.data(), fx.block.hash.bytes, 32);
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

struct EvmTxHashKey {
    evmc::bytes32 v{};
    bool operator==(const EvmTxHashKey& o) const noexcept {
        return std::memcmp(v.bytes, o.v.bytes, 32) == 0;
    }
};

struct EvmTxHashKeyHasher {
    size_t operator()(const EvmTxHashKey& k) const noexcept {
        size_t h = 0;
        std::memcpy(&h, k.v.bytes, sizeof(h));
        return h;
    }
};

struct StashedEntry {
    EvmBlockSideEffects fx;
    uint64_t inserted_at_us{};
};

struct StashedCache {
    std::mutex mu;
    std::unordered_map<EvmTxHashKey, StashedEntry, EvmTxHashKeyHasher> map;

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

}  // namespace

void stash_side_effects(const evmc::bytes32& tx_hash, EvmBlockSideEffects fx) {
    auto& c = g_stashed_cache();
    std::lock_guard<std::mutex> lock(c.mu);
    EvmTxHashKey key{tx_hash};
    auto it = c.map.find(key);
    if (it != c.map.end()) {
        // Re-validation of the same candidate produced bitwise-identical
        // side effects (compute is pure). Refresh the timestamp so the
        // entry stays warm and skip the rewrite.
        it->second.inserted_at_us = StashedCache::now_us();
        return;
    }
    if (c.map.size() >= kMaxStashedSideEffects) {
        c.evict_oldest_locked();
    }
    c.map.emplace(key, StashedEntry{std::move(fx), StashedCache::now_us()});
}

std::optional<EvmBlockSideEffects>
take_side_effects(const evmc::bytes32& tx_hash) {
    auto& c = g_stashed_cache();
    std::lock_guard<std::mutex> lock(c.mu);
    auto it = c.map.find(EvmTxHashKey{tx_hash});
    if (it == c.map.end()) return std::nullopt;
    EvmBlockSideEffects out = std::move(it->second.fx);
    c.map.erase(it);
    return out;
}

size_t stashed_side_effects_count() noexcept {
    auto& c = g_stashed_cache();
    std::lock_guard<std::mutex> lock(c.mu);
    return c.map.size();
}

// ---------------------------------------------------------------------------
// Validator-manager seam helpers.
// ---------------------------------------------------------------------------

bool is_evm_executor_address(const unsigned char addr[32]) noexcept {
    return std::memcmp(addr, kEvmExecutorAddressBytes, 32) == 0;
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

bool apply_stashed_side_effects_for_message(
    const td::Ref<vm::Cell>& msg) noexcept {
    auto tx_hash = try_derive_evm_tx_hash_from_message(msg);
    if (!tx_hash) return false;
    auto fx = take_side_effects(*tx_hash);
    if (!fx) return false;
    apply_block_side_effects(*fx);
    return true;
}

}  // namespace evm_workchain
