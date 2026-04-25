/*
    EVM Workchain — post-accept side-effects application.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm/core/post-accept.h"

#include "evm/core/init.h"
#include "evm/rpc/cache-codec.h"
#include "evm/rpc/cache-db.h"
#include "evm/rpc/subscriptions.h"

#include "td/utils/logging.h"

#include <cstring>

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

}  // namespace evm_workchain
