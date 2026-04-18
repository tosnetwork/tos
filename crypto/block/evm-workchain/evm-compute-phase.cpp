/*
    EVM Workchain — compute phase adapter implementation.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm-compute-phase.h"

#include "evm-transaction.h"
#include "evm-block-context.h"
#include "evm-executor.h"
#include "evm-state-root.h"
#include "evm-incremental-trie.h"
#include "evm-cell-state.h"
#include "evm-init.h"
#include "evm-rpc-cache-codec.h"
#include "evm-rpc-cache-db.h"
#include "evm-subscriptions.h"

#include <ethash/keccak.hpp>
#include "vm/cells/CellBuilder.h"

#include "td/utils/logging.h"

namespace evm_workchain {

bool run_evm_compute_phase(
    block::ComputePhase& cp,
    vm::CellSlice& in_msg_body,
    uint64_t gas_limit,
    EvmState& state,
    uint64_t block_seqno,
    uint64_t timestamp,
    const uint8_t rand_seed[32]) {

    // --- Step 1: Extract the raw Ethereum transaction from the message body ---
    auto payload_opt = extract_evm_payload(in_msg_body);
    if (!payload_opt.has_value()) {
        LOG(WARNING) << "evm-workchain: failed to extract EVM payload from message body";
        cp.skip_reason = block::ComputePhase::sk_bad_state;
        return true;  // infrastructure OK, just a bad message
    }

    // --- Step 2: Decode the RLP transaction and recover sender ---
    auto decode_result = decode_evm_transaction(*payload_opt);
    if (auto* err = std::get_if<TxDecodeError>(&decode_result)) {
        LOG(WARNING) << "evm-workchain: transaction decode failed: " << err->reason;
        cp.skip_reason = block::ComputePhase::sk_bad_state;
        return true;
    }

    auto& decoded = std::get<DecodedTransaction>(decode_result);

    // --- Step 3: Build EVM block context from host-chain metadata ---
    auto block = make_evm_block(block_seqno, timestamp, rand_seed, gas_limit);
    const auto& config = evm_chain_config();

    // Compute EIP-1559 base fee from parent block (same logic as RPC path)
    auto parent_blk = state.get_block_copy(block_seqno > 0 ? block_seqno - 1 : 0);
    if (state.has_block(block_seqno > 0 ? block_seqno - 1 : 0)) {
        block.header.base_fee_per_gas = calc_base_fee(
            parent_blk.base_fee_per_gas, parent_blk.gas_used, parent_blk.gas_limit);
    } else {
        block.header.base_fee_per_gas = intx::uint256{kInitialBaseFee};
    }

    // --- Step 4: Execute the transaction ---
    auto exec_result = execute_evm_transaction(decoded.txn, block, state, config);

    // --- Step 5: Store receipt/transaction/logs for RPC queries ---
    auto tx_hash = decoded.txn.hash();

    StoredReceipt receipt;
    receipt.success = exec_result.success;
    receipt.gas_used = exec_result.gas_used;
    receipt.cumulative_gas_used = exec_result.gas_used;  // TODO: accumulate across block txns
    receipt.block_number = block_seqno;
    receipt.tx_index = 0;  // TODO: set from collator tx ordering
    receipt.from = decoded.sender;
    receipt.to = decoded.txn.to;
    receipt.contract_address = exec_result.contract_address;
    receipt.logs = exec_result.logs;
    receipt.return_data = exec_result.return_data;

    // Phase F.3: persist to side-channel cache db before moving the
    // receipt into RAM. Skipped on the test harness path (no db open).
    //
    // Why `receipt.success` filter: compute-phase runs multiple times per
    // block — once in the collator (applies the tx, success=true), then
    // again in the validator's validate-block (re-applies against state
    // that already has the tx, fails with nonce mismatch → success=false).
    // Writing the second result overwrites the first with garbage. We
    // only persist successful executions; failures are inferred by RPC
    // returning null on tx hash that never produced a receipt.
    if (auto* cache = evm_rpc_cache_db(); cache && receipt.success) {
        td::Bits256 tx_hash_bits;
        std::memcpy(tx_hash_bits.data(), tx_hash.bytes, 32);
        auto cell = encode_persisted_receipt(receipt);
        auto put_status = cache->put_receipt(tx_hash_bits, cell);
        if (put_status.is_error()) {
            LOG(WARNING) << "evm-rpc-cache: put_receipt failed for "
                         << tx_hash_bits.to_hex() << ": "
                         << put_status.message();
        }
    }
    state.store_receipt(tx_hash, std::move(receipt));

    StoredTransaction stored_tx;
    stored_tx.from = decoded.sender;
    stored_tx.to = decoded.txn.to;
    stored_tx.value = decoded.txn.value;
    stored_tx.data = decoded.txn.data;
    stored_tx.nonce = decoded.txn.nonce;
    stored_tx.gas_limit = decoded.txn.gas_limit;
    stored_tx.gas_price = decoded.txn.max_fee_per_gas;
    stored_tx.block_number = block_seqno;
    stored_tx.tx_index = 0;
    stored_tx.raw_rlp = silkworm::Bytes{(*payload_opt).begin(), (*payload_opt).end()};

    // Phase F.6: persist transaction to side-channel cache db. Same
    // `receipt.success` filter as the receipt put — validate-block re-runs
    // against post-state and would write a garbage tx (with the wrong sender
    // recovered from the post-nonce state) over the real one.
    if (auto* cache = evm_rpc_cache_db(); cache && exec_result.success) {
        td::Bits256 tx_hash_bits;
        std::memcpy(tx_hash_bits.data(), tx_hash.bytes, 32);
        auto cell = encode_persisted_transaction(stored_tx);
        auto put_status = cache->put_transaction(tx_hash_bits, cell);
        if (put_status.is_error()) {
            LOG(WARNING) << "evm-rpc-cache: put_transaction failed for "
                         << tx_hash_bits.to_hex() << ": "
                         << put_status.message();
        }
    }
    state.store_transaction(tx_hash, std::move(stored_tx));

    if (!exec_result.logs.empty()) {
        state.store_logs(block_seqno, tx_hash, exec_result.logs);

        // Phase F.6: re-serialize the FULL block log set after each per-tx
        // store_logs and overwrite the persisted entry. Idempotent and
        // last-write-wins — works for blocks with N txs because the final
        // tx of the block produces the complete set. We only persist for
        // successful executions (validate-block re-runs would otherwise
        // re-append duplicate entries via the unconditional store_logs
        // call above; that's a pre-existing bug we leave alone, but we at
        // least avoid baking the duplication into the cache).
        if (auto* cache = evm_rpc_cache_db(); cache && exec_result.success) {
            auto block_logs = state.get_logs_for_block_copy(block_seqno);
            auto cell = encode_persisted_logs_for_block(block_logs);
            auto put_status = cache->put_logs_for_block(block_seqno, cell);
            if (put_status.is_error()) {
                LOG(WARNING) << "evm-rpc-cache: put_logs_for_block failed for #"
                             << block_seqno << ": " << put_status.message();
            }
        }
    }

    // --- Step 5b: Compute EVM stateRoot (always, for cp.new_data) ---
    evmc::bytes32 evm_state_root;
    {
        std::unique_lock trie_lock(state.mutex());
        evm_state_root = global_trie_calculator().compute_state_root(
            state, &state.account_changes(), &state.storage_changes());
        state.clear_change_tracking();
    }

    // --- Step 5c: Embed FULL EVM state cell tree in TOS account data cell ---
    //
    // First-principles atomicity: cp.new_data references the entire
    // CellEvmState root cell. When TOS computes state_hash by hashing
    // ShardState → ShardAccounts → Account → StateInit.data, it transitively
    // hashes the EVM state cell tree. Any EVM state divergence between
    // validators produces a different cell hash, which produces a different
    // TOS state_hash, which fails consensus.
    //
    // Layout (v2, Phase F.2):
    //   magic(24) + Maybe ^EvmStateRootCell + 256-bit Ethereum stateRoot
    //   + Maybe ^EvmRpcCacheRoot
    //   - magic 0x45564D ("EVM") identifies EVM-workchain accounts
    //   - first ref: full CellEvmState root (covers accounts/storage/code)
    //   - 256 bits: Ethereum-format MPT stateRoot (for RPC parity)
    //   - second Maybe: side-channel RPC cache root (Phase F.3+F.4 will
    //     populate). Always emitted; v1 cells (which lack this trailing
    //     bit) are tolerated by the decoder for backward compatibility.
    {
        td::Ref<vm::Cell> evm_state_cell;
        {
            std::unique_lock root_lock(state.mutex());
            auto* cs = dynamic_cast<CellEvmState*>(&state.state());
            if (cs) {
                evm_state_cell = cs->serialize_to_cell();
            }
        }
        vm::CellBuilder data_cb;
        data_cb.store_long(0x45564Dll, 24);  // EVM magic
        if (evm_state_cell.not_null()) {
            data_cb.store_long(1, 1);
            data_cb.store_ref(evm_state_cell);
        } else {
            data_cb.store_long(0, 1);
        }
        // 256-bit Ethereum-format stateRoot (informational, for RPC parity)
        data_cb.store_bytes(reinterpret_cast<const char*>(evm_state_root.bytes), 32);
        // v2: trailing Maybe ^Cell rpc_cache_root. Phase F.2 always emits 0
        // (no cache yet); Phase F.3 will populate via the per-tx receipt
        // accumulator and emit a non-null ref when the cache has entries.
        data_cb.store_long(0, 1);
        cp.new_data = data_cb.finalize();
    }
    // Empty actions cell (action phase runs with 0 actions → succeeds)
    {
        vm::CellBuilder actions_cb;
        cp.actions = actions_cb.finalize();
    }

    // --- Step 5d: Build and store block for RPC queries (first tx only) ---
    if (!state.has_block(block_seqno)) {
        StoredBlock stored_block;
        stored_block.number = block_seqno;
        stored_block.timestamp = timestamp;
        stored_block.gas_used = exec_result.gas_used;
        stored_block.gas_limit = block.header.gas_limit;
        stored_block.base_fee_per_gas = block.header.base_fee_per_gas.value_or(0);
        stored_block.transaction_hashes.push_back(tx_hash);
        stored_block.state_root = evm_state_root;

        auto parent_num = block_seqno > 0 ? block_seqno - 1 : 0;
        stored_block.parent_hash = state.get_block_hash(parent_num);

        uint8_t hash_input[32 + 32 + 8];
        auto bn_be = intx::be::store<evmc::uint256be>(intx::uint256{block_seqno});
        std::memcpy(hash_input, bn_be.bytes, 32);
        std::memcpy(hash_input + 32, stored_block.parent_hash.bytes, 32);
        uint64_t ts_be = __builtin_bswap64(timestamp);
        std::memcpy(hash_input + 64, &ts_be, 8);
        auto h = ethash::keccak256(hash_input, sizeof(hash_input));
        std::memcpy(stored_block.hash.bytes, h.bytes, 32);

        // Logs bloom
        {
            uint8_t bloom[256] = {};
            for (const auto& log : exec_result.logs) {
                auto ah = ethash::keccak256(log.address.bytes, 20);
                for (int i = 0; i < 6; i += 2) {
                    uint16_t bit = (static_cast<uint16_t>(ah.bytes[i]) << 8 | ah.bytes[i + 1]) & 0x7FF;
                    bloom[bit / 8] |= (1 << (bit % 8));
                }
                for (const auto& topic : log.topics) {
                    auto th = ethash::keccak256(topic.bytes, 32);
                    for (int i = 0; i < 6; i += 2) {
                        uint16_t bit = (static_cast<uint16_t>(th.bytes[i]) << 8 | th.bytes[i + 1]) & 0x7FF;
                        bloom[bit / 8] |= (1 << (bit % 8));
                    }
                }
            }
            std::memcpy(stored_block.logs_bloom, bloom, 256);
        }

        stored_block.transactions_root = compute_transactions_root(
            stored_block.transaction_hashes, state);
        stored_block.receipts_root = compute_receipts_root(
            stored_block.transaction_hashes, state);

        state.store_block(stored_block);

        // Phase F.6: persist block to side-channel cache db. Inside the
        // `if (!state.has_block)` guard so validate-block — which sees the
        // collator's already-stored block and skips this branch — doesn't
        // re-write. Two indexes keep the same payload (~2 KB redundancy
        // per block; pruning policy is the operator's lever).
        if (auto* cache = evm_rpc_cache_db()) {
            auto cell = encode_persisted_block(stored_block);
            auto put_n_status = cache->put_block_by_number(block_seqno, cell);
            if (put_n_status.is_error()) {
                LOG(WARNING) << "evm-rpc-cache: put_block_by_number failed for #"
                             << block_seqno << ": " << put_n_status.message();
            }
            td::Bits256 hash_bits;
            std::memcpy(hash_bits.data(), stored_block.hash.bytes, 32);
            auto put_h_status = cache->put_block_by_hash(hash_bits, cell);
            if (put_h_status.is_error()) {
                LOG(WARNING) << "evm-rpc-cache: put_block_by_hash failed for "
                             << hash_bits.to_hex() << ": " << put_h_status.message();
            }
        }

        auto& sub_mgr = global_subscription_manager();
        sub_mgr.notify_new_head(stored_block);
        sub_mgr.notify_new_pending_transaction(tx_hash);
        if (!exec_result.logs.empty()) {
            sub_mgr.notify_logs(block_seqno, tx_hash, exec_result.logs, stored_block.hash);
        }
    }

    // --- Step 6: Map results back into the host-chain ComputePhase ---
    cp.success = exec_result.success;
    cp.accepted = true;
    cp.gas_used = exec_result.gas_used;
    cp.gas_limit = gas_limit;
    cp.gas_credit = 0;
    cp.gas_max = gas_limit;
    cp.exit_code = exec_result.success ? 0 : 1;
    cp.vm_steps = 0;

    cp.vm_init_state_hash.set_zero();
    cp.vm_final_state_hash.set_zero();

    if (!exec_result.error_message.empty()) {
        cp.vm_log = exec_result.error_message;
    }

    LOG(INFO) << "evm-workchain: execution " << (exec_result.success ? "success" : "revert")
              << ", gas_used=" << exec_result.gas_used
              << ", logs=" << exec_result.logs.size()
              << ", tx_hash=0x" << std::hex << tx_hash.bytes[0] << tx_hash.bytes[1];

    return true;
}

}  // namespace evm_workchain
