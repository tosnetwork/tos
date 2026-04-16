/*
    EVM Workchain — compute phase adapter implementation.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm-compute-phase.h"

#include "evm-transaction.h"
#include "evm-block-context.h"
#include "evm-executor.h"

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
    state.store_transaction(tx_hash, std::move(stored_tx));

    if (!exec_result.logs.empty()) {
        state.store_logs(block_seqno, tx_hash, exec_result.logs);
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
