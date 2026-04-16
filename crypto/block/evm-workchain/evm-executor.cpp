/*
    EVM Workchain — executor implementation.

    Uses silkworm::EVM (from ~/s/silkworm/core/execution/evm.hpp) directly
    to run EVM transactions via evmone.

    Gas accounting protocol (matches Ethereum Yellow Paper):
      1. Deduct upfront_cost = gas_limit * gas_price from sender
      2. EVM executes (handles value transfer internally)
      3. Refund unused gas to sender
      4. Pay gas fee to beneficiary

    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm-executor.h"

#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/protocol/intrinsic_gas.hpp>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/state/intra_block_state.hpp>

namespace evm_workchain {

ExecutionResult execute_evm_transaction(
    const silkworm::Transaction& txn,
    const silkworm::Block& block,
    EvmState& evm_state,
    const silkworm::ChainConfig& config) {

    ExecutionResult result;

    auto sender_opt = txn.sender();
    if (!sender_opt) {
        result.error_message = "sender not recovered";
        return result;
    }
    const auto& sender = *sender_opt;

    // Create the IntraBlockState for this execution.
    silkworm::IntraBlockState state(evm_state.state());

    // Create the EVM instance.
    silkworm::EVM evm(block, state, config);

    auto rev = evm.revision();

    // Compute intrinsic gas.
    auto intrinsic = silkworm::protocol::intrinsic_gas(txn, rev);
    if (intrinsic > static_cast<intx::uint128>(txn.gas_limit)) {
        result.error_message = "intrinsic gas exceeds gas limit";
        result.gas_used = txn.gas_limit;
        return result;
    }
    uint64_t execution_gas = txn.gas_limit - static_cast<uint64_t>(intrinsic);

    // Gas price: with base_fee=0, effective = min(max_fee, base + priority) = min(max_fee, priority)
    const intx::uint256 base_fee = block.header.base_fee_per_gas.value_or(0);
    const intx::uint256 effective_gas_price = txn.effective_gas_price(base_fee);

    // 1. Deduct upfront gas cost from sender (Yellow Paper §6).
    const intx::uint256 upfront_gas_cost = intx::uint256{txn.gas_limit} * effective_gas_price;
    state.subtract_from_balance(sender, upfront_gas_cost);

    // 2. Increment sender nonce (for CALL transactions; CREATE increments internally).
    if (txn.to.has_value()) {
        state.set_nonce(sender, state.get_nonce(sender) + 1);
    }

    // 3. Warm up sender and recipient (EIP-2929).
    state.access_account(sender);
    if (txn.to.has_value()) {
        state.access_account(*txn.to);
    }
    state.access_account(block.header.beneficiary);
    for (const auto& entry : txn.access_list) {
        state.access_account(entry.account);
        for (const auto& key : entry.storage_keys) {
            state.access_storage(entry.account, key);
        }
    }

    // 4. Execute the EVM.
    // The EVM internally handles value transfer, CREATE address derivation,
    // and nonce increment for CREATE.
    auto call_result = evm.execute(txn, execution_gas);

    result.success = (call_result.status == EVMC_SUCCESS);
    result.return_data = std::move(call_result.data);
    if (!result.success) {
        result.error_message = call_result.error_message;
    }

    // 5. Calculate gas used and refund.
    uint64_t gas_left = call_result.gas_left;
    uint64_t gas_refund = std::min(call_result.gas_refund, (txn.gas_limit - gas_left) / 5);
    uint64_t gas_used = txn.gas_limit - gas_left - gas_refund;
    result.gas_used = gas_used;
    result.gas_refund = gas_refund;

    // 6. Refund remaining gas to sender.
    uint64_t gas_remaining = txn.gas_limit - gas_used;
    state.add_to_balance(sender, intx::uint256{gas_remaining} * effective_gas_price);

    // 7. Pay base fee portion to beneficiary (priority fee in a more complete impl).
    state.add_to_balance(block.header.beneficiary,
                         intx::uint256{gas_used} * effective_gas_price);

    // Collect logs.
    result.logs = state.logs();

    // Finalize the transaction state.
    state.finalize_transaction(rev);

    // Write in-block state changes to the underlying state store.
    state.write_to_db(block.header.number);

    return result;
}

}  // namespace evm_workchain
