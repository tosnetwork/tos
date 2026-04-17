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

#include <limits>

#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/protocol/intrinsic_gas.hpp>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/core/types/address.hpp>

namespace evm_workchain {

// Shared execution logic used by both execute (mutable) and call (read-only).
static ExecutionResult run_evm(
    const silkworm::Transaction& txn,
    const silkworm::Block& block,
    silkworm::IntraBlockState& state,
    const silkworm::ChainConfig& config,
    bool commit_state) {

    ExecutionResult result;

    auto sender_opt = txn.sender();
    if (!sender_opt) {
        result.error_message = "sender not recovered";
        return result;
    }
    const auto& sender = *sender_opt;

    silkworm::EVM evm(block, state, config);
    auto rev = evm.revision();

    // --- Transaction validation (Yellow Paper §6.2 + EIP-1559) ---
    //
    // All checks in this block are *pre-execution* — a failing check
    // means the tx never enters the mempool / block, so no state
    // mutation occurs (nonce stays, balance stays, gas is not burned).
    // Skip entirely for read-only calls (eth_call / eth_estimateGas).
    if (commit_state) {
        // EIP-3607 (London+): reject txs from accounts that have code.
        if (rev >= EVMC_LONDON) {
            auto sender_code_hash = state.get_code_hash(sender);
            if (sender_code_hash != silkworm::kEmptyHash &&
                sender_code_hash != evmc::bytes32{}) {
                result.error_message = "EIP-3607: sender has code";
                result.gas_used = 0;
                return result;
            }
        }

        // EIP-1559 (London+): max_priority_fee_per_gas must be
        // ≤ max_fee_per_gas. A higher tip than max-cost is nonsensical;
        // the Ethereum mempool rejects these.
        if (rev >= EVMC_LONDON &&
            txn.type != silkworm::TransactionType::kLegacy &&
            txn.max_priority_fee_per_gas > txn.max_fee_per_gas) {
            result.error_message = "priority fee exceeds max fee";
            result.gas_used = 0;
            return result;
        }

        // EIP-1559: max_fee_per_gas must cover the current base fee.
        // Otherwise the tx would pay the miner less than the protocol
        // minimum.
        const intx::uint256 bf = block.header.base_fee_per_gas.value_or(0);
        if (rev >= EVMC_LONDON && txn.max_fee_per_gas < bf) {
            result.error_message = "max fee per gas below base fee";
            result.gas_used = 0;
            return result;
        }

        // Block-gas-limit check: txn.gas_limit must not exceed the
        // block's gas allowance. Ethereum rejects these at the
        // mempool; a miner that included one would produce an invalid
        // block.
        if (txn.gas_limit > block.header.gas_limit) {
            result.error_message = "tx gas limit exceeds block gas limit";
            result.gas_used = 0;
            return result;
        }

        // Intrinsic gas check BEFORE state mutation. A tx with
        // gas_limit < intrinsic_gas fails pre-validation with no
        // balance charged and no nonce bump.
        auto intrinsic_pre = silkworm::protocol::intrinsic_gas(txn, rev);
        if (intrinsic_pre > static_cast<intx::uint128>(txn.gas_limit)) {
            result.error_message = "intrinsic gas exceeds gas limit";
            result.gas_used = 0;
            return result;
        }

        // Nonce check: sender nonce must match transaction nonce.
        {
            uint64_t sender_nonce = state.get_nonce(sender);
            if (sender_nonce != txn.nonce) {
                result.error_message = "nonce mismatch: expected " +
                    std::to_string(sender_nonce) + ", got " + std::to_string(txn.nonce);
                result.gas_used = 0;
                return result;
            }
            // EIP-2681 (Istanbul+): tx with nonce == 2^64 - 1 is
            // rejected because executing it would overflow the nonce
            // counter to 2^64. The spec's TransactionException code is
            // NONCE_IS_MAX.
            if (sender_nonce == std::numeric_limits<uint64_t>::max()) {
                result.error_message = "EIP-2681: nonce at max";
                result.gas_used = 0;
                return result;
            }
        }

        // EIP-1559 balance check: sender must be able to afford
        //   gas_limit * max_fee_per_gas + value
        // even if the effective_gas_price (after base-fee deduction)
        // ends up lower. The Yellow-Paper / Berlin check used
        // effective_gas_price; London+ tightened it to max_fee_per_gas
        // as the upfront-budget ceiling.
        const intx::uint256 max_gas_price = (rev >= EVMC_LONDON &&
                                               txn.type != silkworm::TransactionType::kLegacy)
            ? txn.max_fee_per_gas
            : txn.effective_gas_price(bf);
        const intx::uint512 max_cost = intx::uint512{txn.gas_limit} * intx::uint512{max_gas_price} +
                                        intx::uint512{txn.value};
        if (intx::uint512{state.get_balance(sender)} < max_cost) {
            result.error_message = "insufficient funds for gas + value";
            result.gas_used = 0;
            return result;
        }
    }

    // Compute intrinsic gas (also consumed in the execution_gas math
    // below; above we only used it as a pre-validation gate).
    auto intrinsic = silkworm::protocol::intrinsic_gas(txn, rev);
    if (intrinsic > static_cast<intx::uint128>(txn.gas_limit)) {
        // Already rejected above when commit_state=true; this branch
        // only runs for read-only calls where we mirror spec semantics.
        result.error_message = "intrinsic gas exceeds gas limit";
        result.gas_used = txn.gas_limit;
        return result;
    }
    uint64_t execution_gas = txn.gas_limit - static_cast<uint64_t>(intrinsic);

    const intx::uint256 base_fee = block.header.base_fee_per_gas.value_or(0);
    const intx::uint256 effective_gas_price = txn.effective_gas_price(base_fee);

    // 1. Deduct upfront gas cost.
    const intx::uint256 upfront_gas_cost = intx::uint256{txn.gas_limit} * effective_gas_price;
    state.subtract_from_balance(sender, upfront_gas_cost);

    // 2. Increment sender nonce (CALL only; CREATE increments internally).
    if (txn.to.has_value()) {
        state.set_nonce(sender, state.get_nonce(sender) + 1);
    }

    // 3. Warm up access lists (EIP-2929).
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
    auto call_result = evm.execute(txn, execution_gas);

    result.success = (call_result.status == EVMC_SUCCESS);
    result.return_data = std::move(call_result.data);
    if (!result.success) {
        result.error_message = call_result.error_message;
    }

    // For CREATE: compute the contract address.
    if (!txn.to.has_value() && result.success) {
        uint64_t sender_nonce = state.get_nonce(sender);
        // CREATE uses nonce - 1 because the EVM already incremented it.
        result.contract_address = silkworm::create_address(sender, sender_nonce > 0 ? sender_nonce - 1 : 0);
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

    // 7. Pay the *priority fee* portion to the beneficiary. The
    // base-fee portion is burned (EIP-1559): it's subtracted from the
    // sender via the upfront_gas_cost above but never credited
    // anywhere. Paying the full effective_gas_price to the beneficiary
    // is a consensus bug — Ethereum state-tests (e.g. stSelfBalance/
    // diffPlaces.json) catch it as a beneficiary balance mismatch.
    const intx::uint256 priority_fee_per_gas = txn.priority_fee_per_gas(base_fee);
    state.add_to_balance(block.header.beneficiary,
                         intx::uint256{gas_used} * priority_fee_per_gas);

    // Collect logs.
    result.logs = state.logs();

    // Finalize.
    state.finalize_transaction(rev);

    // Commit state changes only for real execution (not eth_call).
    if (commit_state) {
        state.write_to_db(block.header.number);
    }

    return result;
}

ExecutionResult execute_evm_transaction(
    const silkworm::Transaction& txn,
    const silkworm::Block& block,
    EvmState& evm_state,
    const silkworm::ChainConfig& config) {

    std::unique_lock lock(evm_state.mutex());
    silkworm::IntraBlockState ibs(evm_state.state());
    auto result = run_evm(txn, block, ibs, config, /*commit_state=*/true);

    // Store the block for BLOCKHASH opcode support.
    auto block_hash = intx::be::store<evmc::bytes32>(intx::uint256{block.header.number});
    evm_state.state().insert_block(block, block_hash);

    // Track changed accounts for incremental state root computation.
    // Sender, recipient, and beneficiary are always touched.
    if (auto s = txn.sender()) {
        evm_state.track_account_change(*s);
    }
    if (txn.to) {
        evm_state.track_account_change(*txn.to);
    }
    evm_state.track_account_change(block.header.beneficiary);
    // For CREATE: the new contract address is also changed.
    if (result.contract_address) {
        evm_state.track_account_change(*result.contract_address);
    }

    return result;
}

ExecutionResult call_evm_transaction(
    const silkworm::Transaction& txn,
    const silkworm::Block& block,
    const EvmState& evm_state,
    const silkworm::ChainConfig& config) {

    // IntraBlockState reads from the underlying State lazily and only
    // writes to its internal journal.  With commit_state=false we never
    // call write_to_db(), so the underlying State is not mutated.
    // The const_cast is safe because we guarantee no writes reach the DB.
    std::unique_lock lock(evm_state.mutex());
    auto& mutable_state = const_cast<silkworm::State&>(evm_state.state());
    silkworm::IntraBlockState ibs(mutable_state);
    return run_evm(txn, block, ibs, config, /*commit_state=*/false);
}

}  // namespace evm_workchain
