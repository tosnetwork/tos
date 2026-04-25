/*
    EVM Workchain — executor.

    Wraps silkworm::ExecutionProcessor to provide a single entry point for
    running an EVM transaction within the host-chain compute phase.

    Execution flow:
      1. Caller provides a decoded silkworm::Transaction, block context,
         and a reference to the EVM workchain state.
      2. The executor creates an ExecutionProcessor, runs the transaction,
         and returns a canonical execution result.
      3. The result is mapped back into the host-chain compute phase
         structure (gas used, success/failure, state changes, logs).

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <silkworm/core/types/receipt.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/log.hpp>
#include <silkworm/core/chain/config.hpp>

#include "evm/core/state.h"

namespace evm_workchain {

/// Disposition of an EVM execution attempt.
///
/// Audit #2 (2026-04-26): pre-validation failures (bad nonce, insufficient
/// funds, intrinsic gas exceeds limit, EIP-1559 / 4844 violations, EIP-3607
/// sender-has-code, nonce-at-max) must be distinguishable from a transaction
/// that was admitted, executed, and reverted. The host-chain compute phase
/// uses this disposition to decide whether to admit the tx as cp.accepted=true
/// (Executed*) or short-circuit to cp.skip_reason=sk_bad_state with cp.accepted
/// =false (InvalidPreValidation). Mapping all three to a single "success" bool
/// allowed free blockspace spam: bad-nonce txs returned gas_used=0 yet were
/// still booked as accepted transactions.
enum class EvmTxDisposition {
    /// Pre-execution validation rejected the tx (default for default-constructed
    /// ExecutionResult, so any unset code path is treated as "never executed").
    InvalidPreValidation = 0,
    /// EVM ran, txn reverted (gas charged, state writes journaled-and-rolled-back
    /// but balance/nonce side-effects from gas accounting persist).
    ExecutedReverted = 1,
    /// EVM ran successfully (gas charged, state writes committed).
    ExecutedSucceeded = 2,
};

/// Canonical EVM execution result returned to the host chain.
struct ExecutionResult {
    bool success{false};
    uint64_t gas_used{0};
    uint64_t gas_refund{0};
    silkworm::Bytes return_data;
    std::vector<silkworm::Log> logs;
    std::string error_message;
    std::optional<evmc::address> contract_address;  // set for CREATE
    EvmTxDisposition disposition{EvmTxDisposition::InvalidPreValidation};
};

/// Execute a single EVM transaction against the workchain state.
///
/// This is the primary entry point for the compute phase adapter.
/// It creates an internal ExecutionProcessor, runs the transaction,
/// and returns a canonical result.
///
/// @param txn     Decoded Ethereum transaction (sender must be recovered).
/// @param block   Block context (from make_evm_block).
/// @param state   Mutable reference to the EVM workchain state.
/// @param config  Chain configuration (from evm_chain_config).
/// @return        Execution result with gas, logs, and return data.
ExecutionResult execute_evm_transaction(
    const silkworm::Transaction& txn,
    const silkworm::Block& block,
    EvmState& state,
    const silkworm::ChainConfig& config);

/// Read-only EVM execution for eth_call / eth_estimateGas.
///
/// Runs the transaction against a snapshot of the state — no state is
/// modified.  Returns the execution result with return data and gas used.
ExecutionResult call_evm_transaction(
    const silkworm::Transaction& txn,
    const silkworm::Block& block,
    const EvmState& state,
    const silkworm::ChainConfig& config);

/// Like call_evm_transaction, but inflates the sender's balance to cover
/// txn.value before execution. Mirrors geth/erigon eth_estimateGas
/// behavior — wallets can estimate gas before holding funds. The override
/// is applied to the IntraBlockState only; the underlying State is not
/// mutated. Pass a non-zero `top_up_to_at_least` to request a balance of
/// at least that amount on the sender.
ExecutionResult call_evm_transaction_with_balance_topup(
    const silkworm::Transaction& txn,
    const silkworm::Block& block,
    const EvmState& state,
    const silkworm::ChainConfig& config);

}  // namespace evm_workchain
