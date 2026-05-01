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
#include "evm/core/executor.h"
#include "evm/core/cell-state.h"

#include <exception>
#include <limits>
#include <optional>
#include <utility>

#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/protocol/intrinsic_gas.hpp>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/protocol/validation.hpp>
#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/core/types/address.hpp>

namespace evm_workchain {

namespace {

ExecutionResult make_infrastructure_error(std::string where, const char* message) {
    ExecutionResult result;
    result.success = false;
    result.gas_used = 0;
    result.error_message = std::move(where);
    result.error_message += ": ";
    result.error_message += (message != nullptr ? message : "<no message>");
    result.disposition = EvmTxDisposition::InvalidPreValidation;
    return result;
}

ExecutionResult make_infrastructure_error(std::string where, const std::exception& e) {
    return make_infrastructure_error(std::move(where), e.what());
}

std::optional<std::string> prevalidate_evm_transaction_admission_locked(
    const silkworm::Transaction& txn,
    const silkworm::Block& block,
    silkworm::IntraBlockState& state,
    const silkworm::ChainConfig& config) {

    auto sender_opt = txn.sender();
    if (!sender_opt) {
        return "sender not recovered";
    }
    const auto& sender = *sender_opt;
    const auto rev = config.revision(block.header.number, block.header.timestamp);

    if (txn.chain_id.has_value() &&
        *txn.chain_id != intx::uint256{config.chain_id}) {
        return "wrong chain id";
    }

    if (txn.type == silkworm::TransactionType::kBlob) {
        return "blob transactions not supported on this chain";
    }

    if (auto vr_base = silkworm::protocol::pre_validate_common_base(
            txn, rev, config.chain_id);
        vr_base != silkworm::ValidationResult::kOk) {
        return "pre_validate_common_base failed";
    }
    if (auto vr_forks = silkworm::protocol::pre_validate_common_forks(
            txn, rev, /*blob_gas_price=*/std::nullopt);
        vr_forks != silkworm::ValidationResult::kOk) {
        return "pre_validate_common_forks failed";
    }

    if (rev >= EVMC_LONDON) {
        auto sender_code_hash = state.get_code_hash(sender);
        if (sender_code_hash != silkworm::kEmptyHash &&
            sender_code_hash != evmc::bytes32{}) {
            bool allowed_by_eip7702 = false;
            if (rev >= EVMC_PRAGUE) {
                auto code = state.get_code(sender);
                allowed_by_eip7702 = silkworm::eip7702::is_code_delegated(code);
            }
            if (!allowed_by_eip7702) {
                return "EIP-3607: sender has code";
            }
        }
    }

    if (rev >= EVMC_LONDON &&
        txn.type != silkworm::TransactionType::kLegacy &&
        txn.max_priority_fee_per_gas > txn.max_fee_per_gas) {
        return "priority fee exceeds max fee";
    }

    const intx::uint256 bf = block.header.base_fee_per_gas.value_or(0);
    if (rev >= EVMC_LONDON && txn.max_fee_per_gas < bf) {
        return "max fee per gas below base fee";
    }

    if (txn.gas_limit > block.header.gas_limit) {
        return "tx gas limit exceeds block gas limit";
    }

    auto intrinsic_pre = silkworm::protocol::intrinsic_gas(txn, rev);
    if (intrinsic_pre > static_cast<intx::uint128>(txn.gas_limit)) {
        return "intrinsic gas exceeds gas limit";
    }

    uint64_t sender_nonce = state.get_nonce(sender);
    if (sender_nonce != txn.nonce) {
        return "nonce mismatch: expected " + std::to_string(sender_nonce) +
               ", got " + std::to_string(txn.nonce);
    }
    if (sender_nonce == std::numeric_limits<uint64_t>::max()) {
        return "EIP-2681: nonce at max";
    }

    const intx::uint256 max_gas_price = (rev >= EVMC_LONDON &&
                                           txn.type != silkworm::TransactionType::kLegacy)
        ? txn.max_fee_per_gas
        : txn.effective_gas_price(bf);
    intx::uint512 max_cost = intx::uint512{txn.gas_limit} * intx::uint512{max_gas_price} +
                              intx::uint512{txn.value};
    if (rev >= EVMC_CANCUN &&
        txn.type == silkworm::TransactionType::kBlob) {
        max_cost += intx::uint512{txn.total_blob_gas()} *
                    intx::uint512{txn.max_fee_per_blob_gas};
    }
    if (intx::uint512{state.get_balance(sender)} < max_cost) {
        return "insufficient funds for gas + value";
    }

    if (rev >= EVMC_CANCUN &&
        txn.type == silkworm::TransactionType::kBlob) {
        const auto blob_price = block.header.blob_gas_price().value_or(0);
        if (txn.max_fee_per_blob_gas < blob_price) {
            return "max fee per blob gas below blob base fee";
        }
        if (txn.blob_versioned_hashes.empty()) {
            return "blob tx must carry at least one blob";
        }
        constexpr uint8_t kKzgVersionedHash = 0x01;
        for (const auto& h : txn.blob_versioned_hashes) {
            if (h.bytes[0] != kKzgVersionedHash) {
                return "blob versioned hash has wrong version byte";
            }
        }
    }

    return std::nullopt;
}

}  // namespace

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
        // Security hardening round 1 (H-01): chain-id binding. `eth_sendRawTransaction`
        // already rejects wrong chain_id at the RPC layer, but consensus
        // also accepts ext_in_msgs via `sendBoc` / liteServer that bypass
        // the RPC. Without this check a foreign-chain tx (signed for
        // mainnet, replayed onto TOS-EVM with the same key/nonce) would
        // execute on wc=1 and bypass EIP-155 replay protection. Pre-EIP-155
        // legacy txs (chain_id = nullopt) remain accepted — by spec they
        // are not bound to any chain and Silkworm only enforces the equality
        // when `chain_id.has_value()`.
        if (txn.chain_id.has_value() &&
            *txn.chain_id != intx::uint256{config.chain_id}) {
            result.error_message = "wrong chain id";
            result.gas_used = 0;
            return result;
        }

        // Security hardening round 1 (H-01): consensus has no blob mempool — type-3
        // (EIP-4844) txs cannot be admitted at this layer. The RPC
        // gateway rejects them too, but a raw-BOC ingress path could
        // otherwise smuggle a blob tx into compute, where the executor
        // has no blob_versioned_hashes side-channel. Reject explicitly.
        if (txn.type == silkworm::TransactionType::kBlob) {
            result.error_message = "blob transactions not supported on this chain";
            result.gas_used = 0;
            return result;
        }

        // Security hardening round 2 (H-03): the RPC `eth_sendRawTransaction` admission
        // path runs Silkworm's `pre_validate_common_base()` /
        // `pre_validate_common_forks()` against every accepted tx, but
        // raw-BOC ingress (`sendBoc` / liteServer-sendMessage → wc=1
        // executor) bypasses RPC and lands directly in compute. Without
        // these calls here, the consensus executor admits txs that RPC
        // correctly rejects: EIP-3860 oversized initcode (Shanghai+),
        // EIP-7702 SetCode tx with empty authorizations OR with
        // contract-creation `to=null` (Prague+), EIP-7623 floor-cost
        // violations (Prague+), EIP-7825 per-tx gas cap > 2^24 (Osaka+),
        // unsupported transaction types at the current revision, and
        // `maximum_gas_cost()` 256-bit overflow.
        //
        // Order of checks: our explicit blob rejection runs first
        // because `pre_validate_common_forks` invokes
        // `SILKWORM_ASSERT(blob_gas_price)` for type-3 txs (we pass
        // `nullopt` for blob_gas_price — there is no blob mempool).
        if (auto vr_base = silkworm::protocol::pre_validate_common_base(
                txn, rev, config.chain_id);
            vr_base != silkworm::ValidationResult::kOk) {
            result.error_message = "pre_validate_common_base failed";
            result.gas_used = 0;
            return result;
        }
        if (auto vr_forks = silkworm::protocol::pre_validate_common_forks(
                txn, rev, /*blob_gas_price=*/std::nullopt);
            vr_forks != silkworm::ValidationResult::kOk) {
            result.error_message = "pre_validate_common_forks failed";
            result.gas_used = 0;
            return result;
        }

        // EIP-3607 (London+): reject txs from accounts that have code.
        // EIP-7702 (Prague+) exempts accounts whose code is a delegation
        // designator (0xef 0x01 0x00 || address).
        if (rev >= EVMC_LONDON) {
            auto sender_code_hash = state.get_code_hash(sender);
            if (sender_code_hash != silkworm::kEmptyHash &&
                sender_code_hash != evmc::bytes32{}) {
                bool allowed_by_eip7702 = false;
                if (rev >= EVMC_PRAGUE) {
                    auto code = state.get_code(sender);
                    allowed_by_eip7702 = silkworm::eip7702::is_code_delegated(code);
                }
                if (!allowed_by_eip7702) {
                    result.error_message = "EIP-3607: sender has code";
                    result.gas_used = 0;
                    return result;
                }
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

        // EIP-1559 + EIP-4844 balance check. Sender must afford:
        //   gas_limit * max_fee_per_gas
        //   + total_blob_gas * max_fee_per_blob_gas   (EIP-4844)
        //   + value
        // even if the effective gas/blob prices end up lower.
        const intx::uint256 max_gas_price = (rev >= EVMC_LONDON &&
                                               txn.type != silkworm::TransactionType::kLegacy)
            ? txn.max_fee_per_gas
            : txn.effective_gas_price(bf);
        intx::uint512 max_cost = intx::uint512{txn.gas_limit} * intx::uint512{max_gas_price} +
                                  intx::uint512{txn.value};
        if (rev >= EVMC_CANCUN &&
            txn.type == silkworm::TransactionType::kBlob) {
            max_cost += intx::uint512{txn.total_blob_gas()} *
                        intx::uint512{txn.max_fee_per_blob_gas};
        }
        if (intx::uint512{state.get_balance(sender)} < max_cost) {
            result.error_message = "insufficient funds for gas + value";
            result.gas_used = 0;
            return result;
        }

        // EIP-4844 blob-tx pre-validation suite.
        if (rev >= EVMC_CANCUN &&
            txn.type == silkworm::TransactionType::kBlob) {
            // 1. max_fee_per_blob_gas must cover the current blob
            //    base fee; otherwise the tx underpays the burn.
            const auto blob_price = block.header.blob_gas_price().value_or(0);
            if (txn.max_fee_per_blob_gas < blob_price) {
                result.error_message = "max fee per blob gas below blob base fee";
                result.gas_used = 0;
                return result;
            }
            // 2. A blob (type-3) tx must have ≥ 1 blob hash.
            //    Pyspec: TransactionException.TYPE_3_TX_ZERO_BLOBS
            if (txn.blob_versioned_hashes.empty()) {
                result.error_message = "blob tx must carry at least one blob";
                result.gas_used = 0;
                return result;
            }
            // 3. Each versioned hash's first byte must be the KZG
            //    version marker (0x01).
            //    Pyspec: TransactionException.TYPE_3_TX_INVALID_BLOB_VERSIONED_HASH
            constexpr uint8_t kKzgVersionedHash = 0x01;
            for (const auto& h : txn.blob_versioned_hashes) {
                if (h.bytes[0] != kKzgVersionedHash) {
                    result.error_message = "blob versioned hash has wrong version byte";
                    result.gas_used = 0;
                    return result;
                }
            }
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

    // 1b. EIP-4844: deduct the blob-data fee. blob_gas_price is the
    // current blob base fee (computed from excess_blob_gas via
    // fake_exponential). The full blob_fee is **burned** — it is
    // never credited back to the sender (no refund on revert) and
    // never paid to the beneficiary. Only applicable to blob-type
    // txs (TransactionType::kBlob) when the chain is at Cancun+.
    if (rev >= EVMC_CANCUN &&
        txn.type == silkworm::TransactionType::kBlob &&
        !txn.blob_versioned_hashes.empty()) {
        const intx::uint256 blob_gas_price = block.header.blob_gas_price().value_or(0);
        const intx::uint256 blob_fee = intx::uint256{txn.total_blob_gas()} * blob_gas_price;
        state.subtract_from_balance(sender, blob_fee);
    }

    // 2. Increment sender nonce (CALL only; CREATE increments internally).
    if (txn.to.has_value()) {
        state.set_nonce(sender, state.get_nonce(sender) + 1);
    }

    // 2b. EIP-7702 (Prague+): process the authorization list. Per evmone's
    // state::transition (state.cpp:571–574), this runs AFTER the sender's
    // nonce is bumped but BEFORE the EVM runs. For each authorization:
    //   1. chain_id is 0 or matches the chain
    //   2. authority is recovered from the ECDSA signature
    //   3. authority has no code (or already has a delegation designator)
    //   4. authority.nonce matches auth.nonce  (for self-delegation, this
    //      value is sender's bumped nonce)
    //   5. set authority code to 0xef0100 || auth.address (23-byte
    //      delegation designator)
    //   6. increment authority.nonce
    if (commit_state && rev >= EVMC_PRAGUE &&
        txn.type == silkworm::TransactionType::kSetCode) {
        for (const auto& auth : txn.authorizations) {
            if (auth.chain_id != 0 && auth.chain_id != intx::uint256{config.chain_id}) continue;
            if (auth.nonce == std::numeric_limits<uint64_t>::max()) continue;
            auto authority_opt = auth.recover_authority(txn);
            if (!authority_opt) continue;
            const auto& authority = *authority_opt;

            // Existing code must be empty or already-delegated.
            auto code_hash = state.get_code_hash(authority);
            if (code_hash != silkworm::kEmptyHash && code_hash != evmc::bytes32{}) {
                auto existing = state.get_code(authority);
                if (!silkworm::eip7702::is_code_delegated(existing)) continue;
            }

            const uint64_t cur_nonce = state.get_nonce(authority);
            if (cur_nonce != auth.nonce) continue;

            silkworm::Bytes designation;
            designation.reserve(23);
            designation.push_back(0xef);
            designation.push_back(0x01);
            designation.push_back(0x00);
            designation.insert(designation.end(),
                               auth.address.bytes, auth.address.bytes + 20);
            state.set_nonce(authority, cur_nonce + 1);
            state.set_code(authority, silkworm::ByteView{designation.data(), designation.size()});
        }
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
    // Audit #2: any path that reaches the EVM execute() call has passed
    // pre-validation, so the result is either ExecutedSucceeded or
    // ExecutedReverted. Pre-validation failures early-return above and
    // keep the default InvalidPreValidation.
    result.disposition = result.success ? EvmTxDisposition::ExecutedSucceeded
                                        : EvmTxDisposition::ExecutedReverted;
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

    try {
        std::unique_lock lock(evm_state.mutex());

        silkworm::IntraBlockState ibs(evm_state.state());
        auto result = run_evm(txn, block, ibs, config, /*commit_state=*/true);

        return result;
    } catch (const std::exception& e) {
        return make_infrastructure_error("EVM execution threw", e);
    } catch (...) {
        return make_infrastructure_error("EVM execution threw", "unknown exception");
    }
}

std::optional<std::string> prevalidate_evm_transaction_admission(
    const silkworm::Transaction& txn,
    const silkworm::Block& block,
    const EvmState& evm_state,
    const silkworm::ChainConfig& config) {

    try {
        std::unique_lock lock(evm_state.mutex());
        auto& mutable_state = const_cast<silkworm::State&>(evm_state.state());
        silkworm::IntraBlockState ibs(mutable_state);
        return prevalidate_evm_transaction_admission_locked(txn, block, ibs, config);
    } catch (const std::exception& e) {
        return std::string("EVM prevalidation threw: ") + e.what();
    } catch (...) {
        return std::string("EVM prevalidation threw: unknown exception");
    }
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
    try {
        std::unique_lock lock(evm_state.mutex());
        auto& mutable_state = const_cast<silkworm::State&>(evm_state.state());
        silkworm::IntraBlockState ibs(mutable_state);
        return run_evm(txn, block, ibs, config, /*commit_state=*/false);
    } catch (const std::exception& e) {
        return make_infrastructure_error("EVM read-only call threw", e);
    } catch (...) {
        return make_infrastructure_error("EVM read-only call threw", "unknown exception");
    }
}

ExecutionResult call_evm_transaction_with_balance_topup(
    const silkworm::Transaction& txn,
    const silkworm::Block& block,
    const EvmState& evm_state,
    const silkworm::ChainConfig& config) {

    try {
        std::unique_lock lock(evm_state.mutex());
        auto& mutable_state = const_cast<silkworm::State&>(evm_state.state());
        silkworm::IntraBlockState ibs(mutable_state);

        auto sender_opt = txn.sender();
        if (sender_opt) {
            // Need balance >= value (gas cost is already 0 because the call
            // path zeroes out max_fee_per_gas / max_priority_fee_per_gas).
            const intx::uint256 needed = txn.value;
            if (needed > 0) {
                const auto current = ibs.get_balance(*sender_opt);
                if (current < needed) {
                    ibs.add_to_balance(*sender_opt, needed - current);
                }
            }
        }
        return run_evm(txn, block, ibs, config, /*commit_state=*/false);
    } catch (const std::exception& e) {
        return make_infrastructure_error("EVM balance-topup call threw", e);
    } catch (...) {
        return make_infrastructure_error("EVM balance-topup call threw", "unknown exception");
    }
}

}  // namespace evm_workchain
