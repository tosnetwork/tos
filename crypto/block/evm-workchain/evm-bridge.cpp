/*
    EVM Workchain — cross-workchain asset bridge implementation.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm-bridge.h"

#include "td/utils/logging.h"

namespace evm_workchain {

static std::vector<WithdrawalRequest> g_pending_withdrawals;

bool bridge_deposit(EvmState& state,
                    const evmc::address& to,
                    const intx::uint256& amount) {
    if (amount == 0) return false;

    auto current_balance = state.get_balance(to);
    auto current_nonce = state.get_nonce(to);

    // Credit the account: update_account with new balance
    silkworm::Account acct;
    acct.balance = current_balance + amount;
    acct.nonce = current_nonce;

    // Read existing account to get code_hash etc.
    auto existing = state.state().read_account(to);
    if (existing) {
        acct.code_hash = existing->code_hash;
        acct.incarnation = existing->incarnation;
    }

    state.state().update_account(to, existing, acct);

    LOG(INFO) << "evm-bridge: deposit " << intx::to_string(amount)
              << " wei to 0x" << std::hex;
    for (auto b : to.bytes) LOG(INFO) << std::hex << (int)b;

    return true;
}

const std::vector<WithdrawalRequest>& get_pending_withdrawals() {
    return g_pending_withdrawals;
}

void record_withdrawal(const evmc::address& evm_sender,
                       const std::string& basechain_dest,
                       const intx::uint256& amount,
                       uint64_t block_number,
                       const evmc::bytes32& tx_hash) {
    g_pending_withdrawals.push_back(WithdrawalRequest{
        .evm_sender = evm_sender,
        .basechain_dest = basechain_dest,
        .amount = amount,
        .block_number = block_number,
        .tx_hash = tx_hash,
    });

    LOG(INFO) << "evm-bridge: withdrawal request recorded, "
              << intx::to_string(amount) << " wei, "
              << g_pending_withdrawals.size() << " pending";
}

void clear_withdrawals() {
    g_pending_withdrawals.clear();
}

}  // namespace evm_workchain
