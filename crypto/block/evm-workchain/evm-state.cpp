/*
    EVM Workchain — state adapter implementation.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm-state.h"

namespace evm_workchain {

void EvmState::seed_account(const evmc::address& addr,
                            const intx::uint256& balance,
                            uint64_t nonce) {
    silkworm::Account acct;
    acct.balance = balance;
    acct.nonce = nonce;
    state_.update_account(addr, /*initial=*/std::nullopt, acct);
}

intx::uint256 EvmState::get_balance(const evmc::address& addr) const {
    auto acct = state_.read_account(addr);
    return acct ? acct->balance : intx::uint256{0};
}

uint64_t EvmState::get_nonce(const evmc::address& addr) const {
    auto acct = state_.read_account(addr);
    return acct ? acct->nonce : 0;
}

}  // namespace evm_workchain
