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

void EvmState::store_receipt(const evmc::bytes32& tx_hash, StoredReceipt receipt) {
    receipts_[tx_hash] = std::move(receipt);
}

const StoredReceipt* EvmState::get_receipt(const evmc::bytes32& tx_hash) const {
    auto it = receipts_.find(tx_hash);
    return it != receipts_.end() ? &it->second : nullptr;
}

}  // namespace evm_workchain
