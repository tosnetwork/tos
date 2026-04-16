/*
    EVM Workchain — state adapter implementation.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm-state.h"

namespace evm_workchain {

EvmState::EvmState()
    : backend_(std::make_unique<silkworm::InMemoryState>()) {}

EvmState::EvmState(std::unique_ptr<silkworm::State> backend)
    : backend_(std::move(backend)) {}

void EvmState::seed_account(const evmc::address& addr,
                            const intx::uint256& balance,
                            uint64_t nonce) {
    silkworm::Account acct;
    acct.balance = balance;
    acct.nonce = nonce;
    backend_->update_account(addr, /*initial=*/std::nullopt, acct);
}

intx::uint256 EvmState::get_balance(const evmc::address& addr) const {
    auto acct = backend_->read_account(addr);
    return acct ? acct->balance : intx::uint256{0};
}

uint64_t EvmState::get_nonce(const evmc::address& addr) const {
    auto acct = backend_->read_account(addr);
    return acct ? acct->nonce : 0;
}

// --- Block chain ---

void EvmState::store_block(const StoredBlock& block) {
    blocks_[block.number] = block;
    hash_to_block_[block.hash] = block.number;
    // Keep only last 256 blocks for BLOCKHASH
    while (blocks_.size() > 256) {
        auto oldest = blocks_.begin();
        hash_to_block_.erase(oldest->second.hash);
        blocks_.erase(oldest);
    }
}

const StoredBlock* EvmState::get_block(uint64_t block_num) const {
    auto it = blocks_.find(block_num);
    return it != blocks_.end() ? &it->second : nullptr;
}

const StoredBlock* EvmState::get_block_by_hash(const evmc::bytes32& hash) const {
    auto it = hash_to_block_.find(hash);
    if (it == hash_to_block_.end()) return nullptr;
    return get_block(it->second);
}

evmc::bytes32 EvmState::get_block_hash(uint64_t block_num) const {
    auto blk = get_block(block_num);
    return blk ? blk->hash : evmc::bytes32{};
}

// --- Receipt storage ---

void EvmState::store_receipt(const evmc::bytes32& tx_hash, StoredReceipt receipt) {
    receipts_[tx_hash] = std::move(receipt);
}

const StoredReceipt* EvmState::get_receipt(const evmc::bytes32& tx_hash) const {
    auto it = receipts_.find(tx_hash);
    return it != receipts_.end() ? &it->second : nullptr;
}

// --- Transaction storage ---

void EvmState::store_transaction(const evmc::bytes32& tx_hash, StoredTransaction tx) {
    transactions_[tx_hash] = std::move(tx);
}

const StoredTransaction* EvmState::get_transaction(const evmc::bytes32& tx_hash) const {
    auto it = transactions_.find(tx_hash);
    return it != transactions_.end() ? &it->second : nullptr;
}

// --- Log index ---

void EvmState::store_logs(uint64_t block_number, const evmc::bytes32& tx_hash,
                          const std::vector<silkworm::Log>& logs) {
    auto& block_log_vec = block_logs_[block_number];
    for (uint32_t i = 0; i < logs.size(); ++i) {
        block_log_vec.push_back(IndexedLog{
            .block_number = block_number,
            .tx_hash = tx_hash,
            .log_index = static_cast<uint32_t>(block_log_vec.size()),
            .log = logs[i],
        });
    }
}

static bool matches_address(const silkworm::Log& log,
                             const std::vector<evmc::address>& addresses) {
    if (addresses.empty()) return true;  // no filter = match all
    for (const auto& addr : addresses) {
        if (log.address == addr) return true;
    }
    return false;
}

static bool matches_topics(const silkworm::Log& log,
                            const std::vector<std::vector<evmc::bytes32>>& topic_filters) {
    for (size_t i = 0; i < topic_filters.size(); ++i) {
        const auto& filter_set = topic_filters[i];
        if (filter_set.empty()) continue;  // empty = match any at this position
        if (i >= log.topics.size()) return false;  // log doesn't have this topic position
        bool found = false;
        for (const auto& acceptable : filter_set) {
            if (log.topics[i] == acceptable) { found = true; break; }
        }
        if (!found) return false;
    }
    return true;
}

std::vector<IndexedLog> EvmState::get_logs(
    uint64_t from_block, uint64_t to_block,
    const std::vector<evmc::address>& addresses,
    const std::vector<std::vector<evmc::bytes32>>& topics) const {

    std::vector<IndexedLog> result;
    auto it_begin = block_logs_.lower_bound(from_block);
    auto it_end = block_logs_.upper_bound(to_block);

    for (auto it = it_begin; it != it_end; ++it) {
        for (const auto& indexed_log : it->second) {
            if (matches_address(indexed_log.log, addresses) &&
                matches_topics(indexed_log.log, topics)) {
                result.push_back(indexed_log);
            }
        }
    }
    return result;
}

}  // namespace evm_workchain
