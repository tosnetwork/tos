/*
    EVM Workchain — state adapter implementation.
    Thread-safe with shared_mutex (readers–writer lock).
    Bounded containers with FIFO eviction at capacity limits.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm/core/state.h"
#include "evm/core/cell-state.h"  // dynamic_cast in is_empty()

#include <ethash/keccak.hpp>
#include <silkworm/core/trie/nibbles.hpp>

namespace evm_workchain {

EvmState::EvmState()
    : backend_(std::make_unique<silkworm::InMemoryState>()) {}

EvmState::EvmState(std::unique_ptr<silkworm::State> backend)
    : backend_(std::move(backend)) {}

void EvmState::seed_account(const evmc::address& addr,
                            const intx::uint256& balance,
                            uint64_t nonce) {
    std::unique_lock lock(mutex_);
    silkworm::Account acct;
    acct.balance = balance;
    acct.nonce = nonce;
    backend_->update_account(addr, std::nullopt, acct);
}

bool EvmState::needs_initial_hydration() const {
    std::shared_lock lock(mutex_);
    return needs_initial_hydration_;
}

void EvmState::mark_initial_hydration_done() {
    std::unique_lock lock(mutex_);
    needs_initial_hydration_ = false;
}

bool EvmState::is_empty() const {
    std::shared_lock lock(mutex_);
    // Production path: CellEvmState. The internal account dict's root cell
    // is null iff no accounts are stored.
    if (auto* cs = dynamic_cast<const CellEvmState*>(backend_.get())) {
        return cs->account_dict_root().is_null();
    }
    // Non-cell backend (tests use silkworm::InMemoryState): no public empty
    // check, but the hydration hook only runs in production where the
    // backend is always CellEvmState. Returning false is the safe default
    // (skips hydration in tests).
    return false;
}

intx::uint256 EvmState::get_balance(const evmc::address& addr) const {
    std::shared_lock lock(mutex_);
    auto acct = backend_->read_account(addr);
    return acct ? acct->balance : intx::uint256{0};
}

uint64_t EvmState::get_nonce(const evmc::address& addr) const {
    std::shared_lock lock(mutex_);
    auto acct = backend_->read_account(addr);
    return acct ? acct->nonce : 0;
}

std::optional<silkworm::Account> EvmState::read_account(const evmc::address& addr) const {
    std::shared_lock lock(mutex_);
    return backend_->read_account(addr);
}

silkworm::Bytes EvmState::read_code_copy(const evmc::address& addr, const evmc::bytes32& code_hash) const {
    std::shared_lock lock(mutex_);
    auto code = backend_->read_code(addr, code_hash);
    return silkworm::Bytes{code.begin(), code.end()};
}

evmc::bytes32 EvmState::read_storage_copy(const evmc::address& addr, uint64_t incarnation,
                                          const evmc::bytes32& location) const {
    std::shared_lock lock(mutex_);
    return backend_->read_storage(addr, incarnation, location);
}

// --- Block tracking ---

uint64_t EvmState::block_number() const noexcept {
    std::shared_lock lock(mutex_);
    return block_number_;
}

void EvmState::set_block_number(uint64_t n) noexcept {
    std::unique_lock lock(mutex_);
    block_number_ = n;
}

void EvmState::increment_block_number() noexcept {
    std::unique_lock lock(mutex_);
    ++block_number_;
}

uint64_t EvmState::allocate_next_block_number(std::optional<StoredBlock>& parent_block) noexcept {
    std::unique_lock lock(mutex_);
    ++block_number_;
    auto it = blocks_.find(block_number_ - 1);
    if (it != blocks_.end()) {
        parent_block = it->second;
    } else {
        parent_block.reset();
    }
    return block_number_;
}

// --- Block chain (bounded: kMaxCachedBlocks) ---

void EvmState::store_block(const StoredBlock& block) {
    std::unique_lock lock(mutex_);
    blocks_[block.number] = block;
    hash_to_block_[block.hash] = block.number;
    // Head tracking: every successful store_block advances block_number_ so
    // that eth_blockNumber tracks the highest block we've ever seen. Covers:
    //   * compute-phase live execution (collator + validate-block re-run)
    //   * RPC cache hydration on startup (replays stored blocks)
    //   * sync-path test harness (handle_send_raw_transaction)
    // Monotonic max — out-of-order calls (e.g. a stray older block) never
    // walk the head backwards. Without this hook the field only advances
    // when handle_send_raw_transaction's allocate_next_block_number runs,
    // which never fires on the validator (sendRawTransaction is intercepted
    // by the JSON-RPC server and routed through the ExtMessagePool); the
    // result is eth_blockNumber == 0 even after txs mine into wc=1 blocks.
    if (block.number > block_number_) {
        block_number_ = block.number;
    }
    while (blocks_.size() > kMaxCachedBlocks) {
        auto oldest = blocks_.begin();
        hash_to_block_.erase(oldest->second.hash);
        block_logs_.erase(oldest->first);  // also evict logs for this block
        blocks_.erase(oldest);
    }
}

const StoredBlock* EvmState::get_block(uint64_t block_num) const {
    // No lock — caller must hold shared_lock or unique_lock
    auto it = blocks_.find(block_num);
    return it != blocks_.end() ? &it->second : nullptr;
}

StoredBlock EvmState::get_block_copy(uint64_t block_num) const {
    std::shared_lock lock(mutex_);
    auto it = blocks_.find(block_num);
    return it != blocks_.end() ? it->second : StoredBlock{};
}

bool EvmState::has_block(uint64_t block_num) const {
    std::shared_lock lock(mutex_);
    return blocks_.count(block_num) > 0;
}

const StoredBlock* EvmState::get_block_by_hash(const evmc::bytes32& hash) const {
    // No lock — caller must hold lock
    auto it = hash_to_block_.find(hash);
    if (it == hash_to_block_.end()) return nullptr;
    return get_block(it->second);
}

StoredBlock EvmState::get_block_by_hash_copy(const evmc::bytes32& hash) const {
    std::shared_lock lock(mutex_);
    auto it = hash_to_block_.find(hash);
    if (it == hash_to_block_.end()) return StoredBlock{};
    auto bit = blocks_.find(it->second);
    return bit != blocks_.end() ? bit->second : StoredBlock{};
}

evmc::bytes32 EvmState::get_block_hash(uint64_t block_num) const {
    std::shared_lock lock(mutex_);
    auto it = blocks_.find(block_num);
    return it != blocks_.end() ? it->second.hash : evmc::bytes32{};
}

// --- Receipt storage (bounded: kMaxCachedReceipts) ---

void EvmState::evict_oldest_receipts() {
    while (receipts_.size() > kMaxCachedReceipts && !receipt_insertion_order_.empty()) {
        receipts_.erase(receipt_insertion_order_.front());
        receipt_insertion_order_.erase(receipt_insertion_order_.begin());
    }
}

void EvmState::store_receipt(const evmc::bytes32& tx_hash, StoredReceipt receipt) {
    std::unique_lock lock(mutex_);
    // First-write-wins: g_evm_state is shared between the collator's
    // authoritative execution and validate-query's verification re-run. The
    // re-run sees post-state (nonce already incremented) and would record a
    // failed receipt that overwrites the real one. The collator always wins
    // the race because it executes first; subsequent stores for the same hash
    // are silently dropped.
    if (receipts_.find(tx_hash) != receipts_.end()) {
        return;
    }
    receipt_insertion_order_.push_back(tx_hash);
    receipts_[tx_hash] = std::move(receipt);
    evict_oldest_receipts();
}

const StoredReceipt* EvmState::get_receipt(const evmc::bytes32& tx_hash) const {
    std::shared_lock lock(mutex_);
    auto it = receipts_.find(tx_hash);
    return it != receipts_.end() ? &it->second : nullptr;
}

std::optional<StoredReceipt> EvmState::get_receipt_copy(const evmc::bytes32& tx_hash) const {
    std::shared_lock lock(mutex_);
    auto it = receipts_.find(tx_hash);
    if (it == receipts_.end()) {
        return std::nullopt;
    }
    return it->second;
}

// --- Transaction storage (bounded: kMaxCachedTransactions) ---

void EvmState::evict_oldest_transactions() {
    while (transactions_.size() > kMaxCachedTransactions && !transaction_insertion_order_.empty()) {
        transactions_.erase(transaction_insertion_order_.front());
        transaction_insertion_order_.erase(transaction_insertion_order_.begin());
    }
}

void EvmState::store_transaction(const evmc::bytes32& tx_hash, StoredTransaction tx) {
    std::unique_lock lock(mutex_);
    if (transactions_.find(tx_hash) == transactions_.end()) {
        transaction_insertion_order_.push_back(tx_hash);
    }
    transactions_[tx_hash] = std::move(tx);
    evict_oldest_transactions();
}

const StoredTransaction* EvmState::get_transaction(const evmc::bytes32& tx_hash) const {
    std::shared_lock lock(mutex_);
    auto it = transactions_.find(tx_hash);
    return it != transactions_.end() ? &it->second : nullptr;
}

std::optional<StoredTransaction> EvmState::get_transaction_copy(const evmc::bytes32& tx_hash) const {
    std::shared_lock lock(mutex_);
    auto it = transactions_.find(tx_hash);
    if (it == transactions_.end()) {
        return std::nullopt;
    }
    return it->second;
}

// --- Log index (bounded: kMaxCachedLogBlocks) ---

void EvmState::evict_oldest_log_blocks() {
    while (block_logs_.size() > kMaxCachedLogBlocks) {
        block_logs_.erase(block_logs_.begin());
    }
}

void EvmState::store_logs(uint64_t block_number, const evmc::bytes32& tx_hash,
                          const std::vector<silkworm::Log>& logs,
                          uint32_t tx_index) {
    std::unique_lock lock(mutex_);
    auto& block_log_vec = block_logs_[block_number];
    for (uint32_t i = 0; i < logs.size(); ++i) {
        block_log_vec.push_back(IndexedLog{
            .block_number = block_number,
            .tx_hash = tx_hash,
            .log_index = static_cast<uint32_t>(block_log_vec.size()),
            .tx_index = tx_index,
            .log = logs[i],
        });
    }
    evict_oldest_log_blocks();
}

static bool matches_address(const silkworm::Log& log,
                             const std::vector<evmc::address>& addresses) {
    if (addresses.empty()) return true;
    for (const auto& addr : addresses) {
        if (log.address == addr) return true;
    }
    return false;
}

static bool matches_topics(const silkworm::Log& log,
                            const std::vector<std::vector<evmc::bytes32>>& topic_filters) {
    for (size_t i = 0; i < topic_filters.size(); ++i) {
        const auto& filter_set = topic_filters[i];
        if (filter_set.empty()) continue;
        if (i >= log.topics.size()) return false;
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

    std::shared_lock lock(mutex_);
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

std::vector<IndexedLog> EvmState::get_logs_for_block_copy(uint64_t block_number) const {
    std::shared_lock lock(mutex_);
    auto it = block_logs_.find(block_number);
    if (it == block_logs_.end()) return {};
    return it->second;
}

// --- Change tracking for incremental trie ---

void EvmState::track_account_change(const evmc::address& addr) {
    // Compute keccak256(address) and convert to nibbles for PrefixSet.
    // NOTE: no locking here — caller must hold unique_lock (e.g. execute_evm_transaction),
    // or call from a single-threaded context (e.g. handle_send_raw_transaction).
    auto hashed = ethash::keccak256(addr.bytes, 20);
    silkworm::Bytes hash_bytes(hashed.bytes, hashed.bytes + 32);
    silkworm::Bytes nibbled = silkworm::trie::unpack_nibbles(hash_bytes);
    account_changes_.insert(std::move(nibbled));
}

void EvmState::track_storage_change(const evmc::address& addr, const evmc::bytes32& slot) {
    // For storage changes we track the combined nibbled key:
    // nibbles(keccak256(address)) + nibbles(keccak256(slot))
    auto addr_hash = ethash::keccak256(addr.bytes, 20);
    auto slot_hash = ethash::keccak256(slot.bytes, 32);

    silkworm::Bytes addr_bytes(addr_hash.bytes, addr_hash.bytes + 32);
    silkworm::Bytes slot_bytes(slot_hash.bytes, slot_hash.bytes + 32);

    silkworm::Bytes nibbled_addr = silkworm::trie::unpack_nibbles(addr_bytes);
    silkworm::Bytes nibbled_slot = silkworm::trie::unpack_nibbles(slot_bytes);

    // Combine: the storage PrefixSet key is nibbled_addr + nibbled_slot
    silkworm::Bytes combined;
    combined.reserve(nibbled_addr.size() + nibbled_slot.size());
    combined.insert(combined.end(), nibbled_addr.begin(), nibbled_addr.end());
    combined.insert(combined.end(), nibbled_slot.begin(), nibbled_slot.end());

    // No locking — caller must hold unique_lock or be in single-threaded context.
    storage_changes_.insert(std::move(combined));
}

void EvmState::clear_change_tracking() {
    // No locking — caller must hold unique_lock or be in single-threaded context.
    account_changes_.clear();
    storage_changes_.clear();
}

}  // namespace evm_workchain
