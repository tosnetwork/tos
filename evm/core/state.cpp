/*
    EVM Workchain — state adapter implementation.
    Thread-safe with shared_mutex (readers–writer lock).
    Bounded containers with FIFO eviction at capacity limits.
    Source: TOS-specific adapter (not copied from ~/s).
*/
#include "evm/core/state.h"
#include "evm/core/cell-state.h"  // dynamic_cast in is_empty()

#include <ethash/keccak.hpp>

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

td::Result<silkworm::Bytes> EvmState::read_code_copy_checked(
    const evmc::address& addr, const evmc::bytes32& code_hash) const {
    // Audit H-01: enforce the canonical Ethereum invariant
    // `keccak(code) == account.codeHash` on every checked code read.
    // `eth_getCode` is the production path that this guards: a corrupt
    // import / state sync / disk bit-flip that mutates the per-account
    // bytecode cell (without updating `code_hash`) would otherwise
    // surface the wrong code to wallets and contracts that consult the
    // RPC. The lazy-decode hook inside CellEvmState already records a
    // witness error during executing transactions; here we map the
    // mismatch to a `td::Status::Error` so the RPC handler can return
    // a deterministic JSON-RPC error rather than the wrong code.
    std::shared_lock lock(mutex_);
    if (code_hash == silkworm::kEmptyHash) {
        return silkworm::Bytes{};
    }
    auto code = backend_->read_code(addr, code_hash);
    silkworm::Bytes copy{code.begin(), code.end()};
    if (copy.empty()) {
        // The flat-state account either has no code cell or the lazy
        // decode rejected a structurally invalid one. Both cases must
        // surface as an error here so a corrupt code root never appears
        // as canonical empty code on the RPC.
        return td::Status::Error(
            "corrupt EVM code root: keccak(code) != codeHash");
    }
    auto actual = ethash::keccak256(copy.data(), copy.size());
    evmc::bytes32 actual_hash{};
    std::memcpy(actual_hash.bytes, actual.bytes, sizeof(actual_hash.bytes));
    if (actual_hash != code_hash) {
        return td::Status::Error(
            "corrupt EVM code root: keccak(code) != codeHash");
    }
    return copy;
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
    // Round 86 MEDIUM fix: erase any prior hash → number mapping for
    // this block height before installing the new block.  Pre-fix,
    // when a block at height N was rewritten with a different hash,
    // the old `hash_to_block_[old_hash]` entry stayed alive and
    // `get_block_by_hash_copy(old_hash)` returned the NEW block at
    // height N — RPC handlers like
    // `eth_getBlockTransactionCountByHash`,
    // `eth_getTransactionByBlockHashAndIndex`, and
    // `eth_getRawTransactionByBlockHashAndIndex` (which do not
    // re-verify the hash) thus served the new block under the old
    // hash.
    auto prev_it = blocks_.find(block.number);
    if (prev_it != blocks_.end()) {
        hash_to_block_.erase(prev_it->second.hash);
    }
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
    auto it = receipts_.find(tx_hash);
    if (it != receipts_.end()) {
        // Already-present overwrite — last-write-wins semantically. Under
        // the snapshot-pure compute path the post-accept apply layer
        // dedupes on (block, tx_hash) so this branch is normally not
        // entered; if it is (e.g. cache-hydration replay during init),
        // both writes carry the same payload by construction.
        it->second = std::move(receipt);
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

void EvmState::reset_block_logs(uint64_t block_number) {
    std::unique_lock lock(mutex_);
    block_logs_.erase(block_number);
}

std::size_t EvmState::reconcile_blocks_with_canonical() {
    std::unique_lock lock(mutex_);
    if (!backend_) {
        return 0;
    }
    std::size_t dropped = 0;
    for (auto it = blocks_.begin(); it != blocks_.end(); ) {
        const uint64_t bn = it->first;
        const auto canonical = backend_->canonical_hash(
            static_cast<silkworm::BlockNum>(bn));
        // Round 90 MEDIUM fix: fail closed when canonical_hash
        // returns nullopt.  Pre-fix the gate only dropped on an
        // explicit mismatch, so a cached block from an old/forked/
        // future chain whose height has no canonical entry yet was
        // kept, and `eth_blockNumber`, raw block/header, and
        // freshness gates that self-validate against the same RAM
        // map could treat it as canonical.  An absent canonical
        // entry is not "fresh enough" — drop the cached block and
        // let the post-accept rewrite path re-populate it once
        // the canonical chain catches up.
        bool is_orphan = canonical.has_value()
                             ? (*canonical != it->second.hash)
                             : true;
        if (is_orphan) {
            // Orphan: cached block at this height disagrees with (or
            // has no entry in) the canonical chain.  Drop it and
            // every per-block sidecar that was hydrated under the
            // same orphan attribution.
            hash_to_block_.erase(it->second.hash);
            block_logs_.erase(bn);
            it = blocks_.erase(it);
            ++dropped;
        } else {
            ++it;
        }
    }
    // Round 90 MEDIUM fix (continued): if reconciliation just dropped
    // the previous head, recompute `block_number_` from the
    // surviving blocks so `eth_blockNumber` and `latest` no longer
    // advertise the orphan height.
    if (dropped > 0) {
        block_number_ = blocks_.empty() ? 0 : blocks_.rbegin()->first;
    }
    return dropped;
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

uint64_t EvmState::code_root_hash_mismatch_count() const noexcept {
    // Audit K-02 (H-01 follow-up): direct delegate to the namespace-level
    // accessor in cell-state.cpp. The counter is process-global, not
    // per-backend, so the helper is defined once and shared across
    // CellEvmState and any other (test-only) State backends. No lock is
    // taken because the underlying atomic is read with `relaxed` ordering
    // — the snapshot/check pattern in the RPC handlers requires only
    // that increments performed by the same thread (during silkworm's
    // read_code calls inside the handler's frame) become visible to that
    // same thread, which is automatic.
    return evm_workchain::code_root_hash_mismatch_count();
}

// ---------------------------------------------------------------------------
// W8-A P0-A / P0-B / P1-C forwarders
// ---------------------------------------------------------------------------
//
// Production hot path: compute-phase wraps the EvmState backend in a
// CellEvmState; tests sometimes use silkworm::InMemoryState. The
// forwarders do a `dynamic_cast` and return 0 for non-cell backends
// so the snapshot/check pattern in compute-phase is a safe no-op when
// running against the in-memory test state. Each accessor exists in
// both a locked (caller already holds state.mutex()) and an unlocked
// (helper takes the shared lock internally) variant so the compute
// path can use whichever is appropriate without re-acquiring a held
// lock or skipping a needed acquisition.

uint64_t EvmState::code_integrity_error_count_locked() const noexcept {
    if (auto* cs = dynamic_cast<const CellEvmState*>(backend_.get())) {
        return cs->code_integrity_error_count();
    }
    return 0;
}

uint64_t EvmState::code_integrity_error_count() const noexcept {
    std::shared_lock lock(mutex_);
    return code_integrity_error_count_locked();
}

uint64_t EvmState::state_shape_error_count_locked() const noexcept {
    if (auto* cs = dynamic_cast<const CellEvmState*>(backend_.get())) {
        return cs->state_shape_error_count();
    }
    return 0;
}

uint64_t EvmState::state_shape_error_count() const noexcept {
    std::shared_lock lock(mutex_);
    return state_shape_error_count_locked();
}

}  // namespace evm_workchain
