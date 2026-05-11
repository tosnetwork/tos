/*
    EVM Workchain — state adapter.

    Thread safety: EvmState is accessed concurrently by the block execution
    path and the JSON-RPC handler threads.  All public methods are protected
    by a shared_mutex (readers–writer lock).  Read-only methods acquire a
    shared_lock; mutating methods acquire a unique_lock.

    Pattern follows ~/s/silkworm/db/kv/api/state_cache.hpp which uses
    std::shared_mutex for concurrent read access.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <unordered_map>
#include <vector>
#include <map>

#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/state/state.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/core/types/log.hpp>
#include <silkworm/core/types/transaction.hpp>

#include "td/utils/Status.h"

namespace evm_workchain {

// Capacity limits (following ~/s LruCache pattern: fixed max_size)
constexpr size_t kMaxCachedReceipts      = 10'000;
constexpr size_t kMaxCachedTransactions  = 10'000;
constexpr size_t kMaxCachedBlocks        = 256;
constexpr size_t kMaxCachedLogBlocks     = 256;

/// Stored receipt for a processed transaction.
struct StoredReceipt {
    silkworm::TransactionType type{silkworm::TransactionType::kLegacy};
    bool success{false};
    uint64_t gas_used{0};
    uint64_t cumulative_gas_used{0};  // running total within block
    uint64_t block_number{0};
    uint32_t tx_index{0};
    evmc::address from;
    std::optional<evmc::address> to;
    std::optional<evmc::address> contract_address;
    std::vector<silkworm::Log> logs;
    silkworm::Bytes return_data;
};

/// Stored transaction for eth_getTransactionByHash.
struct StoredTransaction {
    evmc::address from;
    std::optional<evmc::address> to;
    intx::uint256 value;
    silkworm::Bytes data;
    uint64_t nonce{0};
    uint64_t gas_limit{0};
    intx::uint256 gas_price;
    uint64_t block_number{0};
    uint32_t tx_index{0};
    silkworm::Bytes raw_rlp;  // original signed RLP (for eth_getRawTransactionByHash)
};

/// Stored block header for eth_getBlockByNumber / eth_getBlockByHash.
struct StoredBlock {
    uint64_t number{0};
    evmc::bytes32 hash;
    evmc::bytes32 parent_hash;
    uint64_t timestamp{0};
    uint64_t gas_limit{30'000'000};
    uint64_t gas_used{0};
    evmc::address miner;
    intx::uint256 base_fee_per_gas;
    std::vector<evmc::bytes32> transaction_hashes;
    // Block-level derived fields
    uint8_t logs_bloom[256]{};          // Ethereum logs bloom (2048-bit)
    evmc::bytes32 state_root{};         // TOS-native EVM state commitment (cell hash of state_root)
    evmc::bytes32 transactions_root{};  // TOS-native commitment over the ordered transaction list
    evmc::bytes32 receipts_root{};      // TOS-native commitment over the ordered receipt list
};

/// Log entry with block metadata for eth_getLogs.
struct IndexedLog {
    uint64_t block_number;
    evmc::bytes32 tx_hash;
    uint32_t log_index;
    uint32_t tx_index{0};
    silkworm::Log log;
};

/// EVM workchain state facade — thread-safe.
///
/// All public methods are protected by a shared_mutex:
///   - Read methods: shared_lock (multiple concurrent readers allowed)
///   - Write methods: unique_lock (exclusive access)
class EvmState {
  public:
    EvmState();
    explicit EvmState(std::unique_ptr<silkworm::State> backend);

    /// Access the underlying silkworm State.
    /// WARNING: caller must hold the lock via lock_shared() / lock_unique().
    silkworm::State& state() noexcept { return *backend_; }
    const silkworm::State& state() const noexcept { return *backend_; }

    /// Explicit locking for callers that need to hold the lock across
    /// multiple operations (e.g. execute_evm_transaction).
    std::shared_mutex& mutex() const noexcept { return mutex_; }

    void seed_account(const evmc::address& addr,
                      const intx::uint256& balance,
                      uint64_t nonce = 0);

    /// True iff no EVM accounts are stored. Used by the collator/validator
    /// hydration hook to detect a fresh process start that needs to be
    /// rebuilt from the canonical ShardAccounts. Cheap (dict-size check).
    bool is_empty() const;

    /// One-shot flag: true at process start, becomes false after the first
    /// successful hydration from canonical ShardAccounts. Used by
    /// hydrate_global_state_if_empty() so the trigger fires once per process
    /// even when devnet-only bootstrap code has populated the singleton with
    /// a few initial entries.
    bool needs_initial_hydration() const;
    void mark_initial_hydration_done();

    intx::uint256 get_balance(const evmc::address& addr) const;
    uint64_t get_nonce(const evmc::address& addr) const;
    std::optional<silkworm::Account> read_account(const evmc::address& addr) const;
    silkworm::Bytes read_code_copy(const evmc::address& addr, const evmc::bytes32& code_hash) const;

    /// Audit H-01: bytecode read with explicit `keccak(code) == code_hash`
    /// enforcement. The lazy decode in `CellEvmState::read_code` already
    /// fails closed via the witness context when invoked under an
    /// executing transaction; RPC paths (`eth_getCode`) run without a
    /// witness context, so the validity check has to happen here. Returns
    /// `Status::Error("corrupt EVM code root: keccak(code) != codeHash")`
    /// when the cell-tree decode produces bytecode whose hash does not
    /// match the canonical account `code_hash`. The empty-code case
    /// (account.code_hash == kEmptyHash) is canonical empty code and
    /// returns an empty Bytes successfully.
    td::Result<silkworm::Bytes> read_code_copy_checked(
        const evmc::address& addr,
        const evmc::bytes32& code_hash) const;

    evmc::bytes32 read_storage_copy(const evmc::address& addr, uint64_t incarnation,
                                    const evmc::bytes32& location) const;

    /// --- Block tracking ---
    uint64_t block_number() const noexcept;
    void set_block_number(uint64_t n) noexcept;
    void increment_block_number() noexcept;
    uint64_t allocate_next_block_number(std::optional<StoredBlock>& parent_block) noexcept;

    /// --- Block chain ---
    void store_block(const StoredBlock& block);
    StoredBlock get_block_copy(uint64_t block_num) const;
    bool has_block(uint64_t block_num) const;
    StoredBlock get_block_by_hash_copy(const evmc::bytes32& hash) const;
    evmc::bytes32 get_block_hash(uint64_t block_num) const;

    // Non-locking access for internal use (caller must hold lock)
    const StoredBlock* get_block(uint64_t block_num) const;
    const StoredBlock* get_block_by_hash(const evmc::bytes32& hash) const;

    /// --- Receipt storage (bounded: oldest evicted at kMaxCachedReceipts) ---
    void store_receipt(const evmc::bytes32& tx_hash, StoredReceipt receipt);
    const StoredReceipt* get_receipt(const evmc::bytes32& tx_hash) const;
    std::optional<StoredReceipt> get_receipt_copy(const evmc::bytes32& tx_hash) const;

    /// --- Transaction storage (bounded: oldest evicted at kMaxCachedTransactions) ---
    void store_transaction(const evmc::bytes32& tx_hash, StoredTransaction tx);
    const StoredTransaction* get_transaction(const evmc::bytes32& tx_hash) const;
    std::optional<StoredTransaction> get_transaction_copy(const evmc::bytes32& tx_hash) const;

    /// --- Log index (bounded: kMaxCachedLogBlocks blocks) ---
    void store_logs(uint64_t block_number, const evmc::bytes32& tx_hash,
                    const std::vector<silkworm::Log>& logs,
                    uint32_t tx_index = 0);
    /// Round 87 MEDIUM fix: drop the per-block log accumulator for
    /// `block_number` so a same-height rewrite starts fresh.
    /// `store_block` already erases the prior hash mapping; this
    /// helper covers the orthogonal logs index that store_block
    /// alone cannot clear without losing the just-appended new
    /// logs (post-accept calls store_logs BEFORE store_block).
    /// Callers must invoke this before re-applying the rewrite's
    /// txs.
    void reset_block_logs(uint64_t block_number);

    /// Round 89 MEDIUM fix: drop hydrated blocks that disagree with
    /// the canonical chain after canonical hashes are loaded.
    /// `init_evm_workchain` walks the cache DB BEFORE
    /// `populate_state_from_shard_accounts` populates
    /// CellEvmState's canonical_ map, so the round-88 hydration
    /// gate sees `canonical_hash(N) == nullopt` for every cached
    /// block and admits orphans.  Call this AFTER canonical
    /// hashes are loaded to evict orphan blocks (and their
    /// per-block logs) from RAM.  Returns the number of orphan
    /// entries dropped.
    std::size_t reconcile_blocks_with_canonical();

    std::vector<IndexedLog> get_logs(
        uint64_t from_block, uint64_t to_block,
        const std::vector<evmc::address>& addresses = {},
        const std::vector<std::vector<evmc::bytes32>>& topics = {}) const;

    /// Snapshot of all IndexedLog entries for a single block. Returns an
    /// empty vector if the block has no logs (or never existed). Used by the
    /// RPC-cache write hook to re-serialize the block's full log set after
    /// every per-tx store_logs call.
    std::vector<IndexedLog> get_logs_for_block_copy(uint64_t block_number) const;

    /// Audit K-02 (H-01 follow-up): forwarder for the always-on
    /// `read_code` mismatch counter. RPC handlers that run heavy
    /// read-only EVM logic snapshot the counter before silkworm
    /// execution and re-read it afterwards: a non-zero delta means a
    /// corrupt code root was observed during the handler's frame, and
    /// the response should be mapped to JSON-RPC `-32000 corrupt EVM
    /// code root` instead of silently returning the wrong (or empty)
    /// execution result. The counter is process-global and monotone,
    /// so the snapshot/check pattern is correct under any locking
    /// discipline.
    uint64_t code_root_hash_mismatch_count() const noexcept;

    /// W8-A P0-A / P0-B forwarders. Per-state code-integrity error
    /// counter for the underlying CellEvmState backend (returns 0 for
    /// non-cell test backends). Used by the consensus compute path:
    /// the unlocked variant takes the shared mutex internally and is
    /// safe to call between operations; the `_locked` variant assumes
    /// the caller already holds `state.mutex()` (compute-phase invokes
    /// it inline while a unique_lock is held over the side-effect
    /// capture step).
    uint64_t code_integrity_error_count() const noexcept;
    uint64_t code_integrity_error_count_locked() const noexcept;

    /// W8-A P1-C forwarders. Per-state TrustedLazy native-shape error
    /// counter for the underlying CellEvmState backend. Same locking
    /// contract as the code-integrity forwarders above.
    uint64_t state_shape_error_count() const noexcept;
    uint64_t state_shape_error_count_locked() const noexcept;

  private:
    void evict_oldest_receipts();
    void evict_oldest_transactions();
    void evict_oldest_log_blocks();

    std::unique_ptr<silkworm::State> backend_;
    uint64_t block_number_{0};

    // All containers below are bounded by capacity constants.
    std::unordered_map<evmc::bytes32, StoredReceipt> receipts_;
    std::unordered_map<evmc::bytes32, StoredTransaction> transactions_;
    std::map<uint64_t, StoredBlock> blocks_;
    std::unordered_map<evmc::bytes32, uint64_t> hash_to_block_;
    std::map<uint64_t, std::vector<IndexedLog>> block_logs_;

    // Insertion order tracking for eviction (FIFO when at capacity)
    std::vector<evmc::bytes32> receipt_insertion_order_;
    std::vector<evmc::bytes32> transaction_insertion_order_;

    bool needs_initial_hydration_{true};

    mutable std::shared_mutex mutex_;
};

}  // namespace evm_workchain
