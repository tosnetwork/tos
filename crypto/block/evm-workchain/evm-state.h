/*
    EVM Workchain — state adapter.

    This module provides the storage boundary between the EVM workchain and the
    host chain.  It wraps a silkworm::State backend so that the executor can
    read/write EVM account state without knowing about the underlying storage.

    Two backends:
      - InMemoryState  — fast, volatile (default for tests)
      - PersistentEvmState — RocksDB-backed, survives restarts

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>
#include <map>

#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/state/state.hpp>
#include <silkworm/core/types/account.hpp>
#include <silkworm/core/types/log.hpp>

namespace evm_workchain {

/// Stored receipt for a processed transaction.
struct StoredReceipt {
    bool success{false};
    uint64_t gas_used{0};
    uint64_t block_number{0};
    evmc::address from;
    std::optional<evmc::address> to;
    std::optional<evmc::address> contract_address;  // for CREATE
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
};

/// Log entry with block metadata for eth_getLogs.
struct IndexedLog {
    uint64_t block_number;
    evmc::bytes32 tx_hash;
    uint32_t log_index;
    silkworm::Log log;
};

/// EVM workchain state facade.
class EvmState {
  public:
    /// Construct with in-memory backend (volatile — for tests).
    EvmState();

    /// Construct with an external State backend (e.g. PersistentEvmState).
    explicit EvmState(std::unique_ptr<silkworm::State> backend);

    /// Access the underlying silkworm State (used by the executor).
    silkworm::State& state() noexcept { return *backend_; }
    const silkworm::State& state() const noexcept { return *backend_; }

    /// Seed an account with an initial balance (e.g. for genesis / testing).
    void seed_account(const evmc::address& addr,
                      const intx::uint256& balance,
                      uint64_t nonce = 0);

    /// Read the current balance of an account.  Returns 0 for non-existent.
    intx::uint256 get_balance(const evmc::address& addr) const;

    /// Read the current nonce of an account.  Returns 0 for non-existent.
    uint64_t get_nonce(const evmc::address& addr) const;

    /// --- Block tracking ---
    uint64_t block_number() const noexcept { return block_number_; }
    void set_block_number(uint64_t n) noexcept { block_number_ = n; }
    void increment_block_number() noexcept { ++block_number_; }

    /// --- Block hash history (for BLOCKHASH opcode) ---
    void store_block_hash(uint64_t block_num, const evmc::bytes32& hash);
    evmc::bytes32 get_block_hash(uint64_t block_num) const;

    /// --- Receipt storage ---
    void store_receipt(const evmc::bytes32& tx_hash, StoredReceipt receipt);
    const StoredReceipt* get_receipt(const evmc::bytes32& tx_hash) const;

    /// --- Transaction storage ---
    void store_transaction(const evmc::bytes32& tx_hash, StoredTransaction tx);
    const StoredTransaction* get_transaction(const evmc::bytes32& tx_hash) const;

    /// --- Log index (for eth_getLogs) ---
    void store_logs(uint64_t block_number, const evmc::bytes32& tx_hash,
                    const std::vector<silkworm::Log>& logs);

    /// Query logs by block range with optional address and topic filters.
    /// Matching semantics follow Ethereum spec:
    ///   - addresses: log.address must be in the set (empty = match all)
    ///   - topics: topics[i] is a set of acceptable values for log.topics[i]
    ///             (empty set at position i = match any)
    std::vector<IndexedLog> get_logs(
        uint64_t from_block, uint64_t to_block,
        const std::vector<evmc::address>& addresses = {},
        const std::vector<std::vector<evmc::bytes32>>& topics = {}) const;

  private:
    std::unique_ptr<silkworm::State> backend_;
    uint64_t block_number_{0};

    std::unordered_map<evmc::bytes32, StoredReceipt> receipts_;
    std::unordered_map<evmc::bytes32, StoredTransaction> transactions_;
    std::map<uint64_t, evmc::bytes32> block_hashes_;               // block_num → hash
    std::map<uint64_t, std::vector<IndexedLog>> block_logs_;       // block_num → logs
};

}  // namespace evm_workchain
