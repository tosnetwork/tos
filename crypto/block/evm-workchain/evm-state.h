/*
    EVM Workchain — state adapter.

    This module provides the storage boundary between the EVM workchain and the
    host chain.  It implements silkworm::State so that the Silkworm execution
    engine can read/write EVM account state without knowing about host-chain
    internals.

    First-slice implementation: in-memory state backed by hash maps.
    Future: adapter to host-chain persistent storage (RocksDB column family
    or dedicated namespace).

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <mutex>
#include <unordered_map>
#include <vector>

#include <silkworm/core/state/in_memory_state.hpp>
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

/// In-memory EVM state for the first implementation slice.
class EvmState {
  public:
    EvmState() = default;

    /// Access the underlying silkworm State (used by the executor).
    silkworm::InMemoryState& state() noexcept { return state_; }
    const silkworm::InMemoryState& state() const noexcept { return state_; }

    /// Seed an account with an initial balance (e.g. for genesis / testing).
    void seed_account(const evmc::address& addr,
                      const intx::uint256& balance,
                      uint64_t nonce = 0);

    /// Read the current balance of an account.  Returns 0 for non-existent.
    intx::uint256 get_balance(const evmc::address& addr) const;

    /// Read the current nonce of an account.  Returns 0 for non-existent.
    uint64_t get_nonce(const evmc::address& addr) const;

    /// --- Block tracking ---

    /// Current block number (incremented on each tx for now; later per-block).
    uint64_t block_number() const noexcept { return block_number_; }
    void set_block_number(uint64_t n) noexcept { block_number_ = n; }
    void increment_block_number() noexcept { ++block_number_; }

    /// --- Receipt storage ---

    /// Store a receipt keyed by transaction hash.
    void store_receipt(const evmc::bytes32& tx_hash, StoredReceipt receipt);

    /// Look up a receipt by transaction hash.
    const StoredReceipt* get_receipt(const evmc::bytes32& tx_hash) const;

  private:
    silkworm::InMemoryState state_;
    uint64_t block_number_{0};

    // tx_hash → receipt  (in-memory, lost on restart)
    std::unordered_map<evmc::bytes32, StoredReceipt> receipts_;
};

}  // namespace evm_workchain
