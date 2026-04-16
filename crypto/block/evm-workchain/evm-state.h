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

/// EVM workchain state facade.
///
/// Wraps a silkworm::State backend (in-memory or persistent) and provides
/// EVM-workchain-specific helpers for genesis initialisation, state
/// inspection, receipt storage, and block tracking.
class EvmState {
  public:
    /// Construct with in-memory backend (volatile — for tests and first slice).
    EvmState();

    /// Construct with an external State backend (e.g. PersistentEvmState).
    /// Takes ownership of the backend.
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

    /// --- Receipt storage ---
    void store_receipt(const evmc::bytes32& tx_hash, StoredReceipt receipt);
    const StoredReceipt* get_receipt(const evmc::bytes32& tx_hash) const;

  private:
    std::unique_ptr<silkworm::State> backend_;
    uint64_t block_number_{0};
    std::unordered_map<evmc::bytes32, StoredReceipt> receipts_;
};

}  // namespace evm_workchain
