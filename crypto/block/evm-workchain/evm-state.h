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

#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/types/account.hpp>

namespace evm_workchain {

/// In-memory EVM state for the first implementation slice.
///
/// Wraps silkworm::InMemoryState directly — all state lives in RAM and is
/// lost when the process exits.  This is sufficient for proving the
/// execution path end-to-end.  Persistent storage will be added in a later
/// phase, backed by the host chain's DB infrastructure.
///
/// The class is intentionally thin: it just re-exports InMemoryState with
/// EVM-workchain-specific helpers for genesis initialisation and state
/// inspection.
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

  private:
    silkworm::InMemoryState state_;
};

}  // namespace evm_workchain
