/*
    EVM Workchain — incremental state trie calculator.

    Computes the Ethereum state root hash using an Erigon-style incremental
    algorithm backed by Silkworm's HashBuilder.  When change sets are provided
    (PrefixSet of changed account/storage paths), only the affected subtrees
    are recomputed; unchanged subtrees reuse cached intermediate trie nodes.

    The implementation follows the two-cursor merge pattern from Erigon's
    TrieLoader: cached trie branch nodes are merged with live hashed state
    entries in nibbled-key order, feeding the result into HashBuilder which
    produces the root hash and emits intermediate nodes for future reuse.

    Source: TOS-specific adapter (not copied from ~/s).
*/
#pragma once

#include <map>
#include <unordered_map>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/trie/hash_builder.hpp>
#include <silkworm/core/trie/nibbles.hpp>
#include <silkworm/core/trie/node.hpp>
#include <silkworm/core/trie/prefix_set.hpp>
#include <silkworm/core/types/account.hpp>

#include "evm-state.h"

namespace evm_workchain {

/// Persistent cache for intermediate trie nodes.
///
/// Stores branch nodes produced by HashBuilder's node_collector callback.
/// Keyed by packed nibble path.  Two separate caches are maintained:
/// one for the account trie ("TrieOfAccounts") and one per-account for
/// storage tries ("TrieOfStorage").
struct TrieNodeCache {
    /// Account trie intermediate nodes, keyed by packed nibble path.
    std::map<silkworm::Bytes, silkworm::trie::Node> account_nodes;

    /// Storage trie intermediate nodes, keyed by (hashed_addr ++ packed nibble path).
    std::map<silkworm::Bytes, silkworm::trie::Node> storage_nodes;

    void clear() {
        account_nodes.clear();
        storage_nodes.clear();
    }
};

/// Incremental state trie calculator following the Erigon algorithm.
///
/// Usage:
///   IncrementalTrieCalculator calc;
///   // Full regeneration (no change hints):
///   auto root = calc.compute_state_root(state);
///   // Incremental (with change tracking):
///   auto root = calc.compute_state_root(state, &acct_changes, &storage_changes);
///
class IncrementalTrieCalculator {
  public:
    IncrementalTrieCalculator() = default;

    /// Compute the Ethereum state root hash.
    ///
    /// @param state           The EVM state (caller must hold the lock).
    /// @param account_changes If non-null, PrefixSet of nibbled hashed addresses
    ///                        that changed since the last computation.
    /// @param storage_changes If non-null, PrefixSet of nibbled
    ///                        (hashed_addr ++ hashed_slot) paths that changed.
    /// @return                The 32-byte Merkle Patricia Trie state root.
    evmc::bytes32 compute_state_root(
        EvmState& state,
        silkworm::trie::PrefixSet* account_changes = nullptr,
        silkworm::trie::PrefixSet* storage_changes = nullptr);

    /// Clear all cached state (forces full regeneration on next call).
    void reset();

    /// Access the trie node cache (for testing / inspection).
    const TrieNodeCache& cache() const noexcept { return cache_; }

  private:
    /// Compute the storage root for a single account.
    ///
    /// @param state            The EVM state (caller must hold the lock).
    /// @param address          The plain (unhashed) account address.
    /// @param hashed_addr      keccak256(address), as bytes32.
    /// @param incarnation      The account's incarnation number.
    /// @param storage_changes  If non-null, PrefixSet of changed storage paths.
    /// @return                 The 32-byte storage trie root.
    evmc::bytes32 compute_storage_root(
        EvmState& state,
        const evmc::address& address,
        const evmc::bytes32& hashed_addr,
        uint64_t incarnation,
        silkworm::trie::PrefixSet* storage_changes);

    /// Build a sorted map of (hashed_address -> Account) from InMemoryState.
    /// Falls back to iterating the InMemoryState accounts() map.
    static std::map<evmc::bytes32, std::pair<evmc::address, silkworm::Account>>
    collect_hashed_accounts(EvmState& state);

    /// Build a sorted map of (hashed_slot -> value) for one account from InMemoryState.
    static std::map<evmc::bytes32, evmc::bytes32>
    collect_hashed_storage(EvmState& state, const evmc::address& address, uint64_t incarnation);

    /// Encode an account for the state trie (Yellow Paper section 4.1).
    /// Returns RLP([nonce, balance, storageRoot, codeHash]).
    static silkworm::Bytes encode_account_for_trie(
        const silkworm::Account& acct,
        const evmc::bytes32& storage_root);

    /// RLP-encode a storage value (trimming leading zeros).
    static silkworm::Bytes encode_storage_value(const evmc::bytes32& value);

    /// Cache of storage roots: hashed_addr -> root hash.
    std::unordered_map<evmc::bytes32, evmc::bytes32> storage_root_cache_;

    /// Persistent intermediate trie node cache.
    TrieNodeCache cache_;
};

}  // namespace evm_workchain
