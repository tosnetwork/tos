/*
    EVM Workchain — persistent Ethereum Merkle Patricia Trie witness.

    This is the execution-side trie/witness store used by CellEvmState.  It
    keeps canonical Ethereum MPT node RLP alongside a compact cell-native node
    shape, so stateRoot and eth_getProof can be served from persisted witness
    nodes instead of rebuilding the trie from all accounts/storage slots.

    Source: TOS-specific adapter, following the Erigon/Silkworm execution
    model of flat state plus persisted trie witness/intermediate nodes.
*/
#pragma once

#include <atomic>
#include <cstddef>
#include <memory>
#include <vector>

#include <evmc/evmc.hpp>
#include <silkworm/core/common/bytes.hpp>

#include "td/utils/Status.h"
#include "vm/cells.h"

namespace evm_workchain {

#ifdef TOS_EVM_TEST_INSTRUMENTATION
/// Test-only counter for strict recursive validation walks. See
/// `evm/core/mpt-trie.cpp` for the definition; tests reset and read this to
/// confirm the consensus hot path stays on the shallow / path-bounded code
/// path. Must NOT be relied upon for production logic.
extern std::atomic<size_t> g_mpt_strict_validation_nodes;
#endif

/// Selects how `MptTrie::load_from_cell` validates the witness on hydration.
///   - Shallow: only checks the root node's cached fields and shape. Cheap,
///     but trusts the cached RLP and child refs at deeper levels. Acceptable
///     when the witness has previously been strictly validated and is being
///     re-bound to the same state.
///   - StrictRecursive: walks every reachable node, recomputes RLP from the
///     decoded shape (without trusting `rlp_cache`), and verifies each
///     `rlp_cache` byte-equals the recomputation. Used at hydration / import /
///     debug repair so a corrupt or maliciously-mutated witness cell cannot
///     produce an invalid proof or trip a runtime CHECK.
enum class MptWitnessValidationMode {
    Shallow,
    StrictRecursive,
};

/// Per-operation budget for path-walking operations (proof, mutation) on a
/// shallow-loaded MPT. Bounds both the number of nodes decoded along a single
/// root-to-leaf path and the total RLP bytes touched. Designed so that even
/// when a target storage trie is huge, a single tx that mutates one slot only
/// pays for the path length (≤ 64 hashed-key nibbles + intermediates), not
/// for the whole trie.
struct MptPathBudget {
    size_t nodes = 0;
    size_t rlp_bytes = 0;
    static constexpr size_t kMaxPathNodes = 256;
    static constexpr size_t kMaxPathRlpBytes = 2ull * 1024ull * 1024ull;
};

class MptTrie {
  public:
    struct Node;

    MptTrie() = default;

    bool empty() const noexcept { return !root_; }
    void clear() noexcept;

    /// Legacy mutation API. Returns `false` only when the input is malformed
    /// (wrong key length or empty value). Internally delegates to
    /// `upsert_hashed_safe` and discards the status; **consensus consumers
    /// must use the `_safe` variants** so a corrupt lazy node surfaces as a
    /// fail-closed error instead of being silently swallowed.
    bool upsert_hashed(const silkworm::ByteView& hashed_key,
                       const silkworm::ByteView& rlp_value);

    /// Legacy erase API. Same caveat as `upsert_hashed`: consensus paths must
    /// use `erase_hashed_safe` so a corrupt subtree cannot clear a healthy
    /// root.
    bool erase_hashed(const silkworm::ByteView& hashed_key);

    /// Fail-closed mutation API. Returns `td::Status::OK()` when the
    /// operation succeeded (whether or not it changed the trie); returns a
    /// non-OK status when a lazy node along the descent path could not be
    /// decoded. On error the trie root is **not** mutated, so a corrupt
    /// witness can never be turned into a `kEmptyRoot` write that would
    /// silently corrupt consensus state.
    td::Status upsert_hashed_safe(const silkworm::ByteView& hashed_key,
                                   const silkworm::ByteView& rlp_value);
    td::Status erase_hashed_safe(const silkworm::ByteView& hashed_key);

    /// Ethereum MPT root hash. Empty trie returns keccak256(RLP("")).
    evmc::bytes32 root_hash() const;

    /// Fail-closed root-hash variant. Returns an error if the root or one of
    /// its eagerly-required descendants fails to decode while computing the
    /// hash. Hot-path callers that have to publish a deterministic stateRoot
    /// should prefer this so a malformed witness cannot reach consensus as
    /// "empty trie".
    td::Result<evmc::bytes32> root_hash_safe() const;

    /// Standard Ethereum proof nodes, root to terminal/exclusion node.
    std::vector<silkworm::Bytes> proof(const silkworm::ByteView& hashed_key) const;

    /// Fail-closed proof variant. Propagates lazy-decode/structural errors as
    /// `td::Status` instead of triggering a `CHECK` abort, so RPC handlers
    /// can map a corrupt witness to a JSON-RPC error rather than crashing
    /// the node.
    td::Result<std::vector<silkworm::Bytes>> proof_safe(
        const silkworm::ByteView& hashed_key) const;

    /// Persist/load the witness root node. Null cell means empty trie. The
    /// default validation mode is StrictRecursive — callers on a hot path
    /// that have already validated the witness elsewhere may opt into
    /// Shallow for speed.
    td::Ref<vm::Cell> serialize_to_cell() const;
    bool load_from_cell(td::Ref<vm::Cell> root,
                        MptWitnessValidationMode mode =
                            MptWitnessValidationMode::StrictRecursive);

  private:
    std::shared_ptr<Node> root_;
};

/// RLP-encode an Ethereum storage trie value. Zero values are expected to be
/// omitted by callers and are encoded here only for defensive completeness.
silkworm::Bytes encode_mpt_storage_value(const evmc::bytes32& value);

/// Hash helpers used by CellEvmState and tests.
evmc::bytes32 keccak_evm_address(const evmc::address& address);
evmc::bytes32 keccak_bytes32_value(const evmc::bytes32& value);

}  // namespace evm_workchain
