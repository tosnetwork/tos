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
#include <optional>
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

/// Provenance of an `MptTrie` instance. Drives the path-local cached-RLP
/// consistency policy used by the `*_safe` walkers.
///
/// `InMemoryBuilt`
///   The trie was constructed in-process via `upsert_hashed[_safe]` /
///   `erase_hashed[_safe]` and has never been hydrated from a serialized
///   cell. Newly created `Node`s carry an empty `rlp_cache` until the trie
///   is serialized for the first time. In this mode the walkers may fall
///   back to `child->rlp()` to materialize a missing immediate-child
///   cache. This permissive behaviour exists ONLY so test fixtures and
///   internal builders can compute proofs / root hashes before a
///   round-trip; it is NOT part of the production attack surface.
///
/// `LoadedFromCell`
///   The trie's root was bound from a persisted cell via `load_from_cell`
///   — i.e. the witness travelled across an untrusted boundary (disk,
///   network, RPC argument). Path-local consistency checks become strict:
///   an immediate child whose `rlp_cache` cannot be populated from its
///   persisted cell fails closed with an explicit error rather than
///   triggering a recursive `rlp()` materialisation. The strict rule
///   removes the "strict-then-permissive" bypass where an attacker crafts
///   a witness whose strict re-encoding fails so the walker silently
///   re-falls back to trusting `child->rlp()`.
///
///   Per-node exception (option (1) in the security audit): a child
///   carrying both `decoded` and `dirty` flags is an in-memory built node
///   introduced by a post-load mutation (e.g. a fresh `Node::leaf()`
///   allocated by `MptTrie::upsert_hashed_safe` after `load_from_cell`).
///   Such a node has a legitimately empty `rlp_cache` — it has never
///   been serialised. For those children the strict-mode walker permits
///   the recursive `child->rlp()` materialisation as a narrow exception.
///   The bypass remains closed because an attacker-controlled lazy cell
///   that fails to decode never reaches the `decoded && dirty` state:
///   `Node::ensure_decoded()` leaves it `decoded=false`, and `child_ref_local`
///   then refuses to fall back. This per-node distinction is required so
///   production call sites (`CellEvmState::update_storage` →
///   `update_account_trie_leaf` → `root_hash_safe`) keep working when a
///   witness-bound trie is mutated mid-block.
///
/// Security contract: once an `MptTrie` is bound to `LoadedFromCell` it
/// remains so for its lifetime — subsequent `upsert_hashed_safe` /
/// `erase_hashed_safe` mutations do NOT silently downgrade to
/// `InMemoryBuilt`. The trie keeps the strict-only walker policy; only
/// per-node `decoded && dirty` children take the in-memory exception.
/// Only `clear()` (drops the trie entirely) or constructing a fresh
/// `MptTrie` resets the origin.
enum class MptOrigin {
    InMemoryBuilt,
    LoadedFromCell,
};

/// Ethereum-format Merkle-Patricia Trie that backs the persistent EVM
/// state-root witness. Used in two distinct lifecycles:
///
///   * `MptOrigin::InMemoryBuilt` — the trie was constructed in-process
///     from cleartext (key, value) pairs (test fixtures, snapshot
///     rebuild, the first serialize after genesis). The path-walking
///     `*_safe` APIs MAY fall back to `child->rlp()` to populate a
///     missing immediate-child cache because the data is trusted local.
///
///   * `MptOrigin::LoadedFromCell` — the trie was hydrated from a
///     persisted root cell that crossed an untrusted boundary (disk,
///     network, RPC argument). The instance is pinned in strict mode
///     for the rest of its lifetime and never silently downgrades to
///     `InMemoryBuilt`. The `*_safe` walkers enforce path-local cached
///     RLP consistency and refuse to recursively materialise a missing
///     `rlp_cache`. This closes the strict-then-permissive bypass that
///     would otherwise let an attacker craft a witness whose strict
///     re-encode fails so the walker silently re-falls back to
///     trusting a child's recomputed RLP.
///
/// Mutations on a `LoadedFromCell` trie. `upsert_hashed_safe` and
/// `erase_hashed_safe` create fresh in-memory `Node`s flagged
/// `decoded && dirty`. The per-node exception in `child_ref_local`
/// permits those dirty nodes to use `child->rlp()` because they are
/// trusted local mutations — they were never deserialised from a
/// persisted cell. Strict mode therefore continues to apply to every
/// remaining lazy-loaded node along the descent path; only the dirty
/// children take the permissive shortcut. A fully-mutated post-load
/// trie still travels the strict pass for any unmutated witness
/// node it encounters.
///
/// Security contract. An attacker constructing a corrupt witness cell
/// CANNOT bypass strict checks by causing a partial mutation, because
/// dirty nodes only exist after a successful trusted mutation API
/// call — they cannot be created via `load_from_cell`. The
/// `Node::ensure_decoded()` path leaves an undecodable lazy node with
/// `decoded=false`, so `child_ref_local` refuses the shortcut and the
/// `*_safe` walker fails closed. Any subsequent operation on that
/// lazy node returns a status error rather than treating
/// `child->rlp()` as authoritative.
class MptTrie {
  public:
    struct Node;

    MptTrie() = default;

    bool empty() const noexcept { return !root_; }
    void clear() noexcept;

    /// Returns the trie's origin. See `MptOrigin` for the security contract.
    MptOrigin origin() const noexcept { return origin_; }

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

#ifdef TOS_EVM_TEST_INSTRUMENTATION
    /// Test-only Ethereum MPT root hash. Empty trie returns
    /// keccak256(RLP("")). On a corrupt root the legacy boolean wrapper
    /// returns `kEmptyRoot` (status discarded) which would silently corrupt
    /// consensus state — production callers MUST use `root_hash_safe()`.
    ///
    /// L-01 (audit): the symbol is gated behind
    /// `TOS_EVM_TEST_INSTRUMENTATION` so production targets do NOT export
    /// it. Tests link the dedicated `evm_workchain_test{_debug}` libraries
    /// which set the macro; the production `evm_workchain` library does
    /// not, so a future production caller cannot accidentally link
    /// against this symbol.
    evmc::bytes32 root_hash_unsafe_for_tests_only() const;
#endif

    /// Fail-closed root-hash variant. Returns an error if the root or one of
    /// its eagerly-required descendants fails to decode while computing the
    /// hash. Hot-path callers that have to publish a deterministic stateRoot
    /// should prefer this so a malformed witness cannot reach consensus as
    /// "empty trie".
    ///
    /// Path-local cached-RLP consistency: the root's cached RLP is verified
    /// against a non-recursive re-encoding of the decoded shape using cached
    /// child references. A tampered root whose cached RLP disagrees with its
    /// decoded fields fails closed instead of producing a hash over the
    /// tampered cache.
    ///
    /// Strict-only on lazy-loaded witnesses: same contract as `proof_safe`.
    td::Result<evmc::bytes32> root_hash_safe() const;

#ifdef TOS_EVM_TEST_INSTRUMENTATION
    /// Test-only proof helper. Wraps `proof_safe` but discards a non-OK
    /// status as an empty proof — production callers MUST use `proof_safe()`
    /// so a corrupt witness surfaces as a JSON-RPC error rather than a
    /// silently-empty proof.
    ///
    /// L-01 (audit): same `TOS_EVM_TEST_INSTRUMENTATION` gating as
    /// `root_hash_unsafe_for_tests_only`. Production targets must not
    /// export this symbol.
    std::vector<silkworm::Bytes> proof_unsafe_for_tests_only(
        const silkworm::ByteView& hashed_key) const;
#endif

    /// Fail-closed proof variant. Propagates lazy-decode/structural errors as
    /// `td::Status` instead of triggering a `CHECK` abort, so RPC handlers
    /// can map a corrupt witness to a JSON-RPC error rather than crashing
    /// the node.
    ///
    /// Path-local cached-RLP consistency: when called on a lazy-loaded
    /// witness, every node visited along the descent has its cached RLP
    /// re-encoded from the decoded shape using ONLY the immediate
    /// children's cached RLP / hash references (no recursion into off-path
    /// subtrees). The recomputation is then byte-compared against
    /// `rlp_cache`; a mismatch fails closed with `"MPT: cached RLP does
    /// not match decoded shape"` instead of leaking a tampered cached
    /// encoding into the returned proof. The full-tree `StrictRecursive`
    /// walk is still used at hydration / import / repair; the path-local
    /// check is the cheap hot-path companion that scales as O(path
    /// length).
    ///
    /// Strict-only on lazy-loaded witnesses (`MptOrigin::LoadedFromCell`):
    /// an immediate child whose `rlp_cache` cannot be populated from its
    /// persisted cell fails closed with `"MPT: lazy-loaded child has no
    /// cached RLP"`. The legacy permissive fallback that would have
    /// materialised the cache via `child->rlp()` is reachable ONLY for
    /// `MptOrigin::InMemoryBuilt` tries (test fixtures and pre-serialize
    /// builders).
    td::Result<std::vector<silkworm::Bytes>> proof_safe(
        const silkworm::ByteView& hashed_key) const;

    /// Fail-closed value lookup. Walks the path-budgeted descent for
    /// `hashed_key` and returns the leaf's stored value bytes if a matching
    /// leaf is reached, or `std::nullopt` for a canonical absence (the
    /// descent ends short of a matching leaf). Returns a non-OK
    /// `td::Status` on any malformed lazy node, structural inconsistency, or
    /// over-budget descent — same fail-closed contract as `proof_safe`. Used
    /// by `CellEvmState::verify_*_witness_matches_flat_state` to defend
    /// against a structurally valid but semantically corrupt witness.
    ///
    /// Path-local cached-RLP consistency: same invariant as `proof_safe` —
    /// each node visited along the descent has its cached RLP verified
    /// against a non-recursive re-encoding using cached child refs.
    ///
    /// Strict-only on lazy-loaded witnesses: same contract as `proof_safe`.
    td::Result<std::optional<silkworm::Bytes>> value_at_hashed_safe(
        silkworm::ByteView hashed_key) const;

    /// Persist/load the witness root node. Null cell means empty trie. The
    /// default validation mode is StrictRecursive — callers on a hot path
    /// that have already validated the witness elsewhere may opt into
    /// Shallow for speed.
    ///
    /// Successful `load_from_cell` (including the empty-trie clear path)
    /// pins the instance's origin to `MptOrigin::LoadedFromCell` so
    /// subsequent `*_safe` operations use strict-only path-local checks.
    td::Ref<vm::Cell> serialize_to_cell() const;
    bool load_from_cell(td::Ref<vm::Cell> root,
                        MptWitnessValidationMode mode =
                            MptWitnessValidationMode::StrictRecursive);

  private:
    std::shared_ptr<Node> root_;
    /// Tracks where this trie's nodes came from. `LoadedFromCell` enforces
    /// strict-only path-local cached-RLP consistency on the public `*_safe`
    /// API; `InMemoryBuilt` permits a permissive fallback only for nodes
    /// that have never been serialised. See `MptOrigin` for the full
    /// contract.
    MptOrigin origin_{MptOrigin::InMemoryBuilt};
};

/// RLP-encode an Ethereum storage trie value. Zero values are expected to be
/// omitted by callers and are encoded here only for defensive completeness.
silkworm::Bytes encode_mpt_storage_value(const evmc::bytes32& value);

/// Hash helpers used by CellEvmState and tests.
evmc::bytes32 keccak_evm_address(const evmc::address& address);
evmc::bytes32 keccak_bytes32_value(const evmc::bytes32& value);

}  // namespace evm_workchain
