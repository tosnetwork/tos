/*
    Uno Workchain (wc=2) — incremental commitment Merkle tree (§2.3, §5.2).

    Depth-32 sparse Merkle tree over Poseidon2-Goldilocks. Each node hash is
    256 bits (4 × Goldilocks field elements). Only the right-edge "frontier"
    is persisted on-chain: 32 FrontierLevel cells, each holding the sibling
    hash needed to recompute the root when the next leaf is appended.

    Storage layout:
        FrontierLevel_i :=
            filled  : bit        // 0 = sibling is canonical empty-subtree hash at level i
                                 // 1 = sibling is the concrete `hash` below
            hash    : bits256    // sibling hash (meaningful iff filled == 1)
            next    : Maybe ^FrontierLevel_{i+1}

    Append is O(log N) Poseidon2 calls plus O(log N) cell writes (worst case);
    the root is recomputed after every append and cached. Full note history is
    NOT persisted on-chain — wallets reconstruct Merkle paths from the tx log.

    This module owns only the data-structure logic. The Poseidon2 compression
    is forward-declared: Agent 3 supplies the implementation in
    `uno/crypto/poseidon2.{h,cpp}`.

    Source: TOS-specific (not copied from upstream).
*/
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "vm/cells.h"

namespace uno_workchain {

/// Node/leaf width in bytes. Poseidon2-Goldilocks output is 4 field elements,
/// serialized as 32 bytes of canonical little-endian u64 limbs.
static constexpr std::size_t kNoteHashBytes = 32;

/// Commitment-tree depth (§2.3 and §10.2 ConfigParam 26 `tree_depth = 32`).
static constexpr std::size_t kTreeDepth = 32;

/// Maximum number of leaves addressable at depth 32.
static constexpr std::uint64_t kMaxLeaves = (std::uint64_t{1} << kTreeDepth);

/// 256-bit commitment / node-hash value. Opaque byte string in this module;
/// interpretation as Goldilocks field elements is the crypto layer's concern.
using NoteHash = std::array<std::uint8_t, kNoteHashBytes>;

/// Canonical zero (all-bytes-zero) hash, used as a sentinel for "filled" flag
/// bookkeeping. The empty-subtree hash table is a separate, Poseidon2-derived
/// table; see kEmptySubtree below.
constexpr NoteHash kZeroHash{};

/// Forward declaration of the Poseidon2-over-Goldilocks 2-to-1 compression
/// supplied by Agent 3. Contract: writes exactly `kNoteHashBytes` bytes into
/// `out`. Must be deterministic, constant-time with respect to `in_left` /
/// `in_right`, and byte-identical across platforms.
///
/// Defined in `uno/crypto/poseidon2.cpp` (not this module).
extern "C" void poseidon2_goldilocks_compress_2to1(const std::uint8_t in_left[32],
                                                    const std::uint8_t in_right[32],
                                                    std::uint8_t out[32]) noexcept;

/// Empty-subtree hash at every level: `kEmptySubtree[0] = Poseidon2(0, 0)` of
/// zero leaves, and `kEmptySubtree[i+1] = Poseidon2(kEmptySubtree[i],
/// kEmptySubtree[i])`. Lazily populated on first construction; depends only
/// on the Poseidon2 specification, hence safe to cache across all instances.
const NoteHash& empty_subtree_hash(std::size_t level);

/// One level of the append-only frontier.
struct FrontierLevel {
    NoteHash hash{};   // sibling hash at this level (valid iff filled == true)
    bool filled{false};
};

/// Incremental Merkle-tree frontier (§2.3, §5.2).
///
/// Invariants:
///   - `next_position` is the 0-based leaf index of the *next* append target.
///   - For every internal level i where the (next_position >> i) bit is 1,
///     `levels_[i].filled == true` holds the left sibling waiting for its
///     right-child pair.
///   - The cached root `root_` matches `compute_root_from_frontier(levels_,
///     next_position)`; recomputed after every mutation.
class CommitmentTree {
  public:
    /// Construct an empty tree. `root_` is the empty-tree root
    /// (`empty_subtree_hash(kTreeDepth)` by construction).
    CommitmentTree();

    /// Append one commitment and return the new root hash.
    ///
    /// Aborts with `false` iff the tree is full (next_position == kMaxLeaves).
    /// No state mutation occurs in that case.
    bool append(const NoteHash& cm, NoteHash& new_root) noexcept;

    /// Convenience wrapper: returns the new root, aborts (returns zero) on
    /// overflow. Callers that need to detect overflow must use the boolean
    /// form.
    NoteHash append(const NoteHash& cm) noexcept;

    /// Current tree root (256 bits). Matches the `commitment_tree_root`
    /// field of `UnoShardState` (§5.1).
    const NoteHash& get_root() const noexcept { return root_; }

    /// Number of leaves already appended (== position of next append).
    std::uint64_t next_position() const noexcept { return next_position_; }

    /// True iff append() has never succeeded since construction / load.
    bool is_empty() const noexcept { return next_position_ == 0; }

    /// True iff the tree has exhausted its 2^32 capacity. Subsequent
    /// `append` calls return false without mutating state.
    bool is_full() const noexcept { return next_position_ >= kMaxLeaves; }

    /// Access the raw frontier for RPC `uno_getCommitmentTreeFrontier`
    /// (§9.1) and cell serialization.
    const std::array<FrontierLevel, kTreeDepth>& get_frontier() const noexcept { return levels_; }

    /// Replace the in-memory frontier outright. For use by deserialize /
    /// genesis setup only; caller is responsible for the invariant.
    void load_frontier(const std::array<FrontierLevel, kTreeDepth>& levels,
                       std::uint64_t next_position,
                       const NoteHash& root) noexcept;

    /// Serialize the 32 FrontierLevel cells as a linked chain (§5.2).
    /// Returns the head cell ref. The outer `UnoShardState` stores this
    /// head ref under its `^commitment_tree_cell` slot (§5.1).
    td::Ref<vm::Cell> serialize_to_cell() const;

    /// Parse a frontier chain previously produced by `serialize_to_cell`.
    /// On failure leaves `*this` untouched and returns false.
    ///
    /// `next_position` and `root` are typically stored in the parent
    /// `UnoShardState` cell (§5.1) and passed in here so this module does
    /// not redundantly embed them in the frontier chain.
    bool deserialize_from_cell(td::Ref<vm::Cell> head,
                               std::uint64_t next_position,
                               const NoteHash& expected_root);

  private:
    /// Recompute and cache `root_` from the current frontier + next_position.
    /// Called after every successful append and after deserialize.
    void recompute_root() noexcept;

    std::array<FrontierLevel, kTreeDepth> levels_{};
    std::uint64_t next_position_{0};
    NoteHash root_{};
};

}  // namespace uno_workchain
