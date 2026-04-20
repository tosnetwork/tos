/*
    Uno Workchain — in-memory UnoShardState (§5.1).

    UnoShardState is the single mutable object backing the wc=2 executor
    account. It is deliberately thin: all heavy data structures (commitment
    tree frontier, nullifier set, anchor ring, stats) live in separate,
    self-contained sub-objects owned by the state. Each such sub-object
    is serialised via its own cell-codec (Agent 2) and reassembled from
    `cell-state.{h,cpp}` at block boundaries.

    Thread-safety: `UnoStateFacade` owns the working copy used by the compute
    phase, and is accessed concurrently by the JSON-RPC read path. The
    access pattern mirrors `evm_workchain::EvmState` — a `std::shared_mutex`
    on the facade, read methods take `shared_lock`, write methods
    `unique_lock`. The compute phase holds a unique_lock for the duration
    of a block's apply_transfer sequence and publishes the mutated state
    back at end-of-block (§5.7, §7.7 step 10).

    Source: TOS-specific adapter; see doc/uno-workchain.md §5.
*/
#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <shared_mutex>

#include "uno/core/workchain.h"

namespace uno_workchain {

// Forward declarations of sub-object types owned by the state. Concrete
// definitions live in the header files authored by Agent 2; we only need
// a pointer / unique_ptr to them here to keep the state struct independent
// of their implementation details.
//
// Decision #14: names below match A2's real class names.
class CommitmentTree;      // uno/core/commitment-tree.h  (A2)
class NullifierSet;        // uno/core/nullifier-set.h    (A2)
class AnchorWindow;        // uno/core/anchor-window.h    (A2)
class BlockFilterBuilder;  // uno/core/block-filter.h     (A2)

// ---------------------------------------------------------------------------
// Stats (§5.5)
// ---------------------------------------------------------------------------

/// StatsCell content (§5.5). Plain ints; not consensus-critical in the sense
/// that they're derived view-of-history — but they ARE written into the
/// executor's canonical state cell every block, so two validators that
/// computed different stats would produce different state roots.
struct UnoStats {
    uint64_t burned_fees{0};
    uint64_t tx_count{0};
    uint64_t note_count{0};

    bool operator==(const UnoStats& other) const noexcept {
        return burned_fees == other.burned_fees && tx_count == other.tx_count &&
               note_count == other.note_count;
    }
};

// ---------------------------------------------------------------------------
// Live UnoShardState (§5.1)
// ---------------------------------------------------------------------------

/// The data members here mirror the §5.1 layout one-for-one. Nothing in this
/// struct touches the TOS cell tree directly — the conversion to/from
/// cells is owned by `cell-state.{h,cpp}`. That boundary keeps the compute
/// phase free to mutate the state in-memory at per-tx speed and to flush
/// once per block (§5.7, §7.7 step 10).
struct UnoShardState {
    // Header fields (inline in the root cell, §5.1)
    uint8_t  version{kShardStateVersion};   // schema version of this cell
    uint8_t  scheme_id{kSchemeIdV1};        // which crypto suite is active
    uint64_t next_position{0};              // index of next tree append
    std::array<uint8_t, kHashBytes> config_hash{};          // BLAKE3 over live wc=2 config
    std::array<uint8_t, kHashBytes> commitment_tree_root{}; // current Poseidon2 root

    // Sub-objects owned by the state (one ref each in the root cell / MetaCell).
    // Unique ownership: the state is the sole writer; RPC reads take a shared
    // lock on UnoStateFacade and read through these pointers.
    std::unique_ptr<CommitmentTree> commitment_tree;   // ref 0 of root
    std::unique_ptr<NullifierSet>   nullifier_set;     // ref 1 of root
    std::unique_ptr<AnchorWindow>   anchor_window;     // meta.ref 0
    UnoStats                        stats{};           // meta.ref 1 (inline struct)

    // Ref 3 of the root cell is RESERVED (§5.1). Absent by design.

    UnoShardState();
    ~UnoShardState();

    UnoShardState(UnoShardState&&) noexcept;
    UnoShardState& operator=(UnoShardState&&) noexcept;

    UnoShardState(const UnoShardState&) = delete;
    UnoShardState& operator=(const UnoShardState&) = delete;

    /// Construct a zero-initialised state suitable for genesis (§10.3): empty
    /// frontier, empty nullifier set, anchor window seeded with the empty-tree
    /// root, stats zeroed, next_position=0.
    static UnoShardState make_empty();

    /// True when no notes have ever been appended AND no nullifiers recorded.
    /// Used by init to detect a fresh-start process that needs to hydrate
    /// from genesis.
    bool is_empty() const noexcept;
};

// ---------------------------------------------------------------------------
// UnoStateFacade — RPC-safe facade wrapping UnoShardState + a BlockFilter accumulator
// ---------------------------------------------------------------------------

/// Thread-safe wrapper the compute phase and RPC handlers share. Compute
/// path holds a unique_lock for the entire block (§5.7); RPC reads take
/// shared_locks and get a consistent snapshot of the last-committed block
/// (§9.3 "All uno_* reads return the last-committed block's state").
class UnoStateFacade {
  public:
    UnoStateFacade();
    explicit UnoStateFacade(UnoShardState initial);
    ~UnoStateFacade();

    UnoStateFacade(const UnoStateFacade&) = delete;
    UnoStateFacade& operator=(const UnoStateFacade&) = delete;

    /// Direct access to the underlying state. Caller MUST hold the lock
    /// via `lock_shared()` / `mutex()` — mirrors the EVM pattern.
    UnoShardState& state() noexcept { return state_; }
    const UnoShardState& state() const noexcept { return state_; }

    /// Access to the in-progress block-filter accumulator (§2.8, §9.1).
    /// Writable only inside the compute phase (unique_lock held).
    BlockFilterBuilder* current_block_filter() noexcept { return current_block_filter_.get(); }
    const BlockFilterBuilder* current_block_filter() const noexcept {
        return current_block_filter_.get();
    }

    /// Rotate the current block-filter accumulator out and reset to empty.
    /// Called at end-of-block (§5.7) by `init`/compute-phase hook. The
    /// returned filter is what `uno_getBlockFilter` serves (§9.1).
    std::unique_ptr<BlockFilterBuilder> consume_current_block_filter();

    /// Shared/unique lock accessors for callers that need to hold the lock
    /// across multiple operations (e.g. compute-phase per-block critical
    /// section). Same idiom as `evm_workchain::EvmState::mutex()`.
    std::shared_mutex& mutex() const noexcept { return mutex_; }

  private:
    UnoShardState                 state_;
    std::unique_ptr<BlockFilterBuilder>  current_block_filter_;
    mutable std::shared_mutex     mutex_;
};

}  // namespace uno_workchain
