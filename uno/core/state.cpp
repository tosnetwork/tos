/*
    Uno Workchain — UnoShardState / UnoState implementation.

    Responsibilities:
      - Default-construct and destroy the sub-object pointers. The concrete
        types live in headers authored by Agent 2; this translation unit
        therefore needs their full declarations at the point of ctor/dtor.
      - Provide `make_empty()` genesis factory.
      - Provide the RPC-safe facade's book-keeping.

    Source: TOS-specific adapter; see doc/uno-workchain.md §5.
*/
#include "uno/core/state.h"

// Full declarations of the sub-object types. These headers are owned by
// Agent 2 (doc/uno-workchain.md §5.2 / §5.3 / §5.4 / §9.1).
// TODO(uno-integration): Agent 2 must provide headers with the exact names
// `uno/core/commitment-tree.h`, `uno/core/nullifier-set.h`,
// `uno/core/anchor-window.h`, `uno/core/block-filter.h` and classes
// `CommitmentTree`, `NullifierSet`, `AnchorWindow`, `BlockFilter`. Until
// those land the template-less unique_ptr<T> members below will only
// compile once forward declarations become definitions at the ctor/dtor
// points — if Agent 2 uses different names, adjust both state.h and here.
#if __has_include("uno/core/commitment-tree.h")
#include "uno/core/commitment-tree.h"
#endif
#if __has_include("uno/core/nullifier-set.h")
#include "uno/core/nullifier-set.h"
#endif
#if __has_include("uno/core/anchor-window.h")
#include "uno/core/anchor-window.h"
#endif
#if __has_include("uno/core/block-filter.h")
#include "uno/core/block-filter.h"
#endif

namespace uno_workchain {

// ---------------------------------------------------------------------------
// UnoShardState
// ---------------------------------------------------------------------------

UnoShardState::UnoShardState() = default;
UnoShardState::~UnoShardState() = default;

UnoShardState::UnoShardState(UnoShardState&&) noexcept = default;
UnoShardState& UnoShardState::operator=(UnoShardState&&) noexcept = default;

UnoShardState UnoShardState::make_empty() {
    UnoShardState s;
    s.version = kShardStateVersion;
    s.scheme_id = kSchemeIdV1;
    s.next_position = 0;
    s.config_hash.fill(0);           // populated by cell-state serialize path
    s.commitment_tree_root.fill(0);  // populated once the empty-tree root is
                                     // computed by CommitmentTree::empty()

    // The sub-object instances are *not* allocated here. They are constructed
    // by `cell-state::load_state(...)` from existing cells, or by
    // `genesis::build_zerostate(...)` for a fresh chain. Keeping the empty
    // struct pointer-null lets us detect an un-hydrated state via
    // `is_empty()` without falsely counting "empty sub-objects" as populated.
    return s;
}

bool UnoShardState::is_empty() const noexcept {
    if (next_position != 0) return false;
    if (stats.tx_count != 0 || stats.note_count != 0 || stats.burned_fees != 0) {
        return false;
    }
    // Pointer-null counts as empty; a populated state will have all three
    // sub-objects allocated (set by cell-state::load_state or
    // genesis::build_zerostate).
    return commitment_tree == nullptr && nullifier_set == nullptr &&
           anchor_window == nullptr;
}

// ---------------------------------------------------------------------------
// UnoState
// ---------------------------------------------------------------------------

UnoState::UnoState() : state_(UnoShardState::make_empty()) {}

UnoState::UnoState(UnoShardState initial) : state_(std::move(initial)) {}

UnoState::~UnoState() = default;

std::unique_ptr<BlockFilter> UnoState::consume_current_block_filter() {
    // Caller must hold unique_lock on mutex_.
    auto out = std::move(current_block_filter_);
    current_block_filter_.reset();  // defensive; std::move should already null
    return out;
}

}  // namespace uno_workchain
