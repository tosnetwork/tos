/*
    uno/test/fixtures/determinism_state_root.cpp

    Implementation of the cell-state serialiser adapter used by the §12 P.5
    cross-validator determinism test. See the header for the TU-split
    rationale (class UnoState collision between compute-phase.h and state.h).
*/
#include "uno/test/fixtures/determinism_state_root.h"

#include <cstring>

#include "uno/core/anchor-window.h"
#include "uno/core/cell-state.h"
#include "uno/core/commitment-tree.h"
#include "uno/core/nullifier-set.h"
#include "uno/core/state.h"

#include "vm/cells.h"

namespace uno_workchain::test_fixtures {

std::array<uint8_t, 32> compute_state_root_hash(
    std::unique_ptr<uno_workchain::CommitmentTree>& tree,
    std::unique_ptr<uno_workchain::NullifierSet>&   nfs,
    std::unique_ptr<uno_workchain::AnchorWindow>&   aw,
    const DetStats&                                 stats,
    uint64_t                                        next_position) {

    std::array<uint8_t, 32> out{};

    if (!tree || !nfs || !aw) {
        // Caller contract violation — return zero root.
        return out;
    }

    // Temporarily transfer ownership into an UnoShardState so serialize_state
    // sees a populated state. We move the unique_ptrs back out before
    // returning, so the caller's state is undisturbed on exit.
    uno_workchain::UnoShardState s = uno_workchain::UnoShardState::make_empty();
    s.next_position = next_position;

    // Sync the `commitment_tree_root` header field with the live root (the
    // cell-state deserialiser cross-checks this against the recomputed root
    // in A2's CommitmentTree::deserialize_from_cell).
    {
        const auto& root = tree->get_root();
        std::memcpy(s.commitment_tree_root.data(), root.data(), 32);
    }

    s.stats.burned_fees = stats.burned_fees;
    s.stats.tx_count    = stats.tx_count;
    s.stats.note_count  = stats.note_count;

    s.commitment_tree = std::move(tree);
    s.nullifier_set   = std::move(nfs);
    s.anchor_window   = std::move(aw);

    td::Ref<vm::Cell> root_cell = uno_workchain::serialize_state(s);

    // Always move the sub-objects back, even on serialise failure — the
    // caller expects its unique_ptrs to still own the same A2 objects.
    tree = std::move(s.commitment_tree);
    nfs  = std::move(s.nullifier_set);
    aw   = std::move(s.anchor_window);

    if (root_cell.is_null()) {
        return out;  // zeroed
    }

    // `Cell::Hash::as_array()` returns a `std::array<uint8_t, 32>` directly
    // (mirrors the spelling used across the tree: see
    // `evm/core/cell-state.cpp`, `evm/test/test-executor.cpp`,
    // `crypto/vm/tosops.cpp`). Copy in; the array is cheap and avoids
    // aliasing the cell's internal buffer.
    out = root_cell->get_hash().as_array();
    return out;
}

}  // namespace uno_workchain::test_fixtures
