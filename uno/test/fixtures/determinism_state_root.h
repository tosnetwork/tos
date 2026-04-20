/*
    uno/test/fixtures/determinism_state_root.h

    Helper for the §12 P.5 cross-validator determinism test (K-determinism-drive).

    Computes the canonical UnoShardState cell-root hash from a running test
    state backed by A2 primitives. Exists as a separate TU because the
    `class UnoState` spellings in `uno/core/compute-phase.h` (pure-virtual
    consensus interface) and `uno/core/state.h` (RPC-safe UnoShardState
    wrapper) collide when both headers are included in the same translation
    unit (see the comment block in `uno/core/init.cpp` lines 74–82). This
    file is linked into the determinism test binary, includes only the A1
    state/cell-state headers (not compute-phase.h), and lets the main test
    TU stay on the compute-phase `UnoState` contract.

    Usage pattern from the test:
      ValidatorState vs;        // implements compute-phase UnoState
      ... apply transfers ...
      auto root = compute_state_root_hash(vs.commitment_tree_,
                                          vs.nullifier_set_,
                                          vs.anchor_window_,
                                          vs.stats_);
      // `root` is the 32-byte cell hash of serialize_state(...).

    `compute_state_root_hash` temporarily moves the three unique_ptrs into
    an `UnoShardState` (for the serializer's ownership contract), serialises,
    grabs the root cell's representation hash, then moves the pointers back
    into the caller-owned unique_ptrs. After return the caller's unique_ptrs
    still own the same A2 sub-objects. The function is const-correct from
    the caller's perspective — no sub-object mutation happens during
    serialise.
*/
#pragma once

#include <array>
#include <cstdint>
#include <memory>

namespace uno_workchain {

// Forward declarations — real definitions live in their own headers. We
// deliberately keep state.h / cell-state.h out of this header so the test
// TU can include compute-phase.h without collision.
class CommitmentTree;
class NullifierSet;
class AnchorWindow;

}  // namespace uno_workchain

namespace uno_workchain::test_fixtures {

/// Consensus-observable counters mirrored from UnoShardState::stats.
struct DetStats {
    uint64_t burned_fees{0};
    uint64_t tx_count{0};
    uint64_t note_count{0};
};

/// Serialise the current state into an UnoShardState cell and return its
/// 32-byte representation hash (`cell->get_hash().bits().as_array<32>()`).
///
/// The three unique_ptr arguments must be non-null; their owned objects are
/// temporarily moved into an `UnoShardState`, passed to
/// `uno_workchain::serialize_state`, then moved back before return. The
/// caller's unique_ptrs still own the same A2 sub-objects post-call.
///
/// Returns a zeroed array and logs ERROR if `serialize_state` yields a
/// null cell (shouldn't happen for well-formed inputs).
std::array<uint8_t, 32> compute_state_root_hash(
    std::unique_ptr<uno_workchain::CommitmentTree>& tree,
    std::unique_ptr<uno_workchain::NullifierSet>&   nfs,
    std::unique_ptr<uno_workchain::AnchorWindow>&   aw,
    const DetStats&                                 stats,
    uint64_t                                        next_position);

}  // namespace uno_workchain::test_fixtures
