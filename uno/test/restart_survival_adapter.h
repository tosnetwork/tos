/*
    uno/test/restart_survival_adapter.h

    Opaque adapter over `uno_workchain::UnoShardState` (uno/core/state.h)
    for the §12 P.4 restart-survival test. Exists because `state.h` and
    `compute-phase.h` both declare a class named `UnoState` in the same
    namespace; pulling both into one TU is a hard compile conflict. This
    header hides the `state.h` side behind a `void*` handle + plain C++
    functions so `test-restart-survival.cpp` can include only
    `compute-phase.h` while still exercising the cell-state round-trip.

    The adapter owns a real `UnoShardState` with allocated sub-objects
    (`CommitmentTree`, `NullifierSet`, `AnchorWindow`, `UnoStats`) and
    surfaces the exact mutation / read surface that `apply_transfer`
    (uno/core/compute-phase.cpp) calls. Consumers:

      - `test-restart-survival.cpp`'s `ShardStateAdapter` (subclass of
        `uno_workchain::UnoState` from compute-phase.h) delegates each
        virtual into the functions below.
      - The round-trip driver calls `adapter_serialize`, constructs a
        fresh handle via `adapter_make_empty`, deserializes into it via
        `adapter_deserialize`, and byte-compares the resulting cell hash
        and fingerprint to the pre-restart values.

    Determinism: every call is side-effect-free apart from the documented
    mutation on the passed handle. No globals, no wall clock, no RNG.
*/
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "vm/cells/Cell.h"  // td::Ref, vm::Cell

namespace uno_workchain { namespace test_restart {

// Opaque handle to a `UnoShardState` + its three sub-objects.
// Owned by the caller; release with `adapter_destroy`.
struct StateHandle;

/// Structural fingerprint of an UnoShardState. Every field is
/// consensus-observable: mismatch between pre- and post-restart means
/// the §12 P.4 invariant is broken.
struct StateFingerprint {
    // §5.1 inline header fields.
    std::array<uint8_t, 32> commitment_tree_root{};
    uint64_t                next_position{0};

    // §5.3 nullifier set. Only the on-cell dict root hash is
    // consensus-observable; `NullifierSet::size()` is a local counter
    // that `load_from_cell` resets (see nullifier-set.h) unless the
    // caller supplies `known_size`, which cell-state.cpp does not, so
    // we record the 32-byte dict-root cell hash instead. Hash of the
    // empty dict is all-zeros by convention.
    std::array<uint8_t, 32> nullifier_set_root{};

    // §5.4 anchor window — live-entry count + BLAKE3-style digest over
    // the oldest-to-newest entry sequence (computed via sha256 here because
    // the test TU may or may not link the avatar blake3 adapter; the only
    // invariant is that both pre- and post-restart runs hash via the same
    // function, producing byte-identical digests).
    std::size_t             anchor_window_size{0};
    std::array<uint8_t, 32> anchor_window_digest{};

    // §5.5 stats triplet (inline in the StatsCell).
    uint64_t                stats_burned_fees{0};
    uint64_t                stats_tx_count{0};
    uint64_t                stats_note_count{0};
};

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Build a fresh, empty UnoShardState with all sub-objects allocated.
/// Seeds the anchor window with the empty-tree root so the first call
/// to `adapter_anchor_window_contains` on a genesis anchor resolves
/// true (mirrors `LiveUnoState`'s ctor in uno/core/init.cpp).
StateHandle* adapter_make_empty();

void adapter_destroy(StateHandle*);

// ---------------------------------------------------------------------------
// Mutations — called from ShardStateAdapter::append_commitment etc.
// ---------------------------------------------------------------------------

void adapter_append_commitment(StateHandle*, const uint8_t cm[32]);
void adapter_insert_nullifier(StateHandle*, const uint8_t nf[32]);
void adapter_bump_stats(StateHandle*, uint64_t fee, uint64_t note_count_delta);

/// Push the current commitment-tree root into the anchor window. Mirrors
/// `LiveUnoState::finalize_block`'s anchor-push step; callers invoke this
/// to seed the window with a batch of anchors that txs will reference.
void adapter_push_current_anchor(StateHandle*);

/// Push a caller-supplied 32-byte value as an anchor. Used by the driver
/// to install a stable "genesis" anchor that all txs in the batch share.
void adapter_push_anchor_bytes(StateHandle*, const uint8_t anchor[32]);

// ---------------------------------------------------------------------------
// Reads — called from ShardStateAdapter::anchor_window_contains etc.
// ---------------------------------------------------------------------------

bool adapter_anchor_window_contains(const StateHandle*, const uint8_t anchor[32]);
bool adapter_nullifier_is_spent(const StateHandle*, const uint8_t nf[32]);

/// Current commitment-tree root snapshot. Returned by copy.
std::array<uint8_t, 32> adapter_commitment_tree_root(const StateHandle*);

// ---------------------------------------------------------------------------
// Fingerprint + serialise/deserialise
// ---------------------------------------------------------------------------

StateFingerprint adapter_fingerprint(const StateHandle*);

/// Serialise the state into a root Cell (uno/core/cell-state.h). Returns a
/// null ref on codec failure.
td::Ref<vm::Cell> adapter_serialize(const StateHandle*);

/// Deserialise `root` into the target handle, replacing its contents.
/// Returns false on codec failure (target is left default-constructed).
bool adapter_deserialize_into(StateHandle* target, td::Ref<vm::Cell> root);

}}  // namespace uno_workchain::test_restart
