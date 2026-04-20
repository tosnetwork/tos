/*
    uno/test/restart_survival_adapter.cpp

    Implementation of the opaque UnoShardState adapter declared in the
    companion header. Pulls `state.h` / `cell-state.h` / sub-object
    headers; DELIBERATELY does not pull `compute-phase.h` (which would
    clash on the `UnoState` class name in the same namespace).
*/
#include "uno/test/restart_survival_adapter.h"

#include <cstring>

#include "td/utils/crypto.h"     // td::sha256

#include "uno/core/state.h"
#include "uno/core/cell-state.h"
#include "uno/core/commitment-tree.h"
#include "uno/core/nullifier-set.h"
#include "uno/core/anchor-window.h"

namespace uno_workchain { namespace test_restart {

namespace uw = ::uno_workchain;

// ---------------------------------------------------------------------------
// StateHandle definition
// ---------------------------------------------------------------------------
struct StateHandle {
    uw::UnoShardState state;
    // Ordered insertion trace of nullifiers for fingerprint digest.
    // The authoritative vm::Dictionary does not expose iteration, so we
    // keep a side-log here. Not serialised into the cell; re-populated
    // only when new inserts run through the adapter.
    std::vector<std::array<uint8_t, 32>> nullifier_insert_order;
};

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------
StateHandle* adapter_make_empty() {
    auto* h = new StateHandle{};
    h->state = uw::UnoShardState::make_empty();
    // Allocate sub-objects (make_empty leaves the unique_ptrs null; we
    // need full instances for round-trip).
    h->state.commitment_tree = std::make_unique<uw::CommitmentTree>();
    h->state.nullifier_set   = std::make_unique<uw::NullifierSet>();
    h->state.anchor_window   = std::make_unique<uw::AnchorWindow>();

    // Seed commitment_tree_root with the empty-tree root (mirrors
    // LiveUnoState's ctor in uno/core/init.cpp).
    const uw::NoteHash& empty_root = h->state.commitment_tree->get_root();
    std::copy(empty_root.begin(), empty_root.end(),
              h->state.commitment_tree_root.begin());
    h->state.next_position = 0;
    h->state.stats = uw::UnoStats{};
    return h;
}

void adapter_destroy(StateHandle* h) {
    delete h;
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------
void adapter_append_commitment(StateHandle* h, const uint8_t cm[32]) {
    uw::NoteHash nh{};
    std::memcpy(nh.data(), cm, 32);
    uw::NoteHash new_root = h->state.commitment_tree->append(nh);
    std::copy(new_root.begin(), new_root.end(),
              h->state.commitment_tree_root.begin());
    h->state.next_position = h->state.commitment_tree->next_position();
}

void adapter_insert_nullifier(StateHandle* h, const uint8_t nf[32]) {
    uw::Nullifier n{};
    std::memcpy(n.data(), nf, 32);
    bool inserted = h->state.nullifier_set->insert(n);
    if (inserted) {
        std::array<uint8_t, 32> k{};
        std::memcpy(k.data(), nf, 32);
        h->nullifier_insert_order.push_back(k);
    }
}

void adapter_bump_stats(StateHandle* h, uint64_t fee, uint64_t note_count_delta) {
    h->state.stats.burned_fees += fee;
    h->state.stats.tx_count    += 1;
    h->state.stats.note_count  += note_count_delta;
}

void adapter_push_current_anchor(StateHandle* h) {
    uw::NoteHash nh{};
    std::memcpy(nh.data(), h->state.commitment_tree_root.data(), 32);
    h->state.anchor_window->push(nh);
}

void adapter_push_anchor_bytes(StateHandle* h, const uint8_t anchor[32]) {
    uw::NoteHash nh{};
    std::memcpy(nh.data(), anchor, 32);
    h->state.anchor_window->push(nh);
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------
bool adapter_anchor_window_contains(const StateHandle* h, const uint8_t anchor[32]) {
    uw::NoteHash nh{};
    std::memcpy(nh.data(), anchor, 32);
    return h->state.anchor_window->contains(nh);
}

bool adapter_nullifier_is_spent(const StateHandle* h, const uint8_t nf[32]) {
    uw::Nullifier n{};
    std::memcpy(n.data(), nf, 32);
    return h->state.nullifier_set->contains(n);
}

std::array<uint8_t, 32> adapter_commitment_tree_root(const StateHandle* h) {
    std::array<uint8_t, 32> out{};
    std::memcpy(out.data(), h->state.commitment_tree_root.data(), 32);
    return out;
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------
static std::array<uint8_t, 32> sha256_over(const void* p, std::size_t n) {
    std::array<uint8_t, 32> out{};
    // td::Slice rejects a null pointer even when the size is 0. Pass a
    // one-byte stub for the empty case (the empty-anchor-window
    // fingerprint digest is always sha256 over the empty string stub,
    // which is constant across pre- and post-restart — the only
    // invariant this function is used for).
    static const char kEmpty = 0;
    td::Slice in = (p && n) ? td::Slice(reinterpret_cast<const char*>(p), n)
                            : td::Slice(&kEmpty, std::size_t{0});
    td::sha256(in, td::MutableSlice(reinterpret_cast<char*>(out.data()), 32));
    return out;
}

StateFingerprint adapter_fingerprint(const StateHandle* h) {
    StateFingerprint fp;
    std::memcpy(fp.commitment_tree_root.data(),
                h->state.commitment_tree_root.data(), 32);
    fp.next_position   = h->state.next_position;

    // nullifier_set_root: hash of the dict root cell (or zeros when
    // the dict is empty). The dict root uniquely determines the set
    // contents per §5.3.
    auto nf_root = h->state.nullifier_set->dict_root_cell();
    if (nf_root.not_null()) {
        td::Bits256 rh(nf_root->get_hash().bits());
        std::memcpy(fp.nullifier_set_root.data(), rh.data(), 32);
    }

    // Anchor window digest: sha256 over each live entry in oldest-first
    // order. `AnchorWindow::snapshot()` already returns that ordering.
    std::vector<uw::NoteHash> entries = h->state.anchor_window->snapshot();
    fp.anchor_window_size = entries.size();
    std::vector<uint8_t> buf;
    buf.reserve(entries.size() * 32);
    for (const auto& e : entries) {
        buf.insert(buf.end(), e.begin(), e.end());
    }
    fp.anchor_window_digest = sha256_over(buf.data(), buf.size());

    fp.stats_burned_fees = h->state.stats.burned_fees;
    fp.stats_tx_count    = h->state.stats.tx_count;
    fp.stats_note_count  = h->state.stats.note_count;
    return fp;
}

// ---------------------------------------------------------------------------
// Serialise / deserialise
// ---------------------------------------------------------------------------
td::Ref<vm::Cell> adapter_serialize(const StateHandle* h) {
    return uw::serialize_state(h->state);
}

bool adapter_deserialize_into(StateHandle* target, td::Ref<vm::Cell> root) {
    // Reset `target->state`. `deserialize_state` overwrites its `out`
    // argument via `make_empty()` on entry, which wipes the sub-object
    // unique_ptrs and then populates them from the cell tree. After a
    // successful deserialise the sub-objects are re-allocated inside
    // cell-state.cpp.
    target->nullifier_insert_order.clear();
    return uw::deserialize_state(root, target->state);
}

}}  // namespace uno_workchain::test_restart
