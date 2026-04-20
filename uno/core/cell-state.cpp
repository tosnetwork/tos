/*
    Uno Workchain — cell-native serializer implementation.

    See cell-state.h for the layout; this file is the straightforward
    CellBuilder / CellSlice round-trip.

    Source: TOS-specific adapter; see doc/uno-workchain.md §5, §10.3.
*/
#include "uno/core/cell-state.h"
#include "uno/core/workchain.h"

#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/cellslice.h"  // vm::load_cell_slice

#include "td/utils/logging.h"
#include "td/utils/Slice.h"

// Agent 2's sub-object headers. The `serialize_*` / `deserialize_*` codec
// entry points below are declared extern here; Agent 2 provides the
// definitions in commitment-tree.cpp / nullifier-set.cpp / anchor-window.cpp.
// TODO(uno-integration): if Agent 2 chooses different function names or
// signatures, update both this file and Agent 2's headers in the same
// change. Signatures below are the minimum shape §5.2/§5.3/§5.4 imply.
#include "uno/core/commitment-tree.h"
#include "uno/core/nullifier-set.h"
#include "uno/core/anchor-window.h"

namespace uno_workchain {

td::Ref<vm::Cell> serialize_commitment_tree(const CommitmentTree& tree);
bool deserialize_commitment_tree(td::Ref<vm::Cell> cell,
                                 std::unique_ptr<CommitmentTree>& out);

td::Ref<vm::Cell> serialize_nullifier_set(const NullifierSet& set);
bool deserialize_nullifier_set(td::Ref<vm::Cell> cell,
                               std::unique_ptr<NullifierSet>& out);

td::Ref<vm::Cell> serialize_anchor_window(const AnchorWindow& win);
bool deserialize_anchor_window(td::Ref<vm::Cell> cell,
                               std::unique_ptr<AnchorWindow>& out);

}  // namespace uno_workchain

// BLAKE3 is already linked in-tree; the header lives at `keys/blake3` in EVM
// usage, but the exact include path depends on Agent 6's CMake wiring.
// TODO(uno-integration): swap to the canonical BLAKE3 include path once
// Agent 6 pins it at the top-level `uno/CMakeLists.txt`.
#if __has_include("blake3.h")
#include "blake3.h"
#define UNO_HAS_BLAKE3 1
#else
#define UNO_HAS_BLAKE3 0
#endif

namespace uno_workchain {

// ---------------------------------------------------------------------------
// Stats cell
// ---------------------------------------------------------------------------

td::Ref<vm::Cell> encode_stats_cell(const UnoStats& stats) {
    vm::CellBuilder cb;
    // Inline: three u64s, no refs. 192 bits ≤ 1023.
    cb.store_long(static_cast<long long>(stats.burned_fees), 64);
    cb.store_long(static_cast<long long>(stats.tx_count), 64);
    cb.store_long(static_cast<long long>(stats.note_count), 64);
    return cb.finalize();
}

bool decode_stats_cell(td::Ref<vm::Cell> cell, UnoStats& out) {
    if (cell.is_null()) return false;
    auto cs = vm::load_cell_slice(cell);
    long long v = 0;
    if (!cs.fetch_long_bool(64, v)) return false;
    out.burned_fees = static_cast<uint64_t>(v);
    if (!cs.fetch_long_bool(64, v)) return false;
    out.tx_count = static_cast<uint64_t>(v);
    if (!cs.fetch_long_bool(64, v)) return false;
    out.note_count = static_cast<uint64_t>(v);
    return true;
}

// ---------------------------------------------------------------------------
// Meta cell
// ---------------------------------------------------------------------------

td::Ref<vm::Cell> build_meta_cell(td::Ref<vm::Cell> anchor_window_cell,
                                  td::Ref<vm::Cell> stats_cell) {
    if (anchor_window_cell.is_null() || stats_cell.is_null()) {
        LOG(ERROR) << "uno/cell-state: build_meta_cell received null ref(s)";
        return {};
    }
    vm::CellBuilder cb;
    // Meta cell is pure refs; no inline bits.
    if (!cb.store_ref_bool(std::move(anchor_window_cell))) return {};
    if (!cb.store_ref_bool(std::move(stats_cell))) return {};
    return cb.finalize();
}

// ---------------------------------------------------------------------------
// Config hash
// ---------------------------------------------------------------------------

std::array<uint8_t, kHashBytes> compute_config_hash(td::Slice config_cell_bytes) {
    std::array<uint8_t, kHashBytes> out{};
#if UNO_HAS_BLAKE3
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, kConfigHashTag, sizeof(kConfigHashTag) - 1);
    blake3_hasher_update(&h, config_cell_bytes.data(), config_cell_bytes.size());
    blake3_hasher_finalize(&h, out.data(), out.size());
#else
    // TODO(uno-integration): BLAKE3 not wired yet; zero the field so callers
    // can still round-trip cells during early assembly. Production paths
    // MUST have UNO_HAS_BLAKE3 defined.
    (void)config_cell_bytes;
    LOG(WARNING) << "uno/cell-state: BLAKE3 not available; config_hash left zero";
#endif
    return out;
}

// ---------------------------------------------------------------------------
// Root cell serialize / deserialize
// ---------------------------------------------------------------------------

td::Ref<vm::Cell> serialize_state(const UnoShardState& state) {
    // Serialise child refs first, so we can abort without leaving a partial
    // builder on the floor.
    td::Ref<vm::Cell> tree_cell;
    td::Ref<vm::Cell> nullifier_cell;
    td::Ref<vm::Cell> anchor_cell;

    if (state.commitment_tree) {
        tree_cell = serialize_commitment_tree(*state.commitment_tree);
    }
    if (state.nullifier_set) {
        nullifier_cell = serialize_nullifier_set(*state.nullifier_set);
    }
    if (state.anchor_window) {
        anchor_cell = serialize_anchor_window(*state.anchor_window);
    }

    if (tree_cell.is_null() || nullifier_cell.is_null() || anchor_cell.is_null()) {
        LOG(ERROR) << "uno/cell-state: one or more sub-object cells null; "
                   << "aborting serialize (tree=" << !tree_cell.is_null()
                   << " nf=" << !nullifier_cell.is_null()
                   << " anchor=" << !anchor_cell.is_null() << ")";
        return {};
    }

    auto stats_cell = encode_stats_cell(state.stats);
    if (stats_cell.is_null()) return {};

    auto meta_cell = build_meta_cell(std::move(anchor_cell), std::move(stats_cell));
    if (meta_cell.is_null()) return {};

    vm::CellBuilder cb;
    // Header magic + fixed inline fields.
    cb.store_long(kUnoShardStateMagic, kUnoShardStateMagicBits);
    cb.store_long(state.version, 8);
    cb.store_long(state.scheme_id, 8);
    cb.store_long(static_cast<long long>(state.next_position), 64);
    cb.store_bytes(state.config_hash.data(), kHashBytes);
    cb.store_bytes(state.commitment_tree_root.data(), kHashBytes);

    // Inline total: 32 + 8 + 8 + 64 + 256 + 256 = 624 bits ≤ 1023. (The
    // doc's 592-bit budget assumes the magic lives in a TLB tag outside
    // the 1023-bit cell body; we budget the tag too to keep one accounting.)

    // Ref slot 0 = commitment tree (§5.1).
    if (!cb.store_ref_bool(std::move(tree_cell))) return {};
    // Ref slot 1 = nullifier set.
    if (!cb.store_ref_bool(std::move(nullifier_cell))) return {};
    // Ref slot 2 = meta cell.
    if (!cb.store_ref_bool(std::move(meta_cell))) return {};
    // Ref slot 3 = RESERVED — intentionally left absent. CellBuilder records
    // "3 refs stored"; a future extension adds the fourth ref without a
    // schema migration (§5.1).
    static_assert(kStateRefReserved == 3, "reserved slot must be the 4th ref");
    static_assert(kStateRefCount == 4, "root cell budget is 4 refs total");

    return cb.finalize();
}

bool deserialize_state(td::Ref<vm::Cell> root, UnoShardState& out) {
    out = UnoShardState::make_empty();
    if (root.is_null()) {
        LOG(ERROR) << "uno/cell-state: deserialize_state called on null cell";
        return false;
    }

    auto cs = vm::load_cell_slice(root);

    // Magic guard.
    long long magic = 0;
    if (!cs.fetch_long_bool(kUnoShardStateMagicBits, magic) ||
        static_cast<uint32_t>(magic) != kUnoShardStateMagic) {
        LOG(ERROR) << "uno/cell-state: wrong or missing root magic (got 0x"
                   << std::hex << magic << std::dec
                   << ", expected 0x554E4F53)";
        return false;
    }

    long long v = 0;
    if (!cs.fetch_long_bool(8, v)) return false;
    out.version = static_cast<uint8_t>(v);
    if (!cs.fetch_long_bool(8, v)) return false;
    out.scheme_id = static_cast<uint8_t>(v);
    if (!cs.fetch_long_bool(64, v)) return false;
    out.next_position = static_cast<uint64_t>(v);
    if (!cs.fetch_bytes(out.config_hash.data(), kHashBytes)) return false;
    if (!cs.fetch_bytes(out.commitment_tree_root.data(), kHashBytes)) return false;

    if (out.version != kShardStateVersion) {
        LOG(ERROR) << "uno/cell-state: unexpected state version " << int(out.version)
                   << " (expected " << int(kShardStateVersion) << ")";
        return false;
    }

    // Refs. Exactly 3 must be present (ref 3 is reserved-absent).
    if (cs.size_refs() != 3) {
        LOG(ERROR) << "uno/cell-state: root cell has " << cs.size_refs()
                   << " refs, expected 3 (slot 3 is reserved-absent)";
        return false;
    }

    auto tree_cell      = cs.prefetch_ref(kStateRefCommitmentTree);
    auto nullifier_cell = cs.prefetch_ref(kStateRefNullifierSet);
    auto meta_cell      = cs.prefetch_ref(kStateRefMeta);

    if (!deserialize_commitment_tree(std::move(tree_cell), out.commitment_tree)) {
        LOG(ERROR) << "uno/cell-state: commitment tree deserialize failed";
        return false;
    }
    if (!deserialize_nullifier_set(std::move(nullifier_cell), out.nullifier_set)) {
        LOG(ERROR) << "uno/cell-state: nullifier set deserialize failed";
        return false;
    }

    // Meta cell: anchor window + stats.
    auto meta_cs = vm::load_cell_slice(meta_cell);
    if (meta_cs.size_refs() != 2) {
        LOG(ERROR) << "uno/cell-state: meta cell refs=" << meta_cs.size_refs()
                   << ", expected 2";
        return false;
    }
    auto anchor_cell = meta_cs.prefetch_ref(kMetaRefAnchorWindow);
    auto stats_cell  = meta_cs.prefetch_ref(kMetaRefStats);

    if (!deserialize_anchor_window(std::move(anchor_cell), out.anchor_window)) {
        LOG(ERROR) << "uno/cell-state: anchor window deserialize failed";
        return false;
    }
    if (!decode_stats_cell(std::move(stats_cell), out.stats)) {
        LOG(ERROR) << "uno/cell-state: stats cell deserialize failed";
        return false;
    }

    return true;
}

}  // namespace uno_workchain
