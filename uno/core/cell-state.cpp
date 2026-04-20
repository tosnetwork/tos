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

// A2's sub-object headers. Decision #14 pins the API: each class owns a
// method-based codec (`serialize_to_cell()` / `deserialize_from_cell(...)`).
// The obsolete free-function `serialize_commitment_tree(...)` etc. that A1
// forward-declared here never existed in A2; this translation unit now
// dispatches directly through the member functions.
#include "uno/core/commitment-tree.h"
#include "uno/core/nullifier-set.h"
#include "uno/core/anchor-window.h"

// BLAKE3 is wired through the in-tree adapter, which is backed by the
// vendored avatar crypto tree (third-party/avatar-crypto/, decision #41).
// uno/CMakeLists.txt compiles this TU into the `uno_workchain` target with
// UNO_BLAKE3_AVATAR=1 (PUBLIC). An unconfigured build must fail loudly
// rather than silently produce zero-filled hashes.
#ifndef UNO_BLAKE3_AVATAR
#error "cell-state.cpp requires UNO_BLAKE3_AVATAR=1; install third-party/avatar-crypto/ per uno/CMakeLists.txt"
#endif
#include "uno/crypto/internal/blake3_adapter.h"

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
    static_assert(kHashBytes == 32,
                  "compute_config_hash assumes BLAKE3-256 output");
    std::array<uint8_t, kHashBytes> out{};
    uno_workchain::crypto::internal::Blake3Hasher h;
    h.update(td::Slice(reinterpret_cast<const char*>(kConfigHashTag),
                       sizeof(kConfigHashTag) - 1));
    h.update(config_cell_bytes);
    h.finalize_32(out.data());
    return out;
}

// ---------------------------------------------------------------------------
// Root cell serialize / deserialize
// ---------------------------------------------------------------------------

td::Ref<vm::Cell> serialize_state(const UnoShardState& state) {
    // Serialise child refs first, so we can abort without leaving a partial
    // builder on the floor. Decision #14: each sub-object owns a method-
    // based `serialize_to_cell()` codec.
    td::Ref<vm::Cell> tree_cell;
    td::Ref<vm::Cell> nullifier_cell;
    td::Ref<vm::Cell> anchor_cell;

    if (state.commitment_tree) {
        tree_cell = state.commitment_tree->serialize_to_cell();
    }
    if (state.nullifier_set) {
        // NullifierSet exposes the dict root as a Maybe ^Cell. Always wrap
        // in a cell so the root-cell ref slot is never null (even for an
        // empty set), because `store_ref_bool` cannot accept a null ref.
        vm::CellBuilder nf_cb;
        (void)state.nullifier_set->append_to_builder(nf_cb);
        nullifier_cell = nf_cb.finalize();
    }
    if (state.anchor_window) {
        anchor_cell = state.anchor_window->serialize_to_cell();
        if (anchor_cell.is_null()) {
            // Empty window — serialize an empty-marker cell so the meta ref
            // slot is never null (parent cell must always have a ref).
            vm::CellBuilder empty_cb;
            anchor_cell = empty_cb.finalize();
        }
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

    // Decision #14: use A2's method-based codec.
    {
        auto tree = std::make_unique<CommitmentTree>();
        // A2's CommitmentTree::deserialize_from_cell cross-checks the
        // recomputed root against the header value; we pass them through.
        // The `NoteHash` type is a 32-byte array alias — copy in.
        NoteHash expected_root{};
        std::copy(out.commitment_tree_root.begin(),
                  out.commitment_tree_root.end(),
                  expected_root.begin());
        if (!tree->deserialize_from_cell(std::move(tree_cell),
                                         out.next_position,
                                         expected_root)) {
            LOG(ERROR) << "uno/cell-state: commitment tree deserialize failed";
            return false;
        }
        out.commitment_tree = std::move(tree);
    }
    {
        auto nf = std::make_unique<NullifierSet>();
        // `nullifier_cell` is the cell built by `append_to_builder`: it
        // carries one `Maybe ^Cell` bit + optional ref. Load the root-ref
        // directly out of that wrapper.
        auto nf_cs = vm::load_cell_slice(nullifier_cell);
        long long has_root = 0;
        if (!nf_cs.fetch_long_bool(1, has_root)) {
            LOG(ERROR) << "uno/cell-state: nullifier wrapper missing tag bit";
            return false;
        }
        td::Ref<vm::Cell> dict_root;
        if (has_root) {
            if (!nf_cs.fetch_ref_to(dict_root)) {
                LOG(ERROR) << "uno/cell-state: nullifier wrapper missing root ref";
                return false;
            }
        }
        nf->load_from_cell(std::move(dict_root));
        out.nullifier_set = std::move(nf);
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

    {
        auto win = std::make_unique<AnchorWindow>(kDefaultAnchorWindowSize);
        // Empty anchor windows serialize as an empty placeholder cell
        // (size=0 bits, no refs); treat that as "empty window" instead of
        // a parse error.
        auto probe = vm::load_cell_slice(anchor_cell);
        if (probe.size() == 0 && probe.size_refs() == 0) {
            // leave the default-constructed empty window as-is
        } else if (!win->deserialize_from_cell(std::move(anchor_cell),
                                                kDefaultAnchorWindowSize)) {
            LOG(ERROR) << "uno/cell-state: anchor window deserialize failed";
            return false;
        }
        out.anchor_window = std::move(win);
    }
    if (!decode_stats_cell(std::move(stats_cell), out.stats)) {
        LOG(ERROR) << "uno/cell-state: stats cell deserialize failed";
        return false;
    }

    return true;
}

}  // namespace uno_workchain
