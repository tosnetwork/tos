/*
    Uno Workchain — incremental commitment tree implementation (§2.3, §5.2).
    Source: TOS-specific (not copied from upstream).
*/
#include "uno/core/commitment-tree.h"

#include <cstring>

#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

namespace uno_workchain {

// ---------------------------------------------------------------------------
// Empty-subtree hash table (lazily computed, then cached forever).
//
// `empty[0]` is the canonical empty leaf. The v1 choice is all-zero bytes —
// consistent with a note whose commitment would never legitimately be zero
// (Poseidon2 of any non-trivial input is overwhelmingly unlikely to be zero).
// Each higher level is the Poseidon2 compression of two copies of the level
// below. See §2.3.
// ---------------------------------------------------------------------------
namespace {

struct EmptySubtreeTable {
    std::array<NoteHash, kTreeDepth + 1> levels{};
    EmptySubtreeTable() {
        // levels[0] = 32 zero bytes (canonical empty leaf).
        levels[0] = kZeroHash;
        for (std::size_t i = 0; i < kTreeDepth; ++i) {
            poseidon2_goldilocks_compress_2to1(levels[i].data(), levels[i].data(), levels[i + 1].data());
        }
    }
};

const EmptySubtreeTable& empty_subtree_table() {
    // Magic static initialization: thread-safe, computed once per process.
    static const EmptySubtreeTable table;
    return table;
}

}  // namespace

const NoteHash& empty_subtree_hash(std::size_t level) {
    // Clamp defensively; depth-kTreeDepth is the full-tree root.
    const auto& tbl = empty_subtree_table().levels;
    if (level > kTreeDepth) level = kTreeDepth;
    return tbl[level];
}

// ---------------------------------------------------------------------------
// CommitmentTree
// ---------------------------------------------------------------------------

CommitmentTree::CommitmentTree() {
    // All frontier slots start unfilled. Root of an empty depth-32 tree is
    // the precomputed empty-subtree hash at the top level.
    root_ = empty_subtree_hash(kTreeDepth);
}

bool CommitmentTree::append(const NoteHash& cm, NoteHash& new_root) noexcept {
    if (is_full()) return false;

    // Canonical incremental-Merkle frontier walk.
    //
    // `current` starts as the new leaf; at each level i, if levels_[i] is
    // filled we hash (levels_[i].hash, current) into `current` and clear
    // the slot (the two siblings now have a parent, so their parent must
    // propagate upward). Otherwise we store `current` into levels_[i] and
    // stop (this leaf's left-sibling role is recorded, waiting for a future
    // right sibling).
    NoteHash current = cm;
    for (std::size_t i = 0; i < kTreeDepth; ++i) {
        if (levels_[i].filled) {
            NoteHash parent{};
            poseidon2_goldilocks_compress_2to1(levels_[i].hash.data(),
                                               current.data(),
                                               parent.data());
            levels_[i].filled = false;
            levels_[i].hash = NoteHash{};
            current = parent;
        } else {
            levels_[i].filled = true;
            levels_[i].hash = current;
            break;
        }
    }

    next_position_ += 1;
    recompute_root();
    new_root = root_;
    return true;
}

NoteHash CommitmentTree::append(const NoteHash& cm) noexcept {
    NoteHash r{};
    if (!append(cm, r)) return kZeroHash;
    return r;
}

void CommitmentTree::load_frontier(const std::array<FrontierLevel, kTreeDepth>& levels,
                                    std::uint64_t next_position,
                                    const NoteHash& root) noexcept {
    levels_ = levels;
    next_position_ = next_position;
    root_ = root;
    // No recompute here: callers that supply an authoritative root (e.g.
    // from on-chain state) trust it. deserialize_from_cell() cross-checks.
}

void CommitmentTree::recompute_root() noexcept {
    // Walk from level 0 upward. At each level: if levels_[i] is filled use
    // its hash, else combine with the empty-subtree hash. `current` holds
    // the running right-edge hash as it propagates up.
    //
    // Classical trick: `current` starts as the empty-subtree hash at level 0
    // (the phantom "next leaf" slot) and at each level combines the
    // filled-slot sibling (if any) on the left with itself as the right
    // child, or its own continuation with the empty subtree on the right.
    NoteHash current = empty_subtree_hash(0);
    for (std::size_t i = 0; i < kTreeDepth; ++i) {
        NoteHash parent{};
        if (levels_[i].filled) {
            // filled slot is a left sibling; empty/synthetic right child is
            // `empty_subtree_hash(i)` — the subtree that would sit below the
            // not-yet-appended leaf.
            poseidon2_goldilocks_compress_2to1(levels_[i].hash.data(),
                                               current.data(),
                                               parent.data());
        } else {
            // unfilled: empty left child, current continues as the right.
            poseidon2_goldilocks_compress_2to1(empty_subtree_hash(i).data(),
                                               current.data(),
                                               parent.data());
        }
        current = parent;
    }
    root_ = current;
}

// ---------------------------------------------------------------------------
// Cell serialization
//
// Schema (TL-B informal):
//   frontier_level$_  filled:Bool hash:bits256 next:(Maybe ^FrontierLevel)
//       = FrontierLevel;
//
// A fixed chain of exactly kTreeDepth (=32) cells is emitted; the tail cell
// has `next = nothing`.
// ---------------------------------------------------------------------------

td::Ref<vm::Cell> CommitmentTree::serialize_to_cell() const {
    td::Ref<vm::Cell> tail;  // builds bottom-up so each cell can ref the next.
    for (std::size_t ri = 0; ri < kTreeDepth; ++ri) {
        // Iterate from the deepest level down to level 0 so `tail` holds the
        // already-built suffix of the chain.
        std::size_t level = kTreeDepth - 1 - ri;
        vm::CellBuilder cb;
        cb.store_long_bool(levels_[level].filled ? 1 : 0, 1);
        cb.store_bytes(levels_[level].hash.data(), kNoteHashBytes);
        if (tail.not_null()) {
            cb.store_long_bool(1, 1);
            cb.store_ref(tail);
        } else {
            cb.store_long_bool(0, 1);
        }
        tail = cb.finalize();
    }
    return tail;  // head of the chain (level 0 cell)
}

bool CommitmentTree::deserialize_from_cell(td::Ref<vm::Cell> head,
                                            std::uint64_t next_position,
                                            const NoteHash& expected_root) {
    if (head.is_null()) return false;
    if (next_position > kMaxLeaves) return false;

    std::array<FrontierLevel, kTreeDepth> tmp{};
    td::Ref<vm::Cell> cur = head;
    for (std::size_t i = 0; i < kTreeDepth; ++i) {
        if (cur.is_null()) return false;
        auto cs = vm::load_cell_slice(cur);
        long long filled_bit = 0;
        if (!cs.fetch_long_bool(1, filled_bit)) return false;
        unsigned char buf[kNoteHashBytes];
        if (!cs.fetch_bytes(buf, kNoteHashBytes)) return false;
        long long has_next = 0;
        if (!cs.fetch_long_bool(1, has_next)) return false;
        tmp[i].filled = (filled_bit != 0);
        std::memcpy(tmp[i].hash.data(), buf, kNoteHashBytes);
        if (has_next) {
            if (!cs.fetch_ref_to(cur)) return false;
        } else {
            cur = {};
        }
    }
    // After kTreeDepth iterations there should be no tail cell left.
    if (cur.not_null()) return false;

    // Commit to temporary buffers first, cross-check against expected_root.
    auto saved_levels = levels_;
    auto saved_next = next_position_;
    auto saved_root = root_;
    levels_ = tmp;
    next_position_ = next_position;
    recompute_root();
    if (root_ != expected_root) {
        // Roll back; caller's state is untouched.
        levels_ = saved_levels;
        next_position_ = saved_next;
        root_ = saved_root;
        return false;
    }
    return true;
}

}  // namespace uno_workchain
