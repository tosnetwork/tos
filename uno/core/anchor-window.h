/*
    Uno Workchain (wc=2) — anchor window (§5.4).

    Ring buffer of the last 100 commitment-tree roots. At end of block the
    current root is pushed; the oldest is evicted. A `Transfer` tx's `anchor`
    field must match one of the roots in the window for the spend-membership
    proof to be accepted (§4.3 step 1.5).

    Sizing (§5.4): 100 blocks × 32 B/root = 3.2 KB, stored as a linear cell
    chain with ~4 roots inlined per cell (the exact fan-out is set by the
    `kRootsPerCell` constant below). With kRootsPerCell = 4 this costs ~25
    cells, 1–2 levels of cell-walk.

    The window size is declared as `kDefaultAnchorWindowSize = 100` to match
    ConfigParam 26 `anchor_window_size` (§10.2). Callers can instantiate the
    class with any size; consensus must agree on the same value chain-wide.

    Source: TOS-specific (not copied from upstream).
*/
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "uno/core/commitment-tree.h"
#include "vm/cells.h"

namespace uno_workchain {

/// Default window depth (§5.4, matches ConfigParam 26).
static constexpr std::uint32_t kDefaultAnchorWindowSize = 100;

/// Cell serialization fan-out. 4 × 32 B hashes + small header = 1 KB total
/// per cell — well under the 128 B inline-data limit requires we split
/// further, but each cell can carry one 256-bit hash of inline data + ~3
/// refs to child cells; a simpler linear chain (one root per cell + next
/// ref) trades ~25 more cells for a trivially-auditable codec. We take
/// the simple linear chain here.
static constexpr std::size_t kRootsPerCell = 1;

/// 100-block ring buffer of commitment-tree roots (§5.4).
///
/// Semantics:
///   - `push(root)` appends at the head; once `size() == capacity()`,
///     subsequent pushes overwrite the oldest entry.
///   - `contains(r)` is the consensus check run in §4.3 step 1.5.
///   - Serialization writes the roots in oldest-to-newest order (stable
///     across insertion point), so the cell form is a pure value type.
class AnchorWindow {
  public:
    /// Construct an empty window with the default capacity.
    AnchorWindow();

    /// Construct an empty window with a caller-supplied capacity.
    /// `capacity` MUST match ConfigParam 26 `anchor_window_size` or the
    /// chain is non-deterministic.
    explicit AnchorWindow(std::uint32_t capacity);

    /// Push a new root onto the ring. Evicts the oldest entry if full.
    void push(const NoteHash& root);

    /// True iff `root` is one of the currently live entries in the window.
    /// Linear scan; at 100 entries this is a handful of memcmp's and is
    /// dominated by the crypto cost of the enclosing verify path.
    bool contains(const NoteHash& root) const noexcept;

    /// Number of live entries (≤ capacity()).
    std::size_t size() const noexcept { return size_; }

    /// Maximum number of entries retained.
    std::uint32_t capacity() const noexcept { return capacity_; }

    /// True iff no root has ever been pushed.
    bool is_empty() const noexcept { return size_ == 0; }

    /// Copy the live entries in oldest-to-newest order. Used for RPC
    /// `uno_chainInfo()` / `uno_getAnchor()` (§9.1) and for serialization.
    std::vector<NoteHash> snapshot() const;

    /// Serialize as a linear chain of `AnchorCell`s, oldest root first:
    ///
    ///   anchor_cell$_  root:bits256 next:(Maybe ^AnchorCell) = AnchorCell;
    ///
    /// An empty window serializes as a null ref; callers must wrap with a
    /// `Maybe ^Cell` bit.
    td::Ref<vm::Cell> serialize_to_cell() const;

    /// Parse a chain previously produced by `serialize_to_cell`. Supplies
    /// `expected_capacity` so deserialization rejects a chain that doesn't
    /// match the declared ConfigParam 26 value. `head` may be null (empty
    /// window). Returns false on malformed input; leaves `*this` untouched.
    bool deserialize_from_cell(td::Ref<vm::Cell> head, std::uint32_t expected_capacity);

    /// Direct accessor for the i-th entry in oldest-first order. i < size().
    const NoteHash& entry(std::size_t i) const;

  private:
    std::uint32_t capacity_{kDefaultAnchorWindowSize};

    // Ring buffer: `buffer_[head_]` is the oldest live entry when `size_ ==
    // capacity_`; next insertion writes at `buffer_[(head_ + size_) %
    // capacity_]`. When size_ < capacity_, head_ stays at 0 and we simply
    // append.
    std::vector<NoteHash> buffer_;
    std::size_t head_{0};
    std::size_t size_{0};
};

}  // namespace uno_workchain
