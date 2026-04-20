/*
    Uno Workchain — anchor window implementation (§5.4).
    Source: TOS-specific (not copied from upstream).
*/
#include "uno/core/anchor-window.h"

#include <cstring>

#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

namespace uno_workchain {

AnchorWindow::AnchorWindow() : AnchorWindow(kDefaultAnchorWindowSize) {}

AnchorWindow::AnchorWindow(std::uint32_t capacity)
    : capacity_(capacity), buffer_(capacity) {}

void AnchorWindow::push(const NoteHash& root) {
    if (capacity_ == 0) return;
    if (size_ < capacity_) {
        // Not yet full: simple append at logical position size_.
        buffer_[(head_ + size_) % capacity_] = root;
        size_ += 1;
        return;
    }
    // Full: overwrite the oldest, then advance head.
    buffer_[head_] = root;
    head_ = (head_ + 1) % capacity_;
}

bool AnchorWindow::contains(const NoteHash& root) const noexcept {
    for (std::size_t i = 0; i < size_; ++i) {
        if (buffer_[(head_ + i) % capacity_] == root) return true;
    }
    return false;
}

const NoteHash& AnchorWindow::entry(std::size_t i) const {
    return buffer_[(head_ + i) % capacity_];
}

std::vector<NoteHash> AnchorWindow::snapshot() const {
    std::vector<NoteHash> out;
    out.reserve(size_);
    for (std::size_t i = 0; i < size_; ++i) {
        out.push_back(buffer_[(head_ + i) % capacity_]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Cell serialization
//
// Linear chain, oldest root first. Each cell:
//   anchor_cell$_  root:bits256 next:(Maybe ^AnchorCell) = AnchorCell;
//
// `size_` is carried on the parent cell (e.g. MetaCell) — not inside the
// chain — because the chain length is self-describing via the Maybe-next
// bit.
// ---------------------------------------------------------------------------

td::Ref<vm::Cell> AnchorWindow::serialize_to_cell() const {
    if (size_ == 0) return {};
    // Build bottom-up so each cell has a finalized `next` ref.
    td::Ref<vm::Cell> tail;
    // Emit from newest to oldest so, after finalization, the head cell
    // (oldest) is what we return.
    for (std::size_t ri = 0; ri < size_; ++ri) {
        std::size_t logical = size_ - 1 - ri;  // size_-1 (newest) first
        const auto& r = buffer_[(head_ + logical) % capacity_];
        vm::CellBuilder cb;
        cb.store_bytes(r.data(), kNoteHashBytes);
        if (tail.not_null()) {
            cb.store_long_bool(1, 1);
            cb.store_ref(tail);
        } else {
            cb.store_long_bool(0, 1);
        }
        tail = cb.finalize();
    }
    return tail;
}

bool AnchorWindow::deserialize_from_cell(td::Ref<vm::Cell> head, std::uint32_t expected_capacity) {
    // Prepare a scratch window; commit atomically on success.
    AnchorWindow tmp(expected_capacity);
    td::Ref<vm::Cell> cur = head;
    std::size_t count = 0;
    while (cur.not_null()) {
        if (count >= expected_capacity) return false;  // chain longer than window
        auto cs = vm::load_cell_slice(cur);
        unsigned char buf[kNoteHashBytes];
        if (!cs.fetch_bytes(buf, kNoteHashBytes)) return false;
        long long has_next = 0;
        if (!cs.fetch_long_bool(1, has_next)) return false;
        NoteHash r{};
        std::memcpy(r.data(), buf, kNoteHashBytes);
        tmp.push(r);  // oldest first, push() appends in order
        if (has_next) {
            if (!cs.fetch_ref_to(cur)) return false;
        } else {
            cur = {};
        }
        count += 1;
    }
    // Commit.
    *this = std::move(tmp);
    return true;
}

}  // namespace uno_workchain
