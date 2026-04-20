/*
    Uno Workchain — nullifier set implementation (§2.4, §5.3).
    Source: TOS-specific (not copied from upstream).
*/
#include "uno/core/nullifier-set.h"

#include <cstring>

#include "common/bitstring.h"
#include "vm/cells/CellBuilder.h"

namespace uno_workchain {

// ---------------------------------------------------------------------------
// NullifierByteHash
// ---------------------------------------------------------------------------

std::size_t NullifierByteHash::operator()(const Nullifier& n) const noexcept {
    // Nullifiers are already the output of a cryptographic hash (Poseidon2);
    // any 8-byte window is a near-uniform draw. Mix two windows with the
    // classical FNV-ish XOR-of-u64s to resist adversarial low-order-bit
    // collisions on the `unordered_map` bucket.
    std::uint64_t a = 0, b = 0;
    std::memcpy(&a, n.data(), 8);
    std::memcpy(&b, n.data() + 24, 8);
    return static_cast<std::size_t>(a ^ (b + 0x9E3779B97F4A7C15ULL + (a << 6) + (a >> 2)));
}

// ---------------------------------------------------------------------------
// NullifierSet
// ---------------------------------------------------------------------------

NullifierSet::NullifierSet()
    : NullifierSet(kDefaultNullifierLruCapacity) {}

NullifierSet::NullifierSet(std::size_t lru_capacity)
    : dict_(256),
      lru_capacity_(lru_capacity) {
    if (lru_capacity_ > 0) {
        lru_index_.reserve(lru_capacity_);
    }
}

bool NullifierSet::insert(const Nullifier& nf) {
    // Fast path: LRU hit means already-seen — definitively a replay, no dict
    // work needed. The dict was updated on the original insert.
    if (lru_contains(nf)) {
        return false;
    }

    // Fall through to the authoritative dictionary. `dict_contains` costs up
    // to ~24 cell levels at 10 M entries — this is the expensive path the
    // LRU is there to avoid.
    if (dict_contains(nf)) {
        // Already present on-cell; populate LRU so subsequent checks are hot.
        lru_touch(nf);
        return false;
    }

    // New nullifier: record into the dict with an empty value (unit type —
    // `HashmapE(256, True)`). The dict stores a CellSlice value; the empty
    // builder yields an empty slice on finalize.
    vm::CellBuilder empty_cb;
    dict_.set_builder(td::ConstBitPtr{nf.data()}, 256, empty_cb, vm::Dictionary::SetMode::Add);
    size_ += 1;
    lru_touch(nf);
    return true;
}

bool NullifierSet::contains(const Nullifier& nf) const {
    if (lru_contains(nf)) {
        return true;
    }
    if (dict_contains(nf)) {
        lru_touch(nf);
        return true;
    }
    return false;
}

bool NullifierSet::lru_contains(const Nullifier& nf) const noexcept {
    if (lru_capacity_ == 0) return false;
    auto it = lru_index_.find(nf);
    if (it == lru_index_.end()) return false;
    // Promote to front (most recent).
    lru_order_.splice(lru_order_.begin(), lru_order_, it->second);
    return true;
}

bool NullifierSet::dict_contains(const Nullifier& nf) const {
    auto cs = dict_.lookup(td::ConstBitPtr{nf.data()}, 256);
    return cs.not_null();
}

void NullifierSet::lru_touch(const Nullifier& nf) const {
    if (lru_capacity_ == 0) return;
    auto it = lru_index_.find(nf);
    if (it != lru_index_.end()) {
        // Already present; promote.
        lru_order_.splice(lru_order_.begin(), lru_order_, it->second);
        return;
    }
    lru_order_.push_front(nf);
    lru_index_.emplace(nf, lru_order_.begin());
    // Evict tail until size() <= capacity.
    while (lru_order_.size() > lru_capacity_) {
        lru_index_.erase(lru_order_.back());
        lru_order_.pop_back();
    }
}

bool NullifierSet::append_to_builder(vm::CellBuilder& cb) const {
    // HashmapE encoding: 1 bit tag + (iff tag) one ref.
    auto root = dict_.get_root_cell();
    if (root.not_null()) {
        if (!cb.store_long_bool(1, 1)) return false;
        if (!cb.store_ref_bool(std::move(root))) return false;
        return true;
    }
    return cb.store_long_bool(0, 1);
}

void NullifierSet::load_from_cell(td::Ref<vm::Cell> dict_root, std::uint64_t known_size) {
    if (dict_root.is_null()) {
        dict_ = vm::Dictionary(256);
    } else {
        dict_ = vm::Dictionary(std::move(dict_root), 256);
    }
    size_ = known_size;
    clear_lru();
}

void NullifierSet::clear_lru() {
    lru_order_.clear();
    lru_index_.clear();
}

}  // namespace uno_workchain
