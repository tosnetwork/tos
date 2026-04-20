/*
    Uno Workchain — nullifier set implementation (§2.4, §5.3).
    Source: TOS-specific (not copied from upstream).
*/
#include "uno/core/nullifier-set.h"

#include <cstring>

#include "common/bitstring.h"
#include "td/utils/logging.h"
#include "vm/cells/CellBuilder.h"

#include "uno/rpc/metrics.h"

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

    // Track insertion order for `warm_lru()`. Bounded ring buffer — oldest
    // entries age out once we exceed the warm-snapshot cap. Non-consensus,
    // not serialised; see header.
    if (warm_snapshot_cap_ > 0) {
        recent_inserts_.push_back(nf);
        while (recent_inserts_.size() > warm_snapshot_cap_) {
            recent_inserts_.pop_front();
        }
    }
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
    if (lru_capacity_ == 0) {
        // LRU disabled: count as a miss. Dashboard should show 0 hit rate
        // when operators deliberately disable the LRU (advisory per §5.3).
        global_metrics_registry().inc_nullifier_lru_misses();
        return false;
    }
    auto it = lru_index_.find(nf);
    if (it == lru_index_.end()) {
        // K-uno-metrics: cold lookup; caller will fall through to the cell-
        // dict walk. A collapsing hit rate is the §7.3 cold-dict-traversal
        // alert signal.
        global_metrics_registry().inc_nullifier_lru_misses();
        return false;
    }
    // Promote to front (most recent).
    lru_order_.splice(lru_order_.begin(), lru_order_, it->second);
    global_metrics_registry().inc_nullifier_lru_hits();
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
    // The warm-snapshot ring buffer is process-memory only; a full-restart
    // path (which this is) loses insertion-order information. Drop it so
    // `warm_lru()` correctly falls into the dict-traversal fallback.
    recent_inserts_.clear();
}

void NullifierSet::clear_lru() {
    lru_order_.clear();
    lru_index_.clear();
}

void NullifierSet::warm_lru(std::size_t k) {
    if (k == 0 || lru_capacity_ == 0) {
        return;
    }

    // Primary path: the in-memory recent-insertions ring buffer has
    // insertion-order information. Walk the tail `k` entries oldest-to-
    // newest so the newest ends up at the LRU front after `lru_touch()`.
    if (!recent_inserts_.empty()) {
        const std::size_t have = recent_inserts_.size();
        const std::size_t take = (k < have) ? k : have;
        // `recent_inserts_` is FIFO with front = oldest. Start iterating
        // from (size - take) so we visit exactly the newest `take` in
        // oldest-to-newest order.
        auto it = recent_inserts_.begin();
        std::advance(it, have - take);
        for (; it != recent_inserts_.end(); ++it) {
            lru_touch(*it);
        }
        LOG(INFO) << "uno-workchain: nullifier LRU warmed from ring buffer: "
                  << take << " / " << k << " requested (ring has "
                  << have << " entries)";
        return;
    }

    // Fallback: ring buffer is empty (post-restart via `load_from_cell()`).
    // Dict traversal yields entries in key-sorted order, not insertion
    // order — this is a *bounded snapshot*, not a most-recent slice. The
    // LRU is advisory (§5.3), so a warmed subset still only accelerates
    // positive hits and never masks a negative answer.
    if (dict_.is_empty()) {
        return;
    }
    std::size_t warmed = 0;
    dict_.check_for_each(
        [this, k, &warmed](td::Ref<vm::CellSlice> /*value*/,
                           td::ConstBitPtr key, int key_len) -> bool {
            if (warmed >= k) {
                return false;  // stop iteration early
            }
            if (key_len != 256) {
                return false;  // malformed; bail
            }
            Nullifier nf{};
            // Pack the 256-bit key back into the 32-byte nullifier buffer.
            // `ConstBitPtr` is bit-addressed; use `get_bits` to copy whole
            // bytes out without adopting the BitString machinery.
            td::BitPtr(nf.data()).copy_from(key, 256);
            lru_touch(nf);
            ++warmed;
            return true;
        });
    LOG(WARNING) << "uno-workchain: nullifier LRU warm-up fell back to "
                    "dict-key traversal (ring buffer empty after restart); "
                    "warmed "
                 << warmed << " / " << k << " requested";
}

}  // namespace uno_workchain
