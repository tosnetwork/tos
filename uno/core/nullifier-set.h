/*
    Uno Workchain (wc=2) — nullifier set (§2.4, §5.3).

    Authoritative storage: a `vm::Dictionary` with 256-bit keys and a unit
    (zero-length) value — i.e. a TL-B `HashmapE(256, True)`. Each insert is
    O(log N) cell ops; lookup is O(log N). The nullifier domain is append-only
    (nullifiers are forever): no delete path is exposed.

    Hot-path optimization (M2 in §5.3): a bounded in-memory LRU of recently
    seen nullifiers short-circuits dict traversal under the 1 s block budget.
    The LRU is **advisory only, not part of the consensus state root**. A
    positive LRU hit is sufficient to reject a double-spend; a negative LRU
    answer MUST be confirmed by a dict lookup before declaring the nullifier
    unseen.

    Default capacity: 1,000,000 entries (~100 MB RAM at 96 B/entry overhead),
    pinned by decision #7 (§16) / §10.2, tunable at runtime from
    ConfigParam 84. See §5.3.

    Source: TOS-specific (not copied from upstream).
*/
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <list>
#include <unordered_map>

#include "vm/cells.h"
#include "vm/dict.h"

namespace uno_workchain {

/// Nullifier byte width: Poseidon2 output truncated to 256 bits (§2.4).
static constexpr std::size_t kNullifierBytes = 32;

/// Default LRU capacity. 1 M entries ≈ 100 MB RAM (key 32 B + node-overhead).
/// Pinned by decision #7 (§16) / §10.2; override via ConfigParam 84 at init time.
static constexpr std::size_t kDefaultNullifierLruCapacity = 1'000'000;

/// Default warm-snapshot cap — the maximum number of recent insertions we
/// retain in-memory for `warm_lru()`. Matches the default LRU capacity
/// (§5.9 / §10.2 `nullifier_lru_capacity = 1_000_000`) so a full warm-up
/// after cold start can repopulate the LRU to capacity without the ring
/// buffer truncating it first.
static constexpr std::size_t kDefaultNullifierWarmSnapshotCap = 1'048'576;

/// 256-bit nullifier value.
using Nullifier = std::array<std::uint8_t, kNullifierBytes>;

/// Byte-wise hash functor so `Nullifier` is usable as an unordered_map key.
struct NullifierByteHash {
    std::size_t operator()(const Nullifier& n) const noexcept;
};

/// Nullifier set backed by a `vm::Dictionary` (on-cell, consensus-critical)
/// with an in-memory LRU front-end (advisory only).
///
/// Threading: the whole workchain compute-phase runs single-threaded per
/// block per TOS's AccountBlock invariant; readers through RPC take a shared
/// snapshot of the dict-root cell. This class itself is not internally
/// synchronized.
class NullifierSet {
  public:
    /// Construct an empty set with the default LRU capacity.
    NullifierSet();

    /// Construct an empty set with a caller-supplied LRU capacity (0 =
    /// disable the LRU entirely; every lookup goes to the dict).
    explicit NullifierSet(std::size_t lru_capacity);

    /// Insert a nullifier. Returns true iff the nullifier was new. A second
    /// insert of the same nullifier returns false without touching the dict.
    bool insert(const Nullifier& nf);

    /// Membership test. Consults the LRU first; on miss falls through to
    /// the authoritative on-cell dictionary. Updates LRU on positive answer.
    bool contains(const Nullifier& nf) const;

    /// Fast LRU-only membership check. A true return is authoritative
    /// ("definitely present"); a false return means "not in LRU, caller
    /// must still call `contains()` or hit the dict directly" — used by
    /// mempool admission (§4.3a) where a dict miss is cheaper to defer.
    bool lru_contains(const Nullifier& nf) const noexcept;

    /// Current element count as tracked locally. NOTE: the dictionary does
    /// not maintain a native size; this counter is maintained by insert()
    /// and survives restart via `load_from_cell()` + a caller-supplied
    /// count.
    std::uint64_t size() const noexcept { return size_; }

    /// True iff the authoritative dictionary is empty.
    bool is_empty() const noexcept { return dict_.is_empty(); }

    /// LRU capacity (static after construction). 0 = LRU disabled.
    std::size_t lru_capacity() const noexcept { return lru_capacity_; }

    /// Access the underlying dictionary root cell for serialization as
    /// `HashmapE(256, True)`. Null when empty.
    td::Ref<vm::Cell> dict_root_cell() const { return dict_.get_root_cell(); }

    /// Serialize into a caller's `CellBuilder` in `HashmapE(256, True)` form:
    /// one tag bit followed by an optional ref to the root. Mirrors the TOS
    /// `Maybe ^Cell` pattern used throughout the state root.
    bool append_to_builder(vm::CellBuilder& cb) const;

    /// Replace the backing dictionary from a raw root cell (may be null).
    /// `known_size` is an optional size hint (e.g. persisted in StatsCell);
    /// pass 0 if unknown — the local size counter stays consistent as long
    /// as subsequent `insert()`s are respected.
    void load_from_cell(td::Ref<vm::Cell> dict_root, std::uint64_t known_size = 0);

    /// Clear the LRU (e.g. on reorg). Does not touch the authoritative dict.
    /// Does NOT clear the recent-insertions ring buffer used by `warm_lru()` —
    /// a reorg rebuilds the LRU from the warm snapshot on the next verify
    /// pass. Use `load_from_cell()` for the full-restart path.
    void clear_lru();

    /// Warm the LRU with up to `k` recently-inserted nullifiers. Intended to
    /// be called exactly once at validator cold-start (§5.9 / §4.3 step 2)
    /// so the first blocks after restart don't pay the ~24-level cell-dict
    /// walk per nullifier miss.
    ///
    /// Semantics: promotes the tail (most-recent) up-to-`k` entries of the
    /// in-memory recent-insertions ring buffer into the LRU in oldest-to-
    /// newest order, so the newest becomes the LRU front. A warm-snapshot
    /// miss (e.g. after `load_from_cell()` where the ring buffer has been
    /// cleared) falls back to a bounded dict traversal in dict-key order,
    /// capped at `k` entries — still a correct warm-up because the LRU is
    /// advisory (§5.3): a warmed subset only accelerates positive hits; it
    /// can never mask a negative answer because `contains()` still consults
    /// the dict on LRU miss. The fallback mode is flagged with a log line
    /// so the operator sees the degraded path explicitly.
    ///
    /// Idempotent. `k == 0` and `k > warm_snapshot_cap_` are both safe
    /// (the latter is capped to whatever the ring buffer actually holds).
    void warm_lru(std::size_t k);

    /// Current size of the warm-snapshot ring buffer. Exposed for tests /
    /// diagnostics; never exceeds the `warm_snapshot_cap_` passed at
    /// construction (or `kDefaultNullifierWarmSnapshotCap`).
    std::size_t warm_snapshot_size() const noexcept { return recent_inserts_.size(); }

  private:
    /// Raw dict lookup (bypasses LRU). Returns true iff present on-cell.
    bool dict_contains(const Nullifier& nf) const;

    /// Push an entry to the front of the LRU (or promote if already present),
    /// evicting the tail if capacity is exceeded.
    void lru_touch(const Nullifier& nf) const;

    // Authoritative store: 256-bit-keyed dict with unit value.
    mutable vm::Dictionary dict_;

    // Local count of inserts. Authoritative only if `load_from_cell` callers
    // pass an accurate `known_size`; otherwise best-effort.
    std::uint64_t size_{0};

    // LRU — mutable because it's read-through cache updated by `contains()`.
    std::size_t lru_capacity_{kDefaultNullifierLruCapacity};
    mutable std::list<Nullifier> lru_order_;  // front = most recent
    mutable std::unordered_map<Nullifier,
                               std::list<Nullifier>::iterator,
                               NullifierByteHash> lru_index_;

    // In-memory, non-consensus ring buffer of recently-inserted nullifiers
    // used by `warm_lru()`. Populated by `insert()` on successful add; front
    // is the oldest-retained, back is the newest. Capped at
    // `warm_snapshot_cap_` entries — older inserts fall off and become
    // unavailable for warm-up (but still correctly looked up via the dict).
    //
    // NOT serialised: across a validator restart the ring buffer is empty
    // and `warm_lru()` falls back to a bounded dict traversal. This matches
    // the §5.3 "LRU is advisory, not consensus" rule.
    std::size_t warm_snapshot_cap_{kDefaultNullifierWarmSnapshotCap};
    std::deque<Nullifier> recent_inserts_;
};

}  // namespace uno_workchain
