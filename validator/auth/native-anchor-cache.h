#pragma once
#include <map>
#include <optional>
#include <set>
#include <span>
#include <vector>

#include "native-history.h"
#include "native-prefetch.h"
namespace tos::auth {
// Anchors a node resolved once and keeps across block collations.
//
// A registry update names the history it relies on, but resolving that history
// is an archive read and collation is synchronous. The node therefore refuses
// the update in the block where it first sees it, resolves what that update
// declared, and admits it in a later block. This holds what was resolved.
//
// It is node-lifetime state, so it is bounded and evicts deterministically. An
// unbounded cache of history is the shape that looks free for a week and then
// is not; evicting the lowest coordinates first is correct because an approval
// references recent history and the old entries are the ones nothing will ask
// for again.
class NativeAnchorCache {
  std::map<std::uint32_t, Anchor> anchors_;
  std::size_t limit_;

 public:
  explicit NativeAnchorCache(std::size_t limit = 1024) : limit_(limit < 1 ? 1 : limit) {
  }

  // What still has to be fetched before the requested set can be served.
  std::vector<std::uint32_t> missing(std::span<const std::uint32_t> required) const;

  // Records one resolved anchor. An anchor filed under a coordinate it does not
  // carry is refused: the cache is consulted instead of the archive, so a
  // substitution admitted here would never be checked again.
  Result<bool> admit(std::uint32_t at, const Anchor&);

  // A source for exactly the requested set, or a refusal naming that something
  // is still missing. Building a partial source would let execution proceed
  // with history it never resolved.
  Result<PrefetchedAnchorSource> source(std::span<const std::uint32_t> required) const;

  std::size_t size() const {
    return anchors_.size();
  }
};

inline constexpr std::size_t kResolutionCoordinateLimit = 64;

// Serializes asynchronous history resolutions without losing the coordinates
// reported while one is already in flight. Active coordinates are remembered
// separately from pending ones so a repeated deferral for the same history does
// not schedule the same archive read again. The manager owns one instance on
// its actor thread; this type provides no cross-thread synchronization.
class NativeHistoryResolutionQueue {
  std::set<std::uint32_t> active_coordinates_;
  std::set<std::uint32_t> pending_;
  std::size_t batch_limit_;
  bool active_ = false;

  std::vector<std::uint32_t> pending_batch() const {
    std::vector<std::uint32_t> batch;
    for (auto coordinate : pending_) {
      if (batch.size() >= batch_limit_) {
        break;
      }
      batch.push_back(coordinate);
    }
    return batch;
  }

  std::vector<std::uint32_t> start_pending() {
    active_coordinates_.clear();
    auto it = pending_.begin();
    while (it != pending_.end() && active_coordinates_.size() < batch_limit_) {
      const auto coordinate = *it;
      it = pending_.erase(it);
      active_coordinates_.insert(coordinate);
    }
    active_ = !active_coordinates_.empty();
    return {active_coordinates_.begin(), active_coordinates_.end()};
  }

 public:
  explicit NativeHistoryResolutionQueue(std::size_t batch_limit = kResolutionCoordinateLimit)
      : batch_limit_(batch_limit < 1 ? 1 : batch_limit) {
  }

  // Adds a request. When idle, returns the de-duplicated batch that the caller
  // must start now. When busy, retains only coordinates not already in the
  // active batch and returns no work until complete() is called.
  std::optional<std::vector<std::uint32_t>> submit(std::span<const std::uint32_t> coordinates) {
    for (auto coordinate : coordinates) {
      if (!active_coordinates_.contains(coordinate)) {
        pending_.insert(coordinate);
      }
    }
    if (active_ || pending_.empty()) {
      return std::nullopt;
    }
    return start_pending();
  }

  // Ends the current attempt and previews the next bounded batch, if one
  // accumulated while it was in flight. That batch remains pending until the
  // caller submits it again. If the caller temporarily cannot start another
  // archive read, no coordinate disappears merely because the previous attempt
  // completed.
  std::optional<std::vector<std::uint32_t>> complete() {
    if (!active_) {
      return std::nullopt;
    }
    active_ = false;
    active_coordinates_.clear();
    if (pending_.empty()) {
      return std::nullopt;
    }
    return pending_batch();
  }

  bool active() const {
    return active_;
  }

  std::size_t pending_size() const {
    return pending_.size();
  }
};

struct ResolutionBudget {
  std::size_t coordinates = kResolutionCoordinateLimit;  // one authority for queue and resolver bounds
  HistoryReadBudget reads{};
};

struct Resolution {
  std::size_t admitted = 0;                // newly held, or already held and agreeing
  std::vector<std::uint32_t> unavailable;  // this node cannot serve these yet
};

// Fills the cache with the anchors a deferred update declared.
//
// What anchor sits at a coordinate is decided by NativeFinalizedHistory and
// nothing else: it binds the coordinate through the parent state's own record
// of previous blocks, and requires the block served to be the one that record
// names. This adds no second opinion. It only carries an already authenticated
// answer across blocks, because collation cannot wait for an archive read.
//
// A coordinate this node cannot serve yet is reported, not refused -- the
// update was deferred precisely for naming history that had not been fetched.
// A block that is served but does not authenticate is refused outright: the
// cache is consulted instead of the archive afterwards, so a substitution
// admitted here would never be looked at again.
Result<Resolution> resolve_declared_history(std::span<const std::uint32_t> coordinates,
                                            td::Ref<vm::Cell> masterchain_state, const Anchor& head,
                                            const ChainContext&, NativeBlockReader, NativeAnchorCache&,
                                            ResolutionBudget = {});

// Which finalized blocks a resolution would have to read.
//
// A node has to fetch these before it can resolve anything, because fetching is
// asynchronous and resolution is not. The set is derived by asking the same
// authority that will later be asked for the anchors, so it cannot drift from
// what resolution actually wants; a separately written derivation would be a
// second reading of the parent state's record with nothing comparing the two.
//
// Coordinates that need no read at all -- the head, and anything already held
// -- are absent from the set rather than named in it.
Result<std::vector<tos::BlockIdExt>> required_finalized_blocks(std::span<const std::uint32_t> coordinates,
                                                               td::Ref<vm::Cell> masterchain_state, const Anchor& head,
                                                               const ChainContext&, const NativeAnchorCache& held,
                                                               ResolutionBudget = {});
}  // namespace tos::auth
