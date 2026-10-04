#pragma once
#include <algorithm>
#include <deque>
#include <iterator>
#include <list>
#include <map>
#include <mutex>
#include <set>

#include "td/utils/RateLimiterWindow.h"
#include "td/utils/Time.h"

namespace tos::validator::fullnode {

struct RateLimit {
  double window_size;
  size_t window_limit;
};

// Requests are grouped into three cost categories that share per-category
// windows, so rotating through different request types cannot multiply the
// budget. Small requests bypass the global window (they are cheap but still
// read from the database, so they get their own bound); everything else
// consumes both the global window and its category window.
template <typename RequestID = int32_t>
class RateLimiter {
 public:
  RateLimiter(RateLimit global_limit, RateLimit heavy_limit, std::set<RequestID> heavy_requests, RateLimit medium_limit,
              std::set<RequestID> medium_requests, RateLimit small_limit, std::set<RequestID> small_requests)
      : global_window_(global_limit.window_size, global_limit.window_limit) {
    category_windows_[0] = td::RateLimiterWindow{heavy_limit.window_size, heavy_limit.window_limit};
    category_windows_[1] = td::RateLimiterWindow{medium_limit.window_size, medium_limit.window_limit};
    category_windows_[2] = td::RateLimiterWindow{small_limit.window_size, small_limit.window_limit};
    for (const RequestID &id : heavy_requests) {
      request_windows_[id] = 0;
    }
    for (const RequestID &id : medium_requests) {
      request_windows_[id] = 1;
    }
    for (const RequestID &id : small_requests) {
      request_windows_[id] = 2;
    }
  }
  RateLimiter(const RateLimiter &) = delete;
  RateLimiter(RateLimiter &&) = delete;
  RateLimiter &operator=(const RateLimiter &) = delete;
  RateLimiter &operator=(RateLimiter &&) = delete;

  bool check_in(RequestID request, size_t cost = 1, td::Timestamp time = td::Timestamp::now());

 private:
  bool check(td::Timestamp time, size_t cost);
  bool check(RequestID request, td::Timestamp time, size_t cost);
  void insert(td::Timestamp time, size_t cost);
  void insert(RequestID request, td::Timestamp time, size_t cost);

  td::RateLimiterWindow global_window_;
  td::RateLimiterWindow category_windows_[3];
  std::map<RequestID, int> request_windows_;

  // The limiter is shared by every shard actor of the node, so calls may
  // arrive concurrently from different scheduler threads.
  std::mutex mutex_;
};

template <typename RequestID>
bool RateLimiter<RequestID>::check_in(RequestID request, size_t cost, td::Timestamp time) {
  auto category_it = request_windows_.find(request);
  if (category_it == request_windows_.end()) {
    return true;
  }
  if (cost == 0) {
    cost = 1;
  }
  std::unique_lock lock(mutex_);
  bool is_small = category_it->second == 2;
  if ((is_small || check(time, cost)) && check(request, time, cost)) {
    if (!is_small) {
      insert(time, cost);
    }
    insert(request, time, cost);
    return true;
  }
  return false;
}

template <typename RequestID>
bool RateLimiter<RequestID>::check(td::Timestamp time, size_t cost) {
  return global_window_.check(time, cost);
}

template <typename RequestID>
bool RateLimiter<RequestID>::check(RequestID request, td::Timestamp time, size_t cost) {
  auto it = request_windows_.find(request);
  return it == request_windows_.end() || category_windows_[it->second].check(time, cost);
}

template <typename RequestID>
void RateLimiter<RequestID>::insert(td::Timestamp time, size_t cost) {
  global_window_.insert(time, cost);
}

template <typename RequestID>
void RateLimiter<RequestID>::insert(RequestID request, td::Timestamp time, size_t cost) {
  if (auto it = request_windows_.find(request); it != request_windows_.end()) {
    category_windows_[it->second].insert(time, cost);
  }
}

// Sliding-window usage counter whose limit is supplied by the caller, so a
// window can be re-budgeted (for example when the set of shards changes)
// without discarding the usage it has already recorded.
class UsageWindow {
 public:
  UsageWindow() = default;
  explicit UsageWindow(double duration) : duration_(duration) {
  }

  td::uint64 used(td::Timestamp time) {
    gc(time);
    return total_;
  }

  void add(td::Timestamp time, td::uint64 weight) {
    gc(time);
    if (!entries_.empty() && entries_.front().time.at() == time.at()) {
      entries_.front().weight += weight;
    } else {
      entries_.push_front(Entry{time, weight});
    }
    total_ += weight;
  }

 private:
  struct Entry {
    td::Timestamp time;
    td::uint64 weight;
  };

  void gc(td::Timestamp time) {
    while (!entries_.empty() && time - entries_.back().time > duration_) {
      total_ -= entries_.back().weight;
      entries_.pop_back();
    }
  }

  double duration_ = 0.0;
  std::deque<Entry> entries_;
  td::uint64 total_ = 0;
};

// Source- and shard-aware admission for the full-node overlay endpoint.
//
// The aggregate windows (global plus one per cost category) remain the hard
// ceiling on the work the node performs. Inside that ceiling:
//
//  * every source may hold at most a quarter (rounded up) of each window it
//    touches, so one peer cannot exhaust a window that other peers share;
//  * half of each window is reserved and divided equally among the shards that
//    are currently registered, so traffic arriving through one shard's overlay
//    cannot consume another shard's guaranteed part; the other half is shared.
//
// This bounds what any one source or shard can take. It is resource
// protection, not a service guarantee: enough distinct identities on the
// public overlay can still fill the shared half of every window.
//
// A query that cannot be parsed is charged once against its source's own
// small-request and global allowances and against the aggregate global window
// only, so malformed traffic neither escapes accounting nor consumes the
// aggregate small-request budget that well-formed cheap queries rely on.
template <typename RequestID, typename ShardID, typename SourceID>
class SourceAwareRateLimiter {
 public:
  SourceAwareRateLimiter(RateLimit global_limit, RateLimit heavy_limit, std::set<RequestID> heavy_requests,
                         RateLimit medium_limit, std::set<RequestID> medium_requests, RateLimit small_limit,
                         std::set<RequestID> small_requests)
      : limits_{global_limit, heavy_limit, medium_limit, small_limit} {
    for (size_t w = 0; w < kWindows; w++) {
      aggregate_[w] = UsageWindow{limits_[w].window_size};
      shared_[w] = UsageWindow{limits_[w].window_size};
    }
    for (const RequestID &id : heavy_requests) {
      request_windows_[id] = kHeavy;
    }
    for (const RequestID &id : medium_requests) {
      request_windows_[id] = kMedium;
    }
    for (const RequestID &id : small_requests) {
      request_windows_[id] = kSmall;
    }
  }
  SourceAwareRateLimiter(const SourceAwareRateLimiter &) = delete;
  SourceAwareRateLimiter(SourceAwareRateLimiter &&) = delete;
  SourceAwareRateLimiter &operator=(const SourceAwareRateLimiter &) = delete;
  SourceAwareRateLimiter &operator=(SourceAwareRateLimiter &&) = delete;

  // A shard may be registered more than once (for example while an old actor
  // for it is still tearing down); its reservation lasts until the last
  // registration is withdrawn.
  void register_shard(const ShardID &shard) {
    std::unique_lock lock(mutex_);
    auto it = shards_.find(shard);
    if (it == shards_.end()) {
      ShardState state;
      for (size_t w = 0; w < kWindows; w++) {
        state.reserved[w] = UsageWindow{limits_[w].window_size};
      }
      it = shards_.emplace(shard, std::move(state)).first;
    }
    it->second.registrations++;
  }

  void unregister_shard(const ShardID &shard) {
    std::unique_lock lock(mutex_);
    auto it = shards_.find(shard);
    if (it == shards_.end()) {
      return;
    }
    if (--it->second.registrations == 0) {
      shards_.erase(it);
    }
  }

  bool check_in(RequestID request, size_t cost, const ShardID &shard, const SourceID &source,
                td::Timestamp time = td::Timestamp::now()) {
    auto category_it = request_windows_.find(request);
    if (category_it == request_windows_.end()) {
      return true;
    }
    if (cost == 0) {
      cost = 1;
    }
    size_t category = category_it->second;
    Charge charge;
    if (category == kSmall) {
      charge.add(kSmall, true, true);
    } else {
      charge.add(kGlobal, true, true);
      charge.add(category, true, true);
    }
    std::unique_lock lock(mutex_);
    return admit(charge, cost, shard, source, time);
  }

  bool check_in_unparseable(const ShardID &shard, const SourceID &source, td::Timestamp time = td::Timestamp::now()) {
    Charge charge;
    charge.add(kGlobal, true, true);
    charge.add(kSmall, false, true);
    std::unique_lock lock(mutex_);
    return admit(charge, 1, shard, source, time);
  }

  // Number of sources whose usage is still inside some window. Entries are
  // dropped once every window they were charged in has drained.
  size_t tracked_sources(td::Timestamp time = td::Timestamp::now()) {
    std::unique_lock lock(mutex_);
    expire_sources(time);
    return sources_.size();
  }

  static size_t per_source_limit(size_t window_limit) {
    return window_limit / 4 + (window_limit % 4 != 0 ? 1 : 0);
  }

 private:
  static constexpr size_t kGlobal = 0;
  static constexpr size_t kHeavy = 1;
  static constexpr size_t kMedium = 2;
  static constexpr size_t kSmall = 3;
  static constexpr size_t kWindows = 4;

  struct Charge {
    bool aggregate[kWindows] = {false, false, false, false};
    bool source[kWindows] = {false, false, false, false};
    void add(size_t window, bool to_aggregate, bool to_source) {
      aggregate[window] = aggregate[window] || to_aggregate;
      source[window] = source[window] || to_source;
    }
  };

  struct ShardState {
    size_t registrations = 0;
    UsageWindow reserved[kWindows];
  };

  struct SourceState {
    UsageWindow windows[kWindows];
    typename std::list<SourceID>::iterator order;
  };

  // A window with zero duration is disabled (unlimited), matching
  // td::RateLimiterWindow.
  bool limited(size_t w) const {
    return limits_[w].window_size != 0.0;
  }

  // The reserved part is half of the window rounded down; each registered
  // shard owns an equal whole-unit slice of it and the rest is shared.
  size_t reserved_total(size_t w) const {
    return limits_[w].window_limit / 2;
  }
  size_t shard_share(size_t w) const {
    return shards_.empty() ? 0 : reserved_total(w) / shards_.size();
  }

  static bool fits(td::uint64 used, td::uint64 cost, td::uint64 limit) {
    return cost <= limit && used <= limit - cost;
  }

  bool admit(const Charge &charge, size_t cost, const ShardID &shard, const SourceID &source, td::Timestamp time) {
    expire_sources(time);
    auto shard_it = shards_.find(shard);
    auto source_it = sources_.find(source);
    td::uint64 take_reserved[kWindows] = {0, 0, 0, 0};
    td::uint64 take_shared[kWindows] = {0, 0, 0, 0};
    for (size_t w = 0; w < kWindows; w++) {
      if (!limited(w)) {
        continue;
      }
      size_t limit = limits_[w].window_limit;
      if (charge.source[w]) {
        td::uint64 used = source_it == sources_.end() ? 0 : source_it->second.windows[w].used(time);
        if (!fits(used, cost, per_source_limit(limit))) {
          return false;
        }
      }
      if (!charge.aggregate[w]) {
        continue;
      }
      if (!fits(aggregate_[w].used(time), cost, limit)) {
        return false;
      }
      td::uint64 reserved_free = 0;
      if (shard_it != shards_.end()) {
        td::uint64 share = shard_share(w);
        td::uint64 used = shard_it->second.reserved[w].used(time);
        reserved_free = used < share ? share - used : 0;
      }
      take_reserved[w] = std::min<td::uint64>(cost, reserved_free);
      take_shared[w] = cost - take_reserved[w];
      if (!fits(shared_[w].used(time), take_shared[w], limit - reserved_total(w))) {
        return false;
      }
    }

    if (source_it == sources_.end()) {
      SourceState state;
      for (size_t w = 0; w < kWindows; w++) {
        state.windows[w] = UsageWindow{limits_[w].window_size};
      }
      order_.push_back(source);
      state.order = std::prev(order_.end());
      source_it = sources_.emplace(source, std::move(state)).first;
    } else {
      order_.splice(order_.end(), order_, source_it->second.order);
    }
    for (size_t w = 0; w < kWindows; w++) {
      if (!limited(w)) {
        continue;
      }
      if (charge.source[w]) {
        source_it->second.windows[w].add(time, cost);
      }
      if (!charge.aggregate[w]) {
        continue;
      }
      aggregate_[w].add(time, cost);
      if (take_reserved[w] != 0) {
        shard_it->second.reserved[w].add(time, take_reserved[w]);
      }
      if (take_shared[w] != 0) {
        shared_[w].add(time, take_shared[w]);
      }
    }
    return true;
  }

  // Sources are kept in order of their latest charge, so the front entry is
  // normally the first to drain; an entry behind it waits at most one longest
  // window longer. An entry is dropped only once every one of its windows is
  // empty, never while it still holds usage.
  void expire_sources(td::Timestamp time) {
    while (!order_.empty()) {
      auto it = sources_.find(order_.front());
      if (it == sources_.end()) {
        order_.pop_front();
        continue;
      }
      for (size_t w = 0; w < kWindows; w++) {
        if (it->second.windows[w].used(time) != 0) {
          return;
        }
      }
      order_.pop_front();
      sources_.erase(it);
    }
  }

  RateLimit limits_[kWindows];
  UsageWindow aggregate_[kWindows];
  UsageWindow shared_[kWindows];
  std::map<RequestID, size_t> request_windows_;
  std::map<ShardID, ShardState> shards_;
  std::map<SourceID, SourceState> sources_;
  std::list<SourceID> order_;

  // The limiter is shared by every shard actor of the node, so calls may
  // arrive concurrently from different scheduler threads.
  std::mutex mutex_;
};

}  // namespace tos::validator::fullnode
