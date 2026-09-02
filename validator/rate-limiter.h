#pragma once
#include <deque>
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

}  // namespace tos::validator::fullnode
