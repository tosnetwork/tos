#pragma once

#include <string>
#include <unordered_map>

#include "adnl/utils.hpp"
#include "td/utils/Status.h"
#include "td/utils/Time.h"
#include "td/utils/algorithm.h"

namespace tos::quic {

// Addresses tracked at once by default. Each entry is one source that opened
// a connection recently; an entry whose bucket has refilled is dropped by
// cleanup().
inline constexpr size_t kQuicMaxTrackedAddresses = 1 << 16;

class QuicConnectionRateLimiters {
 public:
  QuicConnectionRateLimiters(td::uint32 capacity, double period, size_t max_tracked = kQuicMaxTrackedAddresses)
      : capacity_(capacity), period_(period), max_tracked_(max_tracked) {
  }

  // Admit a new connection from `addr` only if both its own limit and the
  // `global` one allow it. An address is recorded only once it is admitted,
  // so sources the global limit turns away leave nothing behind, and the
  // table never holds more than max_tracked addresses: when it is full and no
  // entry can be dropped, new addresses are refused.
  td::Status take_new_connection(const std::string &addr, adnl::RateLimiter &global) {
    if (capacity_ == 0) {
      if (!global.take()) {
        return td::Status::Error("global new connection rate limit exceeded");
      }
      return td::Status::OK();
    }
    auto it = limiters_.find(addr);
    if (it != limiters_.end() && !it->second.can_take()) {
      return td::Status::Error("new connection rate limit exceeded");
    }
    if (it == limiters_.end() && limiters_.size() >= max_tracked_) {
      drop_refilled();
      if (limiters_.size() >= max_tracked_) {
        return td::Status::Error("new connection rate limit table full");
      }
    }
    if (!global.take()) {
      return td::Status::Error("global new connection rate limit exceeded");
    }
    if (it == limiters_.end()) {
      it = limiters_.try_emplace(addr, capacity_, period_).first;
    }
    it->second.take();
    schedule_cleanup();
    return td::Status::OK();
  }

  void cleanup() {
    if (!(cleanup_at_ && cleanup_at_.is_in_past())) {
      return;
    }
    drop_refilled();
    cleanup_at_ = limiters_.empty() ? td::Timestamp::never() : td::Timestamp::in(10.0);
  }

  size_t tracked() const {
    return limiters_.size();
  }

  td::Timestamp next_cleanup_at() const {
    return cleanup_at_;
  }

 private:
  void drop_refilled() {
    td::table_remove_if(limiters_, [](const auto &it) { return it.second.is_full(); });
  }

  void schedule_cleanup() {
    if (!cleanup_at_) {
      cleanup_at_ = td::Timestamp::in(10.0);
    }
  }

  td::uint32 capacity_ = 0;
  double period_ = 0.0;
  size_t max_tracked_ = kQuicMaxTrackedAddresses;
  std::unordered_map<std::string, adnl::RateLimiter> limiters_;
  td::Timestamp cleanup_at_ = td::Timestamp::never();
};

}  // namespace tos::quic
