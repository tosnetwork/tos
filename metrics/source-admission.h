#pragma once

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace tos::metrics {

// Actor-owned state. Client deadlines never release the actual-work lease.
// A caller must retain ownership until every child has completed.
class SourceAdmission {
 public:
  static constexpr double min_refresh_seconds = 15.0;
  static constexpr double work_budget_seconds = 2.0;
  static constexpr double http_budget_seconds = 3.0;
  static constexpr std::size_t max_waiters = 1;
  static constexpr double max_cache_age_seconds = 30.0;
  static constexpr std::size_t max_snapshot_bytes = 2 * 1024 * 1024;

  bool begin(double now) {
    if (!std::isfinite(now) || inflight_ || now < next_start_) {
      return false;
    }
    inflight_ = true;
    started_ = now;
    next_start_ = now + min_refresh_seconds;
    return true;
  }

  bool expired(double now) const {
    return inflight_ && now - started_ >= work_budget_seconds;
  }

  bool finish(double now, bool valid, std::size_t bytes) {
    if (!inflight_) {
      return false;
    }
    const bool publish = std::isfinite(now) && now >= started_ && !expired(now) && valid &&
                         bytes <= max_snapshot_bytes && generation_ != std::numeric_limits<std::uint64_t>::max();
    inflight_ = false;
    if (publish) {
      completed_ = now;
      ++generation_;
    }
    return publish;
  }

  bool fresh(double now) const {
    return generation_ != 0 && std::isfinite(now) && now >= completed_ && now - completed_ <= max_cache_age_seconds;
  }

  bool inflight() const {
    return inflight_;
  }
  std::uint64_t generation() const {
    return generation_;
  }
  double started() const {
    return started_;
  }

 private:
  bool inflight_ = false;
  double started_ = 0;
  double next_start_ = 0;
  double completed_ = 0;
  std::uint64_t generation_ = 0;
};

}  // namespace tos::metrics
