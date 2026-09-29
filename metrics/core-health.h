#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>

namespace tos::health {
// Fixed process-wide counters. No labels, allocation, locks, or retries on the
// business path. Snapshots are approximate concurrent reads, not atomic views.
struct OperationStats {
  static constexpr std::array<std::uint64_t, 12> bounds_us = {1000,   2000,   5000,   10000,   20000,   50000,
                                                              100000, 200000, 500000, 1000000, 2000000, 5000000};
  std::array<std::array<std::atomic<std::uint64_t>, 13>, 2> buckets{};
  std::array<std::atomic<std::uint64_t>, 2> sum_us{};
  std::atomic<std::uint64_t> completed{0}, failed{0};
  std::atomic<bool> complete{true};

  void increment(std::atomic<std::uint64_t> &counter, std::uint64_t amount) noexcept {
    // Overflow does not interfere with the operation being measured.
    const auto old = counter.fetch_add(amount, std::memory_order_relaxed);
    if (old > std::numeric_limits<std::uint64_t>::max() - amount) {
      complete.store(false, std::memory_order_relaxed);
    }
  }
  void observe(std::uint64_t micros, bool success) noexcept {
    increment(success ? completed : failed, 1);
    increment(sum_us[success ? 0 : 1], micros);
    std::size_t bucket = 0;
    while (bucket < bounds_us.size() && micros > bounds_us[bucket]) {
      ++bucket;
    }
    increment(buckets[success ? 0 : 1][bucket], 1);
  }
};
inline OperationStats pq_sign;
inline OperationStats pq_verify;
// Disabled for the uninstrumented A/B performance baseline.
inline std::atomic<bool> enabled{false};

class OperationTimer {
 public:
  explicit OperationTimer(OperationStats &stats) noexcept
      : stats_(stats), active_(enabled.load(std::memory_order_relaxed)) {
    if (active_) {
      start_ = std::chrono::steady_clock::now();
    }
  }
  void finish(bool success) noexcept {
    if (active_) {
      const auto micros =
          std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start_).count();
      stats_.observe(micros < 0 ? 0 : static_cast<std::uint64_t>(micros), success);
      active_ = false;
    }
  }
  ~OperationTimer() {
    finish(false);
  }
  OperationTimer(const OperationTimer &) = delete;
  OperationTimer &operator=(const OperationTimer &) = delete;

 private:
  OperationStats &stats_;
  bool active_;
  std::chrono::steady_clock::time_point start_{};
};
static_assert(sizeof(OperationStats) * 2 < 4096);
}  // namespace tos::health
