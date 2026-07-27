#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <string_view>
#include <utility>

namespace td {

enum class MemoryTrackerCategory : uint8_t {
  CellDb,
  StateSync,
  Network,
  QuicInbound,
  QuicOutbound,
  Consensus,
  BlockData,
  Plumtree,
  Other,
  Count
};

struct MemoryTrackerStats {
  std::atomic<uint64_t> current_bytes{0};
  std::atomic<uint64_t> peak_bytes{0};
  std::atomic<uint64_t> alloc_count{0};
  std::atomic<uint64_t> free_count{0};
};

inline bool memory_tracker_enabled() {
  static const bool enabled = [] {
    const char *value = std::getenv("TOS_MEMORY_DIAGNOSTICS");
    return value != nullptr && std::string_view(value) == "1";
  }();
  return enabled;
}

inline std::array<MemoryTrackerStats, static_cast<size_t>(MemoryTrackerCategory::Count)> &memory_tracker_stats() {
  static std::array<MemoryTrackerStats, static_cast<size_t>(MemoryTrackerCategory::Count)> stats;
  return stats;
}

inline void memory_tracker_alloc(MemoryTrackerCategory category, uint64_t bytes) {
  if (!memory_tracker_enabled()) {
    return;
  }
  auto &stats = memory_tracker_stats()[static_cast<size_t>(category)];
  auto current = stats.current_bytes.fetch_add(bytes, std::memory_order_relaxed) + bytes;
  stats.alloc_count.fetch_add(1, std::memory_order_relaxed);
  auto peak = stats.peak_bytes.load(std::memory_order_relaxed);
  while (current > peak && !stats.peak_bytes.compare_exchange_weak(peak, current, std::memory_order_relaxed)) {
  }
}

inline void memory_tracker_free(MemoryTrackerCategory category, uint64_t bytes) {
  if (!memory_tracker_enabled()) {
    return;
  }
  auto &stats = memory_tracker_stats()[static_cast<size_t>(category)];
  stats.current_bytes.fetch_sub(bytes, std::memory_order_relaxed);
  stats.free_count.fetch_add(1, std::memory_order_relaxed);
}

inline const char *memory_tracker_category_name(MemoryTrackerCategory category) {
  switch (category) {
    case MemoryTrackerCategory::CellDb:
      return "CellDb";
    case MemoryTrackerCategory::StateSync:
      return "StateSync";
    case MemoryTrackerCategory::Network:
      return "AdnlQueue";
    case MemoryTrackerCategory::QuicInbound:
      return "QuicInbound";
    case MemoryTrackerCategory::QuicOutbound:
      return "QuicOutbound";
    case MemoryTrackerCategory::Consensus:
      return "Consensus";
    case MemoryTrackerCategory::BlockData:
      return "BlockData";
    case MemoryTrackerCategory::Plumtree:
      return "Plumtree";
    case MemoryTrackerCategory::Other:
      return "Other";
    case MemoryTrackerCategory::Count:
      return "Count";
  }
  return "Unknown";
}

// Move-only ownership token for a known amount of live memory. It is intended
// for buffers that cross coroutine suspension or actor-mailbox boundaries:
// moving the token follows the buffer and destruction accounts for release.
class MemoryTrackerToken {
 public:
  MemoryTrackerToken() = default;
  MemoryTrackerToken(MemoryTrackerCategory category, uint64_t bytes) : category_(category), bytes_(bytes) {
    if (bytes_ != 0) {
      memory_tracker_alloc(category_, bytes_);
    }
  }
  MemoryTrackerToken(const MemoryTrackerToken &) = delete;
  MemoryTrackerToken &operator=(const MemoryTrackerToken &) = delete;
  MemoryTrackerToken(MemoryTrackerToken &&other) noexcept
      : category_(other.category_), bytes_(std::exchange(other.bytes_, 0)) {
  }
  MemoryTrackerToken &operator=(MemoryTrackerToken &&other) noexcept {
    if (this != &other) {
      reset();
      category_ = other.category_;
      bytes_ = std::exchange(other.bytes_, 0);
    }
    return *this;
  }
  ~MemoryTrackerToken() {
    reset();
  }

  void add(uint64_t bytes) {
    if (bytes == 0) {
      return;
    }
    memory_tracker_alloc(category_, bytes);
    bytes_ += bytes;
  }
  void reset() {
    if (bytes_ != 0) {
      memory_tracker_free(category_, bytes_);
      bytes_ = 0;
    }
  }
  uint64_t bytes() const {
    return bytes_;
  }

 private:
  MemoryTrackerCategory category_{MemoryTrackerCategory::Other};
  uint64_t bytes_{0};
};

}  // namespace td
