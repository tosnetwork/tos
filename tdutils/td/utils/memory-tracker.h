#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <string_view>

namespace td {

enum class MemoryTrackerCategory : uint8_t { CellDb, StateSync, Network, Consensus, Plumtree, Other, Count };

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

}  // namespace td
