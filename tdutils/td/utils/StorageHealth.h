#pragma once

#include <atomic>
#include <cstdint>

namespace td {

// Process-wide storage health facts written by the RocksDB wrapper on every
// synchronous commit and read by the health exporter. A write stop means the
// engine cannot persist state; that fact must reach the monitor without an
// RPC lane. Lock-free, relaxed: readers only ever see a whole value.
struct StorageHealth {
  // 1 while the most recent committed write observed rocksdb.is-write-stopped.
  std::atomic<std::uint8_t> write_stopped_last{0};
  // Number of committed writes that observed a write stop; monotonic per process.
  std::atomic<std::uint64_t> write_stopped_total{0};
  // Number of committed writes that checked the property at all.
  std::atomic<std::uint64_t> commits_observed{0};
};

inline StorageHealth storage_health;

}  // namespace td
