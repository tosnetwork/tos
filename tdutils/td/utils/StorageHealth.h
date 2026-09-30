#pragma once

#include <atomic>
#include <cstdint>

namespace td {

// Process-wide storage health facts written by the RocksDB wrapper after
// synchronous commits and read by the health exporter. A write stop means the
// engine cannot persist state; that fact must reach the monitor without an
// RPC lane. The probe itself (RocksDB's is-write-stopped property) takes the
// database mutex, so it runs only while `enabled` is set by the health flag
// and at most once per second per database instance. Every database of the
// process writes the same struct: the gauge says "some database is stopped",
// not which one. Fields are relaxed atomics; readers see whole values.
struct StorageHealth {
  // Set by the engine when health instrumentation is on; off means no probe.
  std::atomic<bool> enabled{false};
  // 1 while the most recent committed write observed rocksdb.is-write-stopped.
  std::atomic<std::uint8_t> write_stopped_last{0};
  // Number of committed writes that observed a write stop; monotonic per process.
  std::atomic<std::uint64_t> write_stopped_total{0};
  // Number of committed writes that checked the property at all.
  std::atomic<std::uint64_t> commits_observed{0};
};

inline StorageHealth storage_health;

}  // namespace td
