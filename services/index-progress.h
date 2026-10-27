/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>

#include "td/utils/Status.h"

namespace tos_wallet_index {
class WalletIndexDb;
}

namespace tos::services {

// Cumulative replay counters since process start. The replay thread writes
// them; HTTP handlers and the periodic log line read them. Fixed size: one set
// per process, nothing grows with traffic or chain age.
struct ReplayStats {
  std::atomic<uint64_t> mc_blocks{0};
  std::atomic<uint64_t> shard_blocks{0};
  // Every source request, from posting it to its reply (includes dispatch).
  std::atomic<uint64_t> source_requests{0};
  std::atomic<uint64_t> source_wait_us{0};
  // Observing the source tip: the forced catch-up of every source database
  // and the shard-client read. Its requests are also counted above.
  std::atomic<uint64_t> catch_ups{0};
  std::atomic<uint64_t> catch_up_us{0};
  // Indexing shard blocks, including each block's own write batch.
  std::atomic<uint64_t> walk_us{0};
  // Advancing the durable masterchain checkpoint.
  std::atomic<uint64_t> commits{0};
  std::atomic<uint64_t> commit_us{0};
  // Background token-candidate passes.
  std::atomic<uint64_t> drains{0};
  std::atomic<uint64_t> drain_us{0};
  // Descriptors the process holds, sampled by the replay thread; -1 unknown.
  std::atomic<int64_t> open_fds{-1};

  struct Snapshot {
    double uptime_s = 0;
    uint64_t mc_blocks = 0, shard_blocks = 0, source_requests = 0, source_wait_us = 0, catch_ups = 0, catch_up_us = 0,
             walk_us = 0, commits = 0, commit_us = 0, drains = 0, drain_us = 0;
    // Process-wide archive slice opens and closes, supplied by the caller.
    uint64_t archive_slice_opens = 0, archive_slice_closes = 0;
    int64_t open_fds = -1;
  };
  Snapshot snapshot(double uptime_s, uint64_t archive_slice_opens, uint64_t archive_slice_closes) const;
};

std::string replay_stats_json(const ReplayStats::Snapshot& s);
// One line with the change since `previous`, for the periodic log.
std::string replay_stats_log_line(const ReplayStats::Snapshot& now, const ReplayStats::Snapshot& previous);

// Adds the elapsed wall time to `sink` (microseconds) when destroyed.
class StageTimer {
 public:
  explicit StageTimer(std::atomic<uint64_t>& sink) : sink_(sink), start_(std::chrono::steady_clock::now()) {
  }
  StageTimer(const StageTimer&) = delete;
  StageTimer& operator=(const StageTimer&) = delete;
  ~StageTimer() {
    auto elapsed = std::chrono::steady_clock::now() - start_;
    sink_.fetch_add(static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count()),
                    std::memory_order_relaxed);
  }

 private:
  std::atomic<uint64_t>& sink_;
  std::chrono::steady_clock::time_point start_;
};

// Replay progress as reported by /readyz and by index_state.replay. A value
// that is not known yet is reported as null, never as 0: a restart must not
// look like a reset to a monitor.
struct Progress {
  std::atomic<uint32_t> cursor{0}, tip{0};
  // The durable checkpoint has been read (cursor is meaningful).
  std::atomic<bool> cursor_known{false};
  // The source tip has been observed at least once (tip is meaningful).
  std::atomic<bool> tip_known{false};
  std::atomic<bool> ready{false};
  std::atomic<double> checked_at{0};

  bool is_ready(double now) const {
    return ready.load() && now - checked_at.load() <= 5.0;
  }
  std::string json(double now) const;
  // json() plus the cumulative replay statistics.
  std::string readyz_json(double now, const ReplayStats::Snapshot& stats) const;
};

// Read the durable replay checkpoint before anything is served, so the first
// /readyz after a restart reports the cursor the index resumes from. An index
// without a checkpoint (a fresh directory) leaves the cursor unknown.
td::Status load_checkpoint_progress(tos_wallet_index::WalletIndexDb& db, Progress& progress);

// Where the process's descriptors are listed (Linux procfs).
inline constexpr const char* kProcessFdDirectory = "/proc/self/fd";

// Number of descriptors this process holds, or -1 when they cannot be
// counted (no such directory, as on hosts without procfs). Reported as null.
int64_t count_open_fds(const char* fd_directory = kProcessFdDirectory);

}  // namespace tos::services
