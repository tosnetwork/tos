#pragma once

#include "consensus-health.h"

namespace tos::health {
enum class Work : std::uint8_t { IntentStorage, SignedStorage, ResolveState, FinalizationWait, Count };
enum class WorkResult : std::uint8_t { Success, Failure, Cancelled, Duplicate, Count };
constexpr auto work_count = static_cast<std::size_t>(Work::Count);
struct WorkStats {
  std::array<ConsensusStats::Counter, work_count> pending{};
  std::array<std::array<ConsensusStats::Counter, 4>, work_count> results{};
  std::array<OperationStats, work_count> duration{};
  std::array<std::array<std::array<ConsensusStats::Counter, 3>, 2>, 2> histogram{};
  std::array<std::atomic<bool>, work_count> complete{true, true, true, true};
  struct Row {
    std::atomic<std::uint64_t> started_ns{0};
    std::atomic<Work> work{Work::IntentStorage};
  };
  static constexpr std::size_t max_rows = 512;
  std::array<Row, max_rows> rows{};
  void incomplete(Work work) noexcept {
    complete[static_cast<unsigned>(work)].store(false, std::memory_order_relaxed);
    consensus_stats.global_incomplete(IncompleteReason::ObservationGap);
  }
  void result(Work work, WorkResult result) noexcept {
    if (!consensus_stats.add(results[static_cast<unsigned>(work)][static_cast<unsigned>(result)])) incomplete(work);
  }
  std::uint64_t oldest_started_ns(Work work) const noexcept {
    std::uint64_t oldest = UINT64_MAX;
    for (const auto &row : rows) {
      const auto started = row.started_ns.load(std::memory_order_acquire);
      if (started == 0 || started == UINT64_MAX) continue;
      const auto row_work = row.work.load(std::memory_order_relaxed);
      std::atomic_thread_fence(std::memory_order_acquire);
      if (row_work == work && row.started_ns.load(std::memory_order_relaxed) == started && started < oldest) oldest = started;
    }
    return oldest == UINT64_MAX ? 0 : oldest;
  }
};
inline WorkStats work_stats;

// Observation of an actual database await or registered resolver waiter, with
// no owning reference. An unfinished frame reports cancellation on destruction.
class WorkObservation {
 public:
  explicit WorkObservation(Work work) noexcept : work_(work) {
    if (!enabled.load(std::memory_order_relaxed) || !consensus_enabled.load(std::memory_order_relaxed)) return;
    for (std::size_t i = 0; i < WorkStats::max_rows; ++i) {
      std::uint64_t empty = 0;
      if (work_stats.rows[i].started_ns.compare_exchange_strong(empty, UINT64_MAX, std::memory_order_acquire)) {
        slot_ = i;
        start_ = ConsensusStats::now_ns();
        work_stats.rows[i].work.store(work, std::memory_order_relaxed);
        work_stats.rows[i].started_ns.store(start_, std::memory_order_release);
        recorded_ = consensus_stats.add(work_stats.pending[static_cast<unsigned>(work)]);
        if (!recorded_) work_stats.incomplete(work);
        return;
      }
    }
    work_stats.incomplete(work);
  }
  void finish(WorkResult result) noexcept {
    if (slot_ == WorkStats::max_rows) return;
    const auto elapsed = ConsensusStats::now_ns() - start_;
    work_stats.result(work_, result);
    auto &duration = work_stats.duration[static_cast<unsigned>(work_)];
    // Failure population includes cancelled waits; result counters retain the
    // exact finite classification. Duplicate pre-checks never enter this timer.
    duration.observe(elapsed / 1000, result == WorkResult::Success);
    if (static_cast<unsigned>(work_) < 2) {
      auto &histogram = work_stats.histogram[static_cast<unsigned>(work_)][result == WorkResult::Success ? 0 : 1];
      if (elapsed <= 1000000000) consensus_stats.add(histogram[0]);
      consensus_stats.add(histogram[1]);
      consensus_stats.add(histogram[2], elapsed / 1000);
    }
    if (!duration.complete.load(std::memory_order_relaxed)) work_stats.incomplete(work_);
    if (recorded_) consensus_stats.subtract(work_stats.pending[static_cast<unsigned>(work_)]);
    work_stats.rows[slot_].started_ns.store(0, std::memory_order_release);
    slot_ = WorkStats::max_rows;
  }
  ~WorkObservation() { finish(WorkResult::Cancelled); }
  WorkObservation(const WorkObservation &) = delete;
  WorkObservation &operator=(const WorkObservation &) = delete;
 private:
  Work work_;
  std::size_t slot_ = WorkStats::max_rows;
  std::uint64_t start_ = 0;
  bool recorded_ = false;
};
static_assert(sizeof(WorkStats) < 32 * 1024);
}  // namespace tos::health
