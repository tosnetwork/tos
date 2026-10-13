/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <atomic>
#include <cstdint>
#include <limits>
#include <string>

namespace tos::validator {

// Decisions behind the warnings a node logs when it stops making progress on
// the masterchain. They are pure so the thresholds and rate limits can be
// tested without an actor, a network or a clock.

// Ages derived from two clocks: a clock that went backwards yields a negative
// difference, which is reported as zero rather than as a negative age.
inline double non_negative_age(double now, double at) {
  const double age = now - at;
  return age > 0 ? age : 0;
}

// A block whose data cannot be fetched is retried every 0.1 s, and "not
// ready" answers are expected while a block is still propagating, so single
// failures stay quiet. Once this many consecutive attempts have failed the
// waiter says so at WARNING, then at most once per interval while it keeps
// failing.
inline constexpr std::uint64_t kBlockDataNetFailureWarnThreshold = 10;
inline constexpr double kBlockDataNetFailureWarnIntervalSeconds = 60.0;

// `last_warned_at` is negative when this waiter has not warned yet.
inline bool block_data_net_failure_warning_due(std::uint64_t consecutive_failures, double now, double last_warned_at) {
  if (consecutive_failures < kBlockDataNetFailureWarnThreshold) {
    return false;
  }
  if (last_warned_at < 0) {
    return true;
  }
  return non_negative_age(now, last_warned_at) >= kBlockDataNetFailureWarnIntervalSeconds;
}

// Whether one failed attempt is a warning of its own. "Not ready" never is.
// The first failure of any other kind is, however many "not ready" answers
// came before it; later ones are retried every 0.1 s and left to the
// rate-limited stall warning. `non_routine_warned` is the waiter's record of
// that first warning, cleared when the block arrives.
inline bool block_data_failure_warns(bool not_ready, bool &non_routine_warned) {
  if (not_ready || non_routine_warned) {
    return false;
  }
  non_routine_warned = true;
  return true;
}

// Masterchain blocks come every few seconds, so two minutes without progress
// is a stall, not jitter. The applied state (shard client) is checked as well
// as the last masterchain block: a node can keep accepting new masterchain
// blocks while the state it serves falls hours behind.
inline constexpr double kMasterchainLagWarnSeconds = 120.0;
inline constexpr double kMasterchainLagWarnIntervalSeconds = 60.0;

struct MasterchainLagAlertState {
  bool active = false;
  double last_warned_at = -1;
  // When the applied state (shard client) was first seen unknown while the
  // masterchain head was known; negative while it is known.
  double shard_client_unknown_since = -1;
};

enum class MasterchainLagAction { None, Warn, Clear };

struct MasterchainLagDecision {
  MasterchainLagAction action = MasterchainLagAction::None;
  MasterchainLagAlertState next;
};

// One evaluation of the lag alert: warn when either age exceeds the threshold
// (again at most once per interval while it holds), and clear exactly once
// when both ages are back under it.
inline MasterchainLagDecision decide_masterchain_lag_alert(const MasterchainLagAlertState &state, double now,
                                                           double last_masterchain_block_age, double shard_client_age) {
  MasterchainLagDecision decision;
  decision.next = state;
  const bool behind =
      last_masterchain_block_age > kMasterchainLagWarnSeconds || shard_client_age > kMasterchainLagWarnSeconds;
  if (behind) {
    if (!state.active || state.last_warned_at < 0 ||
        non_negative_age(now, state.last_warned_at) >= kMasterchainLagWarnIntervalSeconds) {
      decision.action = MasterchainLagAction::Warn;
      decision.next.active = true;
      decision.next.last_warned_at = now;
    }
    return decision;
  }
  if (state.active) {
    decision.action = MasterchainLagAction::Clear;
    decision.next = MasterchainLagAlertState{};
  }
  return decision;
}

// Where the bytes of a failed block-data attempt came from. A download is the
// network; a candidate read back from this node's own candidate cache or
// database is local, and bytes that fail to parse there say nothing about the
// network.
enum class BlockDataSource { Network, LocalCandidate };

inline const char *block_data_source_name(BlockDataSource source) {
  return source == BlockDataSource::Network ? "net" : "local candidate store";
}

// Consecutive failed network attempts of one block-data waiter, and the
// warnings they are worth. The waiter calls on_failure for every failed
// attempt and on_delivered once the block is delivered.
class BlockDataNetFailures {
 public:
  struct Report {
    // The block keeps failing: the rate-limited stall warning is due.
    bool stall_warning = false;
    // This failure is worth a warning of its own (see block_data_failure_warns).
    bool failure_warning = false;
    std::uint64_t consecutive = 0;
  };

  // `total` is the process-wide network failure counter the exporter
  // publishes. A local failure is not a network failure: it neither counts
  // nor feeds the stall warning, and it warns once per waiter.
  Report on_failure(BlockDataSource source, bool not_ready, double now, std::atomic<std::uint64_t> &total) {
    if (source != BlockDataSource::Network) {
      Report report;
      report.consecutive = consecutive_;
      report.failure_warning = !local_warned_;
      local_warned_ = true;
      return report;
    }
    if (consecutive_ < std::numeric_limits<std::uint64_t>::max()) {
      ++consecutive_;
    }
    total.fetch_add(1, std::memory_order_relaxed);
    Report report;
    report.consecutive = consecutive_;
    if (block_data_net_failure_warning_due(consecutive_, now, warned_at_)) {
      warned_at_ = now;
      report.stall_warning = true;
    }
    report.failure_warning = block_data_failure_warns(not_ready, non_routine_warned_);
    return report;
  }

  void on_delivered() {
    consecutive_ = 0;
    warned_at_ = -1;
    non_routine_warned_ = false;
  }

 private:
  std::uint64_t consecutive_ = 0;
  double warned_at_ = -1;
  bool non_routine_warned_ = false;
  // Never cleared: a waiter reports a bad local candidate once.
  bool local_warned_ = false;
};

// What one manager tick found about masterchain progress.
struct MasterchainLagReport {
  MasterchainLagAction action = MasterchainLagAction::None;
  double masterchain_age = 0;
  // The applied state's age; while its block time is unknown, the time since
  // it was first seen unknown with a known masterchain head.
  double shard_client_age = 0;
  bool shard_client_known = false;
};

// One manager tick: publishes the two block times (unix seconds, 0 unknown)
// for the exporter and decides the lag alert. Nothing is decided before the
// masterchain head is known. An applied state that stays unknown once the
// head is known is a node that applies nothing, so it ages from the moment it
// was first seen unknown and warns like any other stalled applied state.
inline MasterchainLagReport observe_masterchain_lag(MasterchainLagAlertState &state, std::uint64_t masterchain_unix,
                                                    std::uint64_t shard_client_unix, double wall, double now,
                                                    std::atomic<std::uint64_t> &masterchain_gauge,
                                                    std::atomic<std::uint64_t> &shard_client_gauge) {
  masterchain_gauge.store(masterchain_unix, std::memory_order_relaxed);
  shard_client_gauge.store(shard_client_unix, std::memory_order_relaxed);
  MasterchainLagReport report;
  if (masterchain_unix == 0) {
    return report;
  }
  report.masterchain_age = non_negative_age(wall, static_cast<double>(masterchain_unix));
  if (shard_client_unix != 0) {
    report.shard_client_known = true;
    report.shard_client_age = non_negative_age(wall, static_cast<double>(shard_client_unix));
    state.shard_client_unknown_since = -1;
  } else {
    if (state.shard_client_unknown_since < 0) {
      state.shard_client_unknown_since = now;
    }
    report.shard_client_age = non_negative_age(now, state.shard_client_unknown_since);
  }
  const double unknown_since = state.shard_client_unknown_since;
  auto decision = decide_masterchain_lag_alert(state, now, report.masterchain_age, report.shard_client_age);
  state = decision.next;
  state.shard_client_unknown_since = unknown_since;
  report.action = decision.action;
  return report;
}

// The log line for a Warn or Clear report; empty for None.
inline std::string masterchain_lag_message(const MasterchainLagReport &report) {
  if (report.action == MasterchainLagAction::None) {
    return {};
  }
  const std::string shard_client =
      report.shard_client_known
          ? std::to_string(static_cast<std::uint64_t>(report.shard_client_age)) + " s old"
          : "unknown for " + std::to_string(static_cast<std::uint64_t>(report.shard_client_age)) + " s";
  const std::string masterchain =
      "last masterchain block " + std::to_string(static_cast<std::uint64_t>(report.masterchain_age)) + " s old";
  if (report.action == MasterchainLagAction::Warn) {
    return "masterchain is behind: applied state (shard client) " + shard_client + ", " + masterchain + " (threshold " +
           std::to_string(static_cast<std::uint64_t>(kMasterchainLagWarnSeconds)) + " s)";
  }
  return "masterchain caught up: applied state (shard client) " + shard_client + ", " + masterchain;
}

}  // namespace tos::validator
