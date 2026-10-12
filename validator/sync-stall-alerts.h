/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#pragma once

#include <cstdint>

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

// Masterchain blocks come every few seconds, so two minutes without progress
// is a stall, not jitter. The applied state (shard client) is checked as well
// as the last masterchain block: a node can keep accepting new masterchain
// blocks while the state it serves falls hours behind.
inline constexpr double kMasterchainLagWarnSeconds = 120.0;
inline constexpr double kMasterchainLagWarnIntervalSeconds = 60.0;

struct MasterchainLagAlertState {
  bool active = false;
  double last_warned_at = -1;
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

}  // namespace tos::validator
