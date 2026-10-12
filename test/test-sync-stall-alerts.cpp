/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

// A node that stops applying masterchain blocks must say so at the default log
// level, and a healthy node must not. These tests pin the two decisions behind
// those warnings: when a block that keeps failing to download is worth a
// WARNING, and when the masterchain or the applied state is far enough behind
// to warn, how often, and when the warning clears.

#include "td/utils/tests.h"
#include "validator/sync-stall-alerts.h"

namespace tos::validator {
namespace {

TEST(SyncStallAlerts, AgeOfAClockThatWentBackwardsIsZero) {
  ASSERT_EQ(5.0, non_negative_age(105, 100));
  ASSERT_EQ(0.0, non_negative_age(100, 100));
  ASSERT_EQ(0.0, non_negative_age(90, 100));
}

TEST(SyncStallAlerts, BlockDataFailuresBelowTheThresholdStayQuiet) {
  for (std::uint64_t count = 0; count < kBlockDataNetFailureWarnThreshold; count++) {
    ASSERT_TRUE(!block_data_net_failure_warning_due(count, 1000, -1));
  }
}

TEST(SyncStallAlerts, BlockDataFailuresWarnOnceTheThresholdIsReached) {
  ASSERT_EQ(10u, kBlockDataNetFailureWarnThreshold);
  ASSERT_TRUE(block_data_net_failure_warning_due(kBlockDataNetFailureWarnThreshold, 1000, -1));
  ASSERT_TRUE(block_data_net_failure_warning_due(kBlockDataNetFailureWarnThreshold + 500, 1000, -1));
}

TEST(SyncStallAlerts, BlockDataFailuresWarnAtMostOncePerMinute) {
  const double warned = 1000;
  const auto count = kBlockDataNetFailureWarnThreshold + 1;
  ASSERT_TRUE(!block_data_net_failure_warning_due(count, warned, warned));
  ASSERT_TRUE(!block_data_net_failure_warning_due(count + 300, warned + 59.9, warned));
  ASSERT_TRUE(block_data_net_failure_warning_due(count + 600, warned + 60, warned));
  ASSERT_TRUE(block_data_net_failure_warning_due(count + 900, warned + 3600, warned));
}

TEST(SyncStallAlerts, BlockDataFailuresWithABackwardsClockDoNotFlood) {
  // A clock that went backwards reads as no time elapsed, not as a fresh
  // interval.
  ASSERT_TRUE(!block_data_net_failure_warning_due(kBlockDataNetFailureWarnThreshold, 900, 1000));
}

MasterchainLagDecision evaluate(MasterchainLagAlertState &state, double now, double masterchain_age,
                                double shard_client_age) {
  auto decision = decide_masterchain_lag_alert(state, now, masterchain_age, shard_client_age);
  state = decision.next;
  return decision;
}

TEST(SyncStallAlerts, HealthyNodeNeverWarns) {
  MasterchainLagAlertState state;
  for (int t = 0; t < 600; t++) {
    ASSERT_TRUE(evaluate(state, t, 2, 3).action == MasterchainLagAction::None);
  }
  // Exactly at the threshold is still not behind.
  ASSERT_TRUE(evaluate(state, 600, kMasterchainLagWarnSeconds, kMasterchainLagWarnSeconds).action ==
              MasterchainLagAction::None);
  ASSERT_TRUE(!state.active);
}

TEST(SyncStallAlerts, OldMasterchainBlockWarns) {
  MasterchainLagAlertState state;
  ASSERT_EQ(120.0, kMasterchainLagWarnSeconds);
  ASSERT_TRUE(evaluate(state, 1000, 121, 121).action == MasterchainLagAction::Warn);
  ASSERT_TRUE(state.active);
}

TEST(SyncStallAlerts, AppliedStateBehindWarnsWhileConsensusLooksCurrent) {
  // Consensus keeps finalizing new masterchain blocks while the applied state
  // falls hours behind: the alert must fire on the applied state alone.
  MasterchainLagAlertState state;
  ASSERT_TRUE(evaluate(state, 1000, 2, 9000).action == MasterchainLagAction::Warn);
}

TEST(SyncStallAlerts, LagWarnsAtMostOncePerMinuteWhileItHolds) {
  MasterchainLagAlertState state;
  ASSERT_TRUE(evaluate(state, 1000, 200, 200).action == MasterchainLagAction::Warn);
  int warnings = 0;
  for (int t = 1; t < 60; t++) {
    if (evaluate(state, 1000 + t, 200 + t, 200 + t).action == MasterchainLagAction::Warn) {
      warnings++;
    }
  }
  ASSERT_EQ(0, warnings);
  ASSERT_TRUE(evaluate(state, 1060, 260, 260).action == MasterchainLagAction::Warn);
  ASSERT_TRUE(evaluate(state, 1061, 261, 261).action == MasterchainLagAction::None);
}

TEST(SyncStallAlerts, LagClearsOnceWhenBothAgesRecover) {
  MasterchainLagAlertState state;
  ASSERT_TRUE(evaluate(state, 1000, 300, 300).action == MasterchainLagAction::Warn);
  // The masterchain recovered but the applied state did not: still behind.
  ASSERT_TRUE(evaluate(state, 1001, 2, 300).action == MasterchainLagAction::None);
  ASSERT_TRUE(state.active);
  ASSERT_TRUE(evaluate(state, 1002, 2, 3).action == MasterchainLagAction::Clear);
  ASSERT_TRUE(!state.active);
  ASSERT_TRUE(evaluate(state, 1003, 2, 3).action == MasterchainLagAction::None);
  // A new stall after clearing warns at once, without waiting out the
  // interval of the previous one.
  ASSERT_TRUE(evaluate(state, 1004, 500, 3).action == MasterchainLagAction::Warn);
}

TEST(SyncStallAlerts, LagWithABackwardsClockDoesNotFlood) {
  MasterchainLagAlertState state;
  ASSERT_TRUE(evaluate(state, 1000, 300, 300).action == MasterchainLagAction::Warn);
  ASSERT_TRUE(evaluate(state, 900, 300, 300).action == MasterchainLagAction::None);
}

}  // namespace
}  // namespace tos::validator
