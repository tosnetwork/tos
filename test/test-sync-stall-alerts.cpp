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

#include <atomic>
#include <string>

#include "td/utils/buffer.h"
#include "td/utils/tests.h"
#include "validator/candidate-data-cache.h"
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

TEST(SyncStallAlerts, TheFirstNonRoutineFailureWarnsAfterNotReadyAnswers) {
  // "Not ready" answers first, then a timeout: the timeout is the first failure
  // of its kind and must reach the default log; repeats of it must not.
  bool warned = false;
  ASSERT_TRUE(!block_data_failure_warns(true, warned));
  ASSERT_TRUE(!block_data_failure_warns(true, warned));
  ASSERT_TRUE(!block_data_failure_warns(true, warned));
  ASSERT_TRUE(block_data_failure_warns(false, warned));
  ASSERT_TRUE(!block_data_failure_warns(false, warned));
  ASSERT_TRUE(!block_data_failure_warns(true, warned));
  ASSERT_TRUE(!block_data_failure_warns(false, warned));
  // The waiter clears the record when the block arrives; a later failure of
  // another kind warns again.
  warned = false;
  ASSERT_TRUE(block_data_failure_warns(false, warned));
}

TEST(SyncStallAlerts, LagWithABackwardsClockDoesNotFlood) {
  MasterchainLagAlertState state;
  ASSERT_TRUE(evaluate(state, 1000, 300, 300).action == MasterchainLagAction::Warn);
  ASSERT_TRUE(evaluate(state, 900, 300, 300).action == MasterchainLagAction::None);
}

// The manager's tick, as the manager runs it: block times in, gauges and the
// log line out.
struct Tick {
  MasterchainLagAlertState state;
  std::atomic<std::uint64_t> masterchain_gauge{0};
  std::atomic<std::uint64_t> shard_client_gauge{0};
  MasterchainLagReport run(std::uint64_t masterchain_unix, std::uint64_t shard_client_unix, double wall, double now) {
    return observe_masterchain_lag(state, masterchain_unix, shard_client_unix, wall, now, masterchain_gauge,
                                   shard_client_gauge);
  }
};

TEST(SyncStallAlerts, TickPublishesBothBlockTimes) {
  Tick tick;
  tick.run(1000, 400, 1002, 50);
  ASSERT_EQ(1000u, tick.masterchain_gauge.load());
  ASSERT_EQ(400u, tick.shard_client_gauge.load());
  // Unknown is published as unknown, not as the previous value.
  tick.run(1001, 0, 1003, 51);
  ASSERT_EQ(0u, tick.shard_client_gauge.load());
}

TEST(SyncStallAlerts, TickWarnsWithTheAgesInTheLogLine) {
  Tick tick;
  auto report = tick.run(10000 - 2, 10000 - 9000, 10000, 50);
  ASSERT_TRUE(report.action == MasterchainLagAction::Warn);
  ASSERT_EQ(std::string("masterchain is behind: applied state (shard client) 9000 s old, last masterchain block 2 s "
                        "old (threshold 120 s)"),
            masterchain_lag_message(report));
  report = tick.run(10100 - 2, 10100 - 3, 10100, 150);
  ASSERT_TRUE(report.action == MasterchainLagAction::Clear);
  ASSERT_EQ(std::string("masterchain caught up: applied state (shard client) 3 s old, last masterchain block 2 s old"),
            masterchain_lag_message(report));
  ASSERT_EQ(std::string(), masterchain_lag_message(tick.run(10101 - 2, 10101 - 3, 10101, 151)));
}

TEST(SyncStallAlerts, NothingIsDecidedBeforeTheMasterchainHeadIsKnown) {
  Tick tick;
  for (int t = 0; t < 1000; t += 10) {
    ASSERT_TRUE(tick.run(0, 0, 5000 + t, t).action == MasterchainLagAction::None);
  }
  ASSERT_TRUE(tick.state.shard_client_unknown_since < 0);
}

TEST(SyncStallAlerts, AnAppliedStateThatStaysUnknownWarns) {
  // The masterchain head is current but the shard client never published a
  // handle: once that has lasted past the threshold it is a stalled node.
  Tick tick;
  double now = 100;
  for (; now <= 100 + kMasterchainLagWarnSeconds; now += 1) {
    ASSERT_TRUE(tick.run(5000, 0, 5002, now).action == MasterchainLagAction::None);
  }
  auto report = tick.run(5000, 0, 5002, now);
  ASSERT_TRUE(report.action == MasterchainLagAction::Warn);
  ASSERT_TRUE(!report.shard_client_known);
  ASSERT_EQ(std::string("masterchain is behind: applied state (shard client) unknown for 121 s, last masterchain "
                        "block 2 s old (threshold 120 s)"),
            masterchain_lag_message(report));
  // The grace clock is not restarted by the warning, so it keeps warning
  // once a minute.
  ASSERT_TRUE(tick.run(5000, 0, 5002, now + 30).action == MasterchainLagAction::None);
  ASSERT_TRUE(tick.run(5000, 0, 5002, now + 60).action == MasterchainLagAction::Warn);
  // Once the applied state is known and current the alert clears, and a
  // later unknown period starts a fresh grace clock.
  ASSERT_TRUE(tick.run(5100, 5099, 5102, now + 61).action == MasterchainLagAction::Clear);
  ASSERT_TRUE(tick.run(5100, 0, 5102, now + 62).action == MasterchainLagAction::None);
  ASSERT_EQ(now + 62, tick.state.shard_client_unknown_since);
}

constexpr auto kNet = BlockDataSource::Network;
constexpr auto kLocal = BlockDataSource::LocalCandidate;

TEST(SyncStallAlerts, WaiterCountsEveryFailureAndWarnsOnTheStall) {
  BlockDataNetFailures failures;
  std::atomic<std::uint64_t> total{5};
  int stall_warnings = 0;
  for (std::uint64_t i = 1; i <= kBlockDataNetFailureWarnThreshold; i++) {
    auto report = failures.on_failure(kNet, true, 1000 + 0.1 * static_cast<double>(i), total);
    ASSERT_EQ(i, report.consecutive);
    ASSERT_TRUE(!report.failure_warning);
    stall_warnings += report.stall_warning ? 1 : 0;
  }
  ASSERT_EQ(1, stall_warnings);
  ASSERT_EQ(5u + kBlockDataNetFailureWarnThreshold, total.load());
  // Within the interval: neither the stall nor a repeated "not ready" warns;
  // the first failure of another kind does.
  ASSERT_TRUE(!failures.on_failure(kNet, true, 1010, total).stall_warning);
  auto other = failures.on_failure(kNet, false, 1011, total);
  ASSERT_TRUE(other.failure_warning && !other.stall_warning);
  ASSERT_TRUE(!failures.on_failure(kNet, false, 1012, total).failure_warning);
  ASSERT_TRUE(failures.on_failure(kNet, true, 1061, total).stall_warning);
}

TEST(SyncStallAlerts, WaiterStartsOverWhenTheBlockArrives) {
  BlockDataNetFailures failures;
  std::atomic<std::uint64_t> total{0};
  for (std::uint64_t i = 0; i < kBlockDataNetFailureWarnThreshold; i++) {
    failures.on_failure(kNet, false, 1000, total);
  }
  failures.on_delivered();
  auto report = failures.on_failure(kNet, false, 1001, total);
  ASSERT_EQ(1u, report.consecutive);
  ASSERT_TRUE(report.failure_warning);
  ASSERT_TRUE(!report.stall_warning);
  // The process-wide counter is never reset.
  ASSERT_EQ(kBlockDataNetFailureWarnThreshold + 1, total.load());
}

TEST(SyncStallAlerts, BadLocalCandidateIsReportedOnceAndNotCountedAsANetworkFailure) {
  // A candidate read back from this node's own cache or database that does
  // not parse says nothing about the network: the network counter and the
  // consecutive-failure run must not move, and no stall is claimed.
  BlockDataNetFailures failures;
  std::atomic<std::uint64_t> total{7};
  auto first = failures.on_failure(kLocal, false, 1000, total);
  ASSERT_TRUE(first.failure_warning);
  ASSERT_TRUE(!first.stall_warning);
  ASSERT_EQ(0u, first.consecutive);
  // Far past the stall threshold, and "not ready" or not: still one warning,
  // still nothing counted.
  for (std::uint64_t i = 0; i < 10 * kBlockDataNetFailureWarnThreshold; i++) {
    auto report = failures.on_failure(kLocal, i % 2 == 0, 1000 + static_cast<double>(i), total);
    ASSERT_TRUE(!report.failure_warning);
    ASSERT_TRUE(!report.stall_warning);
    ASSERT_EQ(0u, report.consecutive);
  }
  ASSERT_EQ(7u, total.load());
  // The network path after it starts its own run from one, and its first
  // non-routine failure still warns.
  auto net = failures.on_failure(kNet, false, 2000, total);
  ASSERT_EQ(1u, net.consecutive);
  ASSERT_TRUE(net.failure_warning);
  ASSERT_EQ(8u, total.load());
  // A local failure in the middle of a network run neither extends nor resets
  // it.
  ASSERT_EQ(1u, failures.on_failure(kLocal, false, 2001, total).consecutive);
  ASSERT_EQ(2u, failures.on_failure(kNet, true, 2002, total).consecutive);
  ASSERT_EQ(9u, total.load());
}

TEST(SyncStallAlerts, BadLocalCandidateWarnsOncePerWaiterEvenAfterDelivery) {
  BlockDataNetFailures failures;
  std::atomic<std::uint64_t> total{0};
  ASSERT_TRUE(failures.on_failure(kLocal, false, 1000, total).failure_warning);
  failures.on_delivered();
  ASSERT_TRUE(!failures.on_failure(kLocal, false, 1001, total).failure_warning);
  ASSERT_EQ(0u, total.load());
  // A fresh waiter reports its own bad local candidate.
  BlockDataNetFailures other;
  ASSERT_TRUE(other.on_failure(kLocal, false, 1002, total).failure_warning);
}

// A block request as the manager answers it (send_get_block_request): from the
// candidate cache if the full block check accepts the cached bytes, otherwise
// by a download. `check` stands in for create_block; the cached bytes model a
// candidate that carries the advertised file hash but is not a valid block.
struct BlockRequest {
  CandidateDataCache<int> cache{CandidateDataCacheLimits{4, 4 * CandidateDataCache<int>::charge_for(64), 64}};
  int checks = 0;
  int downloads = 0;
  bool serve(int id, const std::string &good, std::string &out) {
    auto check = [&](const td::BufferSlice &data) {
      checks++;
      return data.as_slice() == td::Slice(good);
    };
    if (auto cached = cache.get_if_valid(id, check, false)) {
      out = cached->as_slice().str();
      return true;
    }
    downloads++;
    out = good;
    return false;
  }
};

TEST(SyncStallAlerts, CachedBlockThatFailsTheFullCheckIsEvictedAndDownloaded) {
  BlockRequest request;
  BlockDataNetFailures failures;
  std::atomic<std::uint64_t> total{3};
  const std::string good = "the block";
  ASSERT_TRUE(request.cache.put(1, td::BufferSlice("right file hash, bad cells")) ==
              CandidateDataCache<int>::PutResult::Stored);
  // The waiter's loop on this path: request, parse (the same check), and
  // report a parse failure as the network's, as loaded_data() does. The bad
  // cached bytes never reach it, so the network counter does not move.
  for (int attempt = 0; attempt < 3; attempt++) {
    std::string bytes;
    request.serve(1, good, bytes);
    if (bytes == good) {
      failures.on_delivered();
    } else {
      failures.on_failure(kNet, false, 1000 + attempt, total);
    }
  }
  ASSERT_EQ(3u, total.load());
  // One failed check evicted the entry; every attempt after it downloads
  // without consulting the cache again.
  ASSERT_EQ(1, request.checks);
  ASSERT_EQ(3, request.downloads);
  ASSERT_TRUE(!request.cache.contains(1));
}

TEST(SyncStallAlerts, CachedBlockThatPassesTheFullCheckIsServedAndKept) {
  BlockRequest request;
  const std::string good = "the block";
  ASSERT_TRUE(request.cache.put(1, td::BufferSlice(good)) == CandidateDataCache<int>::PutResult::Stored);
  std::string bytes;
  ASSERT_TRUE(request.serve(1, good, bytes));
  ASSERT_TRUE(request.serve(1, good, bytes));
  ASSERT_EQ(good, bytes);
  ASSERT_EQ(0, request.downloads);
  ASSERT_TRUE(request.cache.contains(1));
  // A miss downloads and checks nothing.
  ASSERT_TRUE(!request.serve(2, good, bytes));
  ASSERT_EQ(1, request.downloads);
  ASSERT_EQ(2, request.checks);
}

TEST(SyncStallAlerts, BlockDataSourcesAreNamedForTheLog) {
  ASSERT_EQ(std::string("net"), std::string(block_data_source_name(kNet)));
  ASSERT_EQ(std::string("local candidate store"), std::string(block_data_source_name(kLocal)));
}

}  // namespace
}  // namespace tos::validator
