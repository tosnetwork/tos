/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    TOS Blockchain is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// The pure decisions of the startup catch-up mode, with injected clocks.

#include <vector>

#include "td/utils/tests.h"
#include "validator/startup-catchup.h"

using namespace tos;
using namespace tos::validator::startup_catchup;

namespace {

constexpr double kNow = 1'800'000'000.0;

// A literal copy of the startup sync predicate as it was before the mode existed,
// kept as the reference the classification must reproduce.
bool legacy_out_of_sync(BlockSeqno mc, BlockSeqno shard_client, BlockSeqno sync_upto, double block_time, double now,
                        BlockSeqno known_key, bool is_validator) {
  auto seqno = std::min(mc, shard_client);
  if (seqno < sync_upto) {
    return true;
  }
  if (shard_client + 16 < mc) {
    return true;
  }
  if (block_time + 80 > now) {
    return false;
  }
  if (mc < known_key) {
    return true;
  }
  if (is_validator && known_key <= mc) {
    return false;
  }
  return true;
}

SyncInputs inputs(double age, BlockSeqno mc = 1000, BlockSeqno shard_client = 1000, BlockSeqno sync_upto = 0,
                  BlockSeqno known_key = 900) {
  SyncInputs in;
  in.masterchain_seqno = mc;
  in.shard_client_seqno = shard_client;
  in.sync_upto = sync_upto;
  in.block_unix_time = kNow - age;
  in.now = kNow;
  in.known_key_block_seqno = known_key;
  return in;
}

EntryInputs entry_for(double age, bool member = true) {
  EntryInputs e;
  auto in = inputs(age);
  e.reason = classify_sync(in, [&] { return member; });
  e.age_seconds = block_age_seconds(in.now, in.block_unix_time);
  e.holds_validator_keys = true;
  return e;
}

}  // namespace

// T1. Entry boundaries: 299 s stays out; 300 s and 301 s enter; a block time in the
// future is age zero and stays out.
TEST(StartupCatchupPolicy, T1_EntryBoundaries) {
  ASSERT_TRUE(evaluate_entry(entry_for(299.0)) == EntryRefusal::NotStale);
  ASSERT_TRUE(evaluate_entry(entry_for(300.0)) == EntryRefusal::None);
  ASSERT_TRUE(evaluate_entry(entry_for(301.0)) == EntryRefusal::None);
  ASSERT_TRUE(evaluate_entry(entry_for(100.0)) == EntryRefusal::NotStale);
  auto future = entry_for(-50.0);
  ASSERT_EQ(0.0, future.age_seconds);
  ASSERT_TRUE(evaluate_entry(future) == EntryRefusal::NotStale);
  // Every other condition refuses on its own.
  auto e = entry_for(400.0);
  e.holds_validator_keys = false;
  ASSERT_TRUE(evaluate_entry(e) == EntryRefusal::NoValidatorKeys);
  e = entry_for(400.0);
  e.groups_empty = false;
  ASSERT_TRUE(evaluate_entry(e) == EntryRefusal::GroupsExist);
  e = entry_for(400.0);
  e.imports_empty = false;
  ASSERT_TRUE(evaluate_entry(e) == EntryRefusal::OperatorImport);
  e = entry_for(400.0);
  e.next_is_hardfork = true;
  ASSERT_TRUE(evaluate_entry(e) == EntryRefusal::HardforkNext);
  // A key-holding node that is not a member of the restored set enters too.
  ASSERT_TRUE(evaluate_entry(entry_for(400.0, false)) == EntryRefusal::None);
}

// T2. Inside the mode a stale validator keeps importing from 300 s down to 80 s; at
// 79 s the ordinary freshness rule ends it.
TEST(StartupCatchupPolicy, T2_ExitAtTheFreshnessRule) {
  for (double age : {300.0, 200.0, 81.0, 80.0}) {
    auto reason = classify_sync(inputs(age), [] { return true; });
    ASSERT_TRUE(reason == SyncReason::StaleValidator);
    ASSERT_TRUE(out_of_sync_value(reason, true));
  }
  auto reason = classify_sync(inputs(79.0), [] { return true; });
  ASSERT_TRUE(reason == SyncReason::Fresh);
  ASSERT_TRUE(!out_of_sync_value(reason, true));
}

// T3. Every reason other than the stale-validator short-circuit, in its legacy order,
// gives the legacy value whether the mode is on or off; the short-circuit is the one
// intended difference.
TEST(StartupCatchupPolicy, T3_LegacyReasonsUnchanged) {
  struct Row {
    BlockSeqno mc, shard_client, sync_upto;
    double age;
    BlockSeqno known_key;
    bool validator;
  };
  std::vector<Row> rows;
  for (BlockSeqno sync_upto : {0u, 2000u}) {
    for (BlockSeqno lag : {0u, 16u, 17u}) {
      for (double age : {10.0, 79.0, 80.0, 81.0, 500.0}) {
        for (BlockSeqno known_key : {900u, 1000u, 1001u}) {
          for (bool validator : {false, true}) {
            rows.push_back(Row{1000, 1000 - lag, sync_upto, age, known_key, validator});
          }
        }
      }
    }
  }
  int differences = 0;
  for (const auto& r : rows) {
    auto in = inputs(r.age, r.mc, r.shard_client, r.sync_upto, r.known_key);
    bool asked = false;
    auto reason = classify_sync(in, [&] {
      asked = true;
      return r.validator;
    });
    bool legacy =
        legacy_out_of_sync(r.mc, r.shard_client, r.sync_upto, in.block_unix_time, in.now, r.known_key, r.validator);
    ASSERT_EQ(legacy, out_of_sync_value(reason, false));
    if (reason == SyncReason::StaleValidator) {
      ASSERT_TRUE(!legacy);
      ASSERT_TRUE(out_of_sync_value(reason, true));
      differences++;
    } else {
      ASSERT_EQ(legacy, out_of_sync_value(reason, true));
    }
    // The membership test runs only where the legacy predicate reached it.
    ASSERT_EQ(asked, reason == SyncReason::StaleValidator || reason == SyncReason::StaleNonValidator);
  }
  ASSERT_TRUE(differences > 0);
  // The precedence the legacy predicate has: lag beats freshness, freshness beats a
  // newer key block.
  ASSERT_TRUE(classify_sync(inputs(10.0, 1000, 983), [] { return true; }) == SyncReason::ShardClientLag);
  ASSERT_TRUE(classify_sync(inputs(10.0, 1000, 1000, 0, 1001), [] { return true; }) == SyncReason::Fresh);
  ASSERT_TRUE(classify_sync(inputs(80.0, 1000, 1000, 0, 1001), [] { return true; }) == SyncReason::NewerKeyBlock);
  ASSERT_TRUE(classify_sync(inputs(500.0, 1000, 1000, 2000), [] { return true; }) == SyncReason::BelowSyncUpto);
}

// T4. Discovery decisions: one verified successor decides; K distinct explicit
// negatives decide before the deadline; unresponsive peers and too few peers wait for
// the deadline; a peer answering twice counts once.
TEST(StartupCatchupPolicy, T4_DiscoveryAggregation) {
  const double start = 100.0;
  const double deadline = start + kDiscoveryWindowSeconds;
  BlockIdExt next{masterchainId, shardIdAll, 11, {}, {}};
  {
    DiscoveryRound<int> round(deadline, kProbePeers, kProbeBudget);
    auto chosen = round.select(start, {1, 2, 3, 4});
    ASSERT_EQ(3u, chosen.size());
    round.on_answer(1, ProbeAnswer::empty());
    round.on_answer(2, ProbeAnswer::verified(next));
    ASSERT_TRUE(round.outcome(start + 1) == RoundOutcome::Verified);
    ASSERT_TRUE(round.result(start + 1).next == next);
  }
  {
    DiscoveryRound<int> round(deadline, kProbePeers, kProbeBudget);
    round.select(start, {1, 2, 3});
    round.on_answer(1, ProbeAnswer::empty());
    round.on_answer(2, ProbeAnswer::empty());
    ASSERT_TRUE(round.outcome(start + 2) == RoundOutcome::Pending);
    round.on_answer(3, ProbeAnswer::empty());
    ASSERT_TRUE(round.outcome(start + 2) == RoundOutcome::NoVerifiedSuccessor);
  }
  {
    // The same peer answering twice, and a peer never probed, count nothing.
    DiscoveryRound<int> round(deadline, kProbePeers, kProbeBudget);
    round.select(start, {1, 2, 3});
    round.on_answer(1, ProbeAnswer::empty());
    round.on_answer(1, ProbeAnswer::empty());
    round.on_answer(1, ProbeAnswer::empty());
    round.on_answer(9, ProbeAnswer::empty());
    ASSERT_EQ(1u, round.explicit_negatives());
    ASSERT_TRUE(round.outcome(start + 2) == RoundOutcome::Pending);
    // A peer offered again is never probed again.
    ASSERT_EQ(0u, round.select(start + 2, {1}).size());
  }
  {
    // Unresponsive peers: the decision falls at the deadline, not before.
    DiscoveryRound<int> round(deadline, kProbePeers, kProbeBudget);
    round.select(start, {1, 2, 3});
    ASSERT_TRUE(round.outcome(deadline - 1.0) == RoundOutcome::Pending);
    ASSERT_TRUE(round.outcome(deadline) == RoundOutcome::NoVerifiedSuccessor);
  }
  {
    // Fewer than K peers available.
    DiscoveryRound<int> round(deadline, kProbePeers, kProbeBudget);
    round.select(start, {1, 2});
    round.on_answer(1, ProbeAnswer::empty());
    round.on_answer(2, ProbeAnswer::empty());
    ASSERT_TRUE(round.wants_peers(start + 2));
    ASSERT_TRUE(round.outcome(deadline - 0.5) == RoundOutcome::Pending);
    ASSERT_TRUE(round.outcome(deadline + 0.5) == RoundOutcome::NoVerifiedSuccessor);
  }
  {
    // An inconclusive answer frees its slot for a new peer; the budget caps probes.
    DiscoveryRound<int> round(deadline, kProbePeers, kProbeBudget);
    round.select(start, {1, 2, 3});
    for (int p : {1, 2, 3}) {
      round.on_answer(p, ProbeAnswer::inconclusive("timeout"));
    }
    ASSERT_EQ(3u, round.select(start + 2, {4, 5, 6, 7}).size());
    for (int p : {4, 5, 6}) {
      round.on_answer(p, ProbeAnswer::inconclusive("timeout"));
    }
    ASSERT_EQ(kProbeBudget, round.probes_used());
    ASSERT_EQ(0u, round.select(start + 4, {7, 8}).size());
    ASSERT_TRUE(!round.wants_peers(start + 4));
    ASSERT_TRUE(round.outcome(start + 4) == RoundOutcome::Pending);
  }
  // The probe timeout is the fixed cap, or what is left of the window.
  ASSERT_EQ(kProbeQueryTimeoutSeconds, probe_timeout_seconds(start, deadline));
  ASSERT_EQ(2.0, probe_timeout_seconds(deadline - 2.0, deadline));
  ASSERT_TRUE(probe_timeout_seconds(deadline + 1.0, deadline) <= 0);
}

// T5 (policy half). Only a verified successor is progress: every other answer class,
// whatever its cause, is not.
TEST(StartupCatchupPolicy, T5_OnlyVerifiedIsProgress) {
  const double deadline = 130.0;
  for (auto answer : {ProbeAnswer::empty(), ProbeAnswer::inconclusive("malformed"),
                      ProbeAnswer::inconclusive("proof link"), ProbeAnswer::inconclusive("bad hash"),
                      ProbeAnswer::inconclusive("fork"), ProbeAnswer::inconclusive("seqno + 2"),
                      ProbeAnswer::inconclusive("signature"), ProbeAnswer::inconclusive("oversized")}) {
    DiscoveryRound<int> round(deadline, kProbePeers, kProbeBudget);
    round.select(100.0, {1});
    round.on_answer(1, answer);
    ASSERT_TRUE(round.outcome(deadline) == RoundOutcome::NoVerifiedSuccessor);
  }
}

// T6 (policy half). An answer saying the local tip moved ends the round so discovery
// restarts from the new tip; it is neither progress nor a negative.
TEST(StartupCatchupPolicy, T6_FrontierMovedEndsTheRound) {
  DiscoveryRound<int> round(130.0, kProbePeers, kProbeBudget);
  round.select(100.0, {1, 2});
  round.on_answer(1, ProbeAnswer::frontier_moved());
  ASSERT_TRUE(round.outcome(101.0) == RoundOutcome::FrontierMoved);
  ASSERT_EQ(0u, round.explicit_negatives());
}

// T7. Attempt accounting: only durable shard-client progress counts and resets the
// failure count; masterchain-only progress and a non-advancing success are failures;
// a partial attempt that errored after advancing is progress.
TEST(StartupCatchupPolicy, T7_AttemptAccounting) {
  ImportAccounting acc;
  ASSERT_TRUE(acc.record(AttemptResult{100, 150, 100, 150, false}) == AfterAttempt::Continue);
  // Masterchain-only progress.
  ASSERT_TRUE(acc.record(AttemptResult{150, 250, 150, 150, false}) == AfterAttempt::Rediscover);
  ASSERT_EQ(1u, acc.consecutive_failures());
  // A successful attempt that advanced nothing.
  ASSERT_TRUE(acc.record(AttemptResult{250, 250, 150, 150, false}) == AfterAttempt::Rediscover);
  ASSERT_EQ(2u, acc.consecutive_failures());
  ASSERT_TRUE(acc.after_rediscovery(true) == AfterRediscovery::Retry);
  // Partial progress, then an error: progress.
  ASSERT_TRUE(acc.record(AttemptResult{250, 300, 150, 180, true}) == AfterAttempt::Continue);
  ASSERT_EQ(0u, acc.consecutive_failures());
  // Three consecutive failures with a verified successor: abandoned.
  for (int i = 0; i < 3; ++i) {
    ASSERT_TRUE(acc.record(AttemptResult{300, 300, 180, 180, true}) == AfterAttempt::Rediscover);
  }
  ASSERT_TRUE(acc.after_rediscovery(true) == AfterRediscovery::ExitAbandoned);
  // Any failure without a verified successor ends the mode at once.
  ImportAccounting fresh;
  fresh.record(AttemptResult{300, 300, 180, 180, true});
  ASSERT_TRUE(fresh.after_rediscovery(false) == AfterRediscovery::ExitNoVerifiedSuccessor);
}

// T14 (policy half). The decision is taken once; Done is terminal and nothing enters
// the mode again.
TEST(StartupCatchupPolicy, T14_DecidedOnce) {
  Mode mode;
  ASSERT_TRUE(mode.decide(EntryRefusal::None));
  ASSERT_TRUE(mode.fence_closed());
  ASSERT_TRUE(mode.finish(ExitReason::Fresh));
  ASSERT_TRUE(!mode.fence_closed());
  ASSERT_TRUE(!mode.decide(EntryRefusal::None));
  ASSERT_TRUE(mode.done());
  ASSERT_TRUE(!mode.finish(ExitReason::Abandoned));
  ASSERT_TRUE(*mode.exit_reason() == ExitReason::Fresh);
  Mode refused;
  ASSERT_TRUE(!refused.decide(EntryRefusal::NotStale));
  ASSERT_TRUE(refused.done());
  ASSERT_TRUE(!refused.decide(EntryRefusal::None));
  ASSERT_TRUE(!refused.fence_closed());
}
