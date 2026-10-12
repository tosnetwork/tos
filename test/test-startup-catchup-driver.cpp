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

// The startup catch-up mode loop (validator/startup-catchup-driver.h), the same
// coroutine the manager runs, driven by a harness with a fake monotonic clock, a
// scripted discovery and scripted import attempts.

#include <functional>
#include <mutex>
#include <optional>
#include <vector>

#include "common/delay.h"
#include "common/errorcode.h"
#include "td/actor/actor.h"
#include "td/utils/tests.h"
#include "validator/startup-catchup-driver.h"

namespace tos::validator::startup_catchup {
namespace {

BlockIdExt tip_at(BlockSeqno seqno) {
  BlockIdExt id{masterchainId, shardIdAll, seqno, {}, {}};
  id.root_hash.as_slice()[0] = static_cast<char>(seqno & 0xff);
  id.root_hash.as_slice()[1] = static_cast<char>((seqno >> 8) & 0xff);
  return id;
}

struct Observed {
  std::optional<ExitReason> reason;
  bool failed = false;
  std::string failure;
  int rounds = 0;
  int attempts = 0;
  std::vector<BlockIdExt> round_prev;
  std::vector<std::uint32_t> round_budget;
  std::vector<BlockSeqno> attempt_shard_client_before;
  double elapsed = 0;
  bool persist_acked_before_end = true;
  int persists = 0;
};

class DriverHarness : public td::actor::Actor {
 public:
  using RoundFn = std::function<RoundResult(DriverHarness&, BlockIdExt prev, double deadline, std::uint32_t budget)>;
  using AttemptFn = std::function<void(DriverHarness&, double deadline, td::Promise<ImportOutcome>)>;
  using PersistFn = std::function<void(DriverHarness&, BlockSeqno seqno, td::Promise<td::Unit>)>;
  using SyncFn = std::function<bool(DriverHarness&)>;

  DriverHarness(RoundFn round, AttemptFn attempt, PersistFn persist, SyncFn sync, std::shared_ptr<std::mutex> mu,
                std::shared_ptr<Observed> observed)
      : round_(std::move(round))
      , attempt_(std::move(attempt))
      , persist_(std::move(persist))
      , sync_(std::move(sync))
      , mu_(std::move(mu))
      , observed_(std::move(observed)) {
  }

  // --- the owner surface of the driver ---
  double catchup_monotonic_now() {
    return now;
  }
  BlockIdExt catchup_tip() {
    return tip;
  }
  BlockSeqno catchup_masterchain_seqno() {
    return tip.seqno();
  }
  BlockSeqno catchup_shard_client_seqno() {
    return shard_client;
  }
  bool catchup_out_of_sync() {
    return sync_(*this);
  }
  void catchup_phase(Phase) {
  }
  td::actor::Task<RoundResult> catchup_probe_round(BlockIdExt prev, double deadline, std::uint32_t budget) {
    {
      std::lock_guard<std::mutex> lock(*mu_);
      observed_->rounds++;
      observed_->round_prev.push_back(prev);
      observed_->round_budget.push_back(budget);
    }
    co_return round_(*this, prev, deadline, budget);
  }
  td::actor::Task<ImportOutcome> catchup_import_attempt(double deadline) {
    {
      std::lock_guard<std::mutex> lock(*mu_);
      observed_->attempts++;
      observed_->attempt_shard_client_before.push_back(shard_client);
      if (observed_->attempts > 20) {
        co_return td::Status::Error("the mode did not end within 20 attempts");
      }
    }
    auto [task, promise] = td::actor::StartedTask<ImportOutcome>::make_bridge();
    attempt_(*this, deadline, std::move(promise));
    co_return co_await std::move(task);
  }
  td::actor::Task<td::Unit> catchup_persist_shard_client(BlockSeqno seqno) {
    {
      std::lock_guard<std::mutex> lock(*mu_);
      observed_->persists++;
    }
    auto [task, promise] = td::actor::StartedTask<td::Unit>::make_bridge();
    persist_(*this, seqno, std::move(promise));
    co_return co_await std::move(task);
  }
  td::actor::Task<td::Unit> catchup_sleep(double seconds) {
    now += seconds;
    co_return td::Unit{};
  }

  void run() {
    start_ = now;
    [](DriverHarness* self) -> td::actor::Task<> {
      auto r = co_await run_startup_catchup(self).wrap();
      std::lock_guard<std::mutex> lock(*self->mu_);
      if (r.is_error()) {
        self->observed_->failed = true;
        self->observed_->failure = r.error().to_string();
      } else {
        self->observed_->reason = r.ok();
      }
      self->observed_->elapsed = self->now - self->start_;
      self->observed_->persist_acked_before_end = !self->persist_in_flight;
      co_return td::Unit{};
    }(this)
                                                .start()
                                                .detach();
  }

  // A persistence write that completes `delay` real seconds later, durably moving the
  // shard client.
  void hold_persist(BlockSeqno seqno, double delay, td::Promise<td::Unit> promise) {
    persist_in_flight = true;
    tos::delay_action(
        [self = actor_id(this), seqno, promise = std::move(promise)]() mutable {
          td::actor::send_closure(self, &DriverHarness::ack_persist, seqno, std::move(promise));
        },
        td::Timestamp::in(delay));
  }
  void ack_persist(BlockSeqno seqno, td::Promise<td::Unit> promise) {
    shard_client = seqno;
    persist_in_flight = false;
    promise.set_value(td::Unit());
  }

  double now = 1000.0;
  BlockIdExt tip = tip_at(100);
  BlockSeqno shard_client = 100;
  bool persist_in_flight = false;
  int attempt_index = 0;

 private:
  RoundFn round_;
  AttemptFn attempt_;
  PersistFn persist_;
  SyncFn sync_;
  std::shared_ptr<std::mutex> mu_;
  std::shared_ptr<Observed> observed_;
  double start_ = 0;
};

RoundResult verified(DriverHarness& h, std::uint32_t used = 1) {
  RoundResult r;
  r.outcome = RoundOutcome::Verified;
  r.next = tip_at(h.tip.seqno() + 1);
  r.probes_used = used;
  return r;
}
RoundResult negative(std::uint32_t used = 3) {
  RoundResult r;
  r.outcome = RoundOutcome::NoVerifiedSuccessor;
  r.probes_used = used;
  r.explicit_negatives = 3;
  return r;
}
ImportOutcome outcome(BlockSeqno mc, BlockSeqno coherent, td::Status error = td::Status::OK()) {
  ImportOutcome o;
  o.masterchain_top = mc;
  o.coherent_shard_client_seqno = coherent;
  o.first_error = std::move(error);
  return o;
}
void persist_now(DriverHarness& h, BlockSeqno seqno, td::Promise<td::Unit> promise) {
  h.shard_client = seqno;
  promise.set_value(td::Unit());
}

Observed drive(DriverHarness::RoundFn round, DriverHarness::AttemptFn attempt, DriverHarness::PersistFn persist,
             DriverHarness::SyncFn sync) {
  auto mu = std::make_shared<std::mutex>();
  auto observed = std::make_shared<Observed>();
  td::actor::Scheduler scheduler({1});
  td::actor::ActorOwn<DriverHarness> harness;
  scheduler.run_in_context([&] {
    harness = td::actor::create_actor<DriverHarness>("driver", std::move(round), std::move(attempt),
                                                     std::move(persist), std::move(sync), mu, observed);
    td::actor::send_closure(harness, &DriverHarness::run);
  });
  auto deadline = td::Timestamp::in(30.0);
  while (!deadline.is_in_past()) {
    {
      std::lock_guard<std::mutex> lock(*mu);
      if (observed->reason || observed->failed) {
        break;
      }
    }
    scheduler.run(0.01);
  }
  scheduler.run_in_context([&] {
    harness.reset();
    td::actor::SchedulerContext::get().stop();
  });
  while (scheduler.run(1)) {
  }
  std::lock_guard<std::mutex> lock(*mu);
  return *observed;
}

}  // namespace
}  // namespace tos::validator::startup_catchup

using namespace tos;
using namespace tos::validator::startup_catchup;

// T9. A successor is proven every time but no archive is ever served: after three
// consecutive attempts without progress the mode ends Abandoned, within 3 x 332 s of
// fake time, and startup continues.
TEST(StartupCatchupDriver, T9_AbandonedWithinTheBound) {
  auto o = drive([](DriverHarness& h, BlockIdExt, double, std::uint32_t) { return verified(h); },
               [](DriverHarness& h, double deadline, td::Promise<ImportOutcome> p) {
                 h.now = deadline;  // every attempt uses its whole budget
                 p.set_value(outcome(h.tip.seqno(), h.shard_client,
                                     td::Status::Error(ErrorCode::timeout, "no peer serves the archive")));
               },
               persist_now, [](DriverHarness&) { return true; });
  ASSERT_TRUE(!o.failed);
  ASSERT_TRUE(o.reason == ExitReason::Abandoned);
  ASSERT_EQ(3, o.attempts);
  ASSERT_TRUE(o.elapsed <= 3 * (kImportAttemptSeconds + kDiscoveryWindowSeconds + kRetryDelaySeconds));
}

// T10. All validators stopped with unequal tips: a peer proves one successor and serves
// it; after importing it the next attempt fails, re-discovery proves nothing, and the
// mode ends NoVerifiedSuccessor although the tip is still old.
TEST(StartupCatchupDriver, T10_StoppedNetworkUnequalTips) {
  auto o = drive(
      [](DriverHarness& h, BlockIdExt, double, std::uint32_t) {
        return h.tip.seqno() == 100 ? verified(h) : negative();
      },
      [](DriverHarness& h, double, td::Promise<ImportOutcome> p) {
        if (h.tip.seqno() == 100) {
          h.tip = tip_at(110);
          p.set_value(outcome(110, 110));
        } else {
          p.set_value(outcome(110, 110, td::Status::Error("no new masterchain blocks were imported")));
        }
      },
      persist_now, [](DriverHarness&) { return true; });
  ASSERT_TRUE(!o.failed);
  ASSERT_TRUE(o.reason == ExitReason::NoVerifiedSuccessor);
  ASSERT_EQ(2, o.attempts);
}

// T11. The shard-client update that makes an attempt durable is held on its write
// while the attempt deadline passes and the exit condition becomes true: the mode does
// not end until the write is acknowledged.
TEST(StartupCatchupDriver, T11_ExitWaitsForTheShardClientWrite) {
  auto o = drive([](DriverHarness& h, BlockIdExt, double, std::uint32_t) { return verified(h); },
               [](DriverHarness& h, double deadline, td::Promise<ImportOutcome> p) {
                 h.now = deadline + 1.0;
                 h.tip = tip_at(150);
                 p.set_value(outcome(150, 150));
               },
               [](DriverHarness& h, BlockSeqno seqno, td::Promise<td::Unit> p) { h.hold_persist(seqno, 0.5, std::move(p)); },
               [](DriverHarness& h) { return h.tip.seqno() < 150; });
  ASSERT_TRUE(!o.failed);
  ASSERT_TRUE(o.reason == ExitReason::Fresh);
  ASSERT_TRUE(o.persist_acked_before_end);
  ASSERT_EQ(1, o.persists);
}

// T19. The deadline passes while the shard-client write is in flight: the write
// completes and is counted as progress, so the next attempt starts without
// re-discovery, from the durable frontier.
TEST(StartupCatchupDriver, T19_WriteInFlightAtDeadlineIsCounted) {
  auto o = drive([](DriverHarness& h, BlockIdExt, double, std::uint32_t) { return verified(h); },
               [](DriverHarness& h, double deadline, td::Promise<ImportOutcome> p) {
                 if (h.attempt_index++ == 0) {
                   h.now = deadline + 5.0;
                   p.set_value(outcome(140, 140));
                 } else {
                   h.tip = tip_at(160);
                   p.set_value(outcome(160, 160));
                 }
               },
               [](DriverHarness& h, BlockSeqno seqno, td::Promise<td::Unit> p) { h.hold_persist(seqno, 0.3, std::move(p)); },
               [](DriverHarness& h) { return h.tip.seqno() < 160; });
  ASSERT_TRUE(!o.failed);
  ASSERT_TRUE(o.reason == ExitReason::Fresh);
  ASSERT_EQ(1, o.rounds);
  ASSERT_EQ(2, o.attempts);
  ASSERT_EQ(140u, o.attempt_shard_client_before.at(1));
}

// T20 (driver half). Partial progress followed by an error: the coherent frontier is
// made durable before the next attempt, and the failure count is reset by it.
TEST(StartupCatchupDriver, T20_PartialProgressResetsTheCount) {
  auto o = drive([](DriverHarness& h, BlockIdExt, double, std::uint32_t) { return verified(h); },
               [](DriverHarness& h, double, td::Promise<ImportOutcome> p) {
                 switch (h.attempt_index++) {
                   case 0:
                   case 1:
                     p.set_value(outcome(120, h.shard_client, td::Status::Error("no archive")));
                     return;
                   case 2:
                     p.set_value(outcome(120, 103, td::Status::Error(ErrorCode::timeout, "deadline")));
                     return;
                   default:
                     p.set_value(outcome(120, h.shard_client, td::Status::Error("no archive")));
                     return;
                 }
               },
               persist_now, [](DriverHarness&) { return true; });
  ASSERT_TRUE(!o.failed);
  ASSERT_TRUE(o.reason == ExitReason::Abandoned);
  // Two failures, one partial success that resets the count, then three failures.
  ASSERT_EQ(6, o.attempts);
  ASSERT_EQ(103u, o.attempt_shard_client_before.at(3));
}

// T6 / T17 (driver half). The tip moves during discovery: the round about the old tip
// ends and discovery restarts from the new tip within the same window and budget. A
// successor verified for a tip that moved while its proof was checked is discarded.
TEST(StartupCatchupDriver, T6_T17_DiscoveryRestartsFromTheNewTip) {
  {
    auto o = drive(
        [](DriverHarness& h, BlockIdExt prev, double, std::uint32_t) {
          if (prev.seqno() == 100) {
            h.tip = tip_at(101);
            RoundResult r;
            r.outcome = RoundOutcome::FrontierMoved;
            r.probes_used = 2;
            return r;
          }
          return verified(h);
        },
        [](DriverHarness& h, double, td::Promise<ImportOutcome> p) {
          h.tip = tip_at(130);
          p.set_value(outcome(130, 130));
        },
        persist_now, [](DriverHarness& h) { return h.tip.seqno() < 130; });
    ASSERT_TRUE(o.reason == ExitReason::Fresh);
    ASSERT_EQ(2, o.rounds);
    ASSERT_TRUE(o.round_prev.at(1) == tip_at(101));
    ASSERT_EQ(kProbeBudget - 2, o.round_budget.at(1));
  }
  {
    // Verified, but for the old tip: discarded and re-proven for the new one.
    auto o = drive(
        [](DriverHarness& h, BlockIdExt prev, double, std::uint32_t) {
          auto r = verified(h);
          if (prev.seqno() == 100) {
            h.tip = tip_at(101);
          }
          return r;
        },
        [](DriverHarness& h, double, td::Promise<ImportOutcome> p) {
          h.tip = tip_at(130);
          p.set_value(outcome(130, 130));
        },
        persist_now, [](DriverHarness& h) { return h.tip.seqno() < 130; });
    ASSERT_TRUE(o.reason == ExitReason::Fresh);
    ASSERT_EQ(2, o.rounds);
    ASSERT_TRUE(o.round_prev.at(1) == tip_at(101));
  }
  {
    // The budget is shared by restarts: once spent, no further round is started.
    auto o = drive(
        [](DriverHarness& h, BlockIdExt prev, double, std::uint32_t budget) {
          h.tip = tip_at(prev.seqno() + 1);
          RoundResult r;
          r.outcome = RoundOutcome::FrontierMoved;
          r.probes_used = budget < 2 ? budget : 2;
          return r;
        },
        [](DriverHarness&, double, td::Promise<ImportOutcome> p) { p.set_value(outcome(0, 0)); },
        persist_now, [](DriverHarness&) { return true; });
    ASSERT_TRUE(o.reason == ExitReason::NoVerifiedSuccessor);
    ASSERT_EQ(3, o.rounds);
    ASSERT_EQ(0, o.attempts);
  }
}
