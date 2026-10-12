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

// The startup catch-up successor probe and discovery round actors
// (validator/net/startup-probe.cpp). The probe runs its production classification
// on real serialized answers; only the peer transport and the manager's
// verification entry are substituted. The round runs with a substituted transport.

#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <vector>

#include "auto/tl/tos_api.h"
#include "common/checksum.h"
#include "common/errorcode.h"
#include "td/actor/actor.h"
#include "td/utils/tests.h"
#include "validator/full-node-serializer.hpp"
#include "validator/net/startup-probe.hpp"

namespace tos::validator::fullnode {
namespace {

using startup_catchup::ProbeAnswer;
using startup_catchup::ProbeAnswerKind;
using startup_catchup::SuccessorVerdict;

BlockIdExt mc_block(BlockSeqno seqno, td::Slice data) {
  return BlockIdExt{masterchainId, shardIdAll, seqno, td::sha256_bits256(PSLICE() << "root" << seqno),
                    td::sha256_bits256(data)};
}

const BlockIdExt kPrev = mc_block(100, "prev-data");

struct Script {
  // The peer's answer bytes, or an error.
  std::function<td::Result<td::BufferSlice>()> answer;
  // The manager's verdict on the proof.
  std::function<td::Result<SuccessorVerdict>()> verdict = [] { return SuccessorVerdict::Verified; };
  double clock_offset = 0;
};

struct Seen {
  std::mutex mu;
  int queries = 0;
  int verifications = 0;
  size_t max_size = 0;
  double query_timeout = 0;
};

class TestProbe : public ProbeNextMasterchainBlock {
 public:
  TestProbe(Script script, std::shared_ptr<Seen> seen, td::Timestamp deadline, td::Promise<ProbeAnswer> promise)
      : ProbeNextMasterchainBlock(adnl::AdnlNodeIdShort::zero(), overlay::OverlayIdShort{}, kPrev,
                                  adnl::AdnlNodeIdShort::zero(), deadline, {}, {}, {}, std::move(promise))
      , script_(std::move(script))
      , seen_(std::move(seen)) {
  }

 protected:
  double clock_now() const override {
    return td::Time::now() + script_.clock_offset;
  }
  void send_query(td::BufferSlice, size_t max_size, td::Timestamp timeout,
                  td::Promise<td::BufferSlice> promise) override {
    {
      std::lock_guard<std::mutex> lock(seen_->mu);
      seen_->queries++;
      seen_->max_size = max_size;
      seen_->query_timeout = timeout.at() - td::Time::now();
    }
    auto answer = script_.answer();
    // The transport refuses an answer larger than the bound it was given.
    if (answer.is_ok() && answer.ok().size() > max_size) {
      promise.set_error(td::Status::Error(ErrorCode::protoviolation, "answer exceeds the size bound"));
      return;
    }
    promise.set_result(std::move(answer));
  }
  void wait_prev_state(td::Timestamp, td::Promise<td::Ref<ShardState>> promise) override {
    promise.set_error(td::Status::Error("no state in this test"));
  }
  void verify_successor(BlockIdExt, td::BufferSlice, td::Promise<SuccessorVerdict> promise) override {
    {
      std::lock_guard<std::mutex> lock(seen_->mu);
      seen_->verifications++;
    }
    promise.set_result(script_.verdict());
  }

 private:
  Script script_;
  std::shared_ptr<Seen> seen_;
};

td::BufferSlice full_answer(BlockIdExt id, td::Slice proof, td::Slice data, bool is_link = false) {
  return serialize_block_full(id, proof, data, is_link, false).move_as_ok();
}

std::pair<ProbeAnswer, std::shared_ptr<Seen>> probe(Script script, double window = 30.0) {
  auto seen = std::make_shared<Seen>();
  std::mutex mu;
  std::optional<ProbeAnswer> answer;
  td::actor::Scheduler scheduler({1});
  scheduler.run_in_context([&] {
    td::actor::create_actor<TestProbe>("probe", std::move(script), seen, td::Timestamp::in(window),
                                       td::PromiseCreator::lambda([&](td::Result<ProbeAnswer> R) {
                                         std::lock_guard<std::mutex> lock(mu);
                                         answer = R.is_ok() ? R.move_as_ok() : ProbeAnswer::inconclusive("failed");
                                       }))
        .release();
  });
  auto deadline = td::Timestamp::in(20.0);
  while (!deadline.is_in_past()) {
    {
      std::lock_guard<std::mutex> lock(mu);
      if (answer) {
        break;
      }
    }
    scheduler.run(0.01);
  }
  scheduler.run_in_context([&] { td::actor::SchedulerContext::get().stop(); });
  while (scheduler.run(1)) {
  }
  std::lock_guard<std::mutex> lock(mu);
  CHECK(answer.has_value());
  return {*answer, seen};
}

// --- the discovery round with a substituted transport ---

struct RoundWorld {
  std::mutex mu;
  std::vector<std::vector<adnl::AdnlNodeIdShort>> peer_lists;  // successive get_peers answers
  size_t peer_calls = 0;
  std::map<adnl::AdnlNodeIdShort, int> probes;
  std::map<adnl::AdnlNodeIdShort, std::optional<ProbeAnswer>> answers;  // nothing: never answers
  std::vector<td::Promise<ProbeAnswer>> held;
  double first_probe_at = 0;
};

class FakeTransport : public StartupDiscoveryRound::Transport {
 public:
  explicit FakeTransport(std::shared_ptr<RoundWorld> world) : world_(std::move(world)) {
  }
  void get_peers(td::uint32, td::Promise<std::vector<adnl::AdnlNodeIdShort>> promise) override {
    std::lock_guard<std::mutex> lock(world_->mu);
    auto index = std::min(world_->peer_calls, world_->peer_lists.size() - 1);
    world_->peer_calls++;
    promise.set_value(std::vector<adnl::AdnlNodeIdShort>(world_->peer_lists[index]));
  }
  void probe(adnl::AdnlNodeIdShort peer, BlockIdExt, td::Timestamp,
             td::Promise<ProbeAnswer> promise) override {
    std::lock_guard<std::mutex> lock(world_->mu);
    if (world_->first_probe_at == 0) {
      world_->first_probe_at = td::Time::now();
    }
    world_->probes[peer]++;
    auto it = world_->answers.find(peer);
    if (it != world_->answers.end() && it->second) {
      promise.set_value(ProbeAnswer(*it->second));
      return;
    }
    world_->held.push_back(std::move(promise));
  }

 private:
  std::shared_ptr<RoundWorld> world_;
};

adnl::AdnlNodeIdShort peer(int n) {
  return adnl::AdnlNodeIdShort{td::sha256_bits256(PSLICE() << "peer-" << n)};
}

std::pair<startup_catchup::RoundResult, double> run_round(std::shared_ptr<RoundWorld> world, double window,
                                                          std::uint32_t budget = startup_catchup::kProbeBudget) {
  std::mutex mu;
  std::optional<startup_catchup::RoundResult> result;
  double decided_at = 0;
  auto started = td::Time::now();
  td::actor::Scheduler scheduler({1});
  scheduler.run_in_context([&] {
    td::actor::create_actor<StartupDiscoveryRound>(
        "round", kPrev, td::Timestamp::in(window), budget, std::make_unique<FakeTransport>(world),
        td::PromiseCreator::lambda([&](td::Result<startup_catchup::RoundResult> R) {
          std::lock_guard<std::mutex> lock(mu);
          result = R.move_as_ok();
          decided_at = td::Time::now();
        }))
        .release();
  });
  auto deadline = td::Timestamp::in(window + 10.0);
  while (!deadline.is_in_past()) {
    {
      std::lock_guard<std::mutex> lock(mu);
      if (result) {
        break;
      }
    }
    scheduler.run(0.01);
  }
  scheduler.run_in_context([&] {
    {
      std::lock_guard<std::mutex> lock(world->mu);
      world->held.clear();
    }
    td::actor::SchedulerContext::get().stop();
  });
  while (scheduler.run(1)) {
  }
  std::lock_guard<std::mutex> lock(mu);
  CHECK(result.has_value());
  return {*result, decided_at - started};
}

}  // namespace
}  // namespace tos::validator::fullnode

using namespace tos;
using namespace tos::validator::fullnode;
using tos::validator::startup_catchup::ProbeAnswerKind;
using tos::validator::startup_catchup::RoundOutcome;
using tos::validator::startup_catchup::SuccessorVerdict;

// A well-formed successor whose proof the manager verifies is progress.
TEST(StartupCatchupProbe, VerifiedSuccessor) {
  auto next = mc_block(101, "next-data");
  auto [answer, seen] = probe(Script{[&] { return td::Result<td::BufferSlice>(full_answer(next, "proof", "next-data")); }});
  ASSERT_TRUE(answer.kind == ProbeAnswerKind::Verified);
  ASSERT_TRUE(answer.next == next);
  ASSERT_EQ(1, seen->verifications);
  ASSERT_EQ(ProbeNextMasterchainBlock::max_answer_size(), seen->max_size);
}

// T5. Nothing but a proof that passes the manager's check is progress: a malformed
// answer, a proof link, a data hash mismatch, a successor of a different block, a
// seqno + 2, a failed signature check and an oversized answer are all inconclusive;
// an explicit empty answer is a negative.
TEST(StartupCatchupProbe, T5_NotProgress) {
  auto next = mc_block(101, "next-data");
  auto kind_of = [](Script s) { return probe(std::move(s)).first.kind; };
  ASSERT_TRUE(kind_of(Script{[] { return td::Result<td::BufferSlice>(td::BufferSlice("garbage")); }}) ==
              ProbeAnswerKind::Inconclusive);
  ASSERT_TRUE(kind_of(Script{[&] {
                return td::Result<td::BufferSlice>(full_answer(next, "proof", "next-data", true));
              }}) == ProbeAnswerKind::Inconclusive);
  ASSERT_TRUE(kind_of(Script{[&] {
                return td::Result<td::BufferSlice>(full_answer(next, "proof", "other-data"));
              }}) == ProbeAnswerKind::Inconclusive);
  ASSERT_TRUE(kind_of(Script{[&] { return td::Result<td::BufferSlice>(full_answer(next, "proof", "next-data")); },
                             [] {
                               return td::Result<SuccessorVerdict>(
                                   td::Status::Error(ErrorCode::protoviolation, "prev block mismatch"));
                             }}) == ProbeAnswerKind::Inconclusive);
  {
    auto skip = mc_block(102, "skip-data");
    auto [answer, seen] =
        probe(Script{[&] { return td::Result<td::BufferSlice>(full_answer(skip, "proof", "skip-data")); }});
    ASSERT_TRUE(answer.kind == ProbeAnswerKind::Inconclusive);
    ASSERT_EQ(0, seen->verifications);
  }
  ASSERT_TRUE(kind_of(Script{[&] { return td::Result<td::BufferSlice>(full_answer(next, "proof", "next-data")); },
                             [] {
                               return td::Result<SuccessorVerdict>(
                                   td::Status::Error(ErrorCode::protoviolation, "pq signatures: invalid signature"));
                             }}) == ProbeAnswerKind::Inconclusive);
  ASSERT_TRUE(kind_of(Script{[&] {
                std::string big(ProbeNextMasterchainBlock::max_answer_size() + 1, 'x');
                return td::Result<td::BufferSlice>(full_answer(next, "proof", big));
              }}) == ProbeAnswerKind::Inconclusive);
  ASSERT_TRUE(kind_of(Script{[] {
                return td::Result<td::BufferSlice>(
                    create_serialize_tl_object<tos_api::tosNode_dataFullEmpty>());
              }}) == ProbeAnswerKind::Empty);
  ASSERT_TRUE(kind_of(Script{[] {
                return td::Result<td::BufferSlice>(td::Status::Error(ErrorCode::timeout, "query timed out"));
              }}) == ProbeAnswerKind::Inconclusive);
}

// T6 (probe half). The manager's entry reports that the local tip moved: the answer
// says so, and is neither progress nor a negative.
TEST(StartupCatchupProbe, T6_FrontierMovedVerdict) {
  auto next = mc_block(101, "next-data");
  auto [answer, seen] = probe(Script{[&] { return td::Result<td::BufferSlice>(full_answer(next, "proof", "next-data")); },
                                     [] { return td::Result<SuccessorVerdict>(SuccessorVerdict::FrontierMoved); }});
  ASSERT_TRUE(answer.kind == ProbeAnswerKind::FrontierMoved);
}

// T17 (probe half). The query timeout is capped by the discovery window, and a probe
// whose window has closed sends nothing.
TEST(StartupCatchupProbe, T17_WindowCapsTheProbe) {
  auto next = mc_block(101, "next-data");
  {
    auto [answer, seen] =
        probe(Script{[&] { return td::Result<td::BufferSlice>(full_answer(next, "proof", "next-data")); }}, 1.5);
    ASSERT_TRUE(seen->query_timeout > 1.0 && seen->query_timeout < 1.6);
  }
  {
    Script closed{[&] { return td::Result<td::BufferSlice>(full_answer(next, "proof", "next-data")); }};
    closed.clock_offset = 40.0;  // the probe sees its 30 s window already over
    auto [answer, seen] = probe(std::move(closed));
    ASSERT_TRUE(answer.kind == ProbeAnswerKind::Inconclusive);
    ASSERT_EQ(0, seen->queries);
  }
}

// T4 (actor half). The round probes distinct peers only, retries peer selection while
// the overlay is empty, decides early on K distinct explicit negatives, and otherwise
// at the deadline.
TEST(StartupCatchupProbe, T4_RoundOverDistinctPeers) {
  {
    auto world = std::make_shared<RoundWorld>();
    world->peer_lists = {{}, {peer(1), peer(1), peer(2), peer(3)}};
    for (int n : {1, 2, 3}) {
      world->answers[peer(n)] = ProbeAnswer::empty();
    }
    auto [result, took] = run_round(world, 10.0);
    ASSERT_TRUE(result.outcome == RoundOutcome::NoVerifiedSuccessor);
    ASSERT_EQ(3u, result.explicit_negatives);
    ASSERT_TRUE(took < 9.0);
    ASSERT_TRUE(took >= tos::validator::startup_catchup::kPeerReselectSeconds - 0.1);
    for (int n : {1, 2, 3}) {
      ASSERT_EQ(1, world->probes[peer(n)]);
    }
  }
  {
    // Unresponsive peers: the decision falls at the deadline.
    auto world = std::make_shared<RoundWorld>();
    world->peer_lists = {{peer(1), peer(2), peer(3)}};
    auto [result, took] = run_round(world, 1.5);
    ASSERT_TRUE(result.outcome == RoundOutcome::NoVerifiedSuccessor);
    ASSERT_EQ(0u, result.explicit_negatives);
    ASSERT_TRUE(took >= 1.4);
  }
  {
    auto world = std::make_shared<RoundWorld>();
    world->peer_lists = {{peer(1), peer(2), peer(3)}};
    world->answers[peer(1)] = ProbeAnswer::empty();
    world->answers[peer(2)] = ProbeAnswer::verified(mc_block(101, "next-data"));
    auto [result, took] = run_round(world, 10.0);
    ASSERT_TRUE(result.outcome == RoundOutcome::Verified);
    ASSERT_TRUE(took < 5.0);
  }
}
