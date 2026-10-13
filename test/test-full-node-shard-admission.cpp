/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// The admission step every full-node shard runs on an overlay query before
// dispatching it: registration of the shard, parsing, pricing, charging the
// actual source and shard, and refusal before dispatch. Two shards share one
// limiter built with the production request categories.
//
// A query refused for capacity keeps its parsed form and, for the query types
// that have an empty reply, is answered with it while the shared
// refusal-answer budget lasts; every other refusal stays silent. The clocks
// of the limiter and of the budget are held still and advanced by the test.

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "auto/tl/tos_api.h"
#include "td/utils/tests.h"
#include "tl-utils/common-utils.hpp"
#include "validator/full-node-shard-admission.h"

namespace {

using namespace tos;
using tos::validator::fullnode::capacity_refusal_answer;
using tos::validator::fullnode::check_full_node_rate_limits;
using tos::validator::fullnode::default_refusal_answer_limits;
using tos::validator::fullnode::full_node_rate_limits;
using tos::validator::fullnode::FullNodeRateLimiter;
using tos::validator::fullnode::k_default_ratelimit_global;
using tos::validator::fullnode::k_default_ratelimit_window_size;
using tos::validator::fullnode::k_refusal_answer_lifetime;
using tos::validator::fullnode::make_full_node_rate_limiter;
using tos::validator::fullnode::QueryAdmission;
using tos::validator::fullnode::RefusalAnswerBudget;
using tos::validator::fullnode::RefusalAnswerLimits;
using tos::validator::fullnode::ShardQueryAdmission;

const ShardIdFull k_master_shard{masterchainId, shardIdAll};
const ShardIdFull k_base_shard{basechainId, shardIdAll};

adnl::AdnlNodeIdShort source(int n) {
  td::Bits256 bits = td::Bits256::zero();
  bits.data()[0] = static_cast<unsigned char>(n & 0xff);
  bits.data()[1] = static_cast<unsigned char>((n >> 8) & 0xff);
  bits.data()[2] = static_cast<unsigned char>((n >> 16) & 0xff);
  bits.data()[31] = 1;
  return adnl::AdnlNodeIdShort{bits};
}

std::shared_ptr<FullNodeRateLimiter> limiter(size_t global, size_t heavy, size_t medium) {
  return make_full_node_rate_limiter(full_node_rate_limits(1.0, global, heavy, medium));
}

tos_api::object_ptr<tos_api::tosNode_blockIdExt> block(int workchain = basechainId) {
  return create_tl_object<tos_api::tosNode_blockIdExt>(workchain, shardIdAll, 1, td::Bits256::zero(),
                                                       td::Bits256::zero());
}

td::BufferSlice archive_slice(td::int32 max_size) {
  return create_serialize_tl_object<tos_api::tosNode_getArchiveSlice>(1, 0, max_size);
}

td::BufferSlice zero_state() {
  return create_serialize_tl_object<tos_api::tosNode_downloadZeroState>(create_tl_object<tos_api::tosNode_blockIdExt>(
      masterchainId, shardIdAll, 0, td::Bits256::zero(), td::Bits256::zero()));
}

td::BufferSlice block_full() {
  return create_serialize_tl_object<tos_api::tosNode_downloadBlockFull>(block());
}

td::BufferSlice malformed() {
  return td::BufferSlice{"definitely not a tosnode query"};
}

const auto t0 = td::Timestamp::at(1000.0);

td::Timestamp at(double seconds_after_t0) {
  return td::Timestamp::at(t0.at() + seconds_after_t0);
}

bool refused_for_capacity(const QueryAdmission &admission) {
  return admission.outcome() == QueryAdmission::Outcome::refused_for_capacity;
}

// Admit queries from distinct sources until the shard refuses one.
size_t flood(ShardQueryAdmission &admission, int first_source, td::Timestamp t) {
  size_t admitted = 0;
  for (int n = first_source; n < first_source + 64; n++) {
    while (admitted < 1000 && admission.admit(source(n), archive_slice(1 << 21), t).is_admitted()) {
      admitted++;
    }
  }
  return admitted;
}

// Spends `src`'s admission allowance for `query` at `t`; returns how many
// were admitted before the first capacity refusal.
size_t exhaust(ShardQueryAdmission &admission, adnl::AdnlNodeIdShort src, const td::BufferSlice &query,
               td::Timestamp t) {
  for (size_t admitted = 0; admitted < 1000; admitted++) {
    auto result = admission.admit(src, query.clone(), t);
    if (!result.is_admitted()) {
      CHECK(refused_for_capacity(result));
      return admitted;
    }
  }
  UNREACHABLE();
}

// What admit_or_answer settles on the promise, or nothing when the query is
// returned for dispatch.
struct Settled {
  bool dispatched = false;
  std::optional<td::Result<adnl::AdnlQueryAnswer>> answer;
};

Settled settle(ShardQueryAdmission &admission, adnl::AdnlNodeIdShort src, td::BufferSlice query, td::Timestamp t) {
  Settled settled;
  std::optional<td::Result<adnl::AdnlQueryAnswer>> got;
  td::Promise<adnl::AdnlQueryAnswer> promise = [&got](td::Result<adnl::AdnlQueryAnswer> R) { got = std::move(R); };
  auto function = admission.admit_or_answer(src, std::move(query), promise, t);
  settled.dispatched = function != nullptr;
  if (settled.dispatched) {
    promise.set_error(td::Status::Error("dispatched"));
  }
  settled.answer = std::move(got);
  return settled;
}

RefusalAnswerLimits tight_budget(double global_rate, double global_burst, double source_rate, double source_burst,
                                 size_t max_sources = 1024) {
  return RefusalAnswerLimits{global_rate, global_burst, source_rate, source_burst, max_sources};
}

}  // namespace

TEST(ShardQueryAdmission, AdmittedQueryIsReturnedForDispatch) {
  auto shared = limiter(96, 64, 72);
  ShardQueryAdmission admission(shared, k_base_shard);
  admission.start();
  auto R = admission.admit(source(1), archive_slice(1 << 21), t0);
  ASSERT_TRUE(R.is_admitted());
  ASSERT_EQ(tos_api::tosNode_getArchiveSlice::ID, R.function()->get_id());
}

TEST(ShardQueryAdmission, MalformedQueriesAreChargedToTheirSource) {
  // Global 8: each source may hold 2 of it.
  auto shared = limiter(8, 64, 72);
  ShardQueryAdmission admission(shared, k_base_shard);
  admission.start();
  auto first = admission.admit(source(1), malformed(), t0);
  ASSERT_TRUE(first.outcome() == QueryAdmission::Outcome::failed);
  ASSERT_EQ(ErrorCode::protoviolation, first.error().code());
  ASSERT_EQ(ErrorCode::protoviolation, admission.admit(source(1), malformed(), t0).error().code());
  // The third malformed query from the same source exceeds its allowance; it
  // has no parsed form, so it fails rather than being refused for capacity.
  auto third = admission.admit(source(1), malformed(), t0);
  ASSERT_TRUE(third.outcome() == QueryAdmission::Outcome::failed);
  ASSERT_EQ(ErrorCode::failure, third.error().code());
  // A different source has its own allowance.
  ASSERT_EQ(ErrorCode::protoviolation, admission.admit(source(2), malformed(), t0).error().code());
  // The probes used the global window: 8 - 3 = 5 left for well-formed work.
  size_t admitted = flood(admission, 100, t0);
  ASSERT_EQ(5u, admitted);
}

TEST(ShardQueryAdmission, EachSourceIsChargedSeparately) {
  // Heavy 8: each source may hold 2.
  auto shared = limiter(96, 8, 72);
  ShardQueryAdmission admission(shared, k_base_shard);
  admission.start();
  ASSERT_TRUE(admission.admit(source(1), archive_slice(1 << 21), t0).is_admitted());
  ASSERT_TRUE(admission.admit(source(1), archive_slice(1 << 21), t0).is_admitted());
  auto refused = admission.admit(source(1), archive_slice(1 << 21), t0);
  ASSERT_TRUE(refused_for_capacity(refused));
  ASSERT_EQ(tos_api::tosNode_getArchiveSlice::ID, refused.function()->get_id());
  ASSERT_TRUE(admission.admit(source(2), archive_slice(1 << 21), t0).is_admitted());
}

TEST(ShardQueryAdmission, CostFollowsTheClaimedSize) {
  // Heavy 64: each source may hold 16 units, two 16 MiB claims.
  auto shared = limiter(96, 64, 72);
  ShardQueryAdmission admission(shared, k_base_shard);
  admission.start();
  ASSERT_TRUE(admission.admit(source(1), archive_slice(16 << 20), t0).is_admitted());
  ASSERT_TRUE(admission.admit(source(1), archive_slice(16 << 20), t0).is_admitted());
  ASSERT_TRUE(refused_for_capacity(admission.admit(source(1), archive_slice(1 << 21), t0)));
  // A zero state is priced at its full size as well.
  ASSERT_TRUE(admission.admit(source(2), zero_state(), t0).is_admitted());
  ASSERT_TRUE(admission.admit(source(2), zero_state(), t0).is_admitted());
  ASSERT_TRUE(refused_for_capacity(admission.admit(source(2), zero_state(), t0)));
}

TEST(ShardQueryAdmission, EachShardKeepsItsReservation) {
  // Heavy 8: two registered shards reserve 2 each, 4 shared.
  auto shared = limiter(96, 8, 72);
  ShardQueryAdmission master(shared, k_master_shard);
  ShardQueryAdmission base(shared, k_base_shard);
  master.start();
  base.start();
  ASSERT_EQ(6u, flood(base, 100, t0));
  ASSERT_EQ(2u, flood(master, 200, t0));
}

TEST(ShardQueryAdmission, StoppedShardReleasesItsShareAfterItsUsageDrains) {
  // Heavy 12: three shards reserve 2 each, 6 shared.
  auto shared = limiter(96, 12, 72);
  ShardQueryAdmission a(shared, ShardIdFull{basechainId, static_cast<ShardId>(0x4000000000000000ULL)});
  ShardQueryAdmission b(shared, k_master_shard);
  ShardQueryAdmission c(shared, ShardIdFull{basechainId, static_cast<ShardId>(0xc000000000000000ULL)});
  a.start();
  b.start();
  c.start();
  ASSERT_TRUE(a.admit(source(1), archive_slice(1 << 21), t0).is_admitted());
  ASSERT_TRUE(a.admit(source(2), archive_slice(1 << 21), t0).is_admitted());
  a.stop();
  ASSERT_EQ(8u, flood(c, 100, t0));
  ASSERT_EQ(2u, flood(b, 200, t0));
  // A's usage has drained; the reservation is now split two ways.
  auto later = td::Timestamp::at(1001.5);
  ASSERT_EQ(9u, flood(c, 300, later));
  ASSERT_EQ(3u, flood(b, 400, later));
}

TEST(ShardQueryAdmission, WithoutALimiterEverythingIsRefused) {
  ShardQueryAdmission admission(nullptr, k_base_shard, std::make_shared<RefusalAnswerBudget>());
  admission.start();
  auto R = admission.admit(source(1), archive_slice(1 << 21), t0);
  ASSERT_TRUE(R.outcome() == QueryAdmission::Outcome::failed);
  // A missing limiter is not a capacity refusal, so even an answerable type
  // gets the plain error.
  auto settled = settle(admission, source(1), block_full(), t0);
  ASSERT_TRUE(!settled.dispatched);
  ASSERT_TRUE(settled.answer && settled.answer->is_error());
  ASSERT_EQ(ErrorCode::failure, settled.answer->error().code());
}

TEST(ShardQueryAdmission, LimitsThatRefuseMandatoryRequestsAreRejected) {
  // The defaults are accepted.
  ASSERT_TRUE(check_full_node_rate_limits(full_node_rate_limits(1.0, 96, 64, 72)).is_ok());
  // A zero state costs 8 units, so global and heavy need 29 for one source.
  ASSERT_TRUE(check_full_node_rate_limits(full_node_rate_limits(1.0, 29, 29, 1)).is_ok());
  ASSERT_TRUE(check_full_node_rate_limits(full_node_rate_limits(1.0, 29, 28, 1)).is_error());
  ASSERT_TRUE(check_full_node_rate_limits(full_node_rate_limits(1.0, 28, 29, 1)).is_error());
  ASSERT_TRUE(check_full_node_rate_limits(full_node_rate_limits(1.0, 29, 29, 0)).is_error());
  // Disabled windows admit everything.
  ASSERT_TRUE(check_full_node_rate_limits(full_node_rate_limits(0.0, 0, 0, 0)).is_ok());
}

TEST(ShardQueryAdmission, CapacityRefusalIsChargedOnce) {
  // Medium 8: each source may hold 2, the aggregate 8.
  auto shared = limiter(96, 64, 8);
  ShardQueryAdmission admission(shared, k_base_shard, std::make_shared<RefusalAnswerBudget>());
  admission.start();
  ASSERT_EQ(2u, exhaust(admission, source(1), block_full(), t0));
  // Refusals, answered or not, take nothing more from any window.
  for (int i = 0; i < 50; i++) {
    auto settled = settle(admission, source(1), block_full(), t0);
    ASSERT_TRUE(!settled.dispatched);
  }
  ASSERT_EQ(2u, exhaust(admission, source(2), block_full(), t0));
  ASSERT_EQ(2u, exhaust(admission, source(3), block_full(), t0));
  ASSERT_EQ(2u, exhaust(admission, source(4), block_full(), t0));
  ASSERT_EQ(0u, exhaust(admission, source(5), block_full(), t0));
}

TEST(ShardQueryAdmission, AnswerableRefusalsGetTheirTypesEmptyReply) {
  struct Case {
    td::BufferSlice query;
    td::int32 answer_id;
  };
  std::vector<Case> cases;
  cases.push_back({block_full(), tos_api::tosNode_dataFullEmpty::ID});
  cases.push_back({create_serialize_tl_object<tos_api::tosNode_downloadNextBlockFull>(block(masterchainId)),
                   tos_api::tosNode_dataFullEmpty::ID});
  cases.push_back({create_serialize_tl_object<tos_api::tosNode_downloadNextBlocksFull>(block(masterchainId), 10),
                   tos_api::tosNode_nextBlocksFull::ID});
  cases.push_back({create_serialize_tl_object<tos_api::tosNode_prepareBlock>(block()), tos_api::tosNode_notFound::ID});
  cases.push_back({create_serialize_tl_object<tos_api::tosNode_prepareBlockProof>(block(), true),
                   tos_api::tosNode_preparedProofEmpty::ID});
  cases.push_back({create_serialize_tl_object<tos_api::tosNode_prepareKeyBlockProof>(block(masterchainId), false),
                   tos_api::tosNode_preparedProofEmpty::ID});
  cases.push_back({create_serialize_tl_object<tos_api::tosNode_preparePersistentState>(block(), block(masterchainId)),
                   tos_api::tosNode_notFoundState::ID});
  cases.push_back(
      {create_serialize_tl_object<tos_api::tosNode_prepareZeroState>(block()), tos_api::tosNode_notFoundState::ID});

  int n = 1;
  for (auto &c : cases) {
    auto shared = limiter(96, 64, 72);
    auto budget = std::make_shared<RefusalAnswerBudget>(default_refusal_answer_limits(), t0);
    ShardQueryAdmission admission(shared, k_base_shard, budget);
    admission.start();
    auto src = source(n++);
    exhaust(admission, src, c.query, t0);
    auto settled = settle(admission, src, c.query.clone(), t0);
    ASSERT_TRUE(!settled.dispatched);
    ASSERT_TRUE(settled.answer && settled.answer->is_ok());
    auto answered = settled.answer->move_as_ok();
    // The answer may stay in the transport for the refusal lifetime from the
    // admission's own clock, an absolute deadline.
    ASSERT_EQ(t0.at() + k_refusal_answer_lifetime, answered.delivery_deadline.at());
    auto answer = std::move(answered.data);
    ASSERT_EQ(c.answer_id, *reinterpret_cast<const td::int32 *>(answer.as_slice().data()));
    ASSERT_EQ(1u, budget->answered());
    // The bytes are exactly what the type's own handler sends when it has
    // nothing, and they parse as the query's result type.
    switch (c.answer_id) {
      case tos_api::tosNode_dataFullEmpty::ID:
        ASSERT_TRUE(fetch_tl_object<tos_api::tosNode_DataFull>(answer.clone(), true).is_ok());
        break;
      case tos_api::tosNode_nextBlocksFull::ID: {
        auto parsed = fetch_tl_object<tos_api::tosNode_nextBlocksFull>(answer.clone(), true);
        ASSERT_TRUE(parsed.is_ok());
        ASSERT_TRUE(parsed.ok()->blocks_.empty());
        break;
      }
      case tos_api::tosNode_notFound::ID:
        ASSERT_TRUE(fetch_tl_object<tos_api::tosNode_Prepared>(answer.clone(), true).is_ok());
        break;
      case tos_api::tosNode_preparedProofEmpty::ID:
        ASSERT_TRUE(fetch_tl_object<tos_api::tosNode_PreparedProof>(answer.clone(), true).is_ok());
        break;
      case tos_api::tosNode_notFoundState::ID:
        ASSERT_TRUE(fetch_tl_object<tos_api::tosNode_PreparedState>(answer.clone(), true).is_ok());
        break;
      default:
        UNREACHABLE();
    }
  }
}

TEST(ShardQueryAdmission, OtherRefusalsStaySilent) {
  // Types with no empty reply, or no handler, are never answered.
  for (td::int32 id : {tos_api::tosNode_downloadBlock::ID, tos_api::tosNode_downloadBlockProof::ID,
                       tos_api::tosNode_downloadBlockProofLink::ID, tos_api::tosNode_downloadKeyBlockProof::ID,
                       tos_api::tosNode_downloadKeyBlockProofLink::ID, tos_api::tosNode_getArchiveSlice::ID,
                       tos_api::tosNode_getArchiveInfo::ID, tos_api::tosNode_getShardArchiveInfo::ID,
                       tos_api::tosNode_downloadPersistentStateSliceV2::ID,
                       tos_api::tosNode_getPersistentStateSizeV2::ID, tos_api::tosNode_downloadZeroState::ID,
                       tos_api::tosNode_getOutMsgQueueProof::ID, tos_api::tosNode_getNextBlockDescription::ID,
                       tos_api::tosNode_getNextKeyBlockIds::ID, tos_api::tosNode_prepareBlocks::ID,
                       tos_api::tosNode_prepareBlockProofs::ID, tos_api::tosNode_prepareKeyBlockProofs::ID}) {
    ASSERT_TRUE(!capacity_refusal_answer(id).has_value());
  }

  auto shared = limiter(96, 64, 72);
  auto budget = std::make_shared<RefusalAnswerBudget>(default_refusal_answer_limits(), t0);
  ShardQueryAdmission admission(shared, k_base_shard, budget);
  admission.start();
  std::vector<td::BufferSlice> queries;
  queries.push_back(create_serialize_tl_object<tos_api::tosNode_downloadBlock>(block()));
  queries.push_back(create_serialize_tl_object<tos_api::tosNode_downloadBlockProof>(block()));
  queries.push_back(create_serialize_tl_object<tos_api::tosNode_downloadKeyBlockProofLink>(block(masterchainId)));
  queries.push_back(archive_slice(1 << 21));
  queries.push_back(create_serialize_tl_object<tos_api::tosNode_getOutMsgQueueProof>(
      create_tl_object<tos_api::tosNode_shardId>(basechainId, static_cast<td::int64>(shardIdAll)),
      std::vector<tos_api::object_ptr<tos_api::tosNode_blockIdExt>>{},
      create_tl_object<tos_api::tosNode_importedMsgQueueLimits>(1, 1)));
  int n = 100;
  for (auto &query : queries) {
    auto src = source(n++);
    exhaust(admission, src, query, t0);
    auto settled = settle(admission, src, query.clone(), t0);
    ASSERT_TRUE(!settled.dispatched);
    ASSERT_TRUE(settled.answer && settled.answer->is_error());
    ASSERT_EQ(ErrorCode::failure, settled.answer->error().code());
  }
  // None of them touched the answer budget.
  ASSERT_EQ(0u, budget->answered());
  ASSERT_EQ(0u, budget->suppressed());
}

TEST(RefusalAnswerBudget, DefaultsAreTwiceTheDefaultAdmissionRates) {
  auto limits = default_refusal_answer_limits();
  ASSERT_EQ(1.0, k_default_ratelimit_window_size);
  ASSERT_EQ(96u, k_default_ratelimit_global);
  ASSERT_EQ(192.0, limits.global_rate);
  ASSERT_EQ(96.0, limits.global_burst);
  ASSERT_EQ(48.0, limits.source_rate);
  ASSERT_EQ(24.0, limits.source_burst);
  // An answer may stay in the transport this long.
  ASSERT_EQ(3.0, k_refusal_answer_lifetime);
}

TEST(RefusalAnswerBudget, EachSourceGetsItsBurst) {
  RefusalAnswerBudget budget(default_refusal_answer_limits(), t0);
  for (int i = 0; i < 24; i++) {
    ASSERT_TRUE(budget.try_take(source(1), t0));
  }
  ASSERT_TRUE(!budget.try_take(source(1), t0));
  ASSERT_TRUE(budget.try_take(source(2), t0));
  ASSERT_EQ(25u, budget.answered());
  ASSERT_EQ(1u, budget.suppressed());
}

TEST(RefusalAnswerBudget, GlobalBudgetIsSharedAcrossShards) {
  auto shared = limiter(96, 64, 4);
  auto budget = std::make_shared<RefusalAnswerBudget>(default_refusal_answer_limits(), t0);
  ShardQueryAdmission master(shared, k_master_shard, budget);
  ShardQueryAdmission base(shared, k_base_shard, budget);
  master.start();
  base.start();
  auto master_query = create_serialize_tl_object<tos_api::tosNode_downloadBlockFull>(block(masterchainId));
  auto base_query = block_full();
  // Spend every source's admission first so that each query below is a
  // capacity refusal.
  for (int n = 1; n <= 10; n++) {
    exhaust(master, source(n), master_query, t0);
    exhaust(base, source(n), base_query, t0);
  }
  size_t answered = 0;
  size_t silent = 0;
  for (int round = 0; round < 12; round++) {
    for (int n = 1; n <= 10; n++) {
      auto &admission = (n % 2) ? master : base;
      auto &query = (n % 2) ? master_query : base_query;
      auto settled = settle(admission, source(n), query.clone(), t0);
      ASSERT_TRUE(!settled.dispatched);
      if (settled.answer->is_ok()) {
        answered++;
      } else {
        ASSERT_EQ(ErrorCode::failure, settled.answer->error().code());
        silent++;
      }
    }
  }
  // 120 refusals across both shards: one global burst of 96 is answered, the
  // rest are silent and counted.
  ASSERT_EQ(96u, answered);
  ASSERT_EQ(24u, silent);
  ASSERT_EQ(96u, budget->answered());
  ASSERT_EQ(24u, budget->suppressed());
}

TEST(RefusalAnswerBudget, RefillBoundaries) {
  RefusalAnswerBudget budget(default_refusal_answer_limits(), t0);
  for (int i = 0; i < 24; i++) {
    ASSERT_TRUE(budget.try_take(source(1), t0));
  }
  // A source refills at 48 a second: one answer per 1/48 s.
  ASSERT_TRUE(!budget.try_take(source(1), at(0.9 / 48)));
  ASSERT_TRUE(budget.try_take(source(1), at(1.01 / 48)));
  ASSERT_TRUE(!budget.try_take(source(1), at(1.5 / 48)));

  // The global bucket: spend the rest of its burst through fresh sources,
  // then it refills at 192 a second.
  RefusalAnswerBudget global(default_refusal_answer_limits(), t0);
  for (int n = 0; n < 96; n++) {
    ASSERT_TRUE(global.try_take(source(1000 + n), t0));
  }
  ASSERT_TRUE(!global.try_take(source(2000), t0));
  ASSERT_TRUE(!global.try_take(source(2001), at(0.9 / 192)));
  ASSERT_TRUE(global.try_take(source(2002), at(1.01 / 192)));
  ASSERT_TRUE(!global.try_take(source(2003), at(1.5 / 192)));
  // A long idle period refills to the burst, not beyond it.
  size_t after_idle = 0;
  for (int n = 0; n < 200; n++) {
    after_idle += global.try_take(source(3000 + n), at(1000.0)) ? 1 : 0;
  }
  ASSERT_EQ(96u, after_idle);
}

TEST(RefusalAnswerBudget, SourceChurnIsBounded) {
  RefusalAnswerBudget budget(default_refusal_answer_limits(), t0);
  // A new source every millisecond for 100 s: the per-source entries expire
  // once their buckets are full again, so tracking stays small.
  size_t most = 0;
  for (int i = 0; i < 100000; i++) {
    auto now = at(i * 0.001);
    budget.try_take(source(i), now);
    if (i % 997 == 0) {
      most = std::max(most, budget.tracked_sources(now));
    }
  }
  ASSERT_TRUE(most <= 64);
  ASSERT_EQ(0u, budget.tracked_sources(at(200.0)));

  // The hard cap: with slow refill nothing expires, so a new source past the
  // cap is not tracked and its refusal stays silent.
  RefusalAnswerBudget capped(tight_budget(1000.0, 1000.0, 0.001, 2.0, 4), t0);
  for (int n = 0; n < 4; n++) {
    ASSERT_TRUE(capped.try_take(source(n), t0));
  }
  ASSERT_EQ(4u, capped.tracked_sources(t0));
  ASSERT_TRUE(!capped.try_take(source(99), t0));
  ASSERT_EQ(4u, capped.tracked_sources(t0));
  // Sources already tracked keep their own budget.
  ASSERT_TRUE(capped.try_take(source(0), t0));
}

TEST(RefusalAnswerBudget, LooserAdmissionDoesNotLoosenTheBudget) {
  // A node configured with a far larger allowance still answers at most one
  // default burst at once.
  auto shared = limiter(100000, 100000, 8);
  auto budget = std::make_shared<RefusalAnswerBudget>(default_refusal_answer_limits(), t0);
  ShardQueryAdmission admission(shared, k_base_shard, budget);
  admission.start();
  size_t answered = 0;
  for (int n = 0; n < 50; n++) {
    exhaust(admission, source(n), block_full(), t0);
    for (int i = 0; i < 10; i++) {
      auto settled = settle(admission, source(n), block_full(), t0);
      answered += settled.answer->is_ok() ? 1 : 0;
    }
  }
  ASSERT_EQ(96u, answered);
}
