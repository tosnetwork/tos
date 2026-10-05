/*
 * Copyright (c) 2026, TOS Blockchain Teams
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
// The admission step every full-node shard runs on an overlay query before
// dispatching it: registration of the shard, parsing, pricing, charging the
// actual source and shard, and refusal before dispatch. Two shards share one
// limiter built with the production request categories.

#include <memory>
#include <string>

#include "auto/tl/tos_api.h"
#include "td/utils/tests.h"
#include "tl-utils/common-utils.hpp"
#include "validator/full-node-shard-admission.h"

namespace {

using namespace tos;
using tos::validator::fullnode::check_full_node_rate_limits;
using tos::validator::fullnode::full_node_rate_limits;
using tos::validator::fullnode::FullNodeRateLimiter;
using tos::validator::fullnode::make_full_node_rate_limiter;
using tos::validator::fullnode::ShardQueryAdmission;

const ShardIdFull k_master_shard{masterchainId, shardIdAll};
const ShardIdFull k_base_shard{basechainId, shardIdAll};

adnl::AdnlNodeIdShort source(int n) {
  td::Bits256 bits = td::Bits256::zero();
  bits.data()[0] = static_cast<unsigned char>(n & 0xff);
  bits.data()[1] = static_cast<unsigned char>((n >> 8) & 0xff);
  bits.data()[31] = 1;
  return adnl::AdnlNodeIdShort{bits};
}

std::shared_ptr<FullNodeRateLimiter> limiter(size_t global, size_t heavy, size_t medium) {
  return make_full_node_rate_limiter(full_node_rate_limits(1.0, global, heavy, medium));
}

td::BufferSlice archive_slice(td::int32 max_size) {
  return create_serialize_tl_object<tos_api::tosNode_getArchiveSlice>(1, 0, max_size);
}

td::BufferSlice zero_state() {
  return create_serialize_tl_object<tos_api::tosNode_downloadZeroState>(create_tl_object<tos_api::tosNode_blockIdExt>(
      masterchainId, shardIdAll, 0, td::Bits256::zero(), td::Bits256::zero()));
}

td::BufferSlice malformed() {
  return td::BufferSlice{"definitely not a tosnode query"};
}

const auto t0 = td::Timestamp::at(1000.0);

// Admit queries from distinct sources until the shard refuses one.
size_t flood(ShardQueryAdmission &admission, int first_source, td::Timestamp t) {
  size_t admitted = 0;
  for (int n = first_source; n < first_source + 64; n++) {
    while (admitted < 1000 && admission.admit(source(n), archive_slice(1 << 21), t).is_ok()) {
      admitted++;
    }
  }
  return admitted;
}

}  // namespace

TEST(ShardQueryAdmission, AdmittedQueryIsReturnedForDispatch) {
  auto shared = limiter(96, 64, 72);
  ShardQueryAdmission admission(shared, k_base_shard);
  admission.start();
  auto R = admission.admit(source(1), archive_slice(1 << 21), t0);
  ASSERT_TRUE(R.is_ok());
  ASSERT_EQ(tos_api::tosNode_getArchiveSlice::ID, R.ok()->get_id());
}

TEST(ShardQueryAdmission, MalformedQueriesAreChargedToTheirSource) {
  // Global 8: each source may hold 2 of it.
  auto shared = limiter(8, 64, 72);
  ShardQueryAdmission admission(shared, k_base_shard);
  admission.start();
  auto first = admission.admit(source(1), malformed(), t0);
  ASSERT_TRUE(first.is_error());
  ASSERT_EQ(ErrorCode::protoviolation, first.error().code());
  ASSERT_EQ(ErrorCode::protoviolation, admission.admit(source(1), malformed(), t0).error().code());
  // The third malformed query from the same source exceeds its allowance.
  ASSERT_EQ(ErrorCode::failure, admission.admit(source(1), malformed(), t0).error().code());
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
  ASSERT_TRUE(admission.admit(source(1), archive_slice(1 << 21), t0).is_ok());
  ASSERT_TRUE(admission.admit(source(1), archive_slice(1 << 21), t0).is_ok());
  auto refused = admission.admit(source(1), archive_slice(1 << 21), t0);
  ASSERT_TRUE(refused.is_error());
  ASSERT_EQ(ErrorCode::failure, refused.error().code());
  ASSERT_TRUE(admission.admit(source(2), archive_slice(1 << 21), t0).is_ok());
}

TEST(ShardQueryAdmission, CostFollowsTheClaimedSize) {
  // Heavy 64: each source may hold 16 units, two 16 MiB claims.
  auto shared = limiter(96, 64, 72);
  ShardQueryAdmission admission(shared, k_base_shard);
  admission.start();
  ASSERT_TRUE(admission.admit(source(1), archive_slice(16 << 20), t0).is_ok());
  ASSERT_TRUE(admission.admit(source(1), archive_slice(16 << 20), t0).is_ok());
  ASSERT_TRUE(admission.admit(source(1), archive_slice(1 << 21), t0).is_error());
  // A zero state is priced at its full size as well.
  ASSERT_TRUE(admission.admit(source(2), zero_state(), t0).is_ok());
  ASSERT_TRUE(admission.admit(source(2), zero_state(), t0).is_ok());
  ASSERT_TRUE(admission.admit(source(2), zero_state(), t0).is_error());
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
  ASSERT_TRUE(a.admit(source(1), archive_slice(1 << 21), t0).is_ok());
  ASSERT_TRUE(a.admit(source(2), archive_slice(1 << 21), t0).is_ok());
  a.stop();
  ASSERT_EQ(8u, flood(c, 100, t0));
  ASSERT_EQ(2u, flood(b, 200, t0));
  // A's usage has drained; the reservation is now split two ways.
  auto later = td::Timestamp::at(1001.5);
  ASSERT_EQ(9u, flood(c, 300, later));
  ASSERT_EQ(3u, flood(b, 400, later));
}

TEST(ShardQueryAdmission, WithoutALimiterEverythingIsRefused) {
  ShardQueryAdmission admission(nullptr, k_base_shard);
  admission.start();
  ASSERT_TRUE(admission.admit(source(1), archive_slice(1 << 21), t0).is_error());
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
