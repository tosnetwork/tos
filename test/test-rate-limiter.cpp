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

#include <algorithm>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "td/utils/tests.h"
#include "validator/full-node-master-limiter.h"
#include "validator/rate-limiter.h"

namespace {

using tos::validator::fullnode::RateLimit;
using tos::validator::fullnode::RateLimiter;

constexpr int32_t k_heavy_a = 101;
constexpr int32_t k_heavy_b = 102;
constexpr int32_t k_medium_a = 201;
constexpr int32_t k_medium_b = 202;
constexpr int32_t k_small_a = 301;
constexpr int32_t k_small_b = 302;
constexpr int32_t k_unlisted = 999;

std::unique_ptr<RateLimiter<>> make_limiter(size_t global, size_t heavy, size_t medium, size_t small) {
  double w = 1.0;
  return std::make_unique<RateLimiter<>>(RateLimit{w, global}, RateLimit{w, heavy}, std::set{k_heavy_a, k_heavy_b},
                                         RateLimit{w, medium}, std::set{k_medium_a, k_medium_b}, RateLimit{w, small},
                                         std::set{k_small_a, k_small_b});
}

}  // namespace

TEST(RateLimiter, CategoryWindowIsShared) {
  // Alternating between different request types in the same category must not
  // multiply the category budget.
  auto limiter = make_limiter(/* global = */ 100, /* heavy = */ 4, /* medium = */ 100, /* small = */ 100);
  auto t = td::Timestamp::at(1000.0);
  ASSERT_TRUE(limiter->check_in(k_heavy_a, 1, t));
  ASSERT_TRUE(limiter->check_in(k_heavy_b, 1, t));
  ASSERT_TRUE(limiter->check_in(k_heavy_a, 1, t));
  ASSERT_TRUE(limiter->check_in(k_heavy_b, 1, t));
  // The category is exhausted for every request type in it.
  ASSERT_TRUE(!limiter->check_in(k_heavy_a, 1, t));
  ASSERT_TRUE(!limiter->check_in(k_heavy_b, 1, t));
  // Other categories are unaffected.
  ASSERT_TRUE(limiter->check_in(k_medium_a, 1, t));
  ASSERT_TRUE(limiter->check_in(k_small_a, 1, t));
}

TEST(RateLimiter, HeavyExhaustsWindowByCost) {
  auto limiter = make_limiter(/* global = */ 100, /* heavy = */ 8, /* medium = */ 100, /* small = */ 100);
  auto t = td::Timestamp::at(1000.0);
  ASSERT_TRUE(limiter->check_in(k_heavy_a, 5, t));
  // Remaining capacity is 3, so a cost-5 request must be rejected...
  ASSERT_TRUE(!limiter->check_in(k_heavy_b, 5, t));
  // ...while a cost-3 request still fits.
  ASSERT_TRUE(limiter->check_in(k_heavy_b, 3, t));
  ASSERT_TRUE(!limiter->check_in(k_heavy_a, 1, t));
}

TEST(RateLimiter, SmallBypassesGlobalWindow) {
  auto limiter = make_limiter(/* global = */ 2, /* heavy = */ 100, /* medium = */ 100, /* small = */ 5);
  auto t = td::Timestamp::at(1000.0);
  // Exhaust the global window with medium requests.
  ASSERT_TRUE(limiter->check_in(k_medium_a, 1, t));
  ASSERT_TRUE(limiter->check_in(k_medium_b, 1, t));
  ASSERT_TRUE(!limiter->check_in(k_medium_a, 1, t));
  ASSERT_TRUE(!limiter->check_in(k_heavy_a, 1, t));
  // Small requests do not consume and are not blocked by the global window,
  // but their own category window still applies.
  for (int i = 0; i < 5; i++) {
    ASSERT_TRUE(limiter->check_in(k_small_a, 1, t));
  }
  ASSERT_TRUE(!limiter->check_in(k_small_a, 1, t));
  ASSERT_TRUE(!limiter->check_in(k_small_b, 1, t));
}

TEST(RateLimiter, GlobalWindowCapsAcrossCategories) {
  auto limiter = make_limiter(/* global = */ 3, /* heavy = */ 100, /* medium = */ 100, /* small = */ 100);
  auto t = td::Timestamp::at(1000.0);
  ASSERT_TRUE(limiter->check_in(k_heavy_a, 1, t));
  ASSERT_TRUE(limiter->check_in(k_medium_a, 1, t));
  ASSERT_TRUE(limiter->check_in(k_heavy_b, 1, t));
  ASSERT_TRUE(!limiter->check_in(k_medium_b, 1, t));
  ASSERT_TRUE(!limiter->check_in(k_heavy_a, 1, t));
}

TEST(RateLimiter, UnlistedRequestIsNotLimited) {
  auto limiter = make_limiter(/* global = */ 1, /* heavy = */ 1, /* medium = */ 1, /* small = */ 1);
  auto t = td::Timestamp::at(1000.0);
  ASSERT_TRUE(limiter->check_in(k_heavy_a, 1, t));
  ASSERT_TRUE(!limiter->check_in(k_heavy_a, 1, t));
  // A request outside every category (e.g. a capability probe) passes freely.
  for (int i = 0; i < 10; i++) {
    ASSERT_TRUE(limiter->check_in(k_unlisted, 1, t));
  }
}

TEST(RateLimiter, WindowSlides) {
  auto limiter = make_limiter(/* global = */ 100, /* heavy = */ 2, /* medium = */ 100, /* small = */ 100);
  auto t = td::Timestamp::at(1000.0);
  ASSERT_TRUE(limiter->check_in(k_heavy_a, 2, t));
  ASSERT_TRUE(!limiter->check_in(k_heavy_a, 1, t));
  // After the window duration has elapsed the budget is available again.
  auto later = td::Timestamp::at(1001.5);
  ASSERT_TRUE(limiter->check_in(k_heavy_b, 2, later));
  ASSERT_TRUE(!limiter->check_in(k_heavy_a, 1, later));
}

TEST(RateLimiter, ZeroCostCountsAsOne) {
  auto limiter = make_limiter(/* global = */ 100, /* heavy = */ 2, /* medium = */ 100, /* small = */ 100);
  auto t = td::Timestamp::at(1000.0);
  ASSERT_TRUE(limiter->check_in(k_heavy_a, 0, t));
  ASSERT_TRUE(limiter->check_in(k_heavy_a, 0, t));
  ASSERT_TRUE(!limiter->check_in(k_heavy_a, 0, t));
}

// ---------------------------------------------------------------------------
// Source- and shard-aware full-node overlay admission.

namespace {

using tos::validator::fullnode::SourceAwareRateLimiter;
using ShardAwareLimiter = SourceAwareRateLimiter<int32_t, int, int>;

constexpr int k_shard_a = 1;
constexpr int k_shard_b = 2;

std::unique_ptr<ShardAwareLimiter> make_source_limiter(size_t global, size_t heavy, size_t medium, size_t small) {
  double w = 1.0;
  return std::make_unique<ShardAwareLimiter>(RateLimit{w, global}, RateLimit{w, heavy}, std::set{k_heavy_a, k_heavy_b},
                                             RateLimit{w, medium}, std::set{k_medium_a, k_medium_b},
                                             RateLimit{w, small}, std::set{k_small_a, k_small_b});
}

size_t admit_until_refused(ShardAwareLimiter &limiter, int32_t request, size_t cost, int shard, int source,
                           td::Timestamp t) {
  size_t admitted = 0;
  while (admitted < 1000 && limiter.check_in(request, cost, shard, source, t)) {
    admitted++;
  }
  return admitted;
}

size_t flood_from_many_sources(ShardAwareLimiter &limiter, int32_t request, int shard, int first_source,
                               td::Timestamp t) {
  size_t admitted = 0;
  for (int source = first_source; source < first_source + 50; source++) {
    admitted += admit_until_refused(limiter, request, 1, shard, source, t);
  }
  return admitted;
}

}  // namespace

TEST(SourceAwareRateLimiter, OneSourceHoldsAtMostAQuarterOfEachWindow) {
  auto limiter = make_source_limiter(/* global = */ 100, /* heavy = */ 10, /* medium = */ 100, /* small = */ 100);
  limiter->register_shard(k_shard_a);
  auto t = td::Timestamp::at(1000.0);
  // A quarter of 10, rounded up, is 3.
  ASSERT_EQ(3u, admit_until_refused(*limiter, k_heavy_a, 1, k_shard_a, /* source = */ 7, t));
  // Rotating the request type or the shard does not reset the source's share.
  ASSERT_TRUE(!limiter->check_in(k_heavy_b, 1, k_shard_a, 7, t));
  ASSERT_TRUE(!limiter->check_in(k_heavy_a, 1, k_shard_b, 7, t));
  // The rest of the window still serves other sources.
  ASSERT_EQ(3u, admit_until_refused(*limiter, k_heavy_a, 1, k_shard_a, /* source = */ 8, t));
}

TEST(SourceAwareRateLimiter, ClaimedSizeProbesOnlyBurnTheProbersAllowance) {
  // One peer asks for oversized or missing resources in a loop; the cost is
  // priced from its claim before any lookup. It must not consume the heavy
  // budget another peer on another shard relies on. Production defaults.
  auto limiter = make_source_limiter(/* global = */ 96, /* heavy = */ 64, /* medium = */ 72, /* small = */ 200);
  limiter->register_shard(k_shard_a);
  limiter->register_shard(k_shard_b);
  constexpr int k_attacker = 66;
  constexpr int k_honest = 1;
  size_t burned = 0;
  for (int step = 0; step < 1000; step++) {
    auto t = td::Timestamp::at(1000.0 + step * 0.001);
    if (limiter->check_in(k_heavy_a, 8, k_shard_a, k_attacker, t)) {
      burned += 8;
    }
    // A claim larger than the source's whole share is refused outright.
    ASSERT_TRUE(!limiter->check_in(k_heavy_a, 64, k_shard_a, k_attacker, t));
  }
  ASSERT_EQ(16u, burned);
  auto t = td::Timestamp::at(1000.999);
  // An honest peer on the other shard still gets its whole quarter.
  ASSERT_EQ(16u, admit_until_refused(*limiter, k_heavy_a, 1, k_shard_b, k_honest, t));
}

TEST(SourceAwareRateLimiter, ShardReservationSurvivesAFloodThroughAnotherShard) {
  auto limiter = make_source_limiter(/* global = */ 100, /* heavy = */ 8, /* medium = */ 100, /* small = */ 100);
  limiter->register_shard(k_shard_a);
  limiter->register_shard(k_shard_b);
  auto t = td::Timestamp::at(1000.0);
  // Many identities flood through shard A. Half of 8 is reserved, so A gets
  // its own 2 plus the shared 4, and no more.
  ASSERT_EQ(6u, flood_from_many_sources(*limiter, k_heavy_a, k_shard_a, 100, t));
  // Shard B's reserved part is untouched.
  ASSERT_EQ(2u, admit_until_refused(*limiter, k_heavy_a, 1, k_shard_b, /* source = */ 1, t));
  ASSERT_TRUE(!limiter->check_in(k_heavy_a, 1, k_shard_b, /* source = */ 2, t));
}

TEST(SourceAwareRateLimiter, UnregisteredShardOnlyUsesTheSharedHalf) {
  auto limiter = make_source_limiter(/* global = */ 100, /* heavy = */ 8, /* medium = */ 100, /* small = */ 100);
  limiter->register_shard(k_shard_a);
  auto t = td::Timestamp::at(1000.0);
  ASSERT_EQ(4u, flood_from_many_sources(*limiter, k_heavy_a, k_shard_b, 100, t));
  ASSERT_EQ(2u, admit_until_refused(*limiter, k_heavy_a, 1, k_shard_a, /* source = */ 1, t));
}

TEST(SourceAwareRateLimiter, AggregateWindowStaysAHardCeilingAcrossReregistration) {
  auto limiter = make_source_limiter(/* global = */ 100, /* heavy = */ 8, /* medium = */ 100, /* small = */ 100);
  limiter->register_shard(k_shard_a);
  auto t = td::Timestamp::at(1000.0);
  ASSERT_EQ(8u, flood_from_many_sources(*limiter, k_heavy_a, k_shard_a, 100, t));
  // Dropping and re-adding the shard forgets its reserved usage, but not the
  // aggregate usage, so no fresh budget appears inside the window.
  limiter->unregister_shard(k_shard_a);
  limiter->register_shard(k_shard_a);
  ASSERT_TRUE(!limiter->check_in(k_heavy_a, 1, k_shard_a, /* source = */ 200, t));
  // A new shard gets its share of the reservation, not extra capacity.
  limiter->register_shard(k_shard_b);
  ASSERT_TRUE(!limiter->check_in(k_heavy_a, 1, k_shard_b, /* source = */ 201, t));
}

TEST(SourceAwareRateLimiter, ShardRegistrationIsCounted) {
  auto limiter = make_source_limiter(/* global = */ 100, /* heavy = */ 8, /* medium = */ 100, /* small = */ 100);
  limiter->register_shard(k_shard_a);
  limiter->register_shard(k_shard_a);
  limiter->register_shard(k_shard_b);
  limiter->unregister_shard(k_shard_a);
  auto t = td::Timestamp::at(1000.0);
  // Shard A is still registered once, so a flood through B leaves A its 2.
  ASSERT_EQ(6u, flood_from_many_sources(*limiter, k_heavy_a, k_shard_b, 100, t));
  ASSERT_EQ(2u, admit_until_refused(*limiter, k_heavy_a, 1, k_shard_a, /* source = */ 1, t));
}

TEST(SourceAwareRateLimiter, ReregistrationCannotTakeAnotherShardsReservation) {
  // Heavy ceiling 8: shards A and B reserve 2 each, 4 are shared.
  auto limiter = make_source_limiter(/* global = */ 100, /* heavy = */ 8, /* medium = */ 100, /* small = */ 100);
  limiter->register_shard(k_shard_a);
  limiter->register_shard(k_shard_b);
  auto t = td::Timestamp::at(1000.0);
  ASSERT_EQ(6u, flood_from_many_sources(*limiter, k_heavy_a, k_shard_a, 100, t));
  // A leaves and comes back inside the window: its earlier usage comes back
  // with it rather than a fresh reservation.
  limiter->unregister_shard(k_shard_a);
  limiter->register_shard(k_shard_a);
  ASSERT_EQ(0u, flood_from_many_sources(*limiter, k_heavy_a, k_shard_a, 200, t));
  // B keeps the 2 it was promised.
  ASSERT_EQ(2u, flood_from_many_sources(*limiter, k_heavy_a, k_shard_b, 300, t));
}

TEST(SourceAwareRateLimiter, DepartedShardOnlyUsesTheSharedHalf) {
  auto limiter = make_source_limiter(/* global = */ 100, /* heavy = */ 8, /* medium = */ 100, /* small = */ 100);
  limiter->register_shard(k_shard_a);
  limiter->register_shard(k_shard_b);
  auto t = td::Timestamp::at(1000.0);
  // A uses one of its two reserved units, then departs.
  ASSERT_TRUE(limiter->check_in(k_heavy_a, 1, k_shard_a, /* source = */ 1, t));
  limiter->unregister_shard(k_shard_a);
  // Late traffic through A gets only the shared 4, not A's leftover unit.
  ASSERT_EQ(4u, flood_from_many_sources(*limiter, k_heavy_a, k_shard_a, 100, t));
  ASSERT_EQ(2u, flood_from_many_sources(*limiter, k_heavy_a, k_shard_b, 200, t));
}

TEST(SourceAwareRateLimiter, ShardRemovalDoesNotRedistributeConsumedCapacity) {
  // Heavy ceiling 12: shards A, B and C reserve 2 each, 6 are shared.
  auto limiter = make_source_limiter(/* global = */ 100, /* heavy = */ 12, /* medium = */ 100, /* small = */ 100);
  limiter->register_shard(k_shard_a);
  limiter->register_shard(k_shard_b);
  constexpr int k_shard_c = 3;
  limiter->register_shard(k_shard_c);
  auto t = td::Timestamp::at(1000.0);
  // A uses exactly its reservation, then departs while that usage is live.
  ASSERT_TRUE(limiter->check_in(k_heavy_a, 1, k_shard_a, /* source = */ 1, t));
  ASSERT_TRUE(limiter->check_in(k_heavy_a, 1, k_shard_a, /* source = */ 2, t));
  limiter->unregister_shard(k_shard_a);
  // C floods first. Its share stays 2 while A's usage is outstanding, so it
  // takes its 2 plus the shared 6...
  ASSERT_EQ(8u, flood_from_many_sources(*limiter, k_heavy_a, k_shard_c, 100, t));
  // ...and B, which never changed, still gets the 2 it was promised.
  ASSERT_EQ(2u, flood_from_many_sources(*limiter, k_heavy_a, k_shard_b, 200, t));
  ASSERT_EQ(3u, limiter->tracked_shards(t));
  // Once A's usage has drained, it stops counting and the reservation is
  // split between the two remaining shards.
  auto later = td::Timestamp::at(1001.5);
  ASSERT_EQ(2u, limiter->tracked_shards(later));
  ASSERT_EQ(9u, flood_from_many_sources(*limiter, k_heavy_a, k_shard_c, 300, later));
  ASSERT_EQ(3u, flood_from_many_sources(*limiter, k_heavy_a, k_shard_b, 400, later));
}

TEST(SourceAwareRateLimiter, NewShardsShareIsAvailableWithinOneWindow) {
  auto limiter = make_source_limiter(/* global = */ 100, /* heavy = */ 8, /* medium = */ 100, /* small = */ 100);
  limiter->register_shard(k_shard_a);
  auto t = td::Timestamp::at(1000.0);
  ASSERT_EQ(8u, flood_from_many_sources(*limiter, k_heavy_a, k_shard_a, 100, t));
  // B joins while A's usage, admitted under the larger share, is live; the
  // aggregate ceiling holds and B waits.
  limiter->register_shard(k_shard_b);
  ASSERT_EQ(0u, flood_from_many_sources(*limiter, k_heavy_a, k_shard_b, 200, t));
  // One window later, B's share holds against A flooding first.
  auto later = td::Timestamp::at(1001.5);
  ASSERT_EQ(6u, flood_from_many_sources(*limiter, k_heavy_a, k_shard_a, 300, later));
  ASSERT_EQ(2u, flood_from_many_sources(*limiter, k_heavy_a, k_shard_b, 400, later));
}

TEST(SourceAwareRateLimiter, WindowMustAdmitOneMandatoryRequestPerSource) {
  // A source holds a quarter, rounded up: 29 is the least that fits 8.
  ASSERT_TRUE(ShardAwareLimiter::check_window_admits("heavy", RateLimit{1.0, 29}, 8).is_ok());
  ASSERT_TRUE(ShardAwareLimiter::check_window_admits("heavy", RateLimit{1.0, 28}, 8).is_error());
  ASSERT_TRUE(ShardAwareLimiter::check_window_admits("small", RateLimit{1.0, 1}, 1).is_ok());
  ASSERT_TRUE(ShardAwareLimiter::check_window_admits("small", RateLimit{1.0, 0}, 1).is_error());
  // A disabled window admits everything.
  ASSERT_TRUE(ShardAwareLimiter::check_window_admits("heavy", RateLimit{0.0, 0}, 8).is_ok());
  // The boundary holds in the limiter itself.
  auto ok = make_source_limiter(/* global = */ 100, /* heavy = */ 29, /* medium = */ 100, /* small = */ 100);
  auto t = td::Timestamp::at(1000.0);
  ASSERT_TRUE(ok->check_in(k_heavy_a, 8, k_shard_a, 1, t));
  auto tight = make_source_limiter(/* global = */ 100, /* heavy = */ 28, /* medium = */ 100, /* small = */ 100);
  ASSERT_TRUE(!tight->check_in(k_heavy_a, 8, k_shard_a, 1, t));
}

TEST(SourceAwareRateLimiter, UnparseableQueriesAreChargedToTheirSource) {
  auto limiter = make_source_limiter(/* global = */ 8, /* heavy = */ 100, /* medium = */ 100, /* small = */ 12);
  limiter->register_shard(k_shard_a);
  auto t = td::Timestamp::at(1000.0);
  constexpr int k_prober = 9;
  // Bounded by the prober's quarter of the global window (2 of 8).
  ASSERT_TRUE(limiter->check_in_unparseable(k_shard_a, k_prober, t));
  ASSERT_TRUE(limiter->check_in_unparseable(k_shard_a, k_prober, t));
  ASSERT_TRUE(!limiter->check_in_unparseable(k_shard_a, k_prober, t));
  // The probes consumed the prober's own small allowance (3 of 12)...
  ASSERT_TRUE(limiter->check_in(k_small_a, 1, k_shard_a, k_prober, t));
  ASSERT_TRUE(!limiter->check_in(k_small_a, 1, k_shard_a, k_prober, t));
  // ...and the aggregate global window, which now has 6 left for others.
  ASSERT_EQ(6u, flood_from_many_sources(*limiter, k_medium_a, k_shard_a, 100, t));
  // The aggregate small window was not charged by the probes: other sources
  // get its full 12 minus the prober's one small request.
  ASSERT_EQ(11u, flood_from_many_sources(*limiter, k_small_a, k_shard_a, 200, t));
}

TEST(SourceAwareRateLimiter, SourceEntryIsDroppedOnlyAfterEveryWindowDrains) {
  auto limiter = make_source_limiter(/* global = */ 100, /* heavy = */ 4, /* medium = */ 100, /* small = */ 100);
  limiter->register_shard(k_shard_a);
  auto t0 = td::Timestamp::at(1000.0);
  ASSERT_TRUE(limiter->check_in(k_heavy_a, 1, k_shard_a, 5, t0));
  ASSERT_TRUE(!limiter->check_in(k_heavy_a, 1, k_shard_a, 5, t0));
  // Inside the window, another source's activity must not purge the entry
  // and hand source 5 a fresh share.
  auto t1 = td::Timestamp::at(1000.6);
  ASSERT_TRUE(limiter->check_in(k_medium_a, 1, k_shard_a, 6, t1));
  ASSERT_EQ(2u, limiter->tracked_sources(t1));
  ASSERT_TRUE(!limiter->check_in(k_heavy_a, 1, k_shard_a, 5, t1));
  // Once every window has drained the entry goes and the share is back.
  auto t2 = td::Timestamp::at(1001.7);
  ASSERT_EQ(0u, limiter->tracked_sources(t2));
  ASSERT_TRUE(limiter->check_in(k_heavy_a, 1, k_shard_a, 5, t2));
}

TEST(SourceAwareRateLimiter, TrackedSourcesStayBoundedBySprayedIdentities) {
  auto limiter = make_source_limiter(/* global = */ 16, /* heavy = */ 16, /* medium = */ 16, /* small = */ 16);
  limiter->register_shard(k_shard_a);
  size_t peak = 0;
  size_t admitted = 0;
  for (int step = 0; step < 5000; step++) {
    auto t = td::Timestamp::at(1000.0 + step * 0.01);
    admitted += limiter->check_in(k_medium_a, 1, k_shard_a, /* source = */ step, t) ? 1 : 0;
    admitted += limiter->check_in_unparseable(k_shard_a, /* source = */ 100000 + step, t) ? 1 : 0;
    peak = std::max(peak, limiter->tracked_sources(t));
  }
  // Only admitted sources are tracked, and only while their usage is inside a
  // window: at most the global window's 16 admissions.
  ASSERT_TRUE(admitted > 16);
  ASSERT_TRUE(peak <= 16);
}

// ---------------------------------------------------------------------------
// Full-node master admission: allowlist-only, an equal share per slave.

namespace {

using MasterLimiter = tos::validator::fullnode::MasterIngressLimiter<int>;
using tos::validator::fullnode::MasterAdmission;

struct FakeClock {
  std::shared_ptr<td::uint64> ms = std::make_shared<td::uint64>(1000000);
  MasterLimiter::Clock clock() const {
    return [ms = ms]() { return *ms; };
  }
  void advance(td::uint64 delta) {
    *ms += delta;
  }
};

std::unique_ptr<MasterLimiter> make_master(std::set<int> trusted, const FakeClock &clock) {
  auto R = MasterLimiter::create(std::move(trusted), clock.clock());
  CHECK(R.is_ok());
  return R.move_as_ok();
}

std::set<int> trusted_ids(int count) {
  std::set<int> ids;
  for (int i = 1; i <= count; i++) {
    ids.insert(i);
  }
  return ids;
}

bool admitted(MasterLimiter &limiter, int source) {
  return limiter.try_acquire(source) == MasterAdmission::Admitted;
}

constexpr int k_trusted = 1;
constexpr int k_trusted_b = 2;
constexpr int k_trusted_c = 3;

// Unlisted identities all ask once, ahead of anyone else at this instant: the
// arrival order that would leave the least for a slave if they shared its
// budget. Every one of them must be refused as unlisted.
size_t hostile_round(MasterLimiter &limiter, int identities) {
  size_t served = 0;
  for (int h = 0; h < identities; h++) {
    auto admission = limiter.try_acquire(10000 + h);
    CHECK(admission == MasterAdmission::NotListed);
    if (admission == MasterAdmission::Admitted) {
      served++;
    }
  }
  return served;
}

struct InterleaveResult {
  size_t hostile = 0;
  size_t sent = 0;
  size_t admitted = 0;
};

// Every millisecond for `ms_total`: hostiles first, then the requester at its
// own period, then hostiles again.
InterleaveResult interleave(MasterLimiter &limiter, FakeClock &clock, int hostiles, int requester, td::uint64 period_ms,
                            td::uint64 ms_total) {
  InterleaveResult r;
  for (td::uint64 ms = 0; ms < ms_total; ms++) {
    r.hostile += hostile_round(limiter, hostiles);
    if (ms % period_ms == 0) {
      r.sent++;
      if (admitted(limiter, requester)) {
        r.admitted++;
      }
    }
    r.hostile += hostile_round(limiter, hostiles);
    clock.advance(1);
  }
  return r;
}

// Flood every listed identity, in the given order, every millisecond from
// the start instant up to and including `ms_total` later; return what each
// one was granted.
std::vector<size_t> flood(MasterLimiter &limiter, FakeClock &clock, const std::vector<int> &order, td::uint64 ms_total,
                          int hostiles) {
  std::vector<size_t> granted(order.size(), 0);
  for (td::uint64 ms = 0; ms <= ms_total; ms++) {
    hostile_round(limiter, hostiles);
    for (size_t i = 0; i < order.size(); i++) {
      while (granted[i] < 100000 && admitted(limiter, order[i])) {
        granted[i]++;
      }
    }
    if (ms < ms_total) {
      clock.advance(1);
    }
  }
  return granted;
}

}  // namespace

TEST(MasterIngressLimiter, EmptyAllowlistIsRefused) {
  // A master with no configured slave is a configuration error, not an open
  // service: there is no public budget to fall back to.
  FakeClock clock;
  auto R = MasterLimiter::create({}, clock.clock());
  ASSERT_TRUE(R.is_error());
  ASSERT_TRUE(R.error().message().str().find("allowlist-only") != std::string::npos);
  ASSERT_TRUE(MasterLimiter::check_trusted({}).is_error());
  ASSERT_TRUE(MasterLimiter::check_trusted({k_trusted}).is_ok());
}

TEST(MasterIngressLimiter, UnlistedSourcesAreRefusedWithoutBeingCharged) {
  FakeClock clock;
  auto limiter = make_master({k_trusted}, clock);
  // A flood of unlisted identities at a frozen clock is refused as unlisted,
  // not as rate limited, and leaves the slave's whole burst in place.
  for (int round = 0; round < 100; round++) {
    ASSERT_EQ(0u, hostile_round(*limiter, 1000));
  }
  size_t burst = 0;
  while (burst < 64 && admitted(*limiter, k_trusted)) {
    burst++;
  }
  ASSERT_EQ(MasterLimiter::kBurst, burst);
  ASSERT_TRUE(limiter->try_acquire(k_trusted) == MasterAdmission::RateLimited);
  // Still unlisted, not rate limited, once the slave's bucket is empty.
  ASSERT_TRUE(limiter->try_acquire(10000) == MasterAdmission::NotListed);
}

TEST(MasterIngressLimiter, TrustedSlaveKeepsItsShareAgainstFourHostileIdentities) {
  FakeClock clock;
  auto limiter = make_master({k_trusted}, clock);
  // 60 s; the only slave asks at exactly the whole service rate (4 per second).
  auto r = interleave(*limiter, clock, 4, k_trusted, 250, 60000);
  ASSERT_EQ(240u, r.sent);
  ASSERT_EQ(r.sent, r.admitted);
  ASSERT_EQ(0u, r.hostile);
}

TEST(MasterIngressLimiter, TrustedSlaveKeepsItsShareAgainstManyHostileIdentities) {
  FakeClock clock;
  auto limiter = make_master({k_trusted, k_trusted_b}, clock);
  // Two slaves: each owns 2 requests per second; this one asks at that rate.
  auto r = interleave(*limiter, clock, 64, k_trusted, 500, 30000);
  ASSERT_EQ(60u, r.sent);
  ASSERT_EQ(r.sent, r.admitted);
  ASSERT_EQ(0u, r.hostile);
}

TEST(MasterIngressLimiter, TrustedSlaveBurstSurvivesHostileTrafficArrivingFirst) {
  FakeClock clock;
  auto limiter = make_master({k_trusted, k_trusted_b}, clock);
  // Unlisted identities flood for ten seconds while the slaves idle.
  for (td::uint64 ms = 0; ms < 10000; ms++) {
    hostile_round(*limiter, 4);
    clock.advance(1);
  }
  hostile_round(*limiter, 4);
  size_t burst = 0;
  while (burst < 64 && admitted(*limiter, k_trusted)) {
    burst++;
  }
  ASSERT_EQ(MasterLimiter::kBurst / 2, burst);
}

TEST(MasterIngressLimiter, ASlaveThatSpentItsShareHasNoFallback) {
  FakeClock clock;
  auto limiter = make_master({k_trusted, k_trusted_b}, clock);
  for (td::uint64 i = 0; i < MasterLimiter::kBurst / 2; i++) {
    ASSERT_TRUE(admitted(*limiter, k_trusted));
  }
  // No public half to fall back to: the next request is refused although the
  // other slave's bucket is still full.
  ASSERT_TRUE(limiter->try_acquire(k_trusted) == MasterAdmission::RateLimited);
  for (td::uint64 i = 0; i < MasterLimiter::kBurst / 2; i++) {
    ASSERT_TRUE(admitted(*limiter, k_trusted_b));
  }
  ASSERT_TRUE(limiter->try_acquire(k_trusted_b) == MasterAdmission::RateLimited);
}

TEST(MasterIngressLimiter, OneTrustedSlaveCannotDrainAnother) {
  FakeClock clock;
  auto limiter = make_master({k_trusted, k_trusted_b}, clock);
  size_t b_sent = 0;
  size_t b_ok = 0;
  for (td::uint64 ms = 0; ms < 30000; ms++) {
    hostile_round(*limiter, 4);
    // Slave A asks every millisecond, ahead of slave B.
    admitted(*limiter, k_trusted);
    if (ms % 500 == 0) {
      b_sent++;
      b_ok += admitted(*limiter, k_trusted_b) ? 1 : 0;
    }
    clock.advance(1);
  }
  // B's share is 2 per second; asking at that rate it is never refused.
  ASSERT_EQ(60u, b_sent);
  ASSERT_EQ(b_sent, b_ok);
}

TEST(MasterIngressLimiter, EachIdentityGetsExactlyAnEqualShareOfTheUnchangedCeiling) {
  // For every allowlist size, flooding identities for 60 s get exactly
  // (burst + 60 * rate) / n requests each, whichever identity asks first, and
  // together never more than the aggregate ceiling of 16 + 4 per second.
  constexpr td::uint64 kSeconds = 60;
  constexpr td::uint64 kCeiling = MasterLimiter::kBurst + MasterLimiter::kPerSecond * kSeconds;
  static_assert(kCeiling == 256, "the aggregate ceiling is 16 burst and 4 per second");
  for (int n = 1; n <= static_cast<int>(MasterLimiter::kMaxTrusted); n++) {
    FakeClock clock;
    auto limiter = make_master(trusted_ids(n), clock);
    ASSERT_EQ(MasterLimiter::kBurst * MasterLimiter::kUnit, limiter->share_burst_units() * n);
    ASSERT_EQ(MasterLimiter::kPerSecond * MasterLimiter::kUnit / 1000, limiter->share_per_ms_units() * n);
    std::vector<int> order;
    for (int id = n; id >= 1; id--) {
      order.push_back(id);
    }
    auto granted = flood(*limiter, clock, order, kSeconds * 1000, 64);
    size_t total = 0;
    for (size_t g : granted) {
      ASSERT_EQ(kCeiling / n, g);
      total += g;
    }
    ASSERT_TRUE(total <= kCeiling);
    // Only the fractional remainder of each share is left unserved.
    ASSERT_TRUE(total + n > kCeiling);
    if (kCeiling % n == 0) {
      ASSERT_EQ(kCeiling, total);
    }
  }
}

TEST(MasterIngressLimiter, SharesAreFractional) {
  // Three slaves split 16 burst and 4 per second: 16/3 burst and 4/3 per
  // second each. Whole-token arithmetic would round that to 5 and 1.
  FakeClock clock;
  auto limiter = make_master({k_trusted, k_trusted_b, k_trusted_c}, clock);
  std::vector<td::uint64> admitted_at;
  for (td::uint64 ms = 0; ms <= 3600; ms++) {
    hostile_round(*limiter, 64);
    while (admitted_at.size() < 64 && admitted(*limiter, k_trusted)) {
      admitted_at.push_back(ms);
    }
    clock.advance(1);
  }
  // Five at once from 5.33 tokens; the remaining 0.33 reaches one token after
  // 0.5 s, and each further token takes 0.75 s.
  ASSERT_EQ(10u, admitted_at.size());
  for (size_t i = 0; i < 5; i++) {
    ASSERT_EQ(0u, admitted_at[i]);
  }
  ASSERT_EQ(500u, admitted_at[5]);
  ASSERT_EQ(1250u, admitted_at[6]);
  ASSERT_EQ(2000u, admitted_at[7]);
  ASSERT_EQ(2750u, admitted_at[8]);
  ASSERT_EQ(3500u, admitted_at[9]);
}

TEST(MasterIngressLimiter, RefusesMoreThanEightTrustedIdentities) {
  FakeClock clock;
  auto eight = trusted_ids(8);
  std::set<int> nine = eight;
  nine.insert(99);
  ASSERT_TRUE(MasterLimiter::create(eight, clock.clock()).is_ok());
  ASSERT_TRUE(MasterLimiter::create(nine, clock.clock()).is_error());
  ASSERT_TRUE(MasterLimiter::create(trusted_ids(1), nullptr).is_error());
}
