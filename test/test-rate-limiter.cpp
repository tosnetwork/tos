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
// Full-node master admission with reserved capacity for trusted slaves.

namespace {

using MasterLimiter = tos::validator::fullnode::MasterIngressLimiter<int>;

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

constexpr int k_trusted = 1;
constexpr int k_trusted_b = 2;
constexpr int k_trusted_c = 3;

// Hostile identities all ask once, ahead of anyone else at this instant: the
// arrival order that leaves the least for an honest requester.
size_t hostile_round(MasterLimiter &limiter, int identities) {
  size_t admitted = 0;
  for (int h = 0; h < identities; h++) {
    if (limiter.try_acquire(10000 + h)) {
      admitted++;
    }
  }
  return admitted;
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
      if (limiter.try_acquire(requester)) {
        r.admitted++;
      }
    }
    r.hostile += hostile_round(limiter, hostiles);
    clock.advance(1);
  }
  return r;
}

}  // namespace

TEST(MasterIngressLimiter, TrustedSlaveKeepsItsShareAgainstFourHostileIdentities) {
  FakeClock clock;
  auto limiter = make_master({k_trusted}, clock);
  // 60 s; the trusted slave asks at exactly its reserved rate (2 per second).
  auto r = interleave(*limiter, clock, 4, k_trusted, 500, 60000);
  ASSERT_EQ(120u, r.sent);
  ASSERT_EQ(r.sent, r.admitted);
  // The hostile identities are held to the public half: 8 burst + 2 per second.
  ASSERT_TRUE(r.hostile <= 8 + 2 * 60);
  ASSERT_TRUE(r.hostile >= 2 * 60);
  // The aggregate ceiling holds: 16 burst + 4 per second.
  ASSERT_TRUE(r.hostile + r.admitted <= 16 + 4 * 60);
}

TEST(MasterIngressLimiter, TrustedSlaveKeepsItsShareAgainstManyHostileIdentities) {
  FakeClock clock;
  auto limiter = make_master({k_trusted}, clock);
  auto r = interleave(*limiter, clock, 64, k_trusted, 500, 30000);
  ASSERT_EQ(r.sent, r.admitted);
  ASSERT_TRUE(r.hostile <= 8 + 2 * 30);
}

TEST(MasterIngressLimiter, WithoutAllowlistManyIdentitiesStarveAnyoneElse) {
  // The same traffic with no trusted set: the unprotected mode the startup
  // warning describes. Service stays bounded but nobody is guaranteed any.
  FakeClock clock;
  auto limiter = make_master({}, clock);
  auto r = interleave(*limiter, clock, 64, k_trusted, 500, 30000);
  ASSERT_TRUE(r.admitted * 4 < r.sent);
  ASSERT_TRUE(r.hostile + r.admitted <= 16 + 4 * 30);
}

TEST(MasterIngressLimiter, TrustedSlaveBurstSurvivesHostileTrafficArrivingFirst) {
  FakeClock clock;
  auto limiter = make_master({k_trusted}, clock);
  // Hostiles saturate the public half for ten seconds while the slave idles.
  for (td::uint64 ms = 0; ms < 10000; ms++) {
    hostile_round(*limiter, 4);
    clock.advance(1);
  }
  hostile_round(*limiter, 4);
  size_t burst = 0;
  while (burst < 64 && limiter->try_acquire(k_trusted)) {
    burst++;
  }
  ASSERT_EQ(8u, burst);
}

TEST(MasterIngressLimiter, WithoutAllowlistPublicGetsTheWholeCeiling) {
  FakeClock clock;
  auto limiter = make_master({}, clock);
  ASSERT_EQ(16u, hostile_round(*limiter, 100));
  clock.advance(1000);
  size_t admitted = 0;
  for (int source = 2000; source < 2100; source++) {
    admitted += limiter->try_acquire(source) ? 1 : 0;
  }
  ASSERT_EQ(4u, admitted);
}

TEST(MasterIngressLimiter, PublicSourcesShareOnlyThePublicHalf) {
  FakeClock clock;
  auto limiter = make_master({k_trusted}, clock);
  ASSERT_EQ(8u, hostile_round(*limiter, 100));
  // One public source is held to its own bucket of 1 per second.
  clock.advance(1000);
  ASSERT_TRUE(limiter->try_acquire(5000));
  ASSERT_TRUE(!limiter->try_acquire(5000));
}

TEST(MasterIngressLimiter, OneTrustedSlaveCannotDrainAnother) {
  FakeClock clock;
  auto limiter = make_master({k_trusted, k_trusted_b}, clock);
  size_t b_sent = 0;
  size_t b_ok = 0;
  for (td::uint64 ms = 0; ms < 30000; ms++) {
    hostile_round(*limiter, 4);
    // Slave A asks every millisecond, ahead of slave B.
    limiter->try_acquire(k_trusted);
    if (ms % 1000 == 0) {
      b_sent++;
      b_ok += limiter->try_acquire(k_trusted_b) ? 1 : 0;
    }
    clock.advance(1);
  }
  // B's share is 1 per second; asking at that rate it is never refused.
  ASSERT_EQ(30u, b_sent);
  ASSERT_EQ(b_sent, b_ok);
}

TEST(MasterIngressLimiter, EveryoneFloodingStaysUnderTheAggregateCeiling) {
  FakeClock clock;
  std::set<int> trusted;
  for (int i = 1; i <= 8; i++) {
    trusted.insert(i);
  }
  auto limiter = make_master(trusted, clock);
  size_t admitted = 0;
  for (td::uint64 ms = 0; ms < 20000; ms++) {
    admitted += hostile_round(*limiter, 64);
    for (int id : trusted) {
      while (limiter->try_acquire(id)) {
        admitted++;
      }
    }
    clock.advance(1);
  }
  ASSERT_TRUE(admitted <= 16 + 4 * 20);
  ASSERT_TRUE(admitted >= 4 * 20);
}

TEST(MasterIngressLimiter, SharesAreFractional) {
  // Three trusted slaves split 8 burst and 2 per second: 8/3 burst and 2/3 per
  // second each. Whole-token arithmetic would round that to 2 and 0.
  FakeClock clock;
  auto limiter = make_master({k_trusted, k_trusted_b, k_trusted_c}, clock);
  // Drain the public half so only the reserved share answers.
  for (int i = 0; i < 2000; i++) {
    hostile_round(*limiter, 64);
    clock.advance(1);
  }
  std::vector<td::uint64> admitted_at;
  for (td::uint64 ms = 0; ms <= 3600; ms++) {
    hostile_round(*limiter, 64);
    while (admitted_at.size() < 64 && limiter->try_acquire(k_trusted)) {
      admitted_at.push_back(ms);
    }
    clock.advance(1);
  }
  // Two at once from 2.67 tokens; the remaining 0.67 reaches one token after
  // 0.5 s, and each further token takes 1.5 s.
  ASSERT_EQ(5u, admitted_at.size());
  ASSERT_EQ(0u, admitted_at[0]);
  ASSERT_EQ(0u, admitted_at[1]);
  ASSERT_EQ(500u, admitted_at[2]);
  ASSERT_EQ(2000u, admitted_at[3]);
  ASSERT_EQ(3500u, admitted_at[4]);
}

TEST(MasterIngressLimiter, RefusesMoreThanEightTrustedIdentities) {
  FakeClock clock;
  std::set<int> eight;
  for (int i = 1; i <= 8; i++) {
    eight.insert(i);
  }
  std::set<int> nine = eight;
  nine.insert(99);
  ASSERT_TRUE(MasterLimiter::create(eight, clock.clock()).is_ok());
  ASSERT_TRUE(MasterLimiter::create(nine, clock.clock()).is_error());
  auto limiter = make_master({k_trusted}, clock);
  ASSERT_TRUE(limiter->set_trusted(nine).is_error());
  ASSERT_TRUE(limiter->has_trusted());
  ASSERT_TRUE(limiter->set_trusted(eight).is_ok());
}

TEST(MasterIngressLimiter, ConfigurationChangesNeverRaiseABucket) {
  FakeClock clock;
  auto limiter = make_master({k_trusted}, clock);
  // Drain the public half at this instant; the clock does not move in this
  // test, so nothing refills.
  ASSERT_EQ(8u, hostile_round(*limiter, 64));
  // A holds its full reserved burst of 8. Adding B halves A's capacity: A is
  // clamped to 4, and B starts empty.
  ASSERT_TRUE(limiter->set_trusted({k_trusted, k_trusted_b}).is_ok());
  size_t a = 0;
  while (a < 64 && limiter->try_acquire(k_trusted)) {
    a++;
  }
  ASSERT_EQ(4u, a);
  ASSERT_TRUE(!limiter->try_acquire(k_trusted_b));
  // Re-applying the configuration, or dropping and re-adding a member, does
  // not hand out a fresh burst.
  ASSERT_TRUE(limiter->set_trusted({k_trusted, k_trusted_b}).is_ok());
  ASSERT_TRUE(!limiter->try_acquire(k_trusted));
  ASSERT_TRUE(limiter->set_trusted({k_trusted_b}).is_ok());
  ASSERT_TRUE(limiter->set_trusted({k_trusted, k_trusted_b}).is_ok());
  ASSERT_TRUE(!limiter->try_acquire(k_trusted));
  // Removing the allowlist widens the public bucket's capacity, not its level.
  ASSERT_TRUE(limiter->set_trusted({}).is_ok());
  ASSERT_TRUE(!limiter->try_acquire(7777));
}

TEST(MasterIngressLimiter, AddingAnAllowlistClampsThePublicBucket) {
  FakeClock clock;
  auto limiter = make_master({}, clock);
  // The public bucket is full at 16; the allowlist halves its capacity, and
  // the level must follow, not keep the old 16.
  ASSERT_TRUE(limiter->set_trusted({k_trusted}).is_ok());
  ASSERT_EQ(8u, hostile_round(*limiter, 100));
}

TEST(MasterIngressLimiter, PublicSourceTableIsBounded) {
  FakeClock clock;
  auto limiter = make_master({}, clock);
  // Admit 1000 distinct sources, one every 250 ms (the public refill rate).
  for (int source = 0; source < 1000; source++) {
    ASSERT_TRUE(limiter->try_acquire(source));
    clock.advance(250);
  }
  ASSERT_EQ(1000u, limiter->tracked_sources());
  // The table holds only sources seen within the idle period, so a newcomer
  // is refused even though the public bucket has tokens.
  ASSERT_TRUE(!limiter->try_acquire(5000));
  ASSERT_EQ(1000u, limiter->tracked_sources());
  // Once the oldest entry has been idle long enough, it makes room for one.
  clock.advance(MasterLimiter::kPerSourceIdleMs);
  ASSERT_TRUE(limiter->try_acquire(5000));
  ASSERT_EQ(1000u, limiter->tracked_sources());
}
