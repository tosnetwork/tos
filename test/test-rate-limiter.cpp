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

#include "td/utils/tests.h"
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
