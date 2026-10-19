/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// New-connection admission for the QUIC server: the per-address and global
// rate limits, and the bound on how many addresses are tracked.
#include <string>

#include "quic/quic-connection-rate-limiters.h"
#include "td/utils/tests.h"

namespace {

using tos::adnl::RateLimiter;
using tos::quic::QuicConnectionRateLimiters;

std::string source(int n) {
  return "10.0." + std::to_string(n / 256) + "." + std::to_string(n % 256);
}

// A limiter that refills so slowly the test never sees it refill.
constexpr double kNoRefill = 3600.0;

}  // namespace

TEST(QuicAdmission, AddressesRefusedByTheGlobalLimitLeaveNothingBehind) {
  QuicConnectionRateLimiters per_address(4, kNoRefill);
  RateLimiter global(2, kNoRefill);
  ASSERT_TRUE(per_address.take_new_connection(source(0), global).is_ok());
  ASSERT_TRUE(per_address.take_new_connection(source(1), global).is_ok());
  // The global limit is spent: a flood of fresh sources is refused, and none
  // of them gets a table entry.
  for (int i = 2; i < 1000; ++i) {
    ASSERT_TRUE(per_address.take_new_connection(source(i), global).is_error());
  }
  ASSERT_EQ(per_address.tracked(), static_cast<size_t>(2));
}

TEST(QuicAdmission, AnAddressOverItsOwnLimitDoesNotSpendTheGlobalOne) {
  QuicConnectionRateLimiters per_address(2, kNoRefill);
  RateLimiter global(3, kNoRefill);
  ASSERT_TRUE(per_address.take_new_connection(source(0), global).is_ok());
  ASSERT_TRUE(per_address.take_new_connection(source(0), global).is_ok());
  ASSERT_TRUE(per_address.take_new_connection(source(0), global).is_error());
  ASSERT_TRUE(per_address.take_new_connection(source(0), global).is_error());
  // Two global tokens were used; the third is still there for someone else.
  ASSERT_TRUE(per_address.take_new_connection(source(1), global).is_ok());
  ASSERT_TRUE(per_address.take_new_connection(source(2), global).is_error());
}

TEST(QuicAdmission, TheAddressTableIsBounded) {
  QuicConnectionRateLimiters per_address(1, kNoRefill, 4);
  RateLimiter global(1000, kNoRefill);
  for (int i = 0; i < 4; ++i) {
    ASSERT_TRUE(per_address.take_new_connection(source(i), global).is_ok());
  }
  // Every entry is still draining, so none can be dropped: a fifth source is
  // refused, and the table stays at its bound.
  ASSERT_TRUE(per_address.take_new_connection(source(4), global).is_error());
  ASSERT_EQ(per_address.tracked(), static_cast<size_t>(4));
}

TEST(QuicAdmission, AFullTableMakesRoomFromRefilledEntries) {
  QuicConnectionRateLimiters per_address(1, 0.001, 4);
  RateLimiter global(1000, 0.001);
  for (int i = 0; i < 4; ++i) {
    ASSERT_TRUE(per_address.take_new_connection(source(i), global).is_ok());
  }
  // Once the existing entries have refilled they carry no state worth keeping.
  auto until = td::Timestamp::in(0.05);
  while (!until.is_in_past()) {
  }
  ASSERT_TRUE(per_address.take_new_connection(source(4), global).is_ok());
  ASSERT_TRUE(per_address.tracked() <= 4);
}

TEST(QuicAdmission, WithoutPerAddressLimitsOnlyTheGlobalOneApplies) {
  QuicConnectionRateLimiters per_address(0, kNoRefill);
  RateLimiter global(2, kNoRefill);
  ASSERT_TRUE(per_address.take_new_connection(source(0), global).is_ok());
  ASSERT_TRUE(per_address.take_new_connection(source(0), global).is_ok());
  ASSERT_TRUE(per_address.take_new_connection(source(1), global).is_error());
  ASSERT_EQ(per_address.tracked(), static_cast<size_t>(0));
}

TEST(QuicAdmission, AFloodAgainstAFullTableDoesNotScanItPerAddress) {
  QuicConnectionRateLimiters per_address(1, kNoRefill, 4);
  RateLimiter global(100000, 0.00001);
  for (int i = 0; i < 4; ++i) {
    ASSERT_TRUE(per_address.take_new_connection(source(i), global).is_ok());
  }
  for (int i = 4; i < 2000; ++i) {
    ASSERT_TRUE(per_address.take_new_connection(source(i), global).is_error());
  }
  // One scan for room, not one per refused address.
  ASSERT_EQ(per_address.full_table_cleanups(), static_cast<size_t>(1));
}
