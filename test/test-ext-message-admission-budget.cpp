// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
#include <limits>
#include <vector>

#include "td/actor/TestScheduler.h"
#include "td/utils/tests.h"
#include "validator/impl/ext-message-admission-budget.hpp"
#include "validator/impl/ext-message-work-budget.hpp"
#include "validator/impl/ext-message-work-quote.hpp"

namespace tos::validator {
namespace {

TEST(ExtMessageWorkQuote, IncludesSpecialAccountCreditInInitialGas) {
  auto special = external_tvm_initial_gas_bound(1000000, 70000000, 10000, false);
  ASSERT_TRUE(special.is_ok());
  EXPECT_EQ(special.ok(), 70010000u);
  auto ordinary = external_tvm_initial_gas_bound(30000000, 0, 20000, false);
  ASSERT_TRUE(ordinary.is_ok());
  EXPECT_EQ(ordinary.ok(), 20000u);
  auto capped = external_tvm_initial_gas_bound(9, 7, 20000, false);
  ASSERT_TRUE(capped.is_ok());
  EXPECT_EQ(capped.ok(), 14u);
}

TEST(ExtMessageWorkQuote, RefusesUncalibratedPrecompiledProfile) {
  auto result = external_tvm_initial_gas_bound(30000000, 70000000, 20000, true);
  ASSERT_TRUE(result.is_error());
  EXPECT_EQ(result.error().message(), "external admission precompiled execution profile is not calibrated");
}

TEST(ExtMessageWorkQuote, RejectsUnsupportedSignedVmRange) {
  constexpr auto maximum = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
  EXPECT(external_tvm_initial_gas_bound(1, maximum, 1, false).is_error());
  EXPECT(external_tvm_initial_gas_bound(maximum + 1, 0, maximum + 1, false).is_error());
  auto boundary = external_tvm_initial_gas_bound(1, maximum - 1, 1, false);
  ASSERT_TRUE(boundary.is_ok());
  EXPECT_EQ(boundary.ok(), maximum);
}

TEST(ExtMessageWorkBudget, ChargesEveryAttemptUntilTimedRefill) {
  ExtMessageWorkBudget budget(100, 20, 10, 1000);
  // The same charge applies regardless of the eventual checker outcome.
  for (unsigned outcome = 0; outcome < 4; ++outcome) {
    ASSERT_TRUE(budget.try_consume(25, 1000));
    EXPECT_EQ(budget.available(), 100u - (outcome + 1) * 25u);
  }
  EXPECT(!budget.try_consume(1, 1000));
  EXPECT(!budget.try_consume(1, 1009));
  EXPECT(!budget.try_consume(21, 1010));
  EXPECT_EQ(budget.available(), 20u);
  EXPECT(budget.try_consume(20, 1010));
  EXPECT(!budget.try_consume(1, 1019));
  EXPECT(budget.try_consume(20, 1020));
}

TEST(ExtMessageWorkBudget, PreservesFractionalTimeAndBoundsIdleBurst) {
  ExtMessageWorkBudget budget(100, 7, 10, 0);
  ASSERT_TRUE(budget.try_consume(100, 0));
  EXPECT(budget.try_consume(7, 19));
  EXPECT(budget.try_consume(7, 20));
  EXPECT(!budget.try_consume(1, 29));
  EXPECT(budget.try_consume(100, 10000));
  EXPECT(!budget.try_consume(1, 10000));
}

TEST(ExtMessageWorkBudget, RejectsInvalidQuotesAndBackwardClock) {
  ExtMessageWorkBudget budget(100, 20, 10, 1000);
  EXPECT(!budget.try_consume(0, 1000));
  EXPECT(!budget.try_consume(101, 1000));
  EXPECT(!budget.try_consume(1, 999));
  EXPECT_EQ(budget.available(), 100u);
  EXPECT(budget.try_consume(1, 1009));
  EXPECT(!budget.try_consume(1, 1008));
  EXPECT_EQ(budget.available(), 99u);
  EXPECT(budget.try_consume(99, 1009));
  EXPECT(!budget.try_consume(101, 2000));
  EXPECT_EQ(budget.available(), 0u);
  EXPECT(budget.try_consume(100, 2000));
}

TEST(ExtMessageWorkBudget, SaturatesWithoutIntegerOverflow) {
  constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
  ExtMessageWorkBudget budget(maximum, maximum, 1, 0);
  ASSERT_TRUE(budget.try_consume(maximum, 0));
  EXPECT(budget.try_consume(maximum, maximum));
  EXPECT(!budget.try_consume(1, maximum));
  ExtMessageWorkBudget exact(maximum, 1, 1, 0);
  ASSERT_TRUE(exact.try_consume(maximum, 0));
  EXPECT(exact.try_consume(maximum, maximum));
  EXPECT_EQ(exact.available(), 0u);
}

TEST(ExtMessageAdmissionBudget, RejectsAggregateBytesBeforeCountLimit) {
  auto budget = std::make_shared<adnl::AdnlExtByteBudget>(ext_message_admission_bytes);
  std::vector<ExtMessageAdmissionReservation> pending;
  const std::size_t size = 65535;
  const auto capacity = ext_message_admission_bytes / size;
  ASSERT_TRUE(capacity < 50000);
  for (std::size_t i = 0; i < capacity; ++i) {
    auto reservation = ExtMessageAdmissionReservation::acquire(budget, size);
    ASSERT_TRUE(reservation.is_ok());
    pending.push_back(reservation.move_as_ok());
  }
  EXPECT_EQ(budget->used(), capacity * size);
  auto over = ExtMessageAdmissionReservation::acquire(budget, size);
  ASSERT_TRUE(over.is_error());
  EXPECT_EQ(over.error().code(), ErrorCode::notready);
  EXPECT_EQ(budget->used(), capacity * size);
  auto overflow = ExtMessageAdmissionReservation::acquire(budget, std::numeric_limits<std::size_t>::max());
  EXPECT(overflow.is_error());
  pending.clear();
  EXPECT_EQ(budget->used(), 0u);
  EXPECT(ExtMessageAdmissionReservation::acquire(budget, ext_message_admission_bytes).is_ok());
  EXPECT_EQ(budget->used(), 0u);
}

TEST(ExtMessageAdmissionBudget, MoveAndEarlyReturnReleaseExactlyOnce) {
  auto budget = std::make_shared<adnl::AdnlExtByteBudget>(64);
  auto fail_after_reserve = [&]() -> td::Status {
    auto first = ExtMessageAdmissionReservation::acquire(budget, 64);
    ASSERT_TRUE(first.is_ok());
    auto moved = first.move_as_ok();
    EXPECT_EQ(budget->used(), 64u);
    EXPECT(ExtMessageAdmissionReservation::acquire(budget, 1).is_error());
    return td::Status::Error("controlled rejection after reservation");
  };
  for (unsigned i = 0; i < 3; ++i) {
    EXPECT(fail_after_reserve().is_error());
    EXPECT_EQ(budget->used(), 0u);
  }
}

TEST(ExtMessageAdmissionBudget, HoldsAcrossSuspensionAndReleasesOnCompletion) {
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> td::actor::Task<td::Unit> {
    auto budget = std::make_shared<adnl::AdnlExtByteBudget>(64);
    auto suspended = [&](td::actor::StartedTask<> completion,
                         td::actor::StartedTask<>::ExternalPromise ready) -> td::actor::Task<td::Unit> {
      auto reserved = ExtMessageAdmissionReservation::acquire(budget, 64);
      ASSERT_TRUE(reserved.is_ok());
      auto reservation = reserved.move_as_ok();
      ready.set_value(td::Unit{});
      co_await std::move(completion);
      co_return td::Unit{};
    };
    for (unsigned outcome = 0; outcome < 3; ++outcome) {
      auto [completion, promise] = td::actor::StartedTask<>::make_bridge();
      auto [ready, ready_promise] = td::actor::StartedTask<>::make_bridge();
      auto running = suspended(std::move(completion), std::move(ready_promise)).start();
      co_await std::move(ready);
      // A different admission must not borrow bytes while this task is suspended.
      EXPECT_EQ(budget->used(), 64u);
      EXPECT(ExtMessageAdmissionReservation::acquire(budget, 1).is_error());
      if (outcome == 0) {
        promise.set_value(td::Unit{});
      } else if (outcome == 1) {
        promise.set_error(td::Status::Error("controlled checker failure"));
      } else {
        // Destruction of the producer's unresolved promise must also unwind.
        auto abandoned = std::move(promise);
      }
      auto result = co_await std::move(running).wrap();
      EXPECT_EQ(result.is_ok(), outcome == 0);
      EXPECT_EQ(budget->used(), 0u);
    }
    co_return td::Unit{};
  });
}

}  // namespace
}  // namespace tos::validator
