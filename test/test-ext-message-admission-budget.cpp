// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
#include <limits>
#include <vector>

#include "td/actor/TestScheduler.h"
#include "td/utils/tests.h"
#include "validator/impl/ext-message-admission-budget.hpp"

namespace tos::validator {
namespace {

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
