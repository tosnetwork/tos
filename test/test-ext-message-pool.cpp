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

#include "td/actor/TestScheduler.h"
#include "td/utils/tests.h"
#include "validator/impl/ext-message-checker.hpp"
#include "validator/impl/ext-message-pool.hpp"
#include "validator/impl/shard.hpp"
#include "vm/boc.h"

namespace tos::validator {
namespace {

td::BufferSlice make_valid_external_message() {
  // ext_in_msg_info$10, addr_none$00 source, addr_std$10 destination with no
  // anycast in workchain 0, zero address/import fee, no StateInit, empty inline body.
  auto root = vm::CellBuilder()
                  .store_long(2, 2)
                  .store_zeroes(2)
                  .store_long(2, 2)
                  .store_zeroes(1 + 8 + 256 + 4 + 1 + 1)
                  .finalize();
  return vm::std_boc_serialize(std::move(root)).move_as_ok();
}

TEST(ExtMessagePool, RejectsAdmissionBeforeMasterchainState) {
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> td::actor::Task<td::Unit> {
    auto pool = td::actor::create_actor<ExtMessagePool>("ext-message-pool", td::Ref<ValidatorManagerOptions>{},
                                                        td::actor::ActorId<ValidatorManager>{});

    auto result =
        co_await td::actor::ask(pool.get(), &ExtMessagePool::check_add_external_message,
                                td::BufferSlice{"not a bag of cells"}, 0, false, td::optional<PublicKeyHash>{})
            .wrap();

    ASSERT_TRUE(result.is_error());
    EXPECT_EQ(result.error().code(), ErrorCode::notready);
    EXPECT_EQ(result.error().message(), "not ready");
    co_return td::Unit{};
  });
}

TEST(ExtMessagePool, AdmissionByteBudgetRejectsAndReleases) {
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> td::actor::Task<td::Unit> {
    auto budget = std::make_shared<adnl::AdnlExtByteBudget>(32);
    auto pool = td::actor::create_actor<ExtMessagePool>("ext-message-byte-budget", td::Ref<ValidatorManagerOptions>{},
                                                        td::actor::ActorId<ValidatorManager>{}, budget);
    // Hold the capacity as though other checks were suspended. This request
    // must be refused before state lookup, not placed into an uncharged queue.
    ASSERT_TRUE(budget->try_reserve(32));
    auto rejected = co_await td::actor::ask(pool.get(), &ExtMessagePool::check_add_external_message,
                                            td::BufferSlice{"input"}, 0, false, td::optional<PublicKeyHash>{})
                        .wrap();
    ASSERT_TRUE(rejected.is_error());
    EXPECT_EQ(rejected.error().message(), "external message admission byte budget exhausted");
    EXPECT_EQ(budget->used(), 32u);
    ASSERT_TRUE(budget->release(32));
    for (unsigned i = 0; i < 3; ++i) {
      auto unavailable = co_await td::actor::ask(pool.get(), &ExtMessagePool::check_add_external_message,
                                                 td::BufferSlice{"input"}, 0, false, td::optional<PublicKeyHash>{})
                             .wrap();
      ASSERT_TRUE(unavailable.is_error());
      EXPECT_EQ(unavailable.error().message(), "not ready");
      EXPECT_EQ(budget->used(), 0u);
    }
    co_return td::Unit{};
  });
}

TEST(ExtMessageChecker, RejectsMalformedBagOfCellsBeforeStateLookup) {
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> td::actor::Task<td::Unit> {
    auto checker =
        td::actor::create_actor<ExtMessageChecker>("ext-message-checker", td::actor::ActorId<ValidatorManager>{});

    auto result =
        co_await td::actor::ask(checker.get(), &ExtMessageChecker::check, td::BufferSlice{"not a bag of cells"},
                                block::SizeLimitsConfig::ExtMsgLimits{}, td::Ref<MasterchainState>{})
            .wrap();

    ASSERT_TRUE(result.is_error());
    EXPECT(result.error().code() != ErrorCode::notready);
    co_return td::Unit{};
  });
}

TEST(ExtMessageChecker, ParsesValidMessageBeforeStateLookup) {
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> td::actor::Task<td::Unit> {
    auto checker =
        td::actor::create_actor<ExtMessageChecker>("ext-message-checker", td::actor::ActorId<ValidatorManager>{});

    auto result = co_await td::actor::ask(checker.get(), &ExtMessageChecker::check, make_valid_external_message(),
                                          block::SizeLimitsConfig::ExtMsgLimits{}, td::Ref<MasterchainState>{})
                      .wrap();

    ASSERT_TRUE(result.is_error());
    EXPECT_EQ(result.error().code(), ErrorCode::notready);
    EXPECT_EQ(result.error().message(), "masterchain state is not ready");
    co_return td::Unit{};
  });
}

}  // namespace
}  // namespace tos::validator

namespace tos::validator {
class AdmissionLimitsState final : public MasterchainStateQ {
 public:
  explicit AdmissionLimitsState(unsigned max_size)
      : MasterchainStateQ(BlockIdExt{}, td::BufferSlice{}), max_size_(max_size) {}
  block::SizeLimitsConfig::ExtMsgLimits get_ext_msg_limits() const override {
    block::SizeLimitsConfig::ExtMsgLimits limits;
    limits.max_size = max_size_;
    return limits;
  }
 private:
  unsigned max_size_;
};

class ExtMessagePoolTestHarness final : public ExtMessagePool {
 public:
  explicit ExtMessagePoolTestHarness(std::shared_ptr<adnl::AdnlExtByteBudget> bytes)
      : ExtMessagePool({}, {}, std::move(bytes)) {
    last_masterchain_state_ = td::make_ref<AdmissionLimitsState>(65535);
    inflight_checks_ = MAX_INFLIGHT_CHECKS;
  }
  void shrink_limits_and_release() {
    ASSERT_TRUE(admission_waiters_.size() == 1);
    last_masterchain_state_ = td::make_ref<AdmissionLimitsState>(1);
    // Release the synthetic occupancy. The queued request must now re-read
    // limits and reject without dispatching or inflating completion throughput.
    inflight_checks_ = 1;
    release_check_slot(false);
  }
  void verify_released_without_dispatch() {
    EXPECT_EQ(inflight_checks_, 0u);
    EXPECT_EQ(completions_in_rate_window_, 0u);
    EXPECT_EQ(admission_window_.checked, 0u);
    EXPECT_EQ(admission_budget_->used(), 0u);
    EXPECT(admission_waiters_.empty());
  }
};

TEST(ExtMessagePool, QueuedRequestUsesFreshLimitsWithoutCountingDispatch) {
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> td::actor::Task<td::Unit> {
    auto bytes = std::make_shared<adnl::AdnlExtByteBudget>(65535);
    auto pool = td::actor::create_actor<ExtMessagePoolTestHarness>("queued-config", bytes);
    auto pending = td::actor::ask(pool.get(), &ExtMessagePool::check_add_external_message,
                                  td::BufferSlice{"queued input"}, 0, false,
                                  td::optional<PublicKeyHash>{});
    co_await td::actor::ask(pool.get(), &ExtMessagePoolTestHarness::shrink_limits_and_release);
    auto result = co_await std::move(pending).wrap();
    ASSERT_TRUE(result.is_error());
    EXPECT_EQ(result.error().message(), "external message too large, rejecting");
    co_await td::actor::ask(pool.get(), &ExtMessagePoolTestHarness::verify_released_without_dispatch);
    co_return td::Unit{};
  });
}
}  // namespace tos::validator
