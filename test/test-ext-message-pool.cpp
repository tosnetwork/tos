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
