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

#include <cstdio>
#include <filesystem>

#include "block/block-parse.h"
#include "td/actor/TestScheduler.h"
#include "td/utils/filesystem.h"
#include "td/utils/tests.h"
#include "validator/impl/ext-message-checker.hpp"
#include "validator/impl/ext-message-pool.hpp"
#include "validator/impl/shard.hpp"
#include "vm/boc.h"
#include "vm/vm.h"

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
      : MasterchainStateQ(BlockIdExt{}, td::BufferSlice{}), max_size_(max_size) {
  }
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
  ExtMessagePoolTestHarness(td::Ref<ValidatorManagerOptions> options, std::shared_ptr<adnl::AdnlExtByteBudget> bytes)
      : ExtMessagePool(std::move(options), {}, std::move(bytes)) {
    inflight_checks_ = MAX_INFLIGHT_CHECKS;
  }
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
  void rebind_profile_and_release(ExtMessageWorkProfile profile) {
    ASSERT_TRUE(admission_waiters_.size() == 1);
    ASSERT_TRUE(work_admission_ != nullptr);
    EXPECT_EQ(work_admission_->available(), 2u);
    ASSERT_TRUE(configure_work_profile(std::move(profile)).is_ok());
    EXPECT_EQ(work_admission_->available(), 2u);
    inflight_checks_ = 1;
    release_check_slot(false);
  }
  void verify_work_released(bool dispatched) {
    EXPECT_EQ(inflight_checks_, 0u);
    EXPECT_EQ(completions_in_rate_window_, dispatched ? 1u : 0u);
    EXPECT_EQ(admission_window_.checked, dispatched ? 1u : 0u);
    EXPECT_EQ(work_admission_->available(), dispatched ? 1u : 2u);
    EXPECT_EQ(admission_budget_->used(), 0u);
    EXPECT(admission_waiters_.empty());
    for (auto count : checker_inflight_) {
      EXPECT_EQ(count, 0u);
    }
  }
  void cancel_waiter() {
    ASSERT_TRUE(admission_waiters_.size() == 1);
    EXPECT(admission_budget_->used() > 0);
    auto waiter = std::move(admission_waiters_.front());
    admission_waiters_.pop_front();
    // Drop only synthetic occupancy; no real checker was dispatched.
    inflight_checks_ = 0;
    waiter.set_error(td::Status::Error(ErrorCode::cancelled, "queued admission cancelled"));
  }
  void stop_while_queued() {
    ASSERT_TRUE(admission_waiters_.size() == 1);
    EXPECT(admission_budget_->used() > 0);
    stop();
  }
};

TEST(ExtMessagePool, QueuedRequestUsesFreshLimitsWithoutCountingDispatch) {
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> td::actor::Task<td::Unit> {
    auto bytes = std::make_shared<adnl::AdnlExtByteBudget>(65535);
    auto pool = td::actor::create_actor<ExtMessagePoolTestHarness>("queued-config", bytes);
    auto pending = td::actor::ask(pool.get(), &ExtMessagePool::check_add_external_message,
                                  td::BufferSlice{"queued input"}, 0, false, td::optional<PublicKeyHash>{});
    co_await td::actor::ask(pool.get(), &ExtMessagePoolTestHarness::shrink_limits_and_release);
    auto result = co_await std::move(pending).wrap();
    ASSERT_TRUE(result.is_error());
    EXPECT_EQ(result.error().message(), "external message too large, rejecting");
    co_await td::actor::ask(pool.get(), &ExtMessagePoolTestHarness::verify_released_without_dispatch);
    co_return td::Unit{};
  });
}
}  // namespace tos::validator

namespace tos::validator {
namespace {
class VmExecutionCounter final : public td::LogInterface {
 public:
  unsigned starts{0}, finishes{0};
  std::string messages;
  void append(td::CSlice message, int level) override {
    if (level <= VERBOSITY_NAME(ERROR)) {
      td::default_log_interface->append(message, level);
    }
    const auto text = message.str();
    starts += text.find("starting VM") != std::string::npos;
    finishes += text.find("VM terminated with exit code") != std::string::npos;
    messages += text;
  }
};

TEST(ExtMessageChecker, RejectedContractExecutesVmExactlyOnce) {
  ASSERT_TRUE(vm::init_vm().is_ok());
  const auto path = std::filesystem::path(__FILE__).parent_path() / "pq-native/data/c04-pq-genesis.boc";
  auto file = td::read_file(path.string());
  ASSERT_TRUE(file.is_ok());
  auto root = vm::std_boc_deserialize(file.move_as_ok());
  ASSERT_TRUE(root.is_ok());
  auto state_root = root.move_as_ok();
  BlockIdExt id{masterchainId, shardIdAll, 0, state_root->get_hash().bits(), FileHash::zero()};
  auto extracted = block::ConfigInfo::extract_config(state_root, id, 0xFFFF);
  ASSERT_TRUE(extracted.is_ok());
  auto address_cell = extracted.ok()->get_config_param(0);
  ASSERT_TRUE(address_cell.not_null());
  StdSmcAddress address;
  ASSERT_TRUE(vm::load_cell_slice(address_cell).fetch_bits_to(address));
  auto state_result = MasterchainStateQ::fetch(id, td::BufferSlice{}, state_root);
  ASSERT_TRUE(state_result.is_ok());
  td::Ref<MasterchainState> state = state_result.move_as_ok();
  // Valid external envelope, but an empty body cannot authorize the config
  // contract. Count the transaction layer's actual vm.run entry/exit logs.
  auto message = vm::CellBuilder()
                     .store_long(2, 2)
                     .store_zeroes(2)
                     .store_long(2, 2)
                     .store_zeroes(1)
                     .store_long(-1, 8)
                     .store_bits(address.cbits(), 256)
                     .store_zeroes(4 + 1 + 1)
                     .finalize();
  auto encoded = vm::std_boc_serialize(message);
  ASSERT_TRUE(encoded.is_ok());
  VmExecutionCounter counter;
  auto previous_log = td::log_interface;
  auto previous_level = GET_VERBOSITY_LEVEL();
  td::log_interface = &counter;
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(DEBUG));
  {
    SCOPE_EXIT {
      td::log_interface = previous_log;
      SET_VERBOSITY_LEVEL(previous_level);
    };
    td::actor::TestScheduler scheduler;
    scheduler.run([&]() -> td::actor::Task<td::Unit> {
      auto checker = td::actor::create_actor<ExtMessageChecker>("vm-count", td::actor::ActorId<ValidatorManager>{});
      auto result = co_await td::actor::ask(checker.get(), &ExtMessageChecker::check, encoded.move_as_ok(),
                                            state->get_ext_msg_limits(), state)
                        .wrap();
      ASSERT_TRUE(result.is_error());
      co_return td::Unit{};
    });
  }
  if (counter.starts != 1 || counter.finishes != 1) {
    LOG(ERROR) << counter.messages;
  }
  EXPECT_EQ(counter.starts, 1u);
  EXPECT_EQ(counter.finishes, 1u);
}
}  // namespace
}  // namespace tos::validator

namespace tos::validator {
namespace {
void exercise_work_dispatch(bool mismatched_config, bool ordinary_account = false, bool accepted_loop = false) {
  ASSERT_TRUE(vm::init_vm().is_ok());
  auto file =
      td::read_file((std::filesystem::path(__FILE__).parent_path() / "pq-native/data/c04-pq-genesis.boc").string());
  ASSERT_TRUE(file.is_ok());
  auto decoded = vm::std_boc_deserialize(file.move_as_ok());
  ASSERT_TRUE(decoded.is_ok());
  auto root = decoded.move_as_ok();
  if (ordinary_account) {
    // Keep the funded bootstrap wallet and its code intact, but remove the
    // optional special-account list in this synthetic test configuration.
    block::gen::ShardStateUnsplit::Record shard;
    block::gen::McStateExtra::Record extra;
    block::gen::ConfigParams::Record params;
    ASSERT_TRUE(tlb::unpack_cell(root, shard));
    ASSERT_TRUE(tlb::unpack_cell(shard.custom->prefetch_ref(), extra));
    ASSERT_TRUE(tlb::csr_unpack(extra.config, params));
    vm::Dictionary config_dict{params.config, 32};
    ASSERT_TRUE(config_dict.lookup_delete_ref(td::BitArray<32>{31}).not_null());
    params.config = std::move(config_dict).extract_root_cell();
    td::Ref<vm::Cell> params_cell;
    ASSERT_TRUE(tlb::pack_cell(params_cell, params));
    extra.config = vm::load_cell_slice_ref(params_cell);
    td::Ref<vm::Cell> extra_cell;
    ASSERT_TRUE(tlb::pack_cell(extra_cell, extra));
    shard.custom = vm::load_cell_slice_ref(vm::CellBuilder().store_long(1, 1).store_ref(extra_cell).finalize());
    ASSERT_TRUE(tlb::pack_cell(root, shard));
  }
  BlockIdExt id{masterchainId, shardIdAll, 0, root->get_hash().bits(), FileHash::zero()};
  auto loaded = MasterchainStateQ::fetch(id, td::BufferSlice{}, root);
  ASSERT_TRUE(loaded.is_ok());
  td::Ref<MasterchainState> state = loaded.move_as_ok();
  auto config = block::ConfigInfo::extract_config(root, id, 0xFFFF);
  ASSERT_TRUE(config.is_ok());
  StdSmcAddress destination;
  if (ordinary_account) {
    StdSmcAddress config_address, elector_address;
    ASSERT_TRUE(vm::load_cell_slice(config.ok()->get_config_param(0)).fetch_bits_to(config_address));
    ASSERT_TRUE(vm::load_cell_slice(config.ok()->get_config_param(1)).fetch_bits_to(elector_address));
    block::gen::ShardStateUnsplit::Record shard;
    ASSERT_TRUE(tlb::unpack_cell(root, shard));
    vm::AugmentedDictionary accounts{vm::load_cell_slice_ref(shard.accounts), 256, block::tlb::aug_ShardAccounts};
    bool found = false;
    ASSERT_TRUE(accounts.check_for_each([&](td::Ref<vm::CellSlice>, td::ConstBitPtr key, int bits) {
      if (bits != 256) {
        return false;
      }
      StdSmcAddress candidate{key};
      if (!found && candidate != config_address && candidate != elector_address) {
        destination = candidate;
        found = true;
      }
      return true;
    }));
    ASSERT_TRUE(found);
    ASSERT_TRUE(!config.ok()->is_special_smartcontract(destination));
  } else {
    ASSERT_TRUE(vm::load_cell_slice(config.ok()->get_config_param(0)).fetch_bits_to(destination));
  }
  if (accepted_loop) {
    ASSERT_TRUE(ordinary_account);
    auto source =
        td::read_file((std::filesystem::path(__FILE__).parent_path() / "wallet-v5r2/post-accept-probe.boc").string());
    ASSERT_TRUE(source.is_ok());
    auto code = vm::std_boc_deserialize(source.move_as_ok());
    ASSERT_TRUE(code.is_ok());
    block::gen::ShardStateUnsplit::Record shard;
    ASSERT_TRUE(tlb::unpack_cell(root, shard));
    vm::AugmentedDictionary accounts{vm::load_cell_slice_ref(shard.accounts), 256, block::tlb::aug_ShardAccounts};
    block::gen::ShardAccount::Record entry;
    ASSERT_TRUE(tlb::csr_unpack(accounts.lookup(destination), entry));
    block::gen::Account::Record_account account;
    block::gen::AccountStorage::Record storage;
    ASSERT_TRUE(tlb::unpack_cell(entry.account, account));
    ASSERT_TRUE(tlb::csr_unpack(account.storage, storage));
    vm::CellBuilder replacement;
    replacement.store_long(storage.last_trans_lt, 64);
    replacement.append_cellslice(*storage.balance);
    replacement.store_long(1, 1).store_long(0, 2);
    ASSERT_TRUE(replacement.store_maybe_ref(code.move_as_ok()));
    ASSERT_TRUE(replacement.store_maybe_ref(vm::CellBuilder().store_long(0, 32).finalize()));
    replacement.store_long(0, 1);
    account.storage = vm::load_cell_slice_ref(replacement.finalize());
    ASSERT_TRUE(tlb::pack_cell(entry.account, account));
    td::Ref<vm::Cell> entry_cell;
    ASSERT_TRUE(tlb::pack_cell(entry_cell, entry));
    ASSERT_TRUE(accounts.set(destination.cbits(), 256, vm::load_cell_slice_ref(entry_cell)));
    vm::CellBuilder updated_accounts;
    ASSERT_TRUE(updated_accounts.append_cellslice_bool(accounts.get_root()));
    shard.accounts = updated_accounts.finalize();
    ASSERT_TRUE(tlb::pack_cell(root, shard));
    id = BlockIdExt{masterchainId, shardIdAll, 0, root->get_hash().bits(), FileHash::zero()};
    auto updated = MasterchainStateQ::fetch(id, td::BufferSlice{}, root);
    ASSERT_TRUE(updated.is_ok());
    state = updated.move_as_ok();
    config = block::ConfigInfo::extract_config(root, id, 0xFFFF);
    ASSERT_TRUE(config.is_ok());
    ASSERT_TRUE(!config.ok()->is_special_smartcontract(destination));
  }
  auto rejected_root = vm::CellBuilder()
                           .store_long(2, 2)
                           .store_zeroes(2)
                           .store_long(2, 2)
                           .store_zeroes(1)
                           .store_long(-1, 8)
                           .store_bits(destination.cbits(), 256)
                           .store_zeroes(4 + 1 + 1)
                           .store_long(accepted_loop ? 1 : 0, accepted_loop ? 1 : 0)
                           .store_long(accepted_loop ? 5000 : 0, accepted_loop ? 32 : 0)
                           .finalize();
  auto rejected_message = vm::std_boc_serialize(rejected_root);
  ASSERT_TRUE(rejected_message.is_ok());
  VmExecutionCounter counter;
  auto previous_log = td::log_interface;
  auto previous_level = GET_VERBOSITY_LEVEL();
  td::log_interface = &counter;
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(DEBUG));
  SCOPE_EXIT {
    td::log_interface = previous_log;
    SET_VERBOSITY_LEVEL(previous_level);
  };
  ExtMessageWorkProfile profile;
  profile.config_root = config.ok()->get_root_cell()->get_hash().bits();
  if (mismatched_config) {
    profile.config_root.data()[0] ^= 1;
  }
  profile.capacity = 2;
  profile.refill_units = 1;
  profile.refill_interval_ns = std::numeric_limits<std::int64_t>::max();
  profile.attempt_units = 1;
  profile.max_bytes = 65535;
  profile.max_depth = 512;
  auto options = ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{});
  ASSERT_TRUE(options.write().set_ext_message_work_profile(profile).is_ok());
  auto bytes = std::make_shared<adnl::AdnlExtByteBudget>(65535);
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> td::actor::Task<td::Unit> {
    auto pool =
        td::actor::create_actor<ExtMessagePool>("work-budget", options, td::actor::ActorId<ValidatorManager>{}, bytes);
    co_await td::actor::ask(pool.get(), &ExtMessagePool::update_last_masterchain_state, state);
    for (unsigned i = 0; i < 4; ++i) {
      if (i == 2) {
        auto changed_rate = profile;
        changed_rate.capacity = 3;
        auto refused =
            co_await td::actor::ask(pool.get(), &ExtMessagePool::configure_work_profile, changed_rate).wrap();
        ASSERT_TRUE(refused.is_error());
        EXPECT_EQ(refused.error().message(), "external admission rate or cost changes require restart");
        co_await td::actor::ask(pool.get(), &ExtMessagePool::configure_work_profile, profile);
        co_await td::actor::ask(pool.get(), &ExtMessagePool::update_options, options);
        auto unrelated = ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{});
        co_await td::actor::ask(pool.get(), &ExtMessagePool::update_options, unrelated);
      }
      td::optional<PublicKeyHash> peer;
      if (i % 2) {
        auto hash = td::Bits256::zero();
        hash.data()[0] = static_cast<unsigned char>(i);
        peer = PublicKeyHash{hash};
      }
      auto result = co_await td::actor::ask(
                        pool.get(), &ExtMessagePool::check_add_external_message,
                        i == 0 ? rejected_message.ok().clone() : td::BufferSlice{"not a bag of cells"}, 0, false, peer)
                        .wrap();
      if (accepted_loop && i == 0) {
        if (result.is_error()) {
          LOG(ERROR) << result.error();
        }
        ASSERT_TRUE(result.is_ok());
        EXPECT_EQ(bytes->used(), 0u);
        continue;
      }
      ASSERT_TRUE(result.is_error());
      if (mismatched_config) {
        EXPECT_EQ(result.error().message(), "external admission configuration is outside the work profile");
      } else if (i == 0) {
        EXPECT(result.error().message().str().find("External message was not accepted") != std::string::npos);
        if (ordinary_account) {
          std::fprintf(stderr, "Ordinary account rejection: %s\n", result.error().message().str().c_str());
          EXPECT(result.error().message().str().find("gas_used=0") != std::string::npos);
          EXPECT(result.error().message().str().find("steps=0,") == std::string::npos);
        }
      } else if (i == 1) {
        EXPECT(result.error().message().str().find("cannot deserialize bag-of-cells") != std::string::npos);
      } else {
        EXPECT_EQ(result.error().message(), "external message admission work budget exhausted");
      }
      EXPECT_EQ(bytes->used(), 0u);
    }
    auto stats = co_await td::actor::ask(pool.get(), &ExtMessagePool::prepare_stats);
    bool observed = false;
    for (const auto& stat : stats) {
      if (stat.first == "ext_msg_admission_work") {
        EXPECT_EQ(stat.second, mismatched_config ? "available:2 supported:false" : "available:0 supported:true");
        observed = true;
      }
    }
    EXPECT(observed);
    EXPECT_EQ(counter.starts, mismatched_config ? 0u : 1u);
    EXPECT_EQ(counter.finishes, mismatched_config ? 0u : 1u);
    if (accepted_loop) {
      std::fprintf(stderr, "Accepted ordinary VM: %s\n", counter.messages.c_str());
      EXPECT(counter.messages.find("credit=10000") != std::string::npos);
      EXPECT(counter.messages.find("External message is accepted, stopping TVM") != std::string::npos);
      EXPECT(counter.messages.find("accepted=true, success=true") != std::string::npos);
      EXPECT(counter.messages.find("gas: used=436") != std::string::npos);
    }
    co_return td::Unit{};
  });
}
}  // namespace
TEST(ExtMessagePool, WorkBudgetChargesFailuresAcrossPeerAndLocalSources) {
  exercise_work_dispatch(false);
}
TEST(ExtMessagePool, WorkBudgetRejectsUnmatchedConfigurationWithoutDispatch) {
  exercise_work_dispatch(true);
}
TEST(ExtMessagePool, WorkBudgetChargesAcceptedOrdinaryVmStopsAtAccept) {
  exercise_work_dispatch(false, true, true);
}
TEST(ExtMessagePool, WorkBudgetChargesRejectedOrdinaryVmReportingZeroGas) {
  exercise_work_dispatch(false, true);
}

namespace {
void exercise_queued_profile_rebind(bool initially_supported) {
  auto file =
      td::read_file((std::filesystem::path(__FILE__).parent_path() / "pq-native/data/c04-pq-genesis.boc").string());
  ASSERT_TRUE(file.is_ok());
  auto decoded = vm::std_boc_deserialize(file.move_as_ok());
  ASSERT_TRUE(decoded.is_ok());
  auto root = decoded.move_as_ok();
  BlockIdExt id{masterchainId, shardIdAll, 0, root->get_hash().bits(), FileHash::zero()};
  auto loaded = MasterchainStateQ::fetch(id, td::BufferSlice{}, root);
  ASSERT_TRUE(loaded.is_ok());
  td::Ref<MasterchainState> state = loaded.move_as_ok();
  auto config = block::ConfigInfo::extract_config(root, id, 0xFFFF);
  ASSERT_TRUE(config.is_ok());
  ExtMessageWorkProfile profile;
  profile.config_root = config.ok()->get_root_cell()->get_hash().bits();
  profile.capacity = 2;
  profile.refill_units = 1;
  profile.refill_interval_ns = std::numeric_limits<std::int64_t>::max();
  profile.attempt_units = 1;
  profile.max_bytes = 65535;
  profile.max_depth = 512;
  if (!initially_supported) {
    profile.config_root.data()[0] ^= 1;
  }
  auto options = ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{});
  ASSERT_TRUE(options.write().set_ext_message_work_profile(profile).is_ok());
  auto bytes = std::make_shared<adnl::AdnlExtByteBudget>(65535);
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> td::actor::Task<td::Unit> {
    auto pool = td::actor::create_actor<ExtMessagePoolTestHarness>("queued-profile", options, bytes);
    co_await td::actor::ask(pool.get(), &ExtMessagePool::update_last_masterchain_state, state);
    auto pending = td::actor::ask(pool.get(), &ExtMessagePool::check_add_external_message,
                                  td::BufferSlice{"queued malformed input"}, 0, false, td::optional<PublicKeyHash>{});
    // Change only the reviewed config pin while the real coroutine is suspended.
    // The admission decision must observe this update when the slot is released.
    profile.config_root.data()[0] ^= 1;
    co_await td::actor::ask(pool.get(), &ExtMessagePoolTestHarness::rebind_profile_and_release, profile);
    auto result = co_await std::move(pending).wrap();
    ASSERT_TRUE(result.is_error());
    if (initially_supported) {
      EXPECT_EQ(result.error().message(), "external admission configuration is outside the work profile");
    } else {
      EXPECT(result.error().message().str().find("cannot deserialize bag-of-cells") != std::string::npos);
    }
    co_await td::actor::ask(pool.get(), &ExtMessagePoolTestHarness::verify_work_released, !initially_supported);
    co_return td::Unit{};
  });
}
}  // namespace

TEST(ExtMessagePool, QueuedProfileRebindRejectsPreviouslySupportedConfig) {
  exercise_queued_profile_rebind(true);
}
TEST(ExtMessagePool, QueuedProfileRebindAdmitsNewlySupportedConfig) {
  exercise_queued_profile_rebind(false);
}

TEST(ExtMessagePool, QueuedCancellationReleasesBytesWithoutDispatchOrCharge) {
  auto parsed = ExtMessageWorkProfile::parse(std::string(64, 'a') + ",2,1,9223372036854775807,1,65535,512");
  ASSERT_TRUE(parsed.is_ok());
  auto options = ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{});
  ASSERT_TRUE(options.write().set_ext_message_work_profile(parsed.move_as_ok()).is_ok());
  auto bytes = std::make_shared<adnl::AdnlExtByteBudget>(65535);
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> td::actor::Task<td::Unit> {
    auto pool = td::actor::create_actor<ExtMessagePoolTestHarness>("cancel-queued", options, bytes);
    co_await td::actor::ask(pool.get(), &ExtMessagePool::update_last_masterchain_state,
                            td::Ref<MasterchainState>{td::make_ref<AdmissionLimitsState>(65535)});
    auto pending = td::actor::ask(pool.get(), &ExtMessagePool::check_add_external_message,
                                  td::BufferSlice{"queued input"}, 0, false, td::optional<PublicKeyHash>{});
    co_await td::actor::ask(pool.get(), &ExtMessagePoolTestHarness::cancel_waiter);
    auto result = co_await std::move(pending).wrap();
    ASSERT_TRUE(result.is_error());
    EXPECT_EQ(result.error().code(), ErrorCode::cancelled);
    EXPECT_EQ(result.error().message(), "queued admission cancelled");
    co_await td::actor::ask(pool.get(), &ExtMessagePoolTestHarness::verify_work_released, false);
    co_return td::Unit{};
  });
}

TEST(ExtMessagePool, StoppingPoolReleasesQueuedInput) {
  auto bytes = std::make_shared<adnl::AdnlExtByteBudget>(65535);
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> td::actor::Task<td::Unit> {
    auto pool = td::actor::create_actor<ExtMessagePoolTestHarness>("stop-queued", bytes);
    auto pending = td::actor::ask(pool.get(), &ExtMessagePool::check_add_external_message,
                                  td::BufferSlice{"queued input"}, 0, false, td::optional<PublicKeyHash>{});
    td::actor::send_closure(pool.get(), &ExtMessagePoolTestHarness::stop_while_queued);
    auto result = co_await std::move(pending).wrap();
    ASSERT_TRUE(result.is_error());
    co_return td::Unit{};
  });
  EXPECT_EQ(bytes->used(), 0u);
}
}  // namespace tos::validator
