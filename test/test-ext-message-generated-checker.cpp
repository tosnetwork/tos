// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <string>

#include "block/block-parse.h"
#include "quic/quic-sender.h"
#include "td/actor/TestScheduler.h"
#include "td/utils/filesystem.h"
#include "td/utils/tests.h"
#include "validator/impl/applied-ext-message-cleanup.hpp"
#include "validator/impl/ext-message-pool.hpp"
#include "validator/impl/shard.hpp"
#include "validator/manager.hpp"
#include "vm/boc.h"
#include "vm/vm.h"

namespace tos::validator {
namespace {

td::Ref<vm::Cell> read_fixture(const char* filename) {
  const char* directory = std::getenv("TOS_ADMISSION_GENERATED_DIR");
  ASSERT_TRUE(directory != nullptr);
  auto encoded = td::read_file((std::filesystem::path(directory) / filename).string());
  ASSERT_TRUE(encoded.is_ok());
  auto decoded = vm::std_boc_deserialize(encoded.move_as_ok());
  ASSERT_TRUE(decoded.is_ok());
  return decoded.move_as_ok();
}

struct GeneratedStates {
  td::Ref<MasterchainState> masterchain;
  td::Ref<ShardState> basechain;
  td::Bits256 config_root;
  StdSmcAddress destination;
};

td::Ref<vm::Cell> add_probe_account(td::Ref<vm::Cell> root, const block::gen::ShardAccount::Record& prototype,
                                    WorkchainId workchain, const StdSmcAddress& destination, td::Ref<vm::Cell> code) {
  block::gen::ShardStateUnsplit::Record shard;
  ASSERT_TRUE(tlb::unpack_cell(root, shard));
  vm::AugmentedDictionary accounts{vm::load_cell_slice_ref(shard.accounts), 256, block::tlb::aug_ShardAccounts};
  auto entry = prototype;
  block::gen::Account::Record_account account;
  block::gen::AccountStorage::Record storage;
  ASSERT_TRUE(tlb::unpack_cell(entry.account, account));
  ASSERT_TRUE(tlb::csr_unpack(account.storage, storage));
  account.addr = vm::load_cell_slice_ref(vm::CellBuilder()
                                             .store_long(2, 2)
                                             .store_long(0, 1)
                                             .store_long(workchain, 8)
                                             .store_bits(destination.cbits(), 256)
                                             .finalize());
  vm::CellBuilder replacement;
  replacement.store_long(storage.last_trans_lt, 64).append_cellslice(*storage.balance);
  replacement.store_long(1, 1).store_long(0, 2);
  ASSERT_TRUE(replacement.store_maybe_ref(std::move(code)));
  ASSERT_TRUE(replacement.store_maybe_ref(vm::CellBuilder().store_long(0, 32).finalize()));
  replacement.store_long(0, 1);
  account.storage = vm::load_cell_slice_ref(replacement.finalize());
  ASSERT_TRUE(tlb::pack_cell(entry.account, account));
  td::Ref<vm::Cell> entry_cell;
  ASSERT_TRUE(tlb::pack_cell(entry_cell, entry));
  ASSERT_TRUE(
      accounts.set(destination.cbits(), 256, vm::load_cell_slice_ref(entry_cell), vm::Dictionary::SetMode::Add));
  vm::CellBuilder updated_accounts;
  ASSERT_TRUE(updated_accounts.append_cellslice_bool(accounts.get_root()));
  shard.accounts = updated_accounts.finalize();
  auto total = accounts.get_root_extra();
  ASSERT_TRUE(total.write().advance(5));
  block::CurrencyCollection balance;
  ASSERT_TRUE(balance.validate_unpack(total));
  ASSERT_TRUE(balance.pack_to(shard.r1.total_balance));
  ASSERT_TRUE(tlb::pack_cell(root, shard));
  return root;
}

GeneratedStates generated_states() {
  auto masterchain_root = read_fixture("zerostate.boc");
  auto basechain_root = read_fixture("basestate0.boc");
  auto code = read_fixture("checker-gas-probe.boc");
  BlockIdExt initial_id{masterchainId, shardIdAll, 0, masterchain_root->get_hash().bits(), FileHash::zero()};
  auto initial_config = block::ConfigInfo::extract_config(masterchain_root, initial_id, 0xFFFF);
  ASSERT_TRUE(initial_config.is_ok());
  const td::Bits256 config_root{initial_config.ok()->get_root_cell()->get_hash().bits()};
  EXPECT_EQ(initial_config.ok()->get_global_version(), 18);
  auto basechain_prices = initial_config.ok()->get_gas_limits_prices(false);
  auto masterchain_prices = initial_config.ok()->get_gas_limits_prices(true);
  ASSERT_TRUE(basechain_prices.is_ok() && masterchain_prices.is_ok());
  EXPECT_EQ(basechain_prices.ok().gas_credit, 20000u);
  EXPECT_EQ(masterchain_prices.ok().gas_credit, 10000u);

  // Retain the entire generated configuration, including the special-account
  // list. Only ordinary funded probe accounts and their shard descriptor are
  // added to these synthetic account states; no configuration cell is replaced.
  StdSmcAddress config_address, elector_address;
  ASSERT_TRUE(vm::load_cell_slice(initial_config.ok()->get_config_param(0)).fetch_bits_to(config_address));
  ASSERT_TRUE(vm::load_cell_slice(initial_config.ok()->get_config_param(1)).fetch_bits_to(elector_address));
  block::gen::ShardStateUnsplit::Record shard;
  ASSERT_TRUE(tlb::unpack_cell(masterchain_root, shard));
  vm::AugmentedDictionary accounts{vm::load_cell_slice_ref(shard.accounts), 256, block::tlb::aug_ShardAccounts};
  block::gen::ShardAccount::Record prototype;
  bool found = false;
  ASSERT_TRUE(accounts.check_for_each_extra(
      [&](td::Ref<vm::CellSlice> value, td::Ref<vm::CellSlice>, td::ConstBitPtr key, int bits) {
        if (bits != 256) {
          return false;
        }
        StdSmcAddress candidate{key};
        if (!found && candidate != config_address && candidate != elector_address) {
          ASSERT_TRUE(tlb::csr_unpack(value, prototype));
          found = true;
        }
        return true;
      }));
  ASSERT_TRUE(found);
  StdSmcAddress destination = StdSmcAddress::zero();
  destination.data()[0] = 0x57;
  destination.data()[31] = 0x18;
  ASSERT_TRUE(!initial_config.ok()->is_special_smartcontract(destination));
  ASSERT_TRUE(accounts.lookup(destination).is_null());
  masterchain_root = add_probe_account(masterchain_root, prototype, masterchainId, destination, code);
  basechain_root = add_probe_account(basechain_root, prototype, basechainId, destination, code);

  block::gen::ShardStateUnsplit::Record basechain;
  ASSERT_TRUE(tlb::unpack_cell(basechain_root, basechain));
  BlockIdExt basechain_id{basechainId, shardIdAll, 0, basechain_root->get_hash().bits(), FileHash::zero()};
  auto basechain_state = ShardStateQ::fetch(basechain_id, td::BufferSlice{}, basechain_root);
  ASSERT_TRUE(basechain_state.is_ok());
  block::McShardHash descriptor{basechain_id, 0, basechain.gen_lt};
  vm::CellBuilder leaf;
  ASSERT_TRUE(leaf.store_bool_bool(false));
  ASSERT_TRUE(descriptor.pack(leaf));
  vm::Dictionary shard_hashes{32};
  ASSERT_TRUE(shard_hashes.set_ref(td::BitArray<32>{basechainId}, leaf.finalize()));
  block::ShardConfig shard_config{shard_hashes.get_root_cell()};
  ASSERT_TRUE(shard_config.is_valid());
  ASSERT_TRUE(tlb::unpack_cell(masterchain_root, shard));
  block::gen::McStateExtra::Record extra;
  ASSERT_TRUE(tlb::unpack_cell(shard.custom->prefetch_ref(), extra));
  extra.shard_hashes = shard_config.get_root_csr();
  td::Ref<vm::Cell> extra_cell;
  ASSERT_TRUE(tlb::pack_cell(extra_cell, extra));
  shard.custom = vm::load_cell_slice_ref(vm::CellBuilder().store_long(1, 1).store_ref(extra_cell).finalize());
  ASSERT_TRUE(tlb::pack_cell(masterchain_root, shard));
  BlockIdExt masterchain_id{masterchainId, shardIdAll, 0, masterchain_root->get_hash().bits(), FileHash::zero()};
  auto masterchain_state = MasterchainStateQ::fetch(masterchain_id, td::BufferSlice{}, masterchain_root);
  ASSERT_TRUE(masterchain_state.is_ok());
  auto current_config = block::ConfigInfo::extract_config(masterchain_root, masterchain_id, 0xFFFF);
  ASSERT_TRUE(current_config.is_ok());
  ASSERT_TRUE(td::Bits256{current_config.ok()->get_root_cell()->get_hash().bits()} == config_root);
  return {masterchain_state.move_as_ok(), basechain_state.move_as_ok(), config_root, destination};
}

class GeneratedCheckerManager final : public ValidatorManagerImpl {
 public:
  explicit GeneratedCheckerManager(td::Ref<ShardState> basechain)
      : ValidatorManagerImpl(ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{}), "", {}, {}, {}, {}, {})
      , basechain_(std::move(basechain)) {
  }
  void start_up() override {
  }
  void wait_block_state_short(BlockIdExt block_id, td::uint32, td::Timestamp, bool,
                              td::Promise<td::Ref<ShardState>> promise) override {
    ASSERT_TRUE(block_id == basechain_->get_block_id());
    promise.set_value(td::Ref<ShardState>{basechain_});
  }

 private:
  td::Ref<ShardState> basechain_;
};

class ExecutionLog final : public td::LogInterface {
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

void exercise_generated_checker(WorkchainId workchain, unsigned operation, bool accepted) {
  ASSERT_TRUE(vm::init_vm().is_ok());
  auto states = generated_states();
  auto message = vm::CellBuilder()
                     .store_long(2, 2)
                     .store_zeroes(2)
                     .store_long(2, 2)
                     .store_zeroes(1)
                     .store_long(workchain, 8)
                     .store_bits(states.destination.cbits(), 256)
                     .store_zeroes(4 + 1 + 1)
                     .store_long(operation, 8)
                     .store_long(accepted ? 200000 : 1, 32)
                     .store_long(5000, 32)
                     .finalize();
  auto encoded = vm::std_boc_serialize(message);
  ASSERT_TRUE(encoded.is_ok());
  ExtMessageWorkProfile profile;
  profile.config_root = states.config_root;
  profile.capacity = 2;
  profile.refill_units = 1;
  profile.refill_interval_ns = std::numeric_limits<std::int64_t>::max();
  profile.attempt_units = 1;
  profile.max_bytes = 65535;
  profile.max_depth = 512;
  auto options = ValidatorManagerOptions::create(BlockIdExt{}, BlockIdExt{});
  ASSERT_TRUE(options.write().set_ext_message_work_profile(profile).is_ok());
  auto bytes = std::make_shared<adnl::AdnlExtByteBudget>(65535);
  ExecutionLog counter;
  auto previous_log = td::log_interface;
  auto previous_level = GET_VERBOSITY_LEVEL();
  td::log_interface = &counter;
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(DEBUG));
  SCOPE_EXIT {
    td::log_interface = previous_log;
    SET_VERBOSITY_LEVEL(previous_level);
  };
  td::actor::TestScheduler scheduler;
  scheduler.run([&]() -> td::actor::Task<> {
    auto manager = td::actor::create_actor<GeneratedCheckerManager>("generated-checker-manager", states.basechain);
    auto pool = td::actor::create_actor<ExtMessagePool>("generated-checker-pool", options, manager.get(), bytes);
    co_await td::actor::ask(pool, &ExtMessagePool::update_last_masterchain_state, states.masterchain);
    auto result = co_await td::actor::ask(pool, &ExtMessagePool::check_add_external_message, encoded.ok().clone(), 0,
                                          false, td::optional<PublicKeyHash>{})
                      .wrap();
    if (accepted && result.is_error()) {
      LOG(ERROR) << result.error();
    }
    EXPECT(result.is_ok() == accepted);
    if (!accepted && result.is_error()) {
      EXPECT(result.error().message().str().find("External message was not accepted") != std::string::npos);
      EXPECT(result.error().message().str().find("gas_used=0") != std::string::npos);
      EXPECT(result.error().message().str().find("steps=0,") == std::string::npos);
    }
    EXPECT_EQ(bytes->used(), 0u);
    for (unsigned i = 0; i < 2; ++i) {
      auto peer = td::Bits256::zero();
      peer.data()[0] = static_cast<unsigned char>(i + 1);
      auto rejected = co_await td::actor::ask(pool, &ExtMessagePool::check_add_external_message,
                                              td::BufferSlice{"not a bag of cells"}, 0, false,
                                              td::optional<PublicKeyHash>{PublicKeyHash{peer}})
                          .wrap();
      ASSERT_TRUE(rejected.is_error());
      const char* expected =
          i == 0 ? "cannot deserialize bag-of-cells" : "external message admission work budget exhausted";
      EXPECT(rejected.error().message().str().find(expected) != std::string::npos);
      EXPECT_EQ(bytes->used(), 0u);
    }
    EXPECT_EQ(counter.starts, 1u);
    EXPECT_EQ(counter.finishes, 1u);
    const auto credit = workchain == basechainId ? "credit=20000" : "credit=10000";
    EXPECT(counter.messages.find(credit) != std::string::npos);
    if (accepted) {
      EXPECT(counter.messages.find("External message is accepted, stopping TVM") != std::string::npos);
      EXPECT(counter.messages.find("accepted=true, success=true") != std::string::npos);
      const auto marker = counter.messages.find("gas: used=");
      ASSERT_TRUE(marker != std::string::npos);
      const auto begin = marker + std::string("gas: used=").size();
      const auto gas = std::stoull(counter.messages.substr(begin));
      EXPECT(gas < (workchain == basechainId ? 20000u : 10000u));
      std::fprintf(stderr, "Generated checker wc=%d operation=%u gas=%llu config=%s\n", workchain, operation, gas,
                   states.config_root.to_hex().c_str());
    } else {
      EXPECT(counter.messages.find("External message is accepted, stopping TVM") == std::string::npos);
      EXPECT(counter.messages.find("out_of_gas=true") != std::string::npos);
    }
    std::fprintf(stderr, "Generated checker execution: %s\n", counter.messages.c_str());
    co_return td::Unit{};
  });
}

TEST(GeneratedExtMessageChecker, BasechainStopsAtAccept) {
  exercise_generated_checker(basechainId, 0, true);
}
TEST(GeneratedExtMessageChecker, BasechainStopsAtSetGasLimit) {
  exercise_generated_checker(basechainId, 1, true);
}
TEST(GeneratedExtMessageChecker, MasterchainStopsAtAccept) {
  exercise_generated_checker(masterchainId, 0, true);
}
TEST(GeneratedExtMessageChecker, MasterchainStopsAtSetGasLimit) {
  exercise_generated_checker(masterchainId, 1, true);
}
TEST(GeneratedExtMessageChecker, BasechainRejectsInsufficientSetGasLimit) {
  exercise_generated_checker(basechainId, 1, false);
}
TEST(GeneratedExtMessageChecker, MasterchainRejectsInsufficientSetGasLimit) {
  exercise_generated_checker(masterchainId, 1, false);
}

}  // namespace
}  // namespace tos::validator
