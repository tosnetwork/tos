#include "emulator/tvm-emulator.hpp"
#include "fift/utils.h"
#include "td/utils/tests.h"
#include "vm/cells.h"
#include "vm/dict.h"

namespace {

td::Ref<vm::Cell> empty_cell() {
  return vm::CellBuilder().finalize();
}

td::Ref<vm::Cell> delayed_accept(bool accept = true) {
  return fift::compile_asm(td::Slice(accept ? "600 PUSHINT REPEAT:<{ NOP }> ACCEPT" : "600 PUSHINT REPEAT:<{ NOP }>"))
      .move_as_ok();
}

std::shared_ptr<const block::Config> credit_config(td::uint64 base_credit, td::uint64 master_credit,
                                                   bool omit_base = false) {
  vm::Dictionary dict(32);
  auto put = [&](int id, td::Ref<vm::Cell> cell) {
    td::BitArray<32> key;
    key.store_long(id);
    CHECK(dict.set_ref(key, cell));
  };
  put(0, vm::CellBuilder().store_zeroes(256).finalize());
  put(8, vm::CellBuilder().store_long(0xc4, 8).store_long(16, 32).store_zeroes(64).finalize());
  auto gas = [](td::uint64 credit) {
    return vm::CellBuilder()
        .store_long(0xdd, 8)
        .store_long(65536, 64)
        .store_long(1000000, 64)
        .store_long(static_cast<long long>(credit), 64)
        .store_long(10000000, 64)
        .store_long(100000000, 64)
        .store_long(1000000000, 64)
        .finalize();
  };
  put(20, gas(master_credit));
  if (!omit_base) {
    put(21, gas(base_credit));
  }
  auto config =
      std::make_shared<block::Config>(dict.get_root_cell(), td::Bits256::zero(), block::Config::needCapabilities);
  config->unpack().ensure();
  return config;
}

block::StdAddress address(int workchain) {
  return block::StdAddress(workchain, td::Bits256::zero());
}

td::Ref<vm::Tuple> raw_context(vm::StackEntry config) {
  vm::CellBuilder address_cell;
  address_cell.store_long(4, 3).store_long(0, 8).store_zeroes(256);
  std::vector<vm::StackEntry> info(18);
  info[8] = address_cell.as_cellslice_ref();
  info[9] = std::move(config);
  return vm::make_tuple_ref(td::make_cnt_ref<std::vector<vm::StackEntry>>(std::move(info)));
}

void expect_accepted(const tos::SmartContract::Answer& answer) {
  ASSERT_TRUE(answer.accepted);
  ASSERT_TRUE(answer.success);
  ASSERT_TRUE(answer.gas_used > 10000 && answer.gas_used < 20000);
}

void expect_credit_exhausted(const tos::SmartContract::Answer& answer) {
  ASSERT_TRUE(!answer.accepted);
  ASSERT_TRUE(!answer.success);
  ASSERT_EQ(answer.code, ~static_cast<int>(vm::Excno::out_of_gas));
}

}  // namespace

TEST(ExternalCredit, WorkchainDefaults) {
  tos::SmartContract base({delayed_accept(), empty_cell()});
  expect_accepted(base.send_external_message(empty_cell()));
  tos::SmartContract master({delayed_accept(), empty_cell()});
  expect_credit_exhausted(
      master.send_external_message(empty_cell(), tos::SmartContract::Args().set_address(address(-1))));
}

TEST(ExternalCredit, ConfiguredAndHistoricalProfiles) {
  for (auto credit : {10000, 20000}) {
    auto config = credit_config(credit, 10000);
    for (int wc : {0, -1}) {
      emulator::TvmEmulator emulator(delayed_accept(), empty_cell());
      emulator.set_c7(address(wc), 1, 10000000000, td::Bits256::zero(), config);
      auto answer = emulator.send_external_message(empty_cell());
      if (credit == 20000 && wc == 0) {
        expect_accepted(answer);
      } else {
        expect_credit_exhausted(answer);
      }
    }
  }
  // A configured masterchain value must override the fallback too.
  emulator::TvmEmulator emulator(delayed_accept(), empty_cell());
  emulator.set_c7(address(-1), 1, 10000000000, td::Bits256::zero(), credit_config(10000, 20000));
  expect_accepted(emulator.send_external_message(empty_cell()));
}

TEST(ExternalCredit, RawContextWorkchain) {
  auto config = credit_config(20000, 10000);
  for (int wc : {0, -1}) {
    vm::CellBuilder address_cell;
    address_cell.store_long(4, 3).store_long(wc, 8).store_zeroes(256);
    std::vector<vm::StackEntry> info(18);
    info[8] = address_cell.as_cellslice_ref();
    info[9] = config->get_root_cell();
    auto c7 = td::make_cnt_ref<std::vector<vm::StackEntry>>();
    c7.write().emplace_back(td::make_cnt_ref<std::vector<vm::StackEntry>>(std::move(info)));
    emulator::TvmEmulator emulator(delayed_accept(), empty_cell());
    emulator.set_c7_raw(c7);
    auto answer = emulator.send_external_message(empty_cell());
    if (wc == 0) {
      expect_accepted(answer);
    } else {
      expect_credit_exhausted(answer);
    }
  }
}

TEST(ExternalCredit, ExplicitLimitsAndAcceptance) {
  tos::SmartContract contract({delayed_accept(), empty_cell()});
  expect_credit_exhausted(contract.send_external_message(
      empty_cell(), tos::SmartContract::Args().set_limits(vm::GasLimits(0, 1000000, 10000))));
  tos::SmartContract unaccepted({delayed_accept(false), empty_cell()});
  auto answer = unaccepted.send_external_message(empty_cell());
  ASSERT_TRUE(!answer.accepted);
  ASSERT_TRUE(!answer.success);
  ASSERT_TRUE(answer.gas_used > 10000);
}

TEST(ExternalCredit, MissingConfigDoesNotFallBack) {
  emulator::TvmEmulator emulator(delayed_accept(), empty_cell());
  emulator.set_c7(address(0), 1, 10000000000, td::Bits256::zero(), credit_config(20000, 10000, true));
  auto answer = emulator.send_external_message(empty_cell());
  ASSERT_TRUE(!answer.accepted);
  ASSERT_TRUE(!answer.success);
  ASSERT_EQ(answer.gas_used, 0);
  ASSERT_TRUE(answer.vm_log.find("gas prices is absent") != std::string::npos);
}

TEST(ExternalCredit, RawContextWithoutConfig) {
  emulator::TvmEmulator emulator(delayed_accept(), empty_cell());
  emulator.set_c7_raw(raw_context(vm::StackEntry{}));
  expect_accepted(emulator.send_external_message(empty_cell()));
}

TEST(ExternalCredit, MalformedRawConfigDoesNotFallBack) {
  auto valid = credit_config(20000, 10000);
  std::vector<vm::StackEntry> invalid_configs{vm::StackEntry(empty_cell()), vm::StackEntry(td::make_refint(1))};
  // Exercise dictionary parsing, address validation and Config::unpack failures.
  for (int fault : {0, 1, 2}) {
    vm::Dictionary dict(valid->get_root_cell(), 32);
    td::BitArray<32> key;
    key.store_long(fault == 2 ? 8 : 0);
    if (fault == 0) {
      CHECK(dict.lookup_delete_ref(key).not_null());
    } else {
      CHECK(dict.set_ref(key, empty_cell()));
    }
    invalid_configs.emplace_back(dict.get_root_cell());
  }
  for (const auto& config : invalid_configs) {
    // An explicit gas envelope must not turn a parse failure into valid context.
    for (bool explicit_limits : {false, true}) {
      tos::SmartContract contract({delayed_accept(), empty_cell()});
      auto args = tos::SmartContract::Args().set_c7(raw_context(config));
      if (explicit_limits) {
        args.set_limits(vm::GasLimits(0, 1000000, 20000));
      }
      auto answer = contract.send_external_message(empty_cell(), std::move(args));
      ASSERT_TRUE(!answer.accepted);
      ASSERT_TRUE(!answer.success);
      ASSERT_EQ(answer.gas_used, 0);
      ASSERT_EQ(answer.code, ~static_cast<int>(vm::Excno::fatal));
      ASSERT_TRUE(answer.vm_log.find("Invalid external-message c7 configuration") != std::string::npos);
    }
  }
}

TEST(ExternalCredit, MalformedRawContextDoesNotFallBack) {
  std::vector<td::Ref<vm::Tuple>> contexts{{},
                                           vm::make_tuple_ref(),
                                           vm::make_tuple_ref(td::make_refint(1)),
                                           vm::make_tuple_ref(td::make_cnt_ref<std::vector<vm::StackEntry>>(9))};
  for (const auto& c7 : contexts) {
    emulator::TvmEmulator emulator(delayed_accept(), empty_cell());
    emulator.set_c7_raw(c7);
    auto answer = emulator.send_external_message(empty_cell());
    ASSERT_TRUE(!answer.accepted);
    ASSERT_EQ(answer.gas_used, 0);
    ASSERT_TRUE(answer.vm_log.find("Invalid external-message c7 configuration") != std::string::npos);
  }
}
