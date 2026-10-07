/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <atomic>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>

#include "auto/tl/lite_api.h"
#include "auto/tl/lite_api.hpp"
#include "block/get-method-context.h"
#include "td/actor/actor.h"
#include "td/utils/Time.h"
#include "td/utils/base64.h"
#include "tl-utils/lite-utils.hpp"
#include "tos/lite-tl.hpp"
#include "validator/fabric.h"
#include "validator/impl/liteserver.hpp"
#include "validator/manager-disk.hpp"
#include "vm/vm.h"

#include "getter-context-fixture.h"
#include "getter-context-reference.h"

namespace {

using namespace getter_fixture;

int failures = 0;
int checks = 0;
std::string selected;
std::string capture;
std::string baseline;

void check(const std::string& name, bool ok, const std::string& detail) {
  ++checks;
  if (!ok) {
    ++failures;
    std::fprintf(stderr, "GETTER_CONTEXT_FAIL %s: %s\n", name.c_str(), detail.c_str());
  }
}

td::BitArray<256> context_seed(const Ref<vm::Tuple>& c7) {
  require(c7.not_null() && c7->size() == 1, "reference c7");
  auto info = c7->at(0).as_tuple();
  require(info.not_null() && info->size() >= 10 && info->at(6).is_int(), "reference seed slot");
  td::BitArray<256> seed;
  require(info->at(6).as_int()->export_bits(seed.bits(), 256, false), "reference seed bits");
  return seed;
}

std::string serialize_context(const Ref<vm::Tuple>& c7) {
  vm::CellBuilder builder;
  require(vm::StackEntry{c7}.serialize(builder), "context serialization");
  return boc(builder.finalize_novm()).as_slice().str();
}

void context_cases(const std::string& zero, const std::string& elector, const std::string& config_code) {
  for (int version : {3, 4, 6, 9, 11, 14, 15, 17}) {
    auto state = build(zero, elector, config_code, version);
    const auto& getter = state.getters.back();
    auto before = getter_reference::prepare_vm_c7(state.now, state.lt, address_slice(getter.address), getter.balance,
                                                  state.config.get(), getter.code, getter.due_payment);
    auto after =
        block::prepare_get_method_c7(state.now, state.lt, address_slice(getter.address), getter.balance,
                                     state.config.get(), getter.code, getter.due_payment, context_seed(before));
    const auto name = "context-v" + std::to_string(version);
    check(name, after.not_null(), "the extracted context is null");
    if (after.not_null()) {
      check(name, serialize_context(before) == serialize_context(after),
            "the full c7 differs from the independent oracle");
    }
    auto info = before->at(0).as_tuple();
    require(info->at(7).as_tuple()->at(0).as_int()->unsigned_fits_bits(101), "wide balance field");
    require(!info->at(7).as_tuple()->at(0).as_int()->unsigned_fits_bits(64), "the balance exceeds uint64");
    require(info->at(7).as_tuple()->at(1).is_cell(), "extra currencies are present");
    if (version >= 4) {
      require(info->at(13).is_tuple(), "previous blocks are present");
    }
    if (version >= 6) {
      require(info->at(14).is_tuple(), "unpacked configuration is present");
      require(info->at(15).is_int() && info->at(15).as_int()->to_long() == 123456789, "due payment is present");
      require(info->at(16).is_int() && info->at(16).as_int()->to_long() == 43210, "precompiled gas is present");
    }
  }
  auto state = build(zero, elector, config_code);
  const auto& getter = state.getters.back();
  auto before = getter_reference::prepare_vm_c7(state.now, state.lt, address_slice(getter.address), getter.balance);
  auto after = block::prepare_get_method_c7(state.now, state.lt, address_slice(getter.address), getter.balance, nullptr,
                                            {}, td::zero_refint(), context_seed(before));
  check("context-no-config", after.not_null(), "the basic context is null");
  if (after.not_null()) {
    check("context-no-config", serialize_context(before) == serialize_context(after), "the basic c7 differs");
  }
}

struct Result {
  int exit;
  td::int64 gas;
  std::string stack;
};

Result run(const State& state, const Getter& getter, bool reference) {
  auto c7 = getter_reference::prepare_vm_c7(state.now, state.lt, address_slice(getter.address), getter.balance,
                                            state.config.get(), getter.code, getter.due_payment);
  if (!reference) {
    c7 = block::prepare_get_method_c7(state.now, state.lt, address_slice(getter.address), getter.balance,
                                      state.config.get(), getter.code, getter.due_payment, context_seed(c7));
  }
  auto libraries = reference ? getter_reference::libraries(*state.config, getter.libraries)
                             : block::get_method_libraries(*state.config, getter.libraries);
  auto stack = td::make_ref<vm::Stack>();
  for (const auto& argument : getter.arguments) {
    stack.write().push(argument);
  }
  stack.write().push_smallint(static_cast<td::int32>((td::crc16(getter.method) & 0xffff) | 0x10000));
  vm::GasLimits gas{300000, 300000};
  vm::VmState vm{
      getter.code,         state.config->get_global_version(), std::move(stack), gas, 1, getter.data, vm::VmLog::Null(),
      std::move(libraries)};
  vm.set_c7(std::move(c7));
  const int exit = ~vm.run();
  vm::CellBuilder builder;
  require(vm.get_stack_ref()->serialize(builder), "getter result serialization");
  return {exit, vm.get_gas_limits().gas_consumed(), boc(builder.finalize_novm()).as_slice().str()};
}

void vm_cases(const std::string& zero, const std::string& elector, const std::string& config_code) {
  auto state = build(zero, elector, config_code);
  Getter all = state.getters.back();
  all.code = must(fift::compile_asm("DROP c7 PUSH"), "all-context getter");
  auto before = getter_reference::prepare_vm_c7(state.now, state.lt, address_slice(all.address), all.balance,
                                                state.config.get(), all.code, all.due_payment);
  const auto seed = context_seed(before);
  auto after = block::prepare_get_method_c7(state.now, state.lt, address_slice(all.address), all.balance,
                                            state.config.get(), all.code, all.due_payment, seed);
  auto execute = [&](Ref<vm::Tuple> c7, std::vector<Ref<vm::Cell>> libraries) {
    auto stack = td::make_ref<vm::Stack>();
    stack.write().push_smallint(0x10000);
    vm::VmState vm{all.code,
                   state.config->get_global_version(),
                   std::move(stack),
                   vm::GasLimits{300000, 300000},
                   1,
                   all.data,
                   vm::VmLog::Null(),
                   std::move(libraries)};
    vm.set_c7(std::move(c7));
    int exit = ~vm.run();
    vm::CellBuilder result;
    require(vm.get_stack_ref()->serialize(result), "all-context result");
    return Result{exit, vm.get_gas_limits().gas_consumed(), boc(result.finalize_novm()).as_slice().str()};
  };
  const auto old_result = execute(before, getter_reference::libraries(*state.config, all.libraries));
  const auto new_result = execute(after, block::get_method_libraries(*state.config, all.libraries));
  require(old_result.exit == 0, "the context-sensitive getter executes");
  check("vm-context",
        new_result.exit == old_result.exit && new_result.gas == old_result.gas && new_result.stack == old_result.stack,
        "exit code, gas or full stack BOC differs");
  for (const auto& getter : state.getters) {
    const auto original = run(state, getter, true);
    const auto extracted = run(state, getter, false);
    require(original.exit == 0, "reference real getter executes");
    check("vm-" + getter.name,
          original.exit == extracted.exit && original.gas == extracted.gas && original.stack == extracted.stack,
          "the real getter's full result differs");
  }
}

void library_cases(const std::string& zero, const std::string& elector, const std::string& config_code) {
  for (int version : {14, 15}) {
    for (bool global : {false, true}) {
      auto state = build(zero, elector, config_code, version, global);
      auto before = getter_reference::libraries(*state.config, state.account_library);
      auto after = block::get_method_libraries(*state.config, state.account_library);
      const auto name = "libraries-v" + std::to_string(version) + (global ? "-global" : "-no-global");
      require(before.size() == (global ? 1U : 0U) + (version < 15 ? 1U : 0U), "the library oracle speaks");
      check(name, before.size() == after.size(), "library collections differ in count");
      if (before.size() == after.size()) {
        for (std::size_t index = 0; index < before.size(); ++index) {
          check(name, before[index]->get_hash() == after[index]->get_hash(), "library order or contents differ");
        }
      }
      for (bool account : {false, true}) {
        Getter getter = state.getters.back();
        auto library =
            account ? must(fift::compile_asm("DROP 23 PUSHINT"), "account library getter") : state.global_library;
        getter.code = library_reference(library);
        getter.libraries = state.account_library;
        auto original = run(state, getter, true);
        auto extracted = run(state, getter, false);
        const bool available = account ? version < 15 : global;
        require((original.exit == 0) == available, "the library reference resolves only when eligible");
        check(name + (account ? "-account-execution" : "-global-execution"),
              original.exit == extracted.exit && original.gas == extracted.gas && original.stack == extracted.stack,
              "library resolution changes exit code, gas or full result BOC");
      }
    }
  }
}

class FixtureManager final : public tos::validator::ValidatorManagerImpl {
 public:
  explicit FixtureManager(const State& state)
      : ValidatorManagerImpl(tos::PublicKeyHash::zero(), {}, tos::ShardIdFull{tos::masterchainId}, state.id, "")
      , id_(state.id)
      , state_(must(tos::validator::create_shard_state(state.id, state.root), "manager fixture state"))
      , block_(must(tos::validator::create_block(state.id, boc(state.block)), "manager fixture block")) {
  }
  void start_up() override {
  }
  void get_block_data_for_litequery(tos::BlockIdExt id, td::Promise<Ref<tos::validator::BlockData>> promise) override {
    if (id != id_) {
      promise.set_error(td::Status::Error("no such fixture block"));
    } else {
      promise.set_value(td::Ref<tos::validator::BlockData>{block_});
    }
  }
  void get_block_state_for_litequery(tos::BlockIdExt id,
                                     td::Promise<Ref<tos::validator::ShardState>> promise) override {
    if (id != id_) {
      promise.set_error(td::Status::Error("no such fixture state"));
    } else {
      promise.set_value(td::Ref<tos::validator::ShardState>{state_});
    }
  }
  void add_lite_query_stats(int, bool) override {
  }

 private:
  tos::BlockIdExt id_;
  Ref<tos::validator::ShardState> state_;
  Ref<tos::validator::BlockData> block_;
};

std::map<std::string, std::string> read_baseline() {
  std::map<std::string, std::string> entries;
  if (baseline.empty()) {
    return entries;
  }
  std::ifstream file(baseline);
  require(file.good(), "open before-extraction results");
  std::string line;
  while (std::getline(file, line)) {
    auto tab = line.find('\t');
    require(tab != std::string::npos, "baseline row");
    require(entries.emplace(line.substr(0, tab), line.substr(tab + 1)).second, "unique baseline row");
  }
  return entries;
}

void liteserver_cases(const std::string& zero, const std::string& elector, const std::string& config_code) {
  auto state = build(zero, elector, config_code);
  auto expected = read_baseline();
  std::ofstream captured;
  if (!capture.empty()) {
    captured.open(capture);
    require(captured.good(), "open capture output");
  }
  td::actor::Scheduler scheduler{std::vector<td::actor::Scheduler::NodeInfo>{2}};
  td::actor::ActorOwn<FixtureManager> manager;
  scheduler.run_in_context([&] { manager = td::actor::create_actor<FixtureManager>("fixture-manager", state); });
  for (const auto& getter : state.getters) {
    for (int mode : {4, 12, 44}) {
      std::mutex mutex;
      bool done = false;
      td::Result<td::BufferSlice> reply{td::Status::Error("no reply")};
      scheduler.run_in_context([&] {
        auto stack = td::make_ref<vm::Stack>();
        for (const auto& value : getter.arguments) {
          stack.write().push(value);
        }
        vm::CellBuilder params;
        require(stack->serialize(params), "query parameters");
        auto query = tos::create_serialize_tl_object<tos::lite_api::liteServer_runSmcMethod>(
            mode, tos::create_tl_lite_block_id(state.id),
            tos::create_tl_object<tos::lite_api::liteServer_accountId>(getter.address.workchain, getter.address.addr),
            static_cast<td::int64>((td::crc16(getter.method) & 0xffff) | 0x10000), boc(params.finalize_novm()));
        tos::validator::LiteQuery::run_query(std::move(query), manager.get(), {}, {},
                                             [&](td::Result<td::BufferSlice> value) {
                                               std::lock_guard lock(mutex);
                                               reply = std::move(value);
                                               done = true;
                                             });
      });
      auto deadline = td::Timestamp::in(30);
      for (;;) {
        scheduler.run(0.001);
        {
          std::lock_guard lock(mutex);
          if (done) {
            break;
          }
        }
        require(!deadline.is_in_past(), "lite-server query completed before watchdog");
      }
      auto decoded = must(tos::fetch_tl_object<tos::lite_api::liteServer_runMethodResult>(
                              must(std::move(reply), "lite-server answered"), true),
                          "lite-server result");
      const auto reference = run(state, getter, true);
      const std::string result = decoded->result_.as_slice().str();
      check("liteserver-" + getter.name, decoded->exit_code_ == reference.exit && result == reference.stack,
            "the real lite-server exit code or full result BOC differs from its original VM path");
      const auto row = std::to_string(decoded->exit_code_) + "\t" + std::to_string(reference.gas) + "\t" +
                       td::base64_encode(decoded->result_.as_slice());
      if (captured.is_open() && mode == 4) {
        captured << getter.name << '\t' << row << '\n';
      }
      if (!baseline.empty() && mode == 4) {
        auto previous = expected.find(getter.name);
        check("before-after-" + getter.name, previous != expected.end() && previous->second == row,
              "the before-extraction exit code, gas or full stack BOC changed");
      }
      if (mode & 8) {
        auto cell = must(vm::std_boc_deserialize(decoded->init_c7_.as_slice()), "wire c7 BOC");
        vm::StackEntry received;
        require(received.deserialize(cell) && received.is_tuple(), "wire c7 tuple");
        auto actual = received.as_tuple();
        auto expected_c7 = getter_reference::prepare_vm_c7(state.now, state.lt, address_slice(getter.address),
                                                           getter.balance, mode & 32 ? state.config.get() : nullptr,
                                                           mode & 32 ? getter.code : Ref<vm::Cell>{},
                                                           mode & 32 ? getter.due_payment : td::zero_refint());
        require(actual.not_null() && actual->size() == 1 && actual->at(0).is_tuple(), "wire c7 shape");
        auto actual_info = actual->at(0).as_tuple();
        require(actual_info->size() >= 10 && actual_info->at(6).is_int(), "wire c7 seed");
        // Randomness is deliberately fresh for the basic exported context. Compare
        // every other field against the independent construction, including shape.
        auto expected_info = expected_c7->at(0).as_tuple();
        expected_info.write().at(6) = actual_info->at(6);
        expected_c7.write().at(0) = expected_info;
        check("wire-c7-" + getter.name + "-" + std::to_string(mode),
              serialize_context(expected_c7) == serialize_context(actual),
              "exported c7 differs from the independent oracle");
      }
    }
  }
  scheduler.run_in_context([&] { manager.reset(); });
}

}  // namespace

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(ERROR));
  vm::init_vm().ensure();
  if (argc < 4) {
    setup_failed(
        "usage: test-get-method-context ZEROSTATE ELECTOR_DIR CONFIG_CODE [--case NAME] [--capture FILE] [--baseline "
        "FILE]");
  }
  for (int index = 4; index < argc; index += 2) {
    require(index + 1 < argc, "option value");
    const std::string option = argv[index];
    if (option == "--case") {
      selected = argv[index + 1];
    } else if (option == "--capture") {
      capture = argv[index + 1];
    } else if (option == "--baseline") {
      baseline = argv[index + 1];
    } else {
      setup_failed("unknown option");
    }
  }
  if (selected.empty() || selected == "context") {
    context_cases(argv[1], argv[2], argv[3]);
  }
  if (selected.empty() || selected == "vm") {
    vm_cases(argv[1], argv[2], argv[3]);
  }
  if (selected.empty() || selected == "libraries") {
    library_cases(argv[1], argv[2], argv[3]);
  }
  if (selected.empty() || selected == "liteserver") {
    liteserver_cases(argv[1], argv[2], argv[3]);
  }
  require(checks > 0, "at least one selected check ran");
  std::printf("GETTER_CONTEXT_RESULT checks=%d failures=%d\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
