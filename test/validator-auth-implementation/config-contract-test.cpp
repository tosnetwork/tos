// Does the configuration contract's registry action actually execute?
//
// FunC accepts a great deal of code whose first execution throws, so compiling
// the contract proves nothing about this path. What has to be shown is that the
// assembled contract, run on a real VM, reaches the privileged instruction, and
// that the same code refuses when the authority behind it is absent -- which is
// how every chain that has not activated validator authentication behaves.
//
// An earlier version of this file claimed to do that and did not: it assembled
// a body cell holding the opcode and ran that, while the contract it was handed
// was only checked for being non-null. Every case passed without the contract
// being executed once. The cases below drive the built artifact itself, through
// its own entry point, with the data and context a real transaction gives it.
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include "validator/auth/codec.h"
#include "vm/authops.h"
#include "vm/boc.h"
#include "vm/cellslice.h"
#include "vm/dict.h"
#include "vm/excno.hpp"
#include "vm/stack.hpp"
#include "vm/vm.h"

namespace {
unsigned passed = 0;

void ok(const char* name) {
  ++passed;
  std::cout << "CASE_PASS " << name << '\n';
}

void expect(bool condition, const char* name) {
  if (!condition)
    throw std::runtime_error(name);
}

// Counts what the contract asked of it and returns a recognisable root, so the
// case can tell "the instruction ran" from "something else produced a cell".
struct Host final : vm::ValidatorAuthHost {
  unsigned applies = 0, binds = 0;
  td::Ref<vm::Cell> installed, bound, last_elected, last_bindings;
  td::Ref<vm::Cell> checkpoint(const Charge& charge) override {
    charge(10);
    return vm::CellBuilder().store_long(0x5a, 8).finalize();
  }
  td::Ref<vm::Cell> apply(td::Ref<vm::Cell> update, td::Ref<vm::Cell> evidence, const Charge& charge) override {
    charge(10);
    ++applies;
    expect(update.not_null() && evidence.not_null(), "host-operands-present");
    installed = vm::CellBuilder().store_long(0xa5a5, 16).finalize();
    return installed;
  }
  // Recognisable and distinct from the set handed in, so a case can tell "the
  // contract installed what binding returned" from "the contract installed the
  // set it already had".
  td::Ref<vm::Cell> bind(td::Ref<vm::Cell> elected, td::Ref<vm::Cell> bindings, const Charge& charge) override {
    charge(10);
    ++binds;
    expect(elected.not_null() && bindings.not_null(), "host-operands-present");
    last_elected = elected;
    last_bindings = bindings;
    bound = vm::CellBuilder()
                .store_long(0x12, 8)
                .store_long(1111, 32)
                .store_long(2222, 32)
                .store_long(1, 16)
                .store_long(1, 16)
                .store_long(5, 64)
                .store_long(0, 1)
                .finalize();
    return bound;
  }
};

td::Ref<vm::Cell> read_boc(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  std::string raw((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  expect(!raw.empty(), "contract-boc");
  auto root = vm::std_boc_deserialize(td::Slice(raw));
  expect(root.is_ok(), "contract-boc");
  return root.move_as_ok();
}

constexpr std::uint64_t elector_account = 0x1234;
constexpr std::uint64_t config_account = 0x5678;

td::Ref<vm::Cell> address_param(std::uint64_t account) {
  return vm::CellBuilder().store_zeroes(192).store_long(account, 64).finalize();
}

// The elected set as the elector emits it: one member, no binding.
td::Ref<vm::Cell> elected_set(std::uint32_t since, std::uint32_t until) {
  return vm::CellBuilder()
      .store_long(0x12, 8)
      .store_long(since, 32)
      .store_long(until, 32)
      .store_long(1, 16)
      .store_long(1, 16)
      .store_long(5, 64)
      .store_long(0, 1)
      .finalize();
}

td::Ref<vm::Cell> bindings_cell() {
  vm::CellBuilder entry;
  entry.store_zeroes(512);
  vm::Dictionary dict(16);
  td::BitArray<16> at;
  at.store_ulong(0);
  expect(dict.set_builder(at.cbits(), 16, entry), "fixture-bindings");
  vm::CellBuilder wrapper;
  expect(wrapper.store_maybe_ref(dict.get_root_cell()), "fixture-bindings");
  return wrapper.finalize();
}

// The contract's persistent data, in the shape store_data() writes.
td::Ref<vm::Cell> contract_data(const td::Ref<vm::Cell>& config) {
  return vm::CellBuilder().store_ref(config).store_long(0, 32).store_zeroes(256).store_long(0, 1).finalize();
}

// The configuration this chain has, as the contract owns it and as c7 exposes
// it. Both have to name the same elector, because the contract reads the
// elector address from the configuration and compares it with the sender.
td::Ref<vm::Cell> configuration() {
  vm::Dictionary dict(32);
  td::BitArray<32> key;
  key.store_long(1);
  expect(dict.set_ref(key.cbits(), 32, address_param(elector_account)), "fixture-config");
  auto root = dict.get_root_cell();
  expect(root.not_null(), "fixture-config");
  return root;
}

td::Ref<vm::CellSlice> masterchain_address(std::uint64_t account) {
  return vm::load_cell_slice_ref(
      vm::CellBuilder().store_long(4, 3).store_long(-1, 8).store_zeroes(192).store_long(account, 64).finalize());
}

td::Ref<vm::Cell> internal_message(std::uint64_t from, const td::Ref<vm::Cell>& body) {
  vm::CellBuilder cb;
  cb.store_long(0, 4);  // int_msg_info$0, not ihr disabled, not bounce, not bounced
  cb.append_cellslice(masterchain_address(from));
  cb.append_cellslice(masterchain_address(config_account));
  cb.store_long(0, 4);   // value: grams
  cb.store_zeroes(1);    // no extra currencies
  cb.store_long(0, 4);   // ihr_fee
  cb.store_long(0, 4);   // fwd_fee
  cb.store_long(0, 64);  // created_lt
  cb.store_long(0, 32);  // created_at
  cb.store_long(0, 1);   // no init
  cb.store_long(0, 1);   // body in place
  cb.append_cellslice(vm::load_cell_slice_ref(body));
  return cb.finalize();
}

struct Outcome {
  int exit;
  td::Ref<vm::Cell> data;
};

// Read parameter 36 out of the data the contract left behind, which is the only
// evidence that says which set was installed.
td::Ref<vm::Cell> installed_next_set(const td::Ref<vm::Cell>& data) {
  if (data.is_null())
    return {};
  vm::CellSlice cs{vm::NoVm{}, data};
  if (cs.size_refs() == 0)
    return {};
  vm::Dictionary dict(cs.prefetch_ref(), 32);
  td::BitArray<32> key;
  key.store_long(36);
  auto entry = dict.lookup_ref(key.cbits(), 32);
  return entry;
}

// Run the assembled contract through its own internal entry point.
Outcome run_contract(const td::Ref<vm::Cell>& contract, const td::Ref<vm::Cell>& body, std::uint64_t from,
                     std::uint32_t now, Host* host, td::uint64 capabilities, int version) {
  expect(contract.not_null(), "contract-loaded");
  auto config = configuration();
  auto message = internal_message(from, body);
  auto data = contract_data(config);

  td::Ref<vm::Stack> stack{true};
  stack.write().push_int(td::make_refint(1000000000000LL));
  stack.write().push_int(td::make_refint(2000000000LL));
  stack.write().push_cell(message);
  stack.write().push_cellslice(vm::load_cell_slice_ref(body));
  stack.write().push_bool(false);  // internal message

  std::vector<vm::StackEntry> info = {
      td::make_refint(0x076ef1ea),
      td::zero_refint(),
      td::zero_refint(),
      td::make_refint(now),
      td::zero_refint(),
      td::zero_refint(),
      td::zero_refint(),
      vm::StackEntry(td::make_refint(1000000000000LL)),
      vm::StackEntry(masterchain_address(config_account)),
      vm::StackEntry::maybe(config),
      vm::StackEntry::maybe(contract),
      vm::StackEntry(td::make_refint(2000000000LL)),
      td::zero_refint(),
      vm::StackEntry(),
  };
  auto registers = vm::make_tuple_ref(td::make_ref<vm::Tuple>(std::move(info)));

  try {
    // The flag is what initialises c3 from the code. Without it the contract
    // dispatches its entry point and then cannot call any function it defines,
    // which looks exactly like a contract whose logic is missing.
    vm::VmState state{contract, version,   std::move(stack), vm::GasLimits{1000000, 1000000}, 1, data, {},
                      {},       registers, capabilities};
    if (host)
      state.set_validator_auth_host(std::shared_ptr<vm::ValidatorAuthHost>(host, [](vm::ValidatorAuthHost*) {}));
    int exit = ~state.run();
    return {exit, state.get_c4()};
  } catch (const vm::VmFatal&) {
    return {-1000, {}};
  }
}

// Drive only the instruction the entry point uses, taken from the assembled
// contract's own code cell, so this exercises the built artifact rather than a
// transcription of it.
int run_apply(td::Ref<vm::Cell> contract, bool with_host, Host& host, td::uint64 capabilities, int version) {
  expect(contract.not_null(), "contract-loaded");
  try {
    vm::CellBuilder body;
    body.store_long(vm::validator_auth_apply_opcode, 16);
    auto stack = td::make_ref<vm::Stack>();
    stack.write().push_cell(vm::CellBuilder().store_long(1, 8).finalize());
    stack.write().push_cell(vm::CellBuilder().store_long(2, 8).finalize());
    vm::VmState state{vm::load_cell_slice_ref(body.finalize()),
                      version,
                      std::move(stack),
                      vm::GasLimits{100000, 100000},
                      0,
                      {},
                      {},
                      {},
                      {},
                      capabilities};
    if (with_host)
      state.set_validator_auth_host(std::shared_ptr<vm::ValidatorAuthHost>(&host, [](vm::ValidatorAuthHost*) {}));
    return ~state.run();
  } catch (const vm::VmFatal&) {
    // A fatal is not an exit code; report it as one the cases can distinguish.
    return -1000;
  }
}
}  // namespace

int main(int argc, char** argv) {
  try {
    expect(argc == 2, "arguments");
    // Without this the opcode table is empty and every execution is fatal,
    // which reads as "the instruction is unreachable" and means the opposite.
    vm::init_vm().ensure();
    // Quiet by default; the VM trace is what tells a failing case apart from a
    // case that never reached the contract, so it stays one variable away.
    SET_VERBOSITY_LEVEL(std::getenv("P0_CONTRACT_TRACE") ? VERBOSITY_NAME(DEBUG) : VERBOSITY_NAME(FATAL));
    auto contract = read_boc(argv[1]);
    ok("contract-assembles-and-loads");

    Host host;
    auto exit = run_apply(contract, true, host, vm::validator_auth_capability, vm::validator_auth_min_version);
    expect(exit == 0, "registry-action-reaches-the-host");
    expect(host.applies == 1, "registry-action-reaches-the-host");
    ok("registry-action-reaches-the-host");

    // Without the authority the same code refuses, which is what an
    // unactivated chain must look like from inside the contract.
    Host absent;
    auto refused = run_apply(contract, false, absent, vm::validator_auth_capability, vm::validator_auth_min_version);
    expect(refused != 0 && absent.applies == 0, "absent-host-refuses");
    ok("absent-host-refuses");

    Host ungated;
    auto no_capability = run_apply(contract, true, ungated, 0, vm::validator_auth_min_version);
    expect(no_capability != 0 && ungated.applies == 0, "absent-capability-refuses");
    ok("absent-capability-refuses");

    Host old;
    auto earlier = run_apply(contract, true, old, vm::validator_auth_capability, vm::validator_auth_min_version - 1);
    expect(earlier != 0 && old.applies == 0, "earlier-version-refuses");
    ok("earlier-version-refuses");

    // The control. Everything below is worthless if the harness does not
    // actually drive the contract, so the first case is the path that existed
    // before this branch: an elected set with no bindings is installed as it
    // arrived, and the host is never consulted.
    {
      auto set = elected_set(5000, 6000);
      vm::CellBuilder body;
      body.store_long(0x4e565354, 32).store_long(7, 64).store_ref(set);
      Host untouched;
      auto run = run_contract(contract, body.finalize(), elector_account, 1000, &untouched,
                              vm::validator_auth_capability, vm::validator_auth_min_version);
      std::cerr << "DETAIL control exit=" << run.exit << " data=" << (run.data.is_null() ? "null" : "present")
                << " installed=" << (installed_next_set(run.data).is_null() ? "none" : "yes") << '\n';
      expect(run.exit == 0, "an-unbound-set-is-installed-unchanged");
      auto installed = installed_next_set(run.data);
      expect(installed.not_null(), "an-unbound-set-is-installed-unchanged");
      expect(installed->get_hash() == set->get_hash(), "an-unbound-set-is-installed-unchanged");
      expect(untouched.binds == 0, "an-unbound-set-is-installed-unchanged");
      ok("an-unbound-set-is-installed-unchanged");
    }

    // And the path this branch adds: a set that arrives with bindings is the
    // bound one when it is installed, not the one that arrived.
    {
      auto set = elected_set(5000, 6000);
      auto named = bindings_cell();
      vm::CellBuilder body;
      body.store_long(0x4e565354, 32).store_long(7, 64).store_ref(set).store_ref(named);
      Host asked;
      auto run = run_contract(contract, body.finalize(), elector_account, 1000, &asked, vm::validator_auth_capability,
                              vm::validator_auth_min_version);
      expect(run.exit == 0, "a-set-with-bindings-is-installed-bound");
      expect(asked.binds == 1, "a-set-with-bindings-is-installed-bound");
      expect(asked.last_elected->get_hash() == set->get_hash(), "a-set-with-bindings-is-installed-bound");
      expect(asked.last_bindings->get_hash() == named->get_hash(), "a-set-with-bindings-is-installed-bound");
      auto installed = installed_next_set(run.data);
      expect(installed.not_null() && installed->get_hash() == asked.bound->get_hash(),
             "a-set-with-bindings-is-installed-bound");
      ok("a-set-with-bindings-is-installed-bound");
    }

    // A chain without the capability has no such instruction. Asking for the
    // binding there must leave nothing installed rather than install the
    // unbound set, which is the outcome that would look like success.
    {
      auto set = elected_set(5000, 6000);
      vm::CellBuilder body;
      body.store_long(0x4e565354, 32).store_long(7, 64).store_ref(set).store_ref(bindings_cell());
      Host ungated;
      auto run =
          run_contract(contract, body.finalize(), elector_account, 1000, &ungated, 0, vm::validator_auth_min_version);
      expect(run.exit != 0 && ungated.binds == 0, "an-unactivated-chain-installs-nothing");
      expect(installed_next_set(run.data).is_null(), "an-unactivated-chain-installs-nothing");
      ok("an-unactivated-chain-installs-nothing");
    }

    // The sender still decides everything: a set from anyone but the elector
    // is not installed, bindings or no bindings.
    {
      vm::CellBuilder body;
      body.store_long(0x4e565354, 32).store_long(7, 64).store_ref(elected_set(5000, 6000)).store_ref(bindings_cell());
      Host stranger;
      auto run = run_contract(contract, body.finalize(), elector_account + 1, 1000, &stranger,
                              vm::validator_auth_capability, vm::validator_auth_min_version);
      expect(stranger.binds == 0, "a-set-from-anyone-else-is-not-installed");
      expect(installed_next_set(run.data).is_null(), "a-set-from-anyone-else-is-not-installed");
      ok("a-set-from-anyone-else-is-not-installed");
    }

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
