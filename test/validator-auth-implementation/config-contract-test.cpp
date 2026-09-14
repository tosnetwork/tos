// Does the configuration contract's registry action actually execute?
//
// FunC accepts a great deal of code whose first execution throws, so compiling
// the contract proves nothing about this path. What has to be shown is that the
// assembled contract, run on a real VM, reaches the privileged instruction, and
// that the same code refuses when the authority behind it is absent -- which is
// how every chain that has not activated validator authentication behaves.
#include <fstream>
#include <iostream>
#include <stdexcept>

#include "vm/authops.h"
#include "vm/boc.h"
#include "vm/cellslice.h"
#include "vm/excno.hpp"
#include "vm/vm.h"

#include "validator/auth/codec.h"

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
  unsigned applies = 0;
  td::Ref<vm::Cell> installed;
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
};

td::Ref<vm::Cell> read_boc(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  std::string raw((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  expect(!raw.empty(), "contract-boc");
  auto root = vm::std_boc_deserialize(td::Slice(raw));
  expect(root.is_ok(), "contract-boc");
  return root.move_as_ok();
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
      state.set_validator_auth_host(
          std::shared_ptr<vm::ValidatorAuthHost>(&host, [](vm::ValidatorAuthHost*) {}));
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

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
