#include <filesystem>
#include <fstream>
#include <iostream>

#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cp0.h"
#include "vm/vm.h"
namespace {
using Cell = td::Ref<vm::Cell>;
void check(bool ok, const std::string& label) {
  if (!ok)
    throw std::runtime_error(label);
}
Cell cell(unsigned value) {
  return vm::CellBuilder().store_long(value, 8).finalize();
}
struct Host final : vm::ValidatorAuthHost {
  Cell input = cell(0x11), evidence = cell(0x22), state_result = cell(0x31), apply_result = cell(0x32);
  long long cost;
  unsigned states = 0, updates = 0;
  explicit Host(long long amount) : cost(amount) {
  }
  Cell checkpoint(const Charge& charge) override {
    charge(cost);
    ++states;
    return state_result;
  }
  Cell apply(Cell update, Cell auth, const Charge& charge) override {
    charge(cost);
    ++updates;
    if (update->get_hash() != input->get_hash() || auth->get_hash() != evidence->get_hash())
      throw vm::VmError{vm::Excno::range_chk, "native host operand order"};
    return apply_result;
  }
};
struct Result {
  int exit;
  long long gas, top;
  unsigned calls;
};
}  // namespace
int main(int argc, char** argv) {
  try {
    check(argc == 2, "arguments");
    std::filesystem::path out(argv[1]);
    check(std::filesystem::create_directory(out), "fresh-output");
    vm::init_vm().ensure();
    SET_VERBOSITY_LEVEL(0);
    unsigned count = 0;
    auto run = [&](unsigned op, int version, td::uint64 caps, bool present, bool child, bool c7, long long cost,
                   long long budget, unsigned fault, const char* label) {
      auto host = std::make_shared<Host>(cost);
      auto opcode = vm::CellBuilder().store_long(0xf918 + op, 16).finalize();
      Cell code = opcode;
      td::Ref<vm::Stack> stack{true};
      unsigned args = 0;
      if (op && fault != 1) {
        stack.write().push_cell(host->input);
        ++args;
        if (fault != 2) {
          if (fault == 3)
            stack.write().push_smallint(9);
          else
            stack.write().push_cell(host->evidence);
          ++args;
        }
      }
      if (child) {
        stack.write().push_smallint(args);
        stack.write().push_cellslice(vm::load_cell_slice_ref(opcode));
        code = vm::CellBuilder().store_long(0xdb4000, 24).finalize();
      }
      td::Ref<vm::Tuple> registers;
      if (c7)
        registers = td::make_ref<vm::Tuple>(std::vector<vm::StackEntry>{vm::StackEntry(td::make_refint(1024))});
      vm::VmState state{vm::load_cell_slice_ref(code),
                        version,
                        std::move(stack),
                        vm::GasLimits{budget, budget},
                        0,
                        {},
                        {},
                        {},
                        registers,
                        caps};
      if (present)
        state.set_validator_auth_host(host);
      int exit = ~state.run();
      long long top = -1;
      if (exit == 0) {
        top = -2;
        if (state.get_stack().depth()) {
          if (child) {
            auto number = state.get_stack().tos().as_int();
            if (number.not_null() && number->signed_fits_bits(32))
              top = number->to_long();
          } else if (state.get_stack().depth() == 1) {
            auto result = state.get_stack().tos().as_cell();
            if (result.not_null())
              top = result->get_hash() == (op ? host->apply_result : host->state_result)->get_hash() ? 1 : 0;
          }
        }
      }
      auto folder = out / std::to_string(count++);
      check(std::filesystem::create_directory(folder), "case-directory");
      auto raw = vm::std_boc_serialize(code);
      check(raw.is_ok(), "code-boc");
      std::ofstream file(folder / "code", std::ios::binary);
      file.write(raw.ok().data(), raw.ok().size());
      check(file.good(), "code-write");
      std::ofstream meta(folder / "case");
      meta << op << ' ' << version << ' ' << caps << ' ' << present << ' ' << child << ' ' << c7 << ' ' << cost << ' '
           << budget << ' ' << fault << ' ' << exit << ' ' << state.gas_consumed() << ' ' << top << ' '
           << host->states + host->updates << ' ' << label << '\n';
      check(meta.good(), "case-write");
      return Result{exit, state.gas_consumed(), top, host->states + host->updates};
    };
    for (unsigned op : {0U, 1U}) {
      const char* success = op ? "host-apply-success" : "host-state-success";
      auto ok = run(op, 16, 1024, true, false, false, 1000, 100000, 0, success);
      check(ok.exit == 0 && ok.top == 1 && ok.calls == 1, success);
      auto version = run(op, 15, 1024, true, false, false, 1000, 100000, 0, "host-version");
      check(version.exit == 6 && !version.calls, "host-version");
      for (auto caps : {0ULL, 512ULL}) {
        auto denied = run(op, 16, caps, true, false, true, 1000, 100000, 0, "host-capability");
        check(denied.exit == 6 && !denied.calls, "host-capability");
      }
      for (bool fake : {false, true}) {
        auto denied = run(op, 16, 1024, false, false, fake, 1000, 100000, 0, "host-required");
        check(denied.exit == 6 && !denied.calls, "host-required");
      }
      auto child = run(op, 16, 1024, true, true, false, 1000, 100000, 0, "host-child-isolation");
      check(child.exit == 0 && child.top == 6 && !child.calls, "host-child-isolation");
      auto below = run(op, 16, 1024, true, false, false, 1000, 1000, 0, "host-charge-admission");
      check(below.exit == -14 && !below.calls, "host-charge-admission");
      auto at = run(op, 16, 1024, true, false, false, 1000, ok.gas, 0, "host-exact-gas");
      check(at.exit == 0 && at.top == 1 && at.calls == 1, "host-exact-gas");
      below = run(op, 16, 1024, true, false, false, 1000, ok.gas - 1, 0, "host-final-gas-boundary");
      check(below.exit == -14, "host-final-gas-boundary");
      auto negative = run(op, 16, 1024, true, false, false, -1, 100000, 0, "host-negative-gas");
      check(negative.exit == 5 && !negative.calls, "host-negative-gas");
      if (op)
        for (unsigned fault : {1U, 2U, 3U}) {
          auto bad = run(op, 16, 1024, true, false, false, 1000, 100000, fault, "host-operands");
          check(bad.exit == (fault == 3 ? 7 : 2) && !bad.calls, "host-operands");
        }
    }
    std::ofstream(out / "complete") << count << '\n';
    std::cout << "PASS: native transaction host VM gates " << count << " cases\n";
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
