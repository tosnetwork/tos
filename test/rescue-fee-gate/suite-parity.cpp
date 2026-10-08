// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// EXPERIMENT. PQCHECKSIG_SUITE differential driver (C++ VM). Scenario format and output match
// tosctl/src/vm/examples/suite-parity.rs; see test/rescue-fee-gate/suite_scenarios.py.
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "td/utils/logging.h"
#include "vm/boc.h"
#include "vm/vm.h"

namespace {
std::string unhex(const std::string& s) {
  if (s.size() % 2) {
    throw std::runtime_error("invalid hex length");
  }
  std::string out;
  auto n = [](char c) {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return c - 'a' + 10;
    }
    throw std::runtime_error("invalid hex");
  };
  for (std::size_t i = 0; i < s.size(); i += 2) {
    out.push_back(static_cast<char>(n(s[i]) * 16 + n(s[i + 1])));
  }
  return out;
}

void push(td::Ref<vm::Stack>& stack, const std::string& field) {
  if (field == "skip") {
    return;
  }
  if (field.rfind("int:", 0) == 0) {
    stack.write().push_smallint(std::stoll(field.substr(4)));
    return;
  }
  auto bytes = unhex(field);
  auto c = vm::std_boc_deserialize(td::Slice(bytes), false, true);
  if (c.is_error()) {
    throw std::runtime_error("invalid cell BOC");
  }
  stack.write().push_cell(c.move_as_ok());
}
}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc != 2) {
      throw std::runtime_error("usage: suite-parity scenarios.tsv");
    }
    vm::init_vm().ensure();
    SET_VERBOSITY_LEVEL(0);
    std::ifstream file(argv[1]);
    if (!file) {
      throw std::runtime_error("missing scenarios");
    }
    unsigned count = 0;
    for (std::string line; std::getline(file, line);) {
      std::vector<std::string> f;
      std::istringstream row(line);
      for (std::string x; std::getline(row, x, '\t');) {
        f.push_back(x);
      }
      if (f.size() != 9) {
        throw std::runtime_error("invalid scenario");
      }
      const int version = std::stoi(f[1]);
      const long long budget = std::stoll(f[2]);
      td::Ref<vm::Stack> stack{true};
      for (int i = 5; i < 9; ++i) {
        push(stack, f[i]);
      }
      push(stack, f[4]);
      vm::CellBuilder code;
      code.store_long(0xf93102, 24);
      vm::VmState st{vm::load_cell_slice_ref(code.finalize()), version, std::move(stack),
                     vm::GasLimits{budget, budget}};
      const int exit = ~st.run();
      long long value = 99;
      if (exit == 0) {
        if (st.get_stack().depth() != 1) {
          throw std::runtime_error("unexpected stack");
        }
        value = st.get_stack().pop_int_finite()->to_long();
      }
      std::cout << f[0] << '\t' << exit << '\t' << st.gas_consumed() << '\t' << value << '\n';
      ++count;
    }
    if (file.bad() || count < 20) {
      throw std::runtime_error("incomplete scenario set");
    }
    return 0;
  } catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
