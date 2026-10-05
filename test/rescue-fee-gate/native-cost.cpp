// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// EXPERIMENT ONLY: execute raw native cost-control programs, not an admission opcode.
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "td/utils/logging.h"
#include "vm/boc.h"
#include "vm/pqops.h"
#include "pq/lms-fee.h"
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
    if (argc == 5 && std::string(argv[1]) == "--storage") {
      auto bytes = unhex(argv[2]);
      auto root = vm::std_boc_deserialize(td::Slice(bytes), false, true);
      if (root.is_error()) {
        throw std::runtime_error("invalid storage fixture");
      }
      vm::CellStorageStat stat;
      auto cells = std::stoull(argv[3]), bits = std::stoull(argv[4]);
      // Import fees exclude the root cell and its bits.
      auto result = stat.compute_used_storage(root.move_as_ok(), true, 3);
      const bool accepted = result.is_ok() && (!cells || stat.cells <= cells) && (!bits || stat.bits <= bits);
      std::cout << "{\"accepted\":" << (accepted ? "true" : "false")
                << ",\"cells\":" << stat.cells << ",\"bits\":" << stat.bits << "}\n";
      return 0;
    }
    if (argc == 3 && std::string(argv[1]) == "--tariff") {
      auto worst = tos::pq::lms_fee_worst_compressions(unhex(argv[2]), 32);
      if (!worst) {
        throw std::runtime_error("unsupported key");
      }
      std::cout << "{\"worst_compressions\":" << *worst
                << ",\"base_gas\":" << vm::pq_lms_fee_base_gas
                << ",\"per_compression_gas\":" << vm::pq_lms_fee_gas_per_compression
                << ",\"cell_load_gas\":" << vm::VmState::cell_load_gas_price
                << ",\"cell_reload_gas\":" << vm::VmState::cell_reload_gas_price << "}\n";
      return 0;
    }
    if (argc != 2) {
      throw std::runtime_error("usage: fee-native-cost scenarios.tsv | --tariff public-key-hex");
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
      if (f.size() < 4) {
        throw std::runtime_error("invalid scenario");
      }
      const int version = std::stoi(f[1]);
      const long long budget = std::stoll(f[2]);
      td::Ref<vm::Stack> stack{true};
      for (std::size_t i = 4; i < f.size(); ++i) {
        push(stack, f[i]);
      }
      vm::CellBuilder code;
      code.store_bytes(td::Slice(unhex(f[3])));
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
    if (file.bad() || count == 0) {
      throw std::runtime_error("incomplete scenario set");
    }
    return 0;
  } catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
