// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Prints codepage 0 of the C++ VM as the node builds it (debug opcodes disabled): one line per
// range of 24-bit opcodes, covering all of them, in order:
//     first  assigned  bits  version
// first is the range's first opcode (6 hex digits); assigned is 0 for an unassigned gap; bits is
// the prefix width charged as base gas and required before the instruction runs; version is the
// global version that enables it. vm_opcode_table.py turns this into the Rust table.
#include <cstdio>
#include <iostream>
#include <stdexcept>

#include "vm/dispatch.h"
#include "vm/opctable.h"
#include "vm/vm.h"

int main() {
  try {
    vm::init_vm().ensure();
    const auto* table = dynamic_cast<const vm::OpcodeTable*>(vm::DispatchTable::get_table(0));
    if (table == nullptr || !table->is_final()) {
      throw std::runtime_error("codepage 0 is not a finalized opcode table");
    }
    auto prefixes = table->prefixes();
    if (prefixes.empty() || prefixes.front().first != 0) {
      throw std::runtime_error("codepage 0 does not start at opcode 0");
    }
    for (const auto& [first, prefix] : prefixes) {
      std::printf("%06x\t%d\t%u\t%d\n", first, prefix.assigned ? 1 : 0, prefix.bits, prefix.version);
    }
    return 0;
  } catch (const std::exception& e) {
    std::cerr << e.what() << "\n";
    return 1;
  }
}
