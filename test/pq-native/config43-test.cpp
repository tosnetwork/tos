/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// The C++ half of the configuration-parameter-43 lock. The Rust half reads the same file
// and must reach the same values, because how much state an account may hold is not a
// thing two implementations may disagree about.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "block/mc-config.h"
#include "td/utils/misc.h"
#include "vm/boc.h"

namespace {

std::vector<std::string> split(const std::string& line, char sep) {
  std::vector<std::string> out;
  std::istringstream row(line);
  for (std::string field; std::getline(row, field, sep);) {
    out.push_back(field);
  }
  return out;
}

std::string summary(const block::SizeLimitsConfig& limits) {
  std::string loads =
      limits.max_transaction_library_loads ? std::to_string(limits.max_transaction_library_loads.value()) : "-";
  char buffer[512];
  std::snprintf(buffer, sizeof buffer, "%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%s,%u,%u", limits.max_msg_bits,
                limits.max_msg_cells, limits.max_library_cells, limits.max_vm_data_depth,
                limits.ext_msg_limits.max_size, limits.ext_msg_limits.max_depth, limits.max_acc_state_cells,
                limits.max_mc_acc_state_cells, limits.max_acc_public_libraries, limits.defer_out_queue_size_limit,
                limits.max_msg_extra_currencies, limits.max_acc_fixed_prefix_length,
                limits.acc_state_cells_for_storage_dict, loads.c_str(), limits.max_total_msg_bits,
                limits.max_total_msg_cells);
  return buffer;
}

}  // namespace

int main() {
  std::ifstream file(CONFIG43_VECTORS_FILE);
  assert(file);
  int checked = 0, accepted = 0, rejected = 0;
  for (std::string line; std::getline(file, line);) {
    if (line.empty() || line[0] == '#') {
      continue;
    }
    auto fields = split(line, '\t');
    assert(fields.size() == 4);
    const auto& name = fields[0];
    const bool expect_accept = fields[1] == "accept";
    assert(expect_accept || fields[1] == "reject");

    auto boc = td::hex_decode(fields[2]);
    assert(boc.is_ok());
    auto cell = vm::std_boc_deserialize(boc.move_as_ok());
    assert(cell.is_ok());
    auto parsed = block::Config::do_get_size_limits_config(vm::load_cell_slice_ref(cell.move_as_ok()));

    if (!expect_accept) {
      assert(parsed.is_error() && ("accepted a refused encoding: " + name).c_str());
      rejected++;
    } else {
      assert(parsed.is_ok() && ("refused an accepted encoding: " + name).c_str());
      auto got = summary(parsed.move_as_ok());
      if (got != fields[3]) {
        std::printf("FAIL %s\n  want %s\n  got  %s\n", name.c_str(), fields[3].c_str(), got.c_str());
        assert(false);
      }
      accepted++;
    }
    checked++;
  }
  // A file that lost its cases would otherwise pass by checking nothing, and a lock that
  // only carries accepted encodings proves nothing about what must be refused.
  assert(checked >= 8);
  assert(accepted >= 6);
  assert(rejected >= 2);
  std::printf("CONFIG43_VECTORS_OK %d encodings (%d accepted, %d refused)\n", checked, accepted, rejected);
  return 0;
}
