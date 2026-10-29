// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Compare validated unsigned integers separately from unchecked skip.
#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

#include "block/block-parse.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "vm/cells.h"

void require(bool value, const char* message) {
  if (!value)
    throw std::runtime_error(message);
}
int main(int argc, char** argv) {
  try {
    require(argc == 2, "usage: varuint-native input.tsv");
    constexpr std::size_t max_bytes = 8 * 1024 * 1024;
    auto bytes = td::read_file(td::CSlice(argv[1]), max_bytes + 1);
    require(bytes.is_ok(), "read input");
    auto content = bytes.move_as_ok();
    require(content.size() <= max_bytes, "input byte bound");
    std::istringstream input(content.as_slice().str());
    std::string line;
    unsigned count = 0;
    while (std::getline(input, line)) {
      require(++count <= 4096 && line.size() <= 2048, "input bound");
      std::istringstream fields(line);
      std::string name, op, data, extra;
      int n;
      require(bool(fields >> name >> op >> n >> data) && !(fields >> extra), "record");
      require(n == 3 || n == 7 || n == 16 || n == 32, "type");
      block::tlb::VarUInteger type(n);
      td::RefInt256 value;
      bool accepted = false;
      std::string skipped = "-";
      vm::CellBuilder encoded;
      if (op == "read") {
        require(data.size() <= 1023, "bit bound");
        vm::CellBuilder builder;
        if (data != "-")
          for (char ch : data) {
            require(ch == '0' || ch == '1', "binary");
            require(builder.store_long_bool(ch - '0', 1), "store bit");
          }
        auto cell = builder.finalize_novm();
        auto validate = vm::load_cell_slice(cell);
        int budget = 4096;
        accepted = type.validate_skip(&budget, validate, false);
        auto decode = vm::load_cell_slice(cell);
        value = type.as_integer_skip(decode);
        require(accepted == value.not_null(), "native decoder/validator disagreement");
        auto skip = vm::load_cell_slice(cell);
        skipped = type.skip(skip) ? "1" : "0";
        if (accepted)
          require(type.store_integer_value(encoded, *value), "native canonical write");
      } else {
        require(op == "write" && data.size() <= 90, "operation");
        value = td::dec_string_to_int256(data);
        require(value.not_null(), "decimal");
        accepted = type.store_integer_value(encoded, *value);
      }
      std::string hash = "-";
      if (accepted) {
        hash = encoded.finalize_novm()->get_hash().to_hex();
        std::transform(hash.begin(), hash.end(), hash.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
      }
      std::cout << name << '\t' << accepted << '\t' << (accepted ? value->to_dec_string() : "-") << '\t' << hash << '\t'
                << skipped << '\n';
    }
    require(count != 0, "empty input");
    return 0;
  } catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
