// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

#include "block/transaction.h"

namespace {
void require(bool ok, const char* message) {
  if (!ok) {
    throw std::runtime_error(message);
  }
}

unsigned long long number(const std::string& text) {
  require(!text.empty() && text.size() <= 20 &&
              std::all_of(text.begin(), text.end(), [](unsigned char c) { return std::isdigit(c); }),
          "unsigned scalar");
  return std::stoull(text);
}
}  // namespace

int main(int argc, char** argv) {
  try {
    require(argc == 2, "usage: gas-purchase inputs.tsv");
    require(std::filesystem::file_size(argv[1]) <= 8 * 1024 * 1024, "input byte bound");
    std::ifstream input(argv[1]);
    require(input.good(), "open input");
    unsigned count = 0;
    for (std::string line; std::getline(input, line);) {
      require(++count <= 8192 && line.size() <= 1024, "row bound");
      std::istringstream row(line);
      std::string name, price, limit, flat, fee, value, extra;
      require(bool(row >> name >> price >> limit >> flat >> fee >> value) && !(row >> extra), "row fields");
      require(name.size() <= 64 &&
                  std::all_of(name.begin(), name.end(), [](unsigned char c) { return std::isalnum(c) || c == '-'; }),
              "row name");
      require(!value.empty() && value.size() <= 39 &&
                  std::all_of(value.begin(), value.end(), [](unsigned char c) { return std::isdigit(c); }),
              "balance decimal");
      auto amount = td::dec_string_to_int256(value);
      require(amount.not_null() && amount->bit_size(false) <= 128, "balance bound");
      block::ComputePhaseConfig config{};
      config.gas_price = number(price);
      config.gas_limit = number(limit);
      config.flat_gas_limit = number(flat);
      config.flat_gas_price = number(fee);
      config.compute_threshold();
      std::cout << name << '\t' << config.max_gas_threshold->to_dec_string() << '\t' << config.gas_bought_for(amount)
                << '\n';
    }
    require(!input.bad() && count != 0, "incomplete input");
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
