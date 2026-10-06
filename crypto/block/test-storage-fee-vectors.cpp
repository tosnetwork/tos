/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

// Holds every row of storage-fee-vectors.tsv to the node's own storage fee function.
//
// The tosctl executor reproduces this computation in Rust and reads the same file. The
// expected values are therefore only evidence if the node itself produces them, which is
// what this program checks: a row the node disagrees with, a row that cannot be parsed,
// or a file with no rows at all fails it.

#include "block/mc-config.h"
#include "common/refint.h"

#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifndef STORAGE_FEE_VECTORS
#error "STORAGE_FEE_VECTORS must name the vector file"
#endif

namespace {

std::vector<std::string> split(const std::string& text, char separator) {
  std::vector<std::string> parts;
  std::string part;
  std::istringstream stream(text);
  while (std::getline(stream, part, separator)) {
    parts.push_back(part);
  }
  if (!text.empty() && text.back() == separator) {
    parts.emplace_back();
  }
  return parts;
}

td::uint64 parse_u64(const std::string& text) {
  if (text.empty() || text.find_first_not_of("0123456789") != std::string::npos) {
    throw std::runtime_error("not an unsigned integer: '" + text + "'");
  }
  return std::stoull(text);
}

td::uint32 parse_u32(const std::string& text) {
  td::uint64 value = parse_u64(text);
  if (value > 0xffffffffULL) {
    throw std::runtime_error("does not fit 32 bits: " + text);
  }
  return static_cast<td::uint32>(value);
}

bool parse_flag(const std::string& text) {
  if (text == "0") {
    return false;
  }
  if (text == "1") {
    return true;
  }
  throw std::runtime_error("not a 0/1 flag: '" + text + "'");
}

std::vector<block::StoragePrices> parse_periods(const std::string& text) {
  std::vector<block::StoragePrices> periods;
  if (text == "-") {
    return periods;
  }
  for (const auto& period : split(text, ',')) {
    auto fields = split(period, ':');
    if (fields.size() != 5) {
      throw std::runtime_error("a period needs five fields: '" + period + "'");
    }
    periods.emplace_back(parse_u32(fields[0]), parse_u64(fields[1]), parse_u64(fields[2]), parse_u64(fields[3]),
                         parse_u64(fields[4]));
  }
  return periods;
}

}  // namespace

int main(int argc, char** argv) {
  const char* path = argc > 1 ? argv[1] : STORAGE_FEE_VECTORS;
  std::ifstream file(path);
  if (!file) {
    std::cerr << "cannot open " << path << "\n";
    return 1;
  }
  std::string line;
  int line_number = 0;
  int rows = 0;
  int failures = 0;
  while (std::getline(file, line)) {
    ++line_number;
    if (line.empty() || line[0] == '#') {
      continue;
    }
    ++rows;
    try {
      auto fields = split(line, '\t');
      if (fields.size() != 9) {
        throw std::runtime_error("a row needs nine fields, has " + std::to_string(fields.size()));
      }
      const auto& name = fields[0];
      auto now = parse_u32(fields[1]);
      auto last_paid = parse_u32(fields[2]);
      block::StorageUsed used;
      used.cells = parse_u64(fields[3]);
      used.bits = parse_u64(fields[4]);
      bool special = parse_flag(fields[5]);
      bool masterchain = parse_flag(fields[6]);
      auto periods = parse_periods(fields[7]);
      parse_u64(fields[8]);
      const auto& expected = fields[8];
      auto fee =
          block::StoragePrices::compute_storage_fees(now, periods, used, last_paid, special, masterchain);
      if (fee.is_null()) {
        std::cerr << "line " << line_number << " (" << name << "): the node computed no fee\n";
        ++failures;
        continue;
      }
      auto actual = fee->to_dec_string();
      if (actual != expected) {
        std::cerr << "line " << line_number << " (" << name << "): the node charges " << actual << ", the file says "
                  << expected << "\n";
        ++failures;
      }
    } catch (const std::exception& error) {
      std::cerr << "line " << line_number << ": " << error.what() << "\n";
      ++failures;
    }
  }
  if (rows == 0) {
    std::cerr << path << " has no rows\n";
    return 1;
  }
  if (failures != 0) {
    std::cerr << failures << " of " << rows << " rows disagree with the node\n";
    return 1;
  }
  std::cout << "all " << rows << " storage fee rows match the node\n";
  return 0;
}
