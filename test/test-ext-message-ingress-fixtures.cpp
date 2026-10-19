// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
// Public fixture driver for the production structural parser, not admission authority.
#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "td/utils/misc.h"
#include "validator/impl/external-message.hpp"

int main(int argc, char **argv) {
  if (argc != 3) {
    std::cerr << "usage: test-ext-message-ingress-fixtures scenarios.tsv iterations\n";
    return 2;
  }
  try {
    const int iterations = std::stoi(argv[2]);
    if (iterations < 1 || iterations > 10000) {
      return 2;
    }
    std::ifstream input(argv[1]);
    if (!input) {
      return 2;
    }
    block::SizeLimitsConfig::ExtMsgLimits limits;
    if (limits.max_size != 65535 || limits.max_depth != 512) {
      std::cerr << "fixture profile requires explicit review after limit changes\n";
      return 2;
    }
    std::string line;
    unsigned count = 0;
    while (std::getline(input, line)) {
      std::vector<std::string> fields;
      std::istringstream record(line);
      for (std::string field; std::getline(record, field, '\t');) {
        fields.push_back(std::move(field));
      }
      if (fields.size() != 6 || fields[0].empty()) {
        std::cerr << "invalid scenario row\n";
        return 2;
      }
      auto decoded = td::hex_decode(fields[4]);
      if (decoded.is_error()) {
        return 2;
      }
      auto bytes = decoded.move_as_ok();
      std::string verdict;
      std::vector<long long> samples;
      for (int repeat = 0; repeat < iterations + 3; ++repeat) {
        td::BufferSlice data{bytes};
        const auto start = std::chrono::steady_clock::now();
        auto parsed = tos::validator::ExtMessageQ::create_ext_message(std::move(data), limits);
        const auto elapsed = std::chrono::steady_clock::now() - start;
        auto current = parsed.is_ok() ? "ok\t-\t" + td::hex_encode(parsed.ok()->hash().as_slice())
                                      : "reject\t" + td::hex_encode(parsed.error().message()) + "\t-";
        if (repeat == 0) {
          verdict = current;
        } else if (verdict != current) {
          std::cerr << "non-deterministic parser result\n";
          return 3;
        }
        if (repeat >= 3) {
          samples.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
        }
      }
      std::cout << fields[0] << '\t' << verdict << '\t';
      for (std::size_t index = 0; index < samples.size(); ++index) {
        std::cout << (index ? "," : "") << samples[index];
      }
      std::cout << '\n';
      ++count;
    }
    if (!input.eof() || count == 0) {
      return 2;
    }
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 2;
  }
  return 0;
}
