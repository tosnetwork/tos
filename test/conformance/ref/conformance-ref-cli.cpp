// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Line protocol around the conformance reference library:
//     conformance-ref-cli <harness>   one context JSON per stdin line -> one effects JSON per stdout line
//     conformance-ref-cli --info      the reference build identity and the harnesses it provides
// Every input line produces exactly one output line, in order; empty lines are refused, not skipped.
#include <iostream>
#include <string>

#include "conformance-ref.h"

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: conformance-ref-cli <harness>|--info\n";
    return 2;
  }
  const std::string mode = argv[1];
  if (mode == "--info") {
    const char *info = conformance_reference_info();
    if (info == nullptr) {
      return 1;
    }
    std::cout << info << '\n';
    conformance_free(info);
    return 0;
  }
  if (conformance_has_harness(mode.c_str()) == 0) {
    std::cerr << "unknown harness " << mode << '\n';
    return 2;
  }
  std::ios::sync_with_stdio(false);
  for (std::string line; std::getline(std::cin, line);) {
    const char *effects = conformance_run_v1(mode.c_str(), line.c_str());
    if (effects == nullptr) {
      std::cerr << "allocation failed\n";
      return 1;
    }
    std::cout << effects << '\n';
    conformance_free(effects);
  }
  std::cout.flush();
  return std::cin.bad() || !std::cout ? 1 : 0;
}
