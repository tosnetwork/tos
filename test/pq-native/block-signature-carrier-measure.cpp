/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <array>
#include <cassert>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include "block-signature-carrier-common.h"

int main() {
  constexpr std::array<std::size_t, 6> counts{1, 21, 32, 64, 100, 400};
  std::vector<std::string> measured_lines;
  measured_lines.emplace_back(
      "signers\tcells\tdepth\tblock_signatures_boc\tblock_signatures_boc_sha256\t"
      "block_proof_boc\tnode_tl\tlite_tl\tsimplex_certificate_tl\t"
      "boc_minus_certificate\tinput");
  for (const auto count : counts) {
    const bool valid = count <= 100;
    const auto measured = block_signature_carrier_test::measure(count, valid);
    std::ostringstream line;
    line << measured.signers << '\t' << measured.cells << '\t' << measured.depth << '\t'
         << measured.signatures_boc_bytes << '\t' << measured.signatures_boc_sha256 << '\t'
         << measured.block_proof_boc_bytes << '\t' << measured.node_tl_bytes << '\t' << measured.lite_tl_bytes << '\t'
         << measured.certificate_tl_bytes << '\t' << measured.boc_minus_certificate << '\t'
         << (valid ? "valid" : "deterministic-size");
    measured_lines.push_back(line.str());
  }
  measured_lines.emplace_back(
      "401\tREFUSED\tREFUSED\tREFUSED\tREFUSED\tREFUSED\tREFUSED\tREFUSED\tREFUSED\tREFUSED\tstructural");

  std::ifstream input(MEASUREMENTS_FILE);
  assert(input && "the committed carrier measurement file must be readable");
  std::vector<std::string> expected_lines;
  std::string line;
  while (std::getline(input, line)) {
    if (!line.empty() && line[0] != '#') {
      expected_lines.push_back(line);
    }
  }
  if (expected_lines.size() != measured_lines.size()) {
    std::fprintf(stderr, "MEASUREMENT_DRIFT: committed TSV has %zu data rows; measured %zu\n", expected_lines.size(),
                 measured_lines.size());
    return 1;
  }
  for (std::size_t i = 0; i < measured_lines.size(); ++i) {
    if (measured_lines[i] != expected_lines[i]) {
      const char* row = i == 0 ? "header" : (i + 1 == measured_lines.size() ? "401" : nullptr);
      const auto signer = i > 0 && i + 1 < measured_lines.size() ? counts[i - 1] : 0;
      if (row != nullptr) {
        std::fprintf(stderr, "MEASUREMENT_DRIFT: row=%s\nexpected: %s\nmeasured: %s\n", row, expected_lines[i].c_str(),
                     measured_lines[i].c_str());
      } else {
        std::fprintf(stderr, "MEASUREMENT_DRIFT: signers=%zu\nexpected: %s\nmeasured: %s\n", signer,
                     expected_lines[i].c_str(), measured_lines[i].c_str());
      }
      std::fprintf(stderr, "full measured table:\n");
      for (const auto& measured_line : measured_lines) {
        std::fprintf(stderr, "%s\n", measured_line.c_str());
      }
      return 1;
    }
  }
  for (const auto& measured_line : measured_lines) {
    std::printf("%s\n", measured_line.c_str());
  }
  return 0;
}
