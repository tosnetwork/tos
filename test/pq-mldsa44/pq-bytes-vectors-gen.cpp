/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Emits the shared PQBytes vector fixture (authoritative C++ side): for each input,
// the canonical cell's repr hash and its standard BOC. Both C++ and Rust check
// against this committed fixture so the on-chain encoding is identical cross-language.
#include <cstdio>
#include <string>
#include <vector>

#include "crypto/pq/pq-bytes.h"
#include "td/utils/misc.h"
#include "vm/boc.h"

int main() {
  const std::vector<std::size_t> sizes{0, 1, 126, 127, 128, 254, 1312, 2420};
  // line format: <input_hex> <root_hash_hex> <boc_hex>, one vector per line
  for (auto n : sizes) {
    std::string s(n, '\0');
    for (std::size_t i = 0; i < n; i++)
      s[i] = char((i * 131 + 7) & 0xff);
    auto cell = tos::pq::pack_pq_bytes(td::Slice(s), 2420).move_as_ok();
    auto boc = vm::std_boc_serialize(cell, 31).move_as_ok();
    printf("%s %s %s\n", td::hex_encode(td::Slice(s)).c_str(), td::hex_encode(cell->get_hash().as_slice()).c_str(),
           td::hex_encode(boc.as_slice()).c_str());
  }
  return 0;
}
