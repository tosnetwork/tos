// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Observe original AccountStorage through the production account decoder.
#include <cstddef>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

#include "block/transaction.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "vm/boc.h"

namespace {
template <class T>
T require(td::Result<T> result) {
  if (result.is_error()) {
    throw std::runtime_error(result.error().to_string());
  }
  return result.move_as_ok();
}
void check(bool value, const char* message) {
  if (!value) {
    throw std::runtime_error(message);
  }
}
}  // namespace

int main(int argc, char** argv) {
  try {
    check(argc == 2, "usage: test-storage-encoding inputs.tsv");
    constexpr std::size_t max_bytes = 16 * 1024 * 1024;
    auto bytes = require(td::read_file(td::CSlice(argv[1]), max_bytes + 1));
    check(bytes.size() <= max_bytes, "encoding input byte limit");
    std::istringstream input(bytes.as_slice().str());
    std::string line;
    std::size_t rows = 0;
    const auto address = td::Bits256::zero();
    while (std::getline(input, line)) {
      check(++rows <= 4096 && line.size() <= 65536, "encoding row limit");
      const auto separator = line.find('\t');
      check(separator != std::string::npos && separator > 0 && separator <= 256 &&
                line.find('\t', separator + 1) == std::string::npos,
            "invalid encoding record");
      const auto name = line.substr(0, separator);
      check(name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") ==
                std::string::npos,
            "invalid encoding name");
      auto raw = require(td::hex_decode(line.substr(separator + 1)));
      auto shard = require(vm::std_boc_deserialize(raw));
      block::Account account(0, address.bits());
      if (!account.unpack(vm::load_cell_slice_ref(shard), 1780000000, false)) {
        std::cout << name << "\t0\t-\t-\n";
        continue;
      }
      check(account.storage.not_null(), "expected present account storage");
      auto storage = vm::CellBuilder{}.append_cellslice(*account.storage).finalize_novm();
      std::cout << name << "\t1\t" << account.storage->size() << '\t' << storage->get_hash().to_hex() << '\n';
    }
    check(rows != 0, "empty encoding input");
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
