/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-or-later */
// Print the logical content of a stopped wallet index, for comparing two
// replays of the same source: one line per key in key order, "<key hex>
// <sha256 of value hex>", then "keys=<n> sha256=<digest of those lines>".
// The database is opened read-only; RocksDB's own files and metadata are not
// part of the content.
#include <iostream>
#include <string>

#include "td/db/RocksDbReadOnly.h"
#include "td/utils/OptionParser.h"
#include "td/utils/Slice.h"
#include "td/utils/crypto.h"
#include "td/utils/misc.h"

int main(int argc, char** argv) {
  std::string path;
  td::OptionParser parser;
  parser.set_description("Print the logical content of a stopped wallet index (read-only).");
  parser.add_option('\0', "index-dir", "the index directory, <data-dir>/index", [&](td::Slice v) { path = v.str(); });
  auto parsed = parser.run(argc, argv);
  if (parsed.is_error() || path.empty()) {
    std::cerr << "specify --index-dir" << std::endl;
    return 2;
  }
  auto db = td::RocksDbReadOnly::open(path);
  if (db.is_error()) {
    std::cerr << "cannot open " << path << " read-only: " << db.error().message().str() << std::endl;
    return 2;
  }
  td::Sha256State total;
  total.init();
  uint64_t keys = 0;
  auto status = db.ok_ref().for_each([&](td::Slice key, td::Slice value) {
    unsigned char value_hash[32];
    td::sha256(value, td::MutableSlice(value_hash, 32));
    auto line = td::hex_encode(key) + " " + td::hex_encode(td::Slice(value_hash, 32)) + "\n";
    total.feed(line);
    std::cout << line;
    ++keys;
    return td::Status::OK();
  });
  if (status.is_error()) {
    std::cerr << "iteration failed: " << status.message().str() << std::endl;
    return 1;
  }
  unsigned char digest[32];
  total.extract(td::MutableSlice(digest, 32));
  std::cout << "keys=" << keys << " sha256=" << td::hex_encode(td::Slice(digest, 32)) << std::endl;
  return 0;
}
