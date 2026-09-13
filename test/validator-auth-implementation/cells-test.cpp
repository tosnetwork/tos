#include <filesystem>
#include <fstream>
#include <iostream>
#include <sodium.h>
#include <stdexcept>

#include "validator/auth/cells.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
using namespace tos::auth;
void check(bool ok, const char* name) {
  if (!ok)
    throw std::runtime_error(name);
}
td::Slice slice(std::span<const std::uint8_t> raw) {
  return {reinterpret_cast<const char*>(raw.data()), raw.size()};
}
td::Ref<vm::Cell> leaf(std::span<const std::uint8_t> raw) {
  vm::CellBuilder b;
  b.store_long(0, 1).store_long(raw.size(), 7).store_bytes(slice(raw));
  return b.finalize();
}
td::Ref<vm::Cell> root(std::span<const std::uint8_t> raw, td::Ref<vm::Cell> tree, bool corrupt = false) {
  Hash hash;
  check(crypto_hash_sha256(hash.data(), raw.data(), raw.size()) == 0, "hash-backend");
  if (corrupt)
    hash[0] ^= 1;
  vm::CellBuilder b;
  b.store_long(0x76616231, 32).store_long(1, 16).store_long(raw.size(), 32).store_bytes(slice(hash)).store_ref(tree);
  return b.finalize();
}
int main(int argc, char** argv) {
  try {
    std::filesystem::path output;
    if (argc == 2) {
      output = argv[1];
      check(std::filesystem::create_directory(output), "fresh-cell-export");
    } else
      check(argc == 1, "cell-export-arguments");
    auto export_cell = [&](std::string name, td::Ref<vm::Cell> cell, std::size_t budget, bool accepted) {
      if (output.empty())
        return;
      auto serialized = vm::std_boc_serialize(cell, 31);
      check(serialized.is_ok(), "cell-export-boc");
      std::ofstream boc(output / (name + ".boc"), std::ios::binary);
      boc.write(serialized.ok().as_slice().data(), serialized.ok().size());
      check(boc.good(), "cell-export-write");
      std::ofstream meta(output / (name + ".cell"));
      meta << budget << ' ' << accepted << '\n';
      check(meta.good(), "cell-export-meta");
    };
    Bytes small(120, 9);
    auto accepted = unpack_bytes(root(small, leaf(small)));
    check(accepted.ok() && accepted.value() == small, "ordinary-leaf");
    export_cell("valid-leaf", root(small, leaf(small)), 33554432, true);
    export_cell("hash-binding", root(small, leaf(small), true), 33554432, false);
    export_cell("budget-before-allocation", root(small, leaf(small)), 119, false);
    check(!unpack_bytes(root(small, leaf(small), true)).ok(), "hash-binding");
    check(!unpack_bytes(root(small, leaf(small)), 119).ok(), "budget-before-allocation");
    Bytes large(121, 7);
    auto raw = std::span<const std::uint8_t>(large);
    vm::CellBuilder canonical;
    canonical.store_long(1, 1)
        .store_long(2, 3)
        .store_long(121, 32)
        .store_ref(leaf(raw.first(120)))
        .store_ref(leaf(raw.last(1)));
    auto canonical_cell = root(large, canonical.finalize());
    export_cell("valid-branch", canonical_cell, 33554432, true);
    accepted = unpack_bytes(canonical_cell);
    check(accepted.ok() && accepted.value() == large, "ordinary-branch");
    vm::CellBuilder alternative;
    alternative.store_long(1, 1)
        .store_long(2, 3)
        .store_long(121, 32)
        .store_ref(leaf(raw.first(119)))
        .store_ref(leaf(raw.last(2)));
    auto alternative_cell = root(large, alternative.finalize());
    export_cell("canonical-partition", alternative_cell, 33554432, false);
    check(!unpack_bytes(alternative_cell).ok(), "canonical-partition");
    if (!output.empty()) {
      std::ofstream done(output / "complete");
      done << 5 << '\n';
      check(done.good(), "cell-export-complete");
    }
    std::cout << "PASS: native cell semantic guards\n";
    return 0;
  } catch (const std::runtime_error& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
