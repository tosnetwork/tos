#include <iostream>
#include <sodium.h>
#include <stdexcept>

#include "validator/auth/cells.h"
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
int main() {
  try {
    Bytes small(120, 9);
    auto accepted = unpack_bytes(root(small, leaf(small)));
    check(accepted.ok() && accepted.value() == small, "ordinary-leaf");
    check(!unpack_bytes(root(small, leaf(small), true)).ok(), "hash-binding");
    Bytes large(121, 7);
    auto raw = std::span<const std::uint8_t>(large);
    vm::CellBuilder canonical;
    canonical.store_long(1, 1)
        .store_long(2, 3)
        .store_long(121, 32)
        .store_ref(leaf(raw.first(120)))
        .store_ref(leaf(raw.last(1)));
    accepted = unpack_bytes(root(large, canonical.finalize()));
    check(accepted.ok() && accepted.value() == large, "ordinary-branch");
    vm::CellBuilder alternative;
    alternative.store_long(1, 1)
        .store_long(2, 3)
        .store_long(121, 32)
        .store_ref(leaf(raw.first(119)))
        .store_ref(leaf(raw.last(2)));
    check(!unpack_bytes(root(large, alternative.finalize())).ok(), "canonical-partition");
    std::cout << "PASS: native cell semantic guards\n";
    return 0;
  } catch (const std::runtime_error& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
