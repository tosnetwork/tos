/*
    Copyright (C) 2025-2026 TOS Network.

    VmState::max_library_loads enforcement tests. Ports the counting logic
    ton-c added in commit b647a8d5 (crypto/vm/vm.h/.cpp) -- TOS parsed
    ConfigParam 43 v3's max_transaction_library_loads (crypto/block/
    mc-config.cpp) but never enforced it in the VM or wired it into the
    consensus/emulator VM setup paths. See crypto/block/transaction.cpp's
    vm.set_max_library_loads(...) call and crypto/smc-envelope/
    SmartContract.cpp's max_smc_library_loads default for the wiring these
    tests are downstream of.
*/

#include "td/utils/tests.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cp0.h"
#include "vm/dict.h"
#include "vm/vm.h"

namespace {

// VmState::VmState() requires codepage 0's opcode table to already be
// registered; construct it once, lazily, the first time a test needs a
// bare VmState (mirrors how fift/emulator entrypoints call this at startup).
void ensure_cp0() {
  static const bool once = [] {
    vm::init_op_cp0();
    return true;
  }();
  (void)once;
}

// Builds a single-ref "library dict value" cell wrapping `content`, then
// inserts it into a 256-bit dictionary keyed by content's own hash --
// matching the HashmapE 256 ^Cell shape vm::lookup_library_in expects
// (dict value's ref must have the same hash as the lookup key).
td::Ref<vm::Cell> make_library_dict(const std::vector<td::Ref<vm::Cell>>& contents) {
  vm::Dictionary dict{256};
  for (const auto& c : contents) {
    CHECK(dict.set_ref(c->get_hash().bits(), 256, c));
  }
  return dict.get_root_cell();
}

td::Ref<vm::Cell> leaf_cell(td::uint32 tag) {
  vm::CellBuilder cb;
  cb.store_long(tag, 32);
  return cb.finalize();
}

}  // namespace

TEST(VmLibraryLoads, UnlimitedWhenNotSet) {
  ensure_cp0();
  auto a = leaf_cell(1), b = leaf_cell(2), c = leaf_cell(3);
  vm::VmState vm;
  CHECK(vm.register_library_collection(make_library_dict({a, b, c})));
  // No set_max_library_loads() call -- must not restrict anything.
  CHECK(vm.load_library(a->get_hash().bits()).not_null());
  CHECK(vm.load_library(b->get_hash().bits()).not_null());
  CHECK(vm.load_library(c->get_hash().bits()).not_null());
}

TEST(VmLibraryLoads, AllowsUpToLimitDistinctLibraries) {
  ensure_cp0();
  auto a = leaf_cell(10), b = leaf_cell(20);
  vm::VmState vm;
  CHECK(vm.register_library_collection(make_library_dict({a, b})));
  vm.set_max_library_loads(2);
  CHECK(vm.load_library(a->get_hash().bits()).not_null());
  CHECK(vm.load_library(b->get_hash().bits()).not_null());
}

TEST(VmLibraryLoads, RejectsDistinctLibraryBeyondLimit) {
  ensure_cp0();
  auto a = leaf_cell(100), b = leaf_cell(200), c = leaf_cell(300);
  vm::VmState vm;
  CHECK(vm.register_library_collection(make_library_dict({a, b, c})));
  vm.set_max_library_loads(2);
  CHECK(vm.load_library(a->get_hash().bits()).not_null());
  CHECK(vm.load_library(b->get_hash().bits()).not_null());
  // A third *distinct* library must be refused once the cap is reached.
  CHECK(vm.load_library(c->get_hash().bits()).is_null());
}

TEST(VmLibraryLoads, RepeatedLoadOfAlreadyCountedLibraryStaysAllowed) {
  ensure_cp0();
  auto a = leaf_cell(1000), b = leaf_cell(2000);
  vm::VmState vm;
  CHECK(vm.register_library_collection(make_library_dict({a, b})));
  vm.set_max_library_loads(1);
  CHECK(vm.load_library(a->get_hash().bits()).not_null());
  // Re-loading the same (already-counted) library must not be blocked by
  // its own count, even though max_library_loads == loaded_libraries.size().
  CHECK(vm.load_library(a->get_hash().bits()).not_null());
  CHECK(vm.load_library(a->get_hash().bits()).not_null());
  // A different library is refused once the cap is reached.
  CHECK(vm.load_library(b->get_hash().bits()).is_null());
}

TEST(VmLibraryLoads, ZeroLimitRejectsFirstDistinctLoad) {
  ensure_cp0();
  auto a = leaf_cell(1);
  vm::VmState vm;
  CHECK(vm.register_library_collection(make_library_dict({a})));
  vm.set_max_library_loads(0);
  CHECK(vm.load_library(a->get_hash().bits()).is_null());
}
