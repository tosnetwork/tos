#pragma once
// Masterchain-state surgery shared by the committee cases and the genesis
// rehearsal. Both need the same state shape; a second copy would let one of
// them keep passing against a shape the other no longer produces.
#include <functional>

#include "block/mc-config.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "vm/dict.h"

#include "native-fixture.h"
namespace p0_fixture {
inline td::Ref<vm::Cell> replace_config(td::Ref<vm::Cell> root, int index, td::Ref<vm::Cell> replacement) {
  auto cfg = block::Config::extract_from_state(root);
  check(cfg.is_ok(), "fixture-config");
  unsigned count = 0;
  std::function<td::Ref<vm::Cell>(td::Ref<vm::Cell>)> visit = [&](td::Ref<vm::Cell> cell) {
    vm::CellSlice slice(vm::NoVm{}, cell);
    // The McStateExtra config root is its first reference.
    if (slice.size() >= 16 && slice.prefetch_ulong(16) == 0xcc26) {
      vm::Dictionary dictionary(slice.prefetch_ref(), 32);
      td::BitArray<32> key(index);
      check(dictionary.set_ref(key.bits(), 32, replacement), "fixture-param");
      vm::CellBuilder b;
      b.store_bits(slice.fetch_bits(slice.size()));
      slice.fetch_ref();
      b.store_ref(dictionary.get_root_cell());
      while (slice.size_refs())
        b.store_ref(slice.fetch_ref());
      ++count;
      return td::Ref<vm::Cell>(b.finalize());
    }
    vm::CellBuilder b;
    b.store_bits(slice.fetch_bits(slice.size()));
    while (slice.size_refs())
      b.store_ref(visit(slice.fetch_ref()));
    return td::Ref<vm::Cell>(b.finalize());
  };
  auto output = visit(root);
  check(count == 1, "fixture-config-replaced");
  return output;
}

// The selector the native committee path requires; its legacy fallback is not
// accepted, so the rehearsal must install a real CatchainConfig.
inline td::Ref<vm::Cell> catchain_selector(bool shuffle = false) {
  vm::CellBuilder selector;
  selector.store_long(0xc2, 8)
      .store_long(0, 7)
      .store_long(shuffle, 1)
      .store_long(100, 32)
      .store_long(100, 32)
      .store_long(1000, 32)
      .store_long(2, 32);
  return selector.finalize();
}
}  // namespace p0_fixture
