#pragma once

// Builders for the configuration dictionary the masterchain installs. Both the
// gate corpus and the adoption cases model the same layout, so they are written
// once here: two copies of this would let the corpus and the adoption evidence
// describe different configurations while each passed its own checks.

#include "owner-fixture.h"

namespace p0_config_gates_fixture {
using namespace p0_owner_fixture;

inline td::Ref<vm::Cell> put(td::Ref<vm::Cell> root, int key, td::Ref<vm::Cell> val) {
  vm::Dictionary d(root, 32);
  if (val.is_null())
    check(d.lookup_delete_ref(td::BitArray<32>{key}).not_null(), "fixture-delete");
  else
    check(d.set_ref(td::BitArray<32>{key}, val), "fixture-set");
  return d.get_root_cell();
}

inline td::Ref<vm::Cell> get(td::Ref<vm::Cell> root, int key) {
  vm::Dictionary d(root, 32);
  return d.lookup_ref(td::BitArray<32>{key});
}

inline td::Ref<vm::Cell> cap(unsigned version, std::uint64_t bits = 1070) {
  return vm::CellBuilder().store_long(0xc4, 8).store_long(version, 32).store_long(bits, 64).finalize();
}

inline td::Ref<vm::Cell> counts(unsigned max, unsigned main = 100, unsigned min = 1) {
  return vm::CellBuilder().store_long(max, 16).store_long(main, 16).store_long(min, 16).finalize();
}

inline td::Ref<vm::Cell> required(td::Ref<vm::Cell> config, int index, bool add, bool invalid = false) {
  vm::Dictionary d(get(config, index), 32);
  if (add) {
    vm::CellBuilder value;
    if (invalid)
      value.store_long(1, 1);
    check(d.set_builder(td::BitArray<32>{46}, value), "required-put");
  } else
    check(d.lookup_delete(td::BitArray<32>{46}).not_null(), "required-remove");
  return put(config, index, d.get_root_cell());
}

inline td::Ref<vm::Cell> change_registry(td::Ref<vm::Cell> root, unsigned offset, unsigned width, const Bytes& raw) {
  vm::CellSlice s(vm::NoVm{}, root);
  vm::CellBuilder b;
  b.store_bits(s.fetch_bits(offset));
  check(s.advance(width), "registry-field");
  b.store_bits(td::ConstBitPtr(raw.data()), width);
  b.append_cellslice(s);
  return b.finalize();
}

inline td::Ref<vm::Cell> replace_child(td::Ref<vm::Cell> root, unsigned index, td::Ref<vm::Cell> value) {
  vm::CellSlice s(vm::NoVm{}, root);
  vm::CellBuilder b;
  b.store_bits(s.fetch_bits(s.size()));
  for (unsigned i = 0; s.size_refs(); ++i) {
    auto old = s.fetch_ref();
    b.store_ref(i == index ? value : old);
  }
  return b.finalize();
}

inline Bytes integer(std::uint64_t n, unsigned width) {
  Bytes raw(width / 8);
  for (unsigned i = 0; i < raw.size(); ++i)
    raw[raw.size() - i - 1] = static_cast<std::uint8_t>(n >> (8 * i));
  return raw;
}

}  // namespace p0_config_gates_fixture
