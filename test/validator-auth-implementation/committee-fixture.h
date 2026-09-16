#pragma once
// Masterchain-state surgery shared by the committee cases and the genesis
// rehearsal. Both need the same state shape; a second copy would let one of
// them keep passing against a shape the other no longer produces.
#include <functional>

#include "block/mc-config.h"
#include "tos/quorum.h"
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

// One valid masterchain state: the registry, a real elected set and the
// catchain selector the native committee path requires. The committee cases
// and the joined commit cases both need it, and two copies would let one keep
// passing against a shape the other no longer builds.
inline td::Ref<vm::Cell> descriptor(unsigned i, const RegistryState& registry, unsigned variant = 0) {
  vm::CellBuilder pub;
  auto pk = h(variant == 13 ? 10001 : 10000 + i);
  if (variant == 7) {
    auto bytes = registry.keys().begin()->second.public_key_;
    std::copy(bytes.begin(), bytes.end(), pk.begin());
  }
  pub.store_long(0x8e81278a, 32).store_bytes(td::Slice(reinterpret_cast<const char*>(pk.data()), 32));
  vm::CellBuilder cell;
  cell.store_long(variant == 1 ? 0x73 : 0xb3, 8)
      .append_cellslice(vm::CellSlice(vm::NoVm{}, pub.finalize()))
      .store_long(i * 3, 64)
      .store_bytes(td::Slice(reinterpret_cast<const char*>(h(20000 + i).data()), 32));
  if (variant != 1) {
    vm::CellBuilder binding;
    binding
        .store_bytes(td::Slice(reinterpret_cast<const char*>(h((variant == 2 || variant == 12) ? 1
                                                               : variant == 3                  ? 0
                                                                                               : i)
                                                                 .data()),
                               32))
        .store_bytes(td::Slice(reinterpret_cast<const char*>(h((variant == 4 || variant == 12) ? 1001
                                                               : variant == 5                  ? 0
                                                               : variant == 10                 ? 9999
                                                                                               : 1000 + i)
                                                                 .data()),
                               32));
    if (variant == 6)
      binding.store_long(0, 1);
    if (variant == 9)
      binding.store_ref(vm::CellBuilder().finalize());
    cell.store_ref(binding.finalize());
  }
  return cell.finalize();
}
inline td::Ref<vm::Cell> election(const RegistryState& registry, unsigned variant = 0, unsigned count = 4) {
  vm::Dictionary list(16);
  std::uint64_t weight = 0;
  for (unsigned i = 1; i <= count; ++i) {
    td::BitArray<16> key(i - 1);
    check(list.set(key.bits(), 16,
                   td::make_ref<vm::CellSlice>(
                       vm::NoVm{},
                       descriptor(i, registry, i == ((variant == 12 || variant == 13) ? 4u : 2u) ? variant : 0))),
          "list-add");
    check(tos::checked_add_validator_weight(weight, i * 3), "fixture-weight");
  }
  vm::CellBuilder root;
  root.store_long(0x12, 8)
      .store_long(0, 32)
      .store_long(variant == 8 ? 0 : 10000, 32)
      .store_long(count, 16)
      .store_long(variant == 11 ? count : std::min(count, 3u), 16)
      .store_long(weight, 64);
  check(list.append_dict_to_bool(root), "election-list");
  return root.finalize();
}
inline td::Ref<vm::Cell> chain_state(const RegistryState& registry, unsigned variant = 0, bool shuffle = false,
                              unsigned count = 4) {
  auto root = masterchain(registry, registry.coordinate());
  root = replace_config(root, 34, election(registry, variant, count));
  return replace_config(root, 28, catchain_selector(shuffle));
}

}  // namespace p0_fixture
