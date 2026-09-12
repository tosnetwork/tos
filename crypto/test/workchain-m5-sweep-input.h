#pragma once
// TEST ONLY dispatch selector. All authorization fields come from Param84;
// all destinations come from authenticated bucket entries. No caller choices.
#include "block/workchain-confidential-state.h"

namespace block::m3_test {
constexpr unsigned m5_test_sweep_tag = 0x54535731;  // TSW1
inline bool is_m5_test_sweep(const td::Ref<vm::Cell>& root) {
  if (root.is_null()) return false;
  bool special = false;
  auto slice = vm::load_cell_slice_special(root, special);
  return !special && slice.have(32) && slice.prefetch_ulong(32) == m5_test_sweep_tag;
}
inline td::Status decode_m5_test_sweep(const td::Ref<vm::Cell>& root) {
  if (!is_m5_test_sweep(root) || vm::load_cell_slice(root).size_ext() != 32)
    return td::Status::Error(-7200, "malformed test sweep selector");
  return td::Status::OK();
}
inline td::Ref<vm::Cell> encode_m5_test_sweep() {
  return vm::CellBuilder().store_long(m5_test_sweep_tag, 32).finalize();
}
}  // namespace block::m3_test
