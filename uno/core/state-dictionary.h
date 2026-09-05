#pragma once

#include <cstdint>
#include "vm/dict.h"

namespace uno_workchain::detail {

// Structural validation without implicit library resolution. The caller owns
// the leaf policy, aggregate entry budget and exception boundary. Start at 256
// bits for these state dictionaries; every fork reduces the remaining width.
template <class Leaf>
bool validate_state_dictionary(const td::Ref<vm::Cell>& root, int key_bits,
                               std::uint64_t& remaining, const Leaf& leaf) {
  if (root.is_null()) return true;
  if (remaining == 0) return false;
  bool special = false;
  auto slice = vm::load_cell_slice_special(root, special);
  if (special) return false;
  vm::dict::LabelParser label(td::Ref<vm::CellSlice>{true, std::move(slice)}, key_bits);
  label.skip_label();
  if (label.l_bits == key_bits) {
    if (!leaf(*label.remainder)) return false;
    --remaining;
    return true;
  }
  const int child_bits = key_bits - label.l_bits - 1;
  return validate_state_dictionary(label.remainder->prefetch_ref(0), child_bits, remaining, leaf) &&
         validate_state_dictionary(label.remainder->prefetch_ref(1), child_bits, remaining, leaf);
}

}  // namespace uno_workchain::detail
