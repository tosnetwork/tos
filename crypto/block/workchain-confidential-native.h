#pragma once

#include "vm/cells.h"

namespace block {

// Implementation choice for the shared Native wrapper: THROW 63, encoded by
// the VM's 10-bit THROW prefix and 6-bit exception number (contops.cpp).
// It is not a compute implementation. Engine-owned accounts never run Native
// phases; accidental execution must fail rather than silently succeed.
inline td::Ref<vm::Cell> workchain_confidential_native_code() {
  static const auto code = vm::CellBuilder().store_long(0xf23f, 16).finalize();
  return code;
}

inline bool is_workchain_confidential_native_wrapper(const td::Ref<vm::Cell>& code, bool tick, bool tock) {
  return code.not_null() && code->get_hash() == workchain_confidential_native_code()->get_hash() && !tick && !tock;
}

}  // namespace block
