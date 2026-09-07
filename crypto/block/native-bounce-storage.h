#pragma once

#include <cstdint>
#include "vm/boc.h"

namespace block {

struct NativeBounceStorageSize {
  std::uint64_t cells;
  std::uint64_t bits;
};

// Measure the Native pricing closure, excluding the output message root.
// One accumulator deduplicates shared descendants across currency and body
// roots. An absent optional currency root contributes zero; a failed actual
// traversal must never be mistaken for a valid partial size or insufficient
// return funds. This helper adds no catch or failure-source classification.
// The legacy NoVm walker is not a recoverable loader: an unavailable descendant
// can leave an empty slice and lead to a fatal reference access. A batch caller
// must first authenticate, admit and fully materialize/validate its complete
// closure; root is_loaded() alone does not establish descendant availability.
// This preserves the Native storage walk, not a resource-admission boundary.
inline td::Result<NativeBounceStorageSize> measure_native_bounce_storage(
    bool include_currency_root, td::Ref<vm::Cell> currency_root,
    td::Span<td::Ref<vm::Cell>> body_roots) {
  vm::CellStorageStat stat;
  if (include_currency_root && currency_root.not_null()) {
    auto measured = stat.add_used_storage(std::move(currency_root));
    if (measured.is_error()) return measured.move_as_error();
  }
  auto measured = stat.add_used_storage(body_roots);
  if (measured.is_error()) return measured.move_as_error();
  return NativeBounceStorageSize{stat.cells, stat.bits};
}

}  // namespace block
