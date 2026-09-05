#pragma once

#include <limits>

#include "td/utils/Status.h"
#include "vm/cells.h"

namespace tos::validator {

// The BoC already contains every cell's descriptors and data. A spool adds
// a hash/length record header, a refcount, and at most four child references
// carrying all significant hash/depth pairs. Counting the original reference
// indices too is conservative. A rollback manifest may duplicate every record.
inline td::Result<td::uint64> streaming_import_encoding_bound(td::uint64 file_bytes, td::uint64 cells) {
  constexpr td::uint64 extra_per_cell =
      vm::Cell::hash_bytes + sizeof(td::uint32) + sizeof(td::int32) +
      vm::Cell::max_refs * (1 + (vm::Cell::max_level + 1) * (vm::Cell::hash_bytes + vm::Cell::depth_bytes));
  constexpr auto max = std::numeric_limits<td::uint64>::max();
  if (file_bytes == 0 || cells == 0 || cells > max / extra_per_cell) {
    return td::Status::Error("invalid or overflowing streaming import encoding budget");
  }
  auto extra = cells * extra_per_cell;
  if (file_bytes > max - extra || file_bytes + extra > max / 2) {
    return td::Status::Error("streaming import encoding budget overflow");
  }
  return (file_bytes + extra) * 2;
}

}  // namespace tos::validator
