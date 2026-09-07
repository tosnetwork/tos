#pragma once

#include <cstdint>
#include <limits>
#include <vector>

#include "common/bitstring.h"
#include "td/utils/Status.h"
#include "vm/cells.h"

namespace block {

// One binding record per canonical write key. Index is its zero-based position
// in the account effects sequence; neither role nor privileges are self-claimed.
// These are payload records, not TransactionDescr or account wrappers. The host
// must independently reconstruct effects and check actual dictionary coverage.
// No final transaction hash, last_trans hash or resulting shard root is an input.
inline td::Result<std::vector<td::Ref<vm::Cell>>> build_workchain_participant_records(
    const td::Bits256& input_hash, const td::Bits256& effects_hash,
    const std::vector<td::Bits256>& write_keys, std::uint64_t max_participants) {
  // Count and every zero-based effect index must fit the wire's uint32 space.
  if (write_keys.empty() || write_keys.size() > max_participants ||
      write_keys.size() > std::numeric_limits<std::uint32_t>::max()) {
    return td::Status::Error("participant record count outside admitted bounds");
  }
  const td::Bits256* previous = nullptr;
  for (const auto& key : write_keys) {
    if (previous && !(*previous < key)) return td::Status::Error("participant keys not strictly ordered");
    previous = &key;
  }
  std::vector<td::Ref<vm::Cell>> records;
  records.reserve(write_keys.size());
  for (auto it = write_keys.begin(); it != write_keys.end(); ++it) {
    // begin <= it < end and size <= UINT32_MAX establish a nonnegative,
    // representable offset before subtraction and narrowing.
    auto index = static_cast<std::uint32_t>(it - write_keys.begin());
    records.push_back(vm::CellBuilder().store_long(0x35739af6, 32)
        .store_bits(input_hash.bits(), 256).store_bits(effects_hash.bits(), 256)
        .store_bits(it->bits(), 256).store_long(index, 32).finalize());
  }
  return records;
}

}  // namespace block
