#pragma once
#include "td/db/KeyValue.h"
#include "td/utils/buffer.h"

namespace tos::validator {
// Opaque local crash-recovery bytes. Auth semantics are deliberately outside
// StateDb; this layer only provides one bounded, crash-atomic value.
inline constexpr std::size_t validator_auth_finality_journal_max_bytes = 1024;
td::Status store_validator_auth_finality_journal(td::KeyValue&, td::Slice);
td::Result<td::BufferSlice> load_validator_auth_finality_journal(td::KeyValue&);
}  // namespace tos::validator
