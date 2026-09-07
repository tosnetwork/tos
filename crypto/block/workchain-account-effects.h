#pragma once

#include "block/workchain-account-engine.h"

namespace block {

// Engine outputs only, never final Native transaction/AccountBlock/shard roots.
// Entry bounds do not bound referenced data: the enclosing admission/execution
// boundary must account for the complete effects closure and engine work.
inline td::Result<td::Ref<vm::Cell>> encode_workchain_account_effects(
    const WorkchainAccountEffects& effects, std::uint64_t max_updates) {
  if (effects.updates.size() > max_updates) return td::Status::Error("too many account effects");
  vm::Dictionary updates(256);
  const td::Bits256* previous = nullptr;
  for (const auto& update : effects.updates) {
    if ((previous && !(*previous < update.account)) || update.data.is_null()) {
      return td::Status::Error("invalid account effects ordering or data");
    }
    previous = &update.account;
    if (!updates.set_ref(update.account, update.data, vm::Dictionary::SetMode::Add)) {
      return td::Status::Error("cannot encode account effect");
    }
  }
  vm::CellBuilder cb;
  cb.store_long(0x0e15071a, 32);
  if (!updates.append_dict_to_bool(cb) || !cb.store_maybe_ref(effects.payout_request) ||
      !cb.store_maybe_ref(effects.receipts) || !cb.store_maybe_ref(effects.events)) {
    return td::Status::Error("cannot encode account effects references");
  }
  cb.store_long(effects.usage.wire_bytes, 64).store_long(effects.usage.verification_units, 64)
      .store_long(effects.usage.written_cells, 64);
  return cb.finalize();
}

}  // namespace block
