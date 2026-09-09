#pragma once

#include <limits>

#include "block/workchain-account-engine.h"

namespace block {

// Engine outputs only, never final Native transaction/AccountBlock/shard roots.
// Entry bounds do not bound referenced data: the enclosing admission/execution
// boundary must account for the complete effects closure and engine work.
inline td::Result<td::Ref<vm::Cell>> encode_workchain_account_effects(
    const WorkchainAccountEffects& effects, std::uint64_t max_updates, std::uint64_t max_transfers,
    int extra_validation_cells) {
  if (effects.updates.size() > max_updates) return td::Status::Error("too many account effects");
  if (extra_validation_cells <= 0 || effects.native_transfers.size() > max_transfers ||
      effects.native_transfers.size() > std::numeric_limits<std::uint32_t>::max()) {
    return td::Status::Error("native effects exceed admitted limits");
  }
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
  vm::Dictionary transfers(32);
  const WorkchainInternalTransfer* prior = nullptr;
  for (auto it = effects.native_transfers.begin(); it != effects.native_transfers.end(); ++it) {
    if (it->from == it->to) return td::Status::Error("self-directed native transfer");
    if (prior && !(prior->from < it->from || (prior->from == it->from && prior->to < it->to))) {
      return td::Status::Error("native transfers not strictly ordered by source and destination");
    }
    prior = &*it;
    if (updates.lookup_ref(it->from).is_null() || updates.lookup_ref(it->to).is_null()) {
      return td::Status::Error("native transfer endpoint missing from account updates");
    }
    if (it->value.tomis.is_null() || !it->value.tomis->is_valid() ||
        !it->value.tomis->unsigned_fits_bits(256) || it->value.is_zero() ||
        !it->value.validate_extra(extra_validation_cells)) {
      return td::Status::Error("invalid native transfer amount");
    }
    vm::CellBuilder entry;
    entry.store_long(0x6b953015, 32).store_bits(it->from.bits(), 256).store_bits(it->to.bits(), 256);
    if (!it->value.store(entry)) return td::Status::Error("native transfer amount exceeds wire encoding");
    // begin <= it < end and size <= UINT32_MAX establish a nonnegative,
    // representable offset before subtraction and narrowing to the wire index.
    auto index = static_cast<std::uint32_t>(it - effects.native_transfers.begin());
    if (!transfers.set_ref(td::BitArray<32>(index), entry.finalize(), vm::Dictionary::SetMode::Add)) {
      return td::Status::Error("cannot encode native transfer");
    }
  }
  vm::CellBuilder native;
  native.store_long(effects.fees ? 0x67e2d380 : 0x0bd47725, 32);
  if (!native.store_maybe_ref(effects.payout_request) || !transfers.append_dict_to_bool(native)) {
    return td::Status::Error("cannot encode native effects");
  }
  if (effects.fees) {
    TRY_RESULT(totals, checked_workchain_fee_totals(*effects.fees));
    if (!totals.state.is_zero() && effects.native_transfers.size() >= max_transfers) {
      return td::Status::Error("fee edge exceeds admitted transfer count");
    }
    if (updates.lookup_ref(effects.fees->custody).is_null() ||
        updates.lookup_ref(effects.fees->coordinator).is_null()) {
      return td::Status::Error("fee role missing from account updates");
    }
    TRY_RESULT(fees, encode_workchain_fee_settlement(*effects.fees));
    if (!native.store_ref_bool(fees)) return td::Status::Error("cannot encode fee reference");
  }
  vm::CellBuilder cb;
  cb.store_long(0x4155a803, 32);
  if (!updates.append_dict_to_bool(cb) || !cb.store_ref_bool(native.finalize()) ||
      !cb.store_maybe_ref(effects.receipts) || !cb.store_maybe_ref(effects.events)) {
    return td::Status::Error("cannot encode account effects references");
  }
  cb.store_long(effects.usage.wire_bytes, 64).store_long(effects.usage.verification_units, 64)
      .store_long(effects.usage.written_cells, 64);
  return cb.finalize();
}

}  // namespace block
