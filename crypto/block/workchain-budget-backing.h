#pragma once

#include "block/workchain-coordinator-state.h"
#include "block/workchain-unexpected-bucket.h"

namespace block {

// Accounting over an already admitted closure, not capacity admission. These
// bounds are the schema's uint32 widths, NOT substitute policy limits. The
// caller must have admitted the state footprint before traversing this root.
inline td::Result<CurrencyCollection> workchain_budget_bucket_holdings(
    const WorkchainCoordinatorState& state, int extra_validation_cells) {
  if (state.layout_version == 2 && state.unexpected.is_null()) return CurrencyCollection(0);
  if (state.layout_version != 3 || state.unexpected.is_null())
    return td::Status::Error("protected bucket state unavailable");
  TRY_RESULT(bucket, decode_workchain_unexpected_bucket(state.unexpected,
      {UINT32_MAX, UINT32_MAX}, extra_validation_cells));
  return workchain_unexpected_balance(bucket);
}

inline CurrencyCollection workchain_protected_refundable(std::uint64_t amount) {
  auto encoded = vm::CellBuilder().store_long(amount, 64).finalize();
  return CurrencyCollection(vm::load_cell_slice(encoded).fetch_int256(64, false));
}

// This inequality guarantees backing of protected claims, NOT correctness of
// the cumulative ledger. A stronger history-rebuilt operating ledger needs a
// predecessor-bound context, restart recovery and LocalUnavailable for missing
// history; that is an M5/M6 redesign, not one extra comparison. In particular,
// deriving spendable by subtraction would make the corresponding sum equality
// tautological. Classification and backing protect different failure modes.
inline td::Status check_workchain_budget_backing(const CurrencyCollection& balance,
    const CurrencyCollection& refundable, const CurrencyCollection& unexpected) {
  CurrencyCollection protected_total, remainder;
  if (!CurrencyCollection::add(refundable, unexpected, protected_total))
    return td::Status::Error("coordinator protected holdings overflow");
  // Checked subtraction enforces that every currency's balance covers all
  // independently recorded protected claims before any remainder is spendable.
  if (!CurrencyCollection::sub(balance, protected_total, remainder))
    return td::Status::Error("coordinator balance below protected holdings");
  return td::Status::OK();
}

// Inputs are independently reconstructed event amounts, never candidate
// classification choices. A missing bucket credit cannot become income just
// because the aggregate Native balance still reconciles.
inline td::Status check_workchain_bucket_credit_pair(const CurrencyCollection& before,
    const CurrencyCollection& after, const CurrencyCollection& credited) {
  CurrencyCollection expected;
  if (!CurrencyCollection::add(before, credited, expected) || expected != after)
    return td::Status::Error(-7200, "unexpected bucket credit differs from authenticated event");
  return td::Status::OK();
}
}  // namespace block
