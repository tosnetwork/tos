#pragma once

#include "block/workchain-value-flow.h"

namespace block {

struct WorkchainBounceAccounting {
  CurrencyCollection returned;
  WorkchainAccountValueFlow row;
};

// Accounting for an already selected, affordable wrong-destination bounce.
// The original destination need not be the processing account. Authentication,
// the versioned address exceptions and fee pricing are separate obligations.
// No compute/action costs are charged here: this message never runs user code.
// Total and collected fees must come from the shared Native pricing rules.
// This does not select bounce versus credit: an Error must not be interpreted
// as permission to change that branch. Inputs require admitted complete closures;
// allocation and dictionary exceptions propagate to the source-aware boundary.
inline td::Result<WorkchainBounceAccounting> account_workchain_bounce(
    const td::Bits256& processing_account, const CurrencyCollection& old_balance,
    const CurrencyCollection& imported, const td::RefInt256& total_fee_amount,
    const td::RefInt256& collected_fee_amount, int extra_validation_cells) {
  auto valid = [&](const CurrencyCollection& amount) {
    return amount.tomis.not_null() && amount.tomis->is_valid() &&
           amount.tomis->unsigned_fits_bits(256) && amount.validate_extra(extra_validation_cells);
  };
  CurrencyCollection total_fee(total_fee_amount), collected_fee(collected_fee_amount);
  if (extra_validation_cells <= 0 || !valid(old_balance) || !valid(imported) ||
      !valid(total_fee) || !valid(collected_fee)) {
    return td::Status::Error("invalid bounce accounting inputs");
  }
  CurrencyCollection returned, remaining_fee, exported;
  // sub checks every currency and nonnegativity. Principal in old_balance is
  // never a funding source: affordability is checked against imported alone.
  if (!CurrencyCollection::sub(imported, total_fee, returned) ||
      !CurrencyCollection::sub(total_fee, collected_fee, remaining_fee) ||
      !CurrencyCollection::add(returned, remaining_fee, exported) ||
      !exported.tomis->unsigned_fits_bits(256)) {
    return td::Status::Error("bounce fee arithmetic out of bounds");
  }
  WorkchainAccountValueFlow row{processing_account, old_balance, imported, old_balance, exported, collected_fee};
  TRY_STATUS(verify_workchain_value_flow({row}, {}, 1, 0, extra_validation_cells));
  return WorkchainBounceAccounting{std::move(returned), std::move(row)};
}

}  // namespace block
