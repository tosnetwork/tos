#pragma once

#include "block/workchain-value-flow.h"

namespace block {

struct WorkchainPayoutAccounting {
  CurrencyCollection custody_after, operator_after;
  CurrencyCollection exported;  // Payment plus forwarding value still in flight.
  WorkchainInternalTransfer fee_funding;
  // Incremental payout-stage rows: input balances are already post-import,
  // post-allocation and (if enabled) post-disposal. These are not complete
  // transaction rows. Publishers must decode Native artifacts independently.
  std::vector<WorkchainAccountValueFlow> rows;
};

// Native mode-1 fee separation after actual message pricing. The caller must
// derive all three fee/payment values from the reconstructed send, not engine
// claims. No payout authorization, reserve lock or state mutation occurs here.
inline td::Result<WorkchainPayoutAccounting> account_workchain_payout(
    const td::Bits256& custody, const td::Bits256& coordinator,
    const CurrencyCollection& custody_before, const CurrencyCollection& operator_before,
    const CurrencyCollection& payment, const td::RefInt256& total_forwarding_fee,
    const td::RefInt256& collected_fee, int extra_validation_cells) {
  auto valid = [&](const CurrencyCollection& value) {
    return value.tomis.not_null() && value.tomis->is_valid() && value.tomis->unsigned_fits_bits(256) &&
           value.validate_extra(extra_validation_cells);
  };
  CurrencyCollection total_fee(total_forwarding_fee), local_fee(collected_fee);
  if (custody == coordinator || extra_validation_cells <= 0 || !valid(custody_before) ||
      !valid(operator_before) || !valid(payment) || !valid(total_fee) || !valid(local_fee) ||
      payment.tomis->sgn() <= 0) {
    return td::Status::Error("invalid payout accounting inputs");
  }
  CurrencyCollection custody_after, operator_after, remaining_fee, exported;
  // Native subtraction checks sufficient funds and each extra currency. In
  // particular, neither spare operator funds nor custody principal may cover
  // a deficit in the other account's independently checked obligation.
  if (!CurrencyCollection::sub(custody_before, payment, custody_after) ||
      !CurrencyCollection::sub(operator_before, total_fee, operator_after) ||
      !CurrencyCollection::sub(total_fee, local_fee, remaining_fee) ||
      !CurrencyCollection::add(payment, remaining_fee, exported) ||
      !exported.tomis->unsigned_fits_bits(256)) {
    return td::Status::Error("payout principal or fee arithmetic out of bounds");
  }
  WorkchainInternalTransfer funding{coordinator, custody, total_fee};
  std::vector<WorkchainAccountValueFlow> rows{
      {custody, custody_before, CurrencyCollection(0), custody_after, exported, local_fee},
      {coordinator, operator_before, CurrencyCollection(0), operator_after, CurrencyCollection(0), CurrencyCollection(0)}};
  std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) { return a.account < b.account; });
  TRY_STATUS(verify_workchain_value_flow(rows, {funding}, 2, 1, extra_validation_cells));
  return WorkchainPayoutAccounting{custody_after, operator_after, exported, funding, std::move(rows)};
}

}  // namespace block
