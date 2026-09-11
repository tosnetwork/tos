#pragma once
#include "block/block-parse.h"
#include "block/workchain-fee-settlement.h"

namespace block {
// Mandatory authenticated static tariff. No local defaults and no D28 dynamic
// base update. M4 settles D32 because nonzero backing exposes the pre-existing
// missing Native counterpart to confidential operation fees; M4 did not create
// that missing counterpart. Neither state allocation nor collected fees emits
// a message or retains an asynchronous obligation.
struct WorkchainStaticOperationTariff {
  std::uint64_t base, send_tip, collect_tip;
};
struct WorkchainOperationFeeAmounts {
  std::uint64_t state, compute, tip, total;
};

// Units must be reconstructed from the verified operation, never effects.usage
// or a collator-declared aggregate. The existing kernel binds total in its
// challenge; this host reconstruction supplies the independent allocation.
inline td::Result<WorkchainOperationFeeAmounts> derive_workchain_operation_fee_amounts(
    const WorkchainStaticOperationTariff& tariff, std::uint64_t authenticated_slot_fee,
    unsigned relation, std::uint64_t verified_units) {
  if ((relation != 1 && relation != 2) || !verified_units)
    return td::Status::Error(-7201, "unsupported operation fee reconstruction input");
  // D25: SEND's state component is the authenticated slot price; COLLECT has
  // zero state fee. Do not charge COLLECT for freeing an existing receipt slot.
  const auto state = relation == 1 ? authenticated_slot_fee : 0;
  const auto tip = relation == 1 ? tariff.send_tip : tariff.collect_tip;
  std::uint64_t compute, subtotal, total;
  if (__builtin_mul_overflow(tariff.base, verified_units, &compute) ||
      __builtin_add_overflow(state, compute, &subtotal) || __builtin_add_overflow(subtotal, tip, &total))
    return td::Status::Error(-7200, "operation fee exceeds representable public authorization");
  return WorkchainOperationFeeAmounts{state, compute, tip, total};
}
inline td::RefInt256 workchain_unsigned_fee(std::uint64_t amount) {
  // Do not narrow unsigned amounts through make_refint's signed constructor.
  return vm::load_cell_slice(vm::CellBuilder().store_long(amount, 64).finalize()).fetch_int256(64, false);
}
inline WorkchainFeeSettlement materialize_workchain_operation_fees(const WorkchainOperationFeeAmounts& amounts,
    const td::Bits256& custody, const td::Bits256& coordinator) {
  return {custody, coordinator, workchain_unsigned_fee(amounts.state), workchain_unsigned_fee(amounts.compute),
          workchain_unsigned_fee(amounts.tip)};
}

// Compare components, not merely F. Called only after authenticated policy and
// operation reconstruction: disagreement is a candidate fault, not missing data.
// This does not authorize a fee by conservation alone or settle any transaction.
inline td::Status compare_workchain_operation_fee_claim(const WorkchainFeeSettlement& reconstructed,
                                                       const WorkchainFeeSettlement& claimed) {
  auto invalid = [] { return td::Status::Error(-7200, "candidate fee components or authenticated recipients differ"); };
  if (reconstructed.custody != claimed.custody || reconstructed.coordinator != claimed.coordinator)
    return invalid();
  for (const auto& pair : {std::pair{reconstructed.state_fee, claimed.state_fee},
                         std::pair{reconstructed.compute_fee, claimed.compute_fee},
                         std::pair{reconstructed.tip, claimed.tip}}) {
    if (pair.first.is_null() || !pair.first->is_valid())
      return td::Status::Error(-7201, "reconstructed fee unavailable");
    if (pair.second.is_null() || !pair.second->is_valid() || td::cmp(pair.first, pair.second) != 0)
      return invalid();
  }
  return td::Status::OK();
}
}  // namespace block
