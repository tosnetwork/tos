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
// D64: Withdrawal reuses R_SEND's billing unit, not a separately maintained
// number. These are billing units, never proof-work operation counts.
inline constexpr std::uint64_t kWorkchainSendBillingUnits = 1;
inline constexpr std::uint64_t kWorkchainCollectBillingUnits = 3;

// Withdrawal is a distinct operation, even though D64 reuses R_SEND. Its
// one billing unit is frozen; its W-state price is an explicit authenticated
// parameter, not SEND's pending slot price. The sender chooses the remainder
// of the publicly authorized f as tip (D28). No forwarding/reserve value is F.
// Both price arguments must already be obtained from authenticated config;
// this helper cannot classify acquisition failures or supply missing policy.
// An unrepresentable floor is a deterministic content failure, not missing data.
// The subtraction BELOW is the admission check. Comparing total to claimed_fee
// afterwards is tautological and must not be counted as another admission gate.
inline td::Result<WorkchainOperationFeeAmounts> derive_workchain_withdrawal_fee_amounts(
    std::uint64_t authenticated_base, std::uint64_t authenticated_state_fee,
    std::uint64_t claimed_fee) {
  std::uint64_t compute, floor, tip;
  if (__builtin_mul_overflow(authenticated_base, kWorkchainSendBillingUnits, &compute) ||
      __builtin_add_overflow(authenticated_state_fee, compute, &floor))
    return td::Status::Error(-7200, "Withdrawal authenticated fee floor overflow");
  if (__builtin_sub_overflow(claimed_fee, floor, &tip))
    return td::Status::Error(-7200, "Withdrawal public fee below authenticated fee floor");
  return WorkchainOperationFeeAmounts{authenticated_state_fee, compute, tip, claimed_fee};
}

// D28 / section 12.1: billing units are SEND=1, COLLECT=3. They are NOT
// proof-work units. Profile-4 operation counts enforce resource admission only;
// accepting such a count as a fee input previously multiplied prices by orders
// of magnitude. Derive billing units from the relation, never effects.usage or
// a caller-supplied count. This does not implement D28's dynamic base update.
inline td::Result<WorkchainOperationFeeAmounts> derive_workchain_operation_fee_amounts(
    const WorkchainStaticOperationTariff& tariff, std::uint64_t authenticated_slot_fee,
    unsigned relation) {
  if (relation != 1 && relation != 2)
    return td::Status::Error(-7201, "unsupported operation fee reconstruction input");
  // D25: SEND's state component is the authenticated slot price; COLLECT has
  // zero state fee. Do not charge COLLECT for freeing an existing receipt slot.
  const auto state = relation == 1 ? authenticated_slot_fee : 0;
  const auto tip = relation == 1 ? tariff.send_tip : tariff.collect_tip;
  const auto billing_units = relation == 1 ? kWorkchainSendBillingUnits : kWorkchainCollectBillingUnits;
  std::uint64_t compute, subtotal, total;
  if (__builtin_mul_overflow(tariff.base, billing_units, &compute) ||
      __builtin_add_overflow(state, compute, &subtotal) || __builtin_add_overflow(subtotal, tip, &total))
    return td::Status::Error(-7200, "operation fee exceeds representable public authorization");
  return WorkchainOperationFeeAmounts{state, compute, tip, total};
}
inline td::Status check_workchain_operation_public_fee(const WorkchainOperationFeeAmounts& amounts,
                                                       std::uint64_t claimed_fee) {
  if (claimed_fee != amounts.total)
    return td::Status::Error(-7200, "operation public fee differs from authenticated static components");
  return td::Status::OK();
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
  if (reconstructed.custody != claimed.custody || reconstructed.coordinator != claimed.coordinator ||
      reconstructed.compute_payer != claimed.compute_payer)
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
