#pragma once

#include "uno/core/amount.h"

namespace uno_workchain {

// Logical contexts only, not wire tags. Flags here are decoded permissions;
// canonical flag encoding, proofs, anchors and authorization are checked elsewhere.
enum class BundleContext { Transfer, ShieldClaim, Unshield, WithdrawalRefund, Genesis, PrivateFeeDistribution };

inline td::Status validate_bundle_context(BundleContext context, td::int64 value_balance,
                                          bool spend_enabled, bool output_enabled,
                                          const Amount& public_amount, const Amount& fee) {
  Amount magnitude;
  bool negative = false;
  bool requires_spends = false;
  switch (context) {
    case BundleContext::Transfer:
      if (public_amount.high() != 0 || public_amount.low() != 0) {
        return td::Status::Error("UNO transfer has an unexpected public principal");
      }
      magnitude = fee;
      requires_spends = true;
      break;
    case BundleContext::Unshield: {
      if (public_amount.high() == 0 && public_amount.low() == 0) {
        return td::Status::Error("UNO settlement principal must be positive");
      }
      TRY_RESULT(debit, public_amount.checked_add(fee));
      magnitude = debit;
      requires_spends = true;
      break;
    }
    case BundleContext::ShieldClaim:
    case BundleContext::WithdrawalRefund:
    case BundleContext::Genesis:
    case BundleContext::PrivateFeeDistribution:
      if (public_amount.high() == 0 && public_amount.low() == 0) {
        return td::Status::Error("UNO settlement principal must be positive");
      }
      if (fee.high() != 0 || fee.low() != 0) {
        return td::Status::Error("UNO output-only settlement has an unexpected fee");
      }
      magnitude = public_amount;
      negative = true;
      break;
    default:
      return td::Status::Error("unknown UNO bundle context");
  }
  TRY_RESULT(expected_balance, magnitude.checked_bundle_balance(negative));
  if (value_balance != expected_balance) {
    return td::Status::Error("UNO bundle value balance differs from public context");
  }
  if (spend_enabled != requires_spends || !output_enabled) {
    return td::Status::Error("UNO bundle permissions differ from public context");
  }
  return td::Status::OK();
}

}  // namespace uno_workchain
