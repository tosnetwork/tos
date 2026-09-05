#pragma once

#include "uno/core/amount.h"

namespace uno_workchain {

// Public liabilities, not a sum of hidden Notes. Callers must authenticate
// bundles and terminal receipts, enforce unique IDs and commit this result
// together with their tree, tombstones and reservations. These functions do
// not authorize a withdrawal/refund or change the Native backing balance.
struct Accounting {
  Amount notes;
  Amount fees;
  Amount withdrawals;

  // Only after the matching authenticated deposit is consumed exactly once.
  td::Result<Accounting> checked_shield_claim(const Amount& deposit) const {
    TRY_RESULT(claimed_notes, notes.checked_add(deposit));
    return Accounting{claimed_notes, fees, withdrawals};
  }

  td::Result<Accounting> checked_private_fee_distribution(const Amount& reward) const {
    TRY_RESULT(remaining_fees, fees.checked_sub(reward));
    TRY_RESULT(rewarded_notes, notes.checked_add(reward));
    return Accounting{rewarded_notes, remaining_fees, withdrawals};
  }

  // Native rewards create withdrawal liabilities, not completed payments.
  td::Result<Accounting> checked_native_fee_distribution(const Amount& reward) const {
    TRY_RESULT(remaining_fees, fees.checked_sub(reward));
    TRY_RESULT(rewarded_withdrawals, withdrawals.checked_add(reward));
    return Accounting{notes, remaining_fees, rewarded_withdrawals};
  }

  td::Result<Accounting> checked_transfer_fee(const Amount& fee) const {
    TRY_RESULT(next_notes, notes.checked_sub(fee));
    TRY_RESULT(next_fees, fees.checked_add(fee));
    return Accounting{next_notes, next_fees, withdrawals};
  }

  td::Result<Accounting> checked_prepare_withdrawal(const Amount& principal, const Amount& fee) const {
    TRY_RESULT(debit, principal.checked_add(fee));
    TRY_RESULT(next_notes, notes.checked_sub(debit));
    TRY_RESULT(next_fees, fees.checked_add(fee));
    TRY_RESULT(next_withdrawals, withdrawals.checked_add(principal));
    return Accounting{next_notes, next_fees, next_withdrawals};
  }

  td::Result<Accounting> checked_paid_ack(const Amount& principal) const {
    TRY_RESULT(next_withdrawals, withdrawals.checked_sub(principal));
    return Accounting{notes, fees, next_withdrawals};
  }

  td::Result<Accounting> checked_refund(const Amount& principal) const {
    TRY_RESULT(next_withdrawals, withdrawals.checked_sub(principal));
    TRY_RESULT(next_notes, notes.checked_add(principal));
    return Accounting{next_notes, fees, next_withdrawals};
  }
};

}  // namespace uno_workchain
