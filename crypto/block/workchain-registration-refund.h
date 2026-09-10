#pragma once

#include "block/workchain-confidential-state.h"
#include "block/workchain-execution-errors.h"

namespace block {

struct WorkchainRegistrationRefund {
  std::uint64_t amount;
  std::int32_t workchain;
  td::Bits256 account;
  std::uint64_t remaining_refundable_deposits;
};

// Arithmetic preparation only, not closure authorization or a commit. The host
// must establish exhausted available and empty pending, then atomically close
// the account and materialize a one-way Native message (NOT guarantee receipt).
// Forwarding fees come from coordinator operating funds, never this debit.
// No M3 return association, compensation or claim is established. The
// M3 no-obligation condition is structural
// and expiry-guarded at the closure API, never inferred by this arithmetic.
// registered_accounts is deliberately absent: a refund never decrements it.
inline td::Result<WorkchainRegistrationRefund> prepare_workchain_registration_refund(
    const WorkchainRegistrationFunding& historical_funding,
    std::uint64_t authenticated_refundable_deposits) {
  // Section 10 allows governance to change registration prices. Refunding the
  // current price would create a surplus or deficit against historical deposits.
  // This is the refund counterpart of its prohibition on inferring historical
  // account counts from today's unit price. No current-price input is accepted.
  const auto amount = historical_funding.paid_deposit;
  if (amount > authenticated_refundable_deposits) {
    return td::Status::Error(static_cast<int>(WorkchainExecutionFailure::AuthenticatedStateCorrupt),
                            "refundable deposit bucket is smaller than recorded paid deposit");
  }
  // Subtraction cannot underflow: the recorded deposit was checked against the
  // authenticated dedicated bucket above. Principal/operating funds cannot cover
  // a deficit; this bucket is not principal and cannot fund any other purpose.
  return WorkchainRegistrationRefund{amount, historical_funding.refund_workchain,
                                    historical_funding.refund_account,
                                    authenticated_refundable_deposits - amount};
}

}  // namespace block
