#pragma once

// Test-only observations, not an authenticated codec or a production gate.
// Adapters must reconstruct event-local deltas from actual artifacts; whole-block
// net balances can hide spending behind unrelated income. No default policy.
#include "block/block-parse.h"
#include "block/workchain-budget-backing.h"
#include <map>

namespace block::m5_test {
using C = CurrencyCollection;

// Complete account-to-pending commitments at the isolated operation boundary,
// including both pending kinds and their counts. An adapter must derive these
// from authenticated states, not just inspect the source account's effects.
// This test interface does not implement that adapter or a consensus encoding.
using PendingCommitments = std::map<td::Bits256, td::Bits256>;
inline td::Status withdrawal_pending(const PendingCommitments& before, const PendingCommitments& after) {
  if (before != after)
    return td::Status::Error("D64: Withdrawal changed pending state");
  return td::Status::OK();
}

// Isolated payout forwarding stage: principal and outgoing fee leave custody;
// the separately locked return allowance stays there. Other fees/income must
// be accounted for separately before presenting this observation.
inline td::Status payout_forwarding(const C& custody_before, const C& custody_after,
    const C& operating_before, const C& operating_after, const C& principal, const C& outgoing_fee) {
  if (operating_before != operating_after)
    return td::Status::Error("D61: withdrawal forwarding fee charged to operating budget");
  C debit, expected;
  if (!C::add(principal, outgoing_fee, debit) || !C::sub(custody_before, debit, expected) ||
      expected != custody_after)
    return td::Status::Error("D61: custody debit differs from principal plus outgoing fee");
  return td::Status::OK();
}

struct SweepState {
  C coordinator, refundable, bucket, custody, reserve_book, confidential_book;
};

// An isolated type-2 sweep, compared at committed batch boundaries. The slot
// fee stays at coordinator; it never makes a round trip through custody.
inline td::Status type_two_sweep(const SweepState& before, const SweepState& after,
    const C& gross, const C& slot_fee) {
  C net, expected;
  if (!C::sub(gross, slot_fee, net)) return td::Status::Error("D63: fee exceeds bucket value");
  if (!C::add(before.custody, net, expected) || expected != after.custody)
    return td::Status::Error("D63: missing physical custody credit");
  if (!C::add(before.reserve_book, net, expected) || expected != after.reserve_book)
    return td::Status::Error("D63: reserve book credit mismatch");
  if (!C::add(before.confidential_book, net, expected) || expected != after.confidential_book)
    return td::Status::Error("D63: confidential book credit mismatch");
  if (!C::sub(before.coordinator, net, expected) || expected != after.coordinator)
    return td::Status::Error("D63: coordinator debit mismatch");
  if (!C::sub(before.bucket, gross, expected) || expected != after.bucket)
    return td::Status::Error("D63: bucket release mismatch");
  if (before.refundable != after.refundable)
    return td::Status::Error("D63: refundable deposits changed");
  TRY_STATUS(check_workchain_budget_backing(before.coordinator, before.refundable, before.bucket));
  return check_workchain_budget_backing(after.coordinator, after.refundable, after.bucket);
}

// A complete trace for ONE entry, including its returned successor. Production
// has no such authenticated lineage interface yet. The future adapter must
// establish that association from authenticated artifacts, not a supplied ID.
// Synthetic tests below establish only the assertion's behavior. A governance
// sweep is not an ordinary return attempt and is outside this trace predicate.
struct ReturnStep {
  bool failed_before, failed_after;
  unsigned ordinary_return_messages;
  bool return_bounce_received;
  unsigned ordinary_deposit_credits;
};
inline td::Status single_return(const std::vector<ReturnStep>& trace) {
  bool attempted = false, failed = false;
  for (const auto& step : trace) {
    if (step.failed_before != failed)
      return td::Status::Error("D62: return-failure state discontinuity");
    if (step.ordinary_return_messages > 1 ||
        (step.ordinary_return_messages && (attempted || failed)))
      return td::Status::Error("D62: repeated ordinary return attempt");
    if (failed && step.ordinary_deposit_credits != 0)
      return td::Status::Error("D62: failed entry retried as Deposit");
    attempted = attempted || step.ordinary_return_messages != 0;
    if (step.return_bounce_received && !attempted)
      return td::Status::Error("D62: return bounce without an attempt");
    failed = failed || step.return_bounce_received;
    if (step.failed_after != failed)
      return td::Status::Error("D62: return-failure bit not preserved");
  }
  return td::Status::OK();
}
}  // namespace block::m5_test
