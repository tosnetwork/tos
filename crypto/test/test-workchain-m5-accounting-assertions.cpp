// Assertion tests only. D61 additionally executes the existing payout helper;
// its output now follows D61; synthetic old-policy output remains a red control.
#include "td/utils/tests.h"
#include "block/workchain-payout-accounting.h"
#include "workchain-m5-accounting-assertions.h"

using namespace block::m5_test;
namespace {
void error_is(td::Status status, td::Slice message) {
  ASSERT_TRUE(status.is_error());
  ASSERT_EQ(status.message(), message);
}
}

TEST(M5Accounting, D61PayoutChargesCustodyNotOperatingBudget) {
  auto custody = td::Bits256::zero(), coordinator = custody;
  coordinator.as_slice().back() = 1;
  auto result = block::account_workchain_payout(custody, coordinator, C(1000), C(100), C(700),
      td::make_refint(30), td::make_refint(10), 100);
  ASSERT_TRUE(result.is_ok());
  auto observed = result.move_as_ok();
  ASSERT_TRUE(observed.custody_after == C(270));
  ASSERT_TRUE(observed.operator_after == C(100));
  ASSERT_TRUE(payout_forwarding(C(1000), observed.custody_after, C(100), observed.operator_after,
      C(700), C(30)).is_ok());
  error_is(payout_forwarding(C(1000), C(300), C(100), C(70), C(700), C(30)),
      "D61: withdrawal forwarding fee charged to operating budget");
  // Synthetic expected-policy observation; no production implementation claim.
  ASSERT_TRUE(payout_forwarding(C(1000), C(270), C(100), C(100), C(700), C(30)).is_ok());
  error_is(payout_forwarding(C(1000), C(300), C(100), C(100), C(700), C(30)),
      "D61: custody debit differs from principal plus outgoing fee");
}

TEST(M5Accounting, D63PhysicalAndBookPairing) {
  SweepState before{C(200), C(100), C(100), C(300), C(300), C(300)};
  SweepState after{C(150), C(100), C(40), C(350), C(350), C(350)};
  ASSERT_TRUE(type_two_sweep(before, after, C(60), C(10)).is_ok());
  auto missing = after;
  missing.custody = before.custody;
  error_is(type_two_sweep(before, missing, C(60), C(10)), "D63: missing physical custody credit");
  // A mixed snapshot (new balance, old holdings) fails. It must not be published.
  error_is(block::check_workchain_budget_backing(after.coordinator, before.refundable, before.bucket),
      "coordinator balance below protected holdings");
  ASSERT_TRUE(block::check_workchain_budget_backing(after.coordinator, after.refundable, after.bucket).is_ok());
}

TEST(M5Accounting, D62SingleReturnTrace) {
  ASSERT_TRUE(single_return({{false, false, 1, false, 0}, {false, true, 0, true, 0}, {true, true, 0, false, 0}}).is_ok());
  error_is(single_return({{false, false, 1, false, 0}, {false, true, 0, true, 0}, {true, true, 1, false, 0}}),
      "D62: repeated ordinary return attempt");
  error_is(single_return({{false, false, 1, false, 0}, {false, true, 0, true, 0}, {true, true, 0, false, 1}}),
      "D62: failed entry retried as Deposit");
  error_is(single_return({{false, false, 2, false, 0}}), "D62: repeated ordinary return attempt");
  error_is(single_return({{false, false, 1, false, 0}, {false, false, 0, true, 0}}),
      "D62: return-failure bit not preserved");
  error_is(single_return({{false, false, 1, false, 0}, {false, false, 1, false, 0}}),
      "D62: repeated ordinary return attempt");
}

TEST(M5Accounting, D64NoPendingInstallation) {
  // Synthetic commitment observations, not a host-executed Withdrawal.
  auto account = td::Bits256::zero(), original = account, installed = account;
  original.as_slice().back() = 1;
  installed.as_slice().back() = 2;
  PendingCommitments before{{account, original}};
  ASSERT_TRUE(withdrawal_pending(before, before).is_ok());
  error_is(withdrawal_pending(before, {{account, installed}}), "D64: Withdrawal changed pending state");
  auto extra_account = account;
  extra_account.as_slice().back() = 3;
  auto after = before;
  after.emplace(extra_account, installed);
  error_is(withdrawal_pending(before, after), "D64: Withdrawal changed pending state");
}
