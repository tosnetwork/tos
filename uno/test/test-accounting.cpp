#include "uno/core/accounting.h"
#include "td/utils/tests.h"

using uno_workchain::Accounting;
using uno_workchain::Amount;

namespace {
Amount amount(td::uint64 value) { return Amount::from_nanotomi(value); }
void expect_amount(const Amount& actual, const Amount& expected) {
  ASSERT_EQ(actual.high(), expected.high());
  ASSERT_EQ(actual.low(), expected.low());
}
void expect_state(const Accounting& actual, const Accounting& expected) {
  expect_amount(actual.notes, expected.notes);
  expect_amount(actual.fees, expected.fees);
  expect_amount(actual.withdrawals, expected.withdrawals);
}
}  // namespace

TEST(UnoAccounting, FeeAndWithdrawalBranches) {
  const Accounting before{amount(100), amount(7), amount(11)};
  auto transfer = before.checked_transfer_fee(amount(3)).move_as_ok();
  expect_state(transfer, {amount(97), amount(10), amount(11)});
  auto prepared = before.checked_prepare_withdrawal(amount(40), amount(3)).move_as_ok();
  expect_state(prepared, {amount(57), amount(10), amount(51)});
  auto paid = prepared.checked_paid_ack(amount(40)).move_as_ok();
  expect_state(paid, {amount(57), amount(10), amount(11)});
  auto refunded = prepared.checked_refund(amount(40)).move_as_ok();
  expect_state(refunded, transfer);
  expect_state(before, {amount(100), amount(7), amount(11)});
  expect_state(prepared, {amount(57), amount(10), amount(51)});
}

TEST(UnoAccounting, RejectionLeavesInputIntact) {
  const auto max = std::numeric_limits<td::uint64>::max();
  const auto wide_max = Amount::from_words(max, max);
  const Accounting state{amount(100), wide_max, amount(0)};
  ASSERT_TRUE(state.checked_transfer_fee(amount(1)).is_error());
  ASSERT_TRUE(state.checked_prepare_withdrawal(amount(1), amount(1)).is_error());
  const Accounting low_notes{amount(100), amount(0), amount(0)};
  ASSERT_TRUE(low_notes.checked_transfer_fee(amount(101)).is_error());
  ASSERT_TRUE(low_notes.checked_prepare_withdrawal(amount(100), amount(1)).is_error());
  const Accounting full_withdrawals{amount(100), amount(0), wide_max};
  ASSERT_TRUE(full_withdrawals.checked_prepare_withdrawal(amount(1), amount(0)).is_error());
  const Accounting wide_notes{wide_max, amount(0), amount(0)};
  ASSERT_TRUE(wide_notes.checked_prepare_withdrawal(wide_max, amount(1)).is_error());
  expect_state(state, {amount(100), wide_max, amount(0)});
  expect_state(low_notes, {amount(100), amount(0), amount(0)});
  expect_state(full_withdrawals, {amount(100), amount(0), wide_max});
  expect_state(wide_notes, {wide_max, amount(0), amount(0)});
  const Accounting empty{};
  ASSERT_TRUE(empty.checked_paid_ack(amount(1)).is_error());
  ASSERT_TRUE(empty.checked_refund(amount(1)).is_error());
  const Accounting full_notes{wide_max, amount(7), amount(1)};
  ASSERT_TRUE(full_notes.checked_refund(amount(1)).is_error());
  expect_state(full_notes, {wide_max, amount(7), amount(1)});
  expect_state(empty, {});
}

TEST(UnoAccounting, WidePoolAndZeroArithmetic) {
  const Accounting before{Amount::from_words(1, 0), amount(0), amount(0)};
  auto prepared = before.checked_prepare_withdrawal(amount(1), amount(1)).move_as_ok();
  expect_state(prepared, {amount(18446744073709551614ULL), amount(1), amount(1)});
  expect_state(before.checked_transfer_fee(amount(0)).move_as_ok(), before);
  expect_state(before.checked_prepare_withdrawal(amount(0), amount(0)).move_as_ok(), before);
  expect_state(before.checked_paid_ack(amount(0)).move_as_ok(), before);
  expect_state(before.checked_refund(amount(0)).move_as_ok(), before);
}
