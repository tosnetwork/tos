#include "uno/core/transition-budget.h"
#include "td/utils/tests.h"

using uno_workchain::Amount;
using uno_workchain::LeafBudget;
using uno_workchain::TransitionBudget;

namespace {
Amount value(td::uint64 n) { return Amount::from_nanotomi(n); }
void expect_budget(const TransitionBudget& budget, td::uint64 notes, td::uint64 fees, td::uint64 withdrawals,
                   td::uint64 next, td::uint64 reserved) {
  ASSERT_EQ(budget.accounting.notes.checked_note_value().move_as_ok(), notes);
  ASSERT_EQ(budget.accounting.fees.checked_note_value().move_as_ok(), fees);
  ASSERT_EQ(budget.accounting.withdrawals.checked_note_value().move_as_ok(), withdrawals);
  ASSERT_EQ(budget.leaves.next_position(), next);
  ASSERT_EQ(budget.leaves.reserved_refund_leaves(), reserved);
}
}

TEST(UnoTransitionBudget, CoupledWithdrawalBranches) {
  const auto start = LeafBudget::capacity - 3;
  const TransitionBudget before{{value(100), value(0), value(0)}, LeafBudget::from_counts(start, 0).move_as_ok()};
  auto prepared = before.checked_prepare_withdrawal(value(40), value(3), 1, 2).move_as_ok();
  expect_budget(prepared, 57, 3, 40, start + 1, 2);
  auto paid = prepared.checked_paid_ack(value(40), 2).move_as_ok();
  expect_budget(paid, 57, 3, 0, start + 1, 0);
  auto refund = prepared.checked_refund(value(40), 2).move_as_ok();
  expect_budget(refund, 97, 3, 0, LeafBudget::capacity, 0);
  expect_budget(before, 100, 0, 0, start, 0);
  expect_budget(prepared, 57, 3, 40, start + 1, 2);
}

TEST(UnoTransitionBudget, RejectPartialCalculations) {
  const auto start = LeafBudget::capacity - 2;
  const TransitionBudget before{{value(100), value(0), value(0)}, LeafBudget::from_counts(start, 0).move_as_ok()};
  ASSERT_TRUE(before.checked_prepare_withdrawal(value(40), value(3), 1, 2).is_error());
  ASSERT_TRUE(before.checked_prepare_withdrawal(value(100), value(1), 0, 1).is_error());
  expect_budget(before, 100, 0, 0, start, 0);
  const TransitionBudget pending{{value(57), value(3), value(40)},
                                LeafBudget::from_counts(start, 1).move_as_ok()};
  ASSERT_TRUE(pending.checked_paid_ack(value(40), 2).is_error());
  ASSERT_TRUE(pending.checked_refund(value(40), 2).is_error());
  ASSERT_TRUE(pending.checked_paid_ack(value(41), 1).is_error());
  ASSERT_TRUE(pending.checked_refund(value(41), 1).is_error());
  expect_budget(pending, 57, 3, 40, start, 1);
}
