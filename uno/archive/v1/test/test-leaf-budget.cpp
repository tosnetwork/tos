#include <limits>
#include "uno/core/leaf-budget.h"
#include "td/utils/tests.h"

using uno_workchain::LeafBudget;

TEST(UnoLeafBudget, ReserveBeforeTreeExhaustion) {
  auto initial = LeafBudget::from_counts(LeafBudget::capacity - 4, 0).move_as_ok();
  auto prepared = initial.checked_prepare(1, 2).move_as_ok();
  ASSERT_EQ(prepared.next_position(), LeafBudget::capacity - 3);
  ASSERT_EQ(prepared.reserved_refund_leaves(), 2u);
  ASSERT_EQ(prepared.available(), 1u);
  auto filled = prepared.checked_append(1).move_as_ok();
  ASSERT_TRUE(filled.checked_append(1).is_error());
  auto refunded = filled.checked_refund_append(2).move_as_ok();
  ASSERT_EQ(refunded.next_position(), LeafBudget::capacity);
  ASSERT_EQ(refunded.reserved_refund_leaves(), 0u);
  ASSERT_TRUE(refunded.checked_append(1).is_error());
  auto paid = filled.checked_release(2).move_as_ok();
  ASSERT_EQ(paid.next_position(), LeafBudget::capacity - 2);
  ASSERT_EQ(paid.available(), 2u);
  ASSERT_EQ(initial.next_position(), LeafBudget::capacity - 4);
  ASSERT_EQ(initial.reserved_refund_leaves(), 0u);
  ASSERT_EQ(filled.reserved_refund_leaves(), 2u);
}

TEST(UnoLeafBudget, RejectInvalidCounts) {
  const auto max = std::numeric_limits<td::uint64>::max();
  ASSERT_TRUE(LeafBudget::from_counts(LeafBudget::capacity + 1, 0).is_error());
  ASSERT_TRUE(LeafBudget::from_counts(LeafBudget::capacity, 1).is_error());
  ASSERT_TRUE(LeafBudget::from_counts(max, max).is_error());
  auto initial = LeafBudget::from_counts(LeafBudget::capacity - 2, 1).move_as_ok();
  ASSERT_TRUE(initial.checked_reserve(2).is_error());
  ASSERT_TRUE(initial.checked_release(2).is_error());
  ASSERT_TRUE(initial.checked_refund_append(2).is_error());
  ASSERT_TRUE(initial.checked_append(max).is_error());
  ASSERT_TRUE(initial.checked_reserve(max).is_error());
  ASSERT_TRUE(initial.checked_prepare(1, 1).is_error());
  ASSERT_EQ(initial.next_position(), LeafBudget::capacity - 2);
  ASSERT_EQ(initial.reserved_refund_leaves(), 1u);
  auto empty = LeafBudget::from_counts(0, 0).move_as_ok();
  auto no_op = empty.checked_prepare(0, 0).move_as_ok().checked_refund_append(0).move_as_ok();
  ASSERT_EQ(no_op.next_position(), 0u);
  ASSERT_EQ(no_op.reserved_refund_leaves(), 0u);
}
