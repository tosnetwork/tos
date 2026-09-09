#include <limits>

#include "td/utils/tests.h"
#include "uno/core/slot-epoch.h"

using uno_workchain::SlotEpoch;

TEST(UnoSlotEpoch, TimeBoundaries) {
  ASSERT_TRUE(SlotEpoch::genesis(1000, 0).is_error());
  auto epoch = SlotEpoch::genesis(1000, 75).move_as_ok();
  ASSERT_TRUE(epoch.slot_at(999).is_error());
  ASSERT_EQ(epoch.slot_at(1000).move_as_ok(), 0u);
  ASSERT_EQ(epoch.slot_at(1074).move_as_ok(), 0u);
  ASSERT_EQ(epoch.slot_at(1075).move_as_ok(), 1u);
  ASSERT_EQ(epoch.slot_at(1750).move_as_ok(), 10u);
  auto alternate = SlotEpoch::genesis(1000, 13).move_as_ok();
  ASSERT_EQ(alternate.slot_at(1026).move_as_ok(), 2u);
}

TEST(UnoSlotEpoch, SuccessorAndMissedSlots) {
  auto epoch = SlotEpoch::genesis(1000, 75).move_as_ok();
  ASSERT_TRUE(epoch.validate_successor(7, 9, 8, 10, 1750).is_ok());
  ASSERT_TRUE(epoch.validate_successor(7, 9, 8, 20, 2500).is_ok());
  ASSERT_TRUE(epoch.validate_successor(7, 9, 9, 10, 1750).is_error());
  ASSERT_TRUE(epoch.validate_successor(7, 9, 7, 10, 1750).is_error());
  ASSERT_TRUE(epoch.validate_successor(7, 10, 8, 10, 1750).is_error());
  ASSERT_TRUE(epoch.validate_successor(7, 11, 8, 10, 1750).is_error());
  ASSERT_TRUE(epoch.validate_successor(7, 9, 8, 10, 2500).is_error());
  ASSERT_TRUE(epoch.validate_successor(7, 9, 8, 21, 2500).is_error());
  ASSERT_TRUE(epoch.validate_successor(7, 9, 8, 10, 999).is_error());
  const auto max = std::numeric_limits<td::uint64>::max();
  ASSERT_TRUE(epoch.validate_successor(max, 9, 0, 10, 1750).is_error());
}

TEST(UnoSlotEpoch, ContinuousEpochChange) {
  auto original = SlotEpoch::genesis(1000, 75).move_as_ok();
  ASSERT_TRUE(original.checked_next_epoch(1750, 0).is_error());
  ASSERT_TRUE(original.checked_next_epoch(999, 30).is_error());
  ASSERT_TRUE(original.checked_next_epoch(1000, 30).is_error());
  ASSERT_TRUE(original.checked_next_epoch(1749, 30).is_error());
  auto faster = original.checked_next_epoch(1750, 30).move_as_ok();
  ASSERT_EQ(original.slot_at(1749).move_as_ok(), 9u);
  ASSERT_TRUE(faster.slot_at(1749).is_error());
  ASSERT_EQ(faster.slot_at(1750).move_as_ok(), 10u);
  ASSERT_EQ(faster.slot_at(1779).move_as_ok(), 10u);
  ASSERT_EQ(faster.slot_at(1780).move_as_ok(), 11u);
  ASSERT_TRUE(faster.validate_successor(3, 9, 4, 10, 1750).is_ok());
  auto slower = faster.checked_next_epoch(1810, 100).move_as_ok();
  ASSERT_EQ(slower.slot_at(1810).move_as_ok(), 12u);
  ASSERT_EQ(slower.slot_at(1910).move_as_ok(), 13u);
  ASSERT_EQ(original.slot_at(1810).move_as_ok(), 10u);
}

TEST(UnoSlotEpoch, FullWidthTime) {
  const auto max = std::numeric_limits<td::uint64>::max();
  auto epoch = SlotEpoch::genesis(0, 1).move_as_ok();
  ASSERT_EQ(epoch.slot_at(max).move_as_ok(), max);
  auto last = epoch.checked_next_epoch(max, 1).move_as_ok();
  ASSERT_EQ(last.slot_at(max).move_as_ok(), max);
  ASSERT_TRUE(last.checked_next_epoch(max, 1).is_error());
  ASSERT_TRUE(last.validate_successor(1, max, 2, max, max).is_error());
  auto late = SlotEpoch::genesis(max - 1, max).move_as_ok();
  ASSERT_EQ(late.slot_at(max).move_as_ok(), 0u);
}
