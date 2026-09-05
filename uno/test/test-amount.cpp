#include "uno/core/amount.h"
#include "td/utils/tests.h"

using uno_workchain::Amount;

TEST(UnoAmount, CheckedWideArithmetic) {
  const auto max = std::numeric_limits<td::uint64>::max();
  const auto one = Amount::from_nanotomi(1);
  const auto boundary = Amount::from_nanotomi(max);
  auto sum = boundary.checked_add(one).move_as_ok();
  ASSERT_EQ(sum.high(), 1u);
  ASSERT_EQ(sum.low(), 0u);
  auto restored = sum.checked_sub(one).move_as_ok();
  ASSERT_EQ(restored.high(), 0u);
  ASSERT_EQ(restored.low(), max);
  ASSERT_EQ(boundary.low(), max);
  ASSERT_TRUE(Amount::from_words(max, max).checked_add(one).is_error());
  ASSERT_TRUE(Amount().checked_sub(one).is_error());
  auto zero = sum.checked_sub(sum).move_as_ok();
  ASSERT_EQ(zero.high(), 0u);
  ASSERT_EQ(zero.low(), 0u);
}

TEST(UnoAmount, ExplicitNarrowing) {
  const auto max = std::numeric_limits<td::uint64>::max();
  ASSERT_EQ(Amount::from_nanotomi(max).checked_note_value().move_as_ok(), max);
  ASSERT_TRUE(Amount::from_words(1, 0).checked_note_value().is_error());
  const auto signed_max = std::numeric_limits<td::int64>::max();
  auto magnitude = Amount::from_nanotomi(static_cast<td::uint64>(signed_max));
  ASSERT_EQ(magnitude.checked_bundle_balance(false).move_as_ok(), signed_max);
  ASSERT_EQ(magnitude.checked_bundle_balance(true).move_as_ok(), -signed_max);
  auto too_large = magnitude.checked_add(Amount::from_nanotomi(1)).move_as_ok();
  ASSERT_TRUE(too_large.checked_bundle_balance(false).is_error());
  ASSERT_TRUE(too_large.checked_bundle_balance(true).is_error());
  ASSERT_EQ(Amount().checked_bundle_balance(true).move_as_ok(), 0);
  auto genesis = Amount::from_nanotomi(100000000000000000ULL);
  ASSERT_EQ(genesis.checked_bundle_balance(false).move_as_ok(), 100000000000000000LL);
}
