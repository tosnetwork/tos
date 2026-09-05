#include "uno/core/used-nullifiers.h"
#include "td/utils/tests.h"

using namespace uno_workchain;

TEST(UnoUsedNullifiers, PermanentAndAtomic) {
  td::Bits256 zero = td::Bits256::zero();
  td::Bits256 one = zero;
  one.as_slice()[31] = 1;
  td::Bits256 high = zero;
  high.as_slice()[0] = static_cast<char>(128);
  UsedNullifiers empty;
  ASSERT_TRUE(empty.root().is_null());
  ASSERT_TRUE(!empty.contains(zero));
  auto first = empty.with_used({zero, one}).move_as_ok();
  ASSERT_TRUE(first.contains(zero));
  ASSERT_TRUE(first.contains(one));
  ASSERT_TRUE(!first.contains(high));
  ASSERT_TRUE(!empty.contains(zero));
  auto hash = first.root()->get_hash();
  ASSERT_TRUE(first.with_used({high, zero}).is_error());
  ASSERT_TRUE(!first.contains(high));
  ASSERT_TRUE(first.root()->get_hash() == hash);
  ASSERT_TRUE(empty.with_used({high, high}).is_error());
  ASSERT_TRUE(empty.root().is_null());
  auto second = first.with_used({high}).move_as_ok();
  ASSERT_TRUE(second.contains(zero));
  ASSERT_TRUE(second.contains(one));
  ASSERT_TRUE(second.contains(high));
  ASSERT_TRUE(second.with_used({one}).is_error());
  ASSERT_TRUE(second.with_used({}).move_as_ok().root()->get_hash() == second.root()->get_hash());
  auto reversed = empty.with_used({high, one, zero}).move_as_ok();
  ASSERT_TRUE(reversed.root()->get_hash() == second.root()->get_hash());
}
