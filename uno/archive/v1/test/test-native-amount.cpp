#include "uno/core/native-amount.h"
#include "block/block-parse.h"
#include "vm/cells.h"
#include "td/utils/tests.h"

using namespace uno_workchain;

TEST(UnoNativeAmount, ExactTomisRoundTrip) {
  ASSERT_EQ(td::dec_string(checked_native_tomis(Amount::from_words(1, 0)).move_as_ok()), "18446744073709551616");
  ASSERT_EQ(td::dec_string(checked_native_tomis(Amount::from_nanotomi(100000000000000000ULL)).move_as_ok()),
            "100000000000000000");
  for (auto amount : {Amount{}, Amount::from_nanotomi(100000000000000000ULL),
                      Amount::from_nanotomi(18446744073709551615ULL),
                      Amount::from_words(1, 0), Amount::from_words(0x00ffffffffffffffULL, 18446744073709551615ULL)}) {
    auto native = checked_native_tomis(amount).move_as_ok();
    vm::CellBuilder cb;
    ASSERT_TRUE(block::tlb::t_Tomis.store_integer_value(cb, *native));
    auto cell = cb.finalize();
    auto slice = vm::load_cell_slice(cell);
    auto decoded = block::tlb::t_Tomis.as_integer_skip(slice);
    ASSERT_TRUE(slice.empty_ext());
    auto restored = checked_amount_from_native_tomis(decoded).move_as_ok();
    ASSERT_EQ(restored.high(), amount.high());
    ASSERT_EQ(restored.low(), amount.low());
  }
}

TEST(UnoNativeAmount, RejectOutOfRange) {
  auto oversized = Amount::from_words(0x0100000000000000ULL, 0);
  ASSERT_TRUE(checked_native_tomis(oversized).is_error());
  auto too_large = td::make_refint(1) << 120;
  ASSERT_TRUE(checked_amount_from_native_tomis(too_large).is_error());
  ASSERT_TRUE(checked_amount_from_native_tomis(td::make_refint(-1)).is_error());
  ASSERT_TRUE(checked_amount_from_native_tomis({}).is_error());
  vm::CellBuilder cb;
  ASSERT_TRUE(!block::tlb::t_Tomis.store_integer_value(cb, *too_large));
}
