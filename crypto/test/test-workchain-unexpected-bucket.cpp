#include "block/workchain-unexpected-bucket.h"
#include "block/block-parse.h"
#include "td/utils/tests.h"

namespace {
block::WorkchainUnexpectedSender sender(unsigned value) {
  td::Bits256 address;
  address.as_slice().fill(static_cast<char>(value));
  return {0, address};
}
block::WorkchainUnexpectedBucket empty_bucket() {
  return {{}, {}, td::make_refint(0), {}, 0};
}
}  // namespace

TEST(WorkchainUnexpectedBucket, BothFullNeverRejectsAndPreservesValue) {
  // Small explicit test limits reach both boundaries; M4 configuration uses
  // unfrozen 256/256. There is no production default in the implementation.
  const block::WorkchainUnexpectedLimits limits{1, 1};
  auto old = empty_bucket();
  auto first = block::credit_workchain_unexpected(old, limits, sender(1), block::CurrencyCollection(7), 100).move_as_ok();
  ASSERT_EQ(old.entries.size(), 0u);
  ASSERT_EQ(first.bucket.entries.size(), 1u);
  ASSERT_TRUE(!first.sender_attribution_lost);
  auto second = block::credit_workchain_unexpected(first.bucket, limits, sender(2), block::CurrencyCollection(11), 100).move_as_ok();
  ASSERT_EQ(second.bucket.overflow.size(), 1u);
  ASSERT_TRUE(!second.sender_attribution_lost);
  auto same = block::credit_workchain_unexpected(second.bucket, limits, sender(2), block::CurrencyCollection(13), 100).move_as_ok();
  ASSERT_TRUE(!same.sender_attribution_lost);
  ASSERT_EQ(td::cmp(same.bucket.overflow[0].tomis, 24), 0);
  auto full = block::credit_workchain_unexpected(same.bucket, limits, sender(3), block::CurrencyCollection(17), 100).move_as_ok();
  ASSERT_TRUE(full.sender_attribution_lost);
  ASSERT_EQ(td::cmp(full.bucket.unkeyed, 17), 0);
  ASSERT_EQ(td::cmp(block::workchain_unexpected_balance(full.bucket).move_as_ok().tomis, 48), 0);
  auto root = block::encode_workchain_unexpected_bucket(full.bucket, limits, 100).move_as_ok();
  auto decoded = block::decode_workchain_unexpected_bucket(root, limits, 100).move_as_ok();
  ASSERT_EQ(td::cmp(block::workchain_unexpected_balance(decoded).move_as_ok().tomis, 48), 0);
  ASSERT_EQ(block::encode_workchain_unexpected_bucket(decoded, limits, 100).move_as_ok()->get_hash(), root->get_hash());
  ASSERT_TRUE(block::decode_workchain_unexpected_bucket(root, {0, 1}, 100).is_error());
}

TEST(WorkchainUnexpectedBucket, ExactShapeAndNoPartialMutation) {
  const block::WorkchainUnexpectedLimits limits{1, 1};
  auto old = empty_bucket();
  auto root = block::encode_workchain_unexpected_bucket(old, limits, 100).move_as_ok();
  ASSERT_TRUE(block::decode_workchain_unexpected_bucket(root, limits, 100).is_ok());
  vm::CellBuilder wrong;
  wrong.store_long(0x554e5835, 32);
  ASSERT_TRUE(block::decode_workchain_unexpected_bucket(wrong.finalize(), limits, 100).is_error());
  vm::CellBuilder trailing;
  trailing.append_cellslice(vm::load_cell_slice(root)).store_long(1, 1);
  ASSERT_TRUE(block::decode_workchain_unexpected_bucket(trailing.finalize(), limits, 100).is_error());
  old.overflow = {{sender(1), td::make_refint(1)}, {sender(1), td::make_refint(2)}};
  ASSERT_TRUE(block::encode_workchain_unexpected_bucket(old, {1, 2}, 100).is_error());
  old = empty_bucket();
  old.unkeyed = (td::make_refint(1) << 256) - 1;
  ASSERT_TRUE(block::credit_workchain_unexpected(old, {0, 0}, sender(1), block::CurrencyCollection(1), 100).is_error());
  ASSERT_EQ(td::cmp(old.unkeyed, (td::make_refint(1) << 256) - 1), 0);
  ASSERT_EQ(old.entries.size(), 0u);
}

TEST(WorkchainUnexpectedBucket, ExtraCurrenciesAreRetainedWithoutBodyOrAttribution) {
  vm::Dictionary extra(32);
  vm::CellBuilder amount;
  ASSERT_TRUE(block::tlb::t_VarUInteger_32.store_integer_value(amount, *td::make_refint(5)));
  ASSERT_TRUE(extra.set_builder(td::BitArray<32>(7), amount, vm::Dictionary::SetMode::Add));
  block::CurrencyCollection imported(td::make_refint(3), extra.get_root_cell());
  auto result = block::credit_workchain_unexpected(empty_bucket(), {1, 1}, sender(1), imported, 100).move_as_ok();
  ASSERT_TRUE(result.extra_attribution_lost);
  ASSERT_TRUE(!result.sender_attribution_lost);
  ASSERT_TRUE(block::workchain_unexpected_balance(result.bucket).move_as_ok() == imported);
  auto root = block::encode_workchain_unexpected_bucket(result.bucket, {1, 1}, 100).move_as_ok();
  auto read = block::decode_workchain_unexpected_bucket(root, {1, 1}, 100).move_as_ok();
  ASSERT_TRUE(block::workchain_unexpected_balance(read).move_as_ok() == imported);
}
