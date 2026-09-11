#include "td/utils/tests.h"
#include "block/workchain-withdrawal-codec.h"
using namespace block;
namespace {
td::Bits256 word(unsigned n) {
  auto value = td::Bits256::zero(); value.as_slice().back() = static_cast<char>(n); return value;
}
WorkchainConfidentialAddress owner() { return {2, word(1), word(2)}; }
WorkchainWithdrawalData data() {
  return {{owner(), 7, 8, 9, 100, 11}, {0, word(3)}, {100, 4, 20, 11},
          {word(4), word(5)}, word(6)};
}
WorkchainWithdrawalRecord record() {
  return {word(7), word(8), 7, 100, owner(), {0, word(3)},
          {4, 20, 3, 17}, {0, 1000, 10, 0, 30}};
}
td::Ref<vm::Cell> special() {
  return vm::CellBuilder().store_long(2, 8).store_bits(word(9).bits(), 256).finalize(true);
}
}
TEST(WithdrawalCodec, RecordRoundtripAndSeparateCosts) {
  auto value = record();
  auto root = encode_workchain_withdrawal_record(value); ASSERT_TRUE(root.is_ok());
  auto decoded = decode_workchain_withdrawal_record(root.ok()); ASSERT_TRUE(decoded.is_ok());
  ASSERT_EQ(decoded.ok().costs.outward_fee_paid, 4u);
  ASSERT_EQ(decoded.ok().costs.original_reserve, 20u);
  ASSERT_EQ(decoded.ok().costs.consumed_return_cost, 3u);
  ASSERT_EQ(decoded.ok().costs.refundable_reserve, 17u);
  ASSERT_TRUE(encode_workchain_withdrawal_record(decoded.ok()).move_as_ok()->get_hash() == root.ok()->get_hash());
  value.costs.refundable_reserve = 18;
  ASSERT_TRUE(encode_workchain_withdrawal_record(value).is_error());
  value = record(); value.timing.phase = 1; value.timing.queue_removed_height = 12;
  ASSERT_TRUE(encode_workchain_withdrawal_record(value).is_ok());
  value.timing.queue_removed_height = UINT32_MAX;
  ASSERT_TRUE(encode_workchain_withdrawal_record(value).is_error());
}
TEST(WithdrawalCodec, IdentitiesDoNotUseFutureLt) {
  gen::UnoV2OperationNetworkV1::Record net{-99, word(10), word(11)};
  auto id = derive_workchain_withdrawal_id(net, owner(), 7); ASSERT_TRUE(id.is_ok());
  ASSERT_TRUE(id.ok() != derive_workchain_closure_operation_id(net, owner(), 7).move_as_ok());
  ASSERT_TRUE(id.ok() != derive_workchain_operation_id(net, owner(), 1, 7).move_as_ok());
  ASSERT_TRUE(id.ok() != derive_workchain_withdrawal_id(net, owner(), 8).move_as_ok());
  auto attempt = derive_workchain_attempt_id(id.ok()).move_as_ok();
  ASSERT_TRUE(attempt == derive_workchain_attempt_id(id.ok()).move_as_ok());
  auto next = derive_workchain_withdrawal_id(net, owner(), 8).move_as_ok();
  ASSERT_TRUE(attempt != derive_workchain_attempt_id(next).move_as_ok());
}
TEST(WithdrawalCodec, ExactInputAndCheckedSum) {
  auto value = data();
  ASSERT_EQ(workchain_withdrawal_total(value.amounts).move_as_ok(), 124u);
  value.amounts.principal = UINT64_MAX;
  ASSERT_TRUE(workchain_withdrawal_total(value.amounts).is_error());
  ASSERT_TRUE(encode_workchain_withdrawal_data(value).is_error());
  value = data();
  // No V_max gate exists in this codec. The proof owns that property (D66).
  value.amounts.principal = (std::uint64_t(1) << 62);
  ASSERT_TRUE(encode_workchain_withdrawal_data(value).is_ok());
  WorkchainWithdrawalInput input{word(7), word(8), data(),
      {std::vector<td::Bits256>(8, word(12)), std::vector<td::Bits256>(6, word(13)), std::string(864, 'x')}};
  auto root = encode_workchain_withdrawal_input(input); ASSERT_TRUE(root.is_ok());
  auto decoded = decode_workchain_withdrawal_input(root.ok()); ASSERT_TRUE(decoded.is_ok());
  ASSERT_TRUE(encode_workchain_withdrawal_input(decoded.ok()).move_as_ok()->get_hash() == root.ok()->get_hash());
  input.authorization.range_proof[0] = 'y';
  ASSERT_TRUE(encode_workchain_withdrawal_input(input).move_as_ok()->get_hash() != root.ok()->get_hash());
  input.authorization.range_proof.pop_back();
  ASSERT_TRUE(encode_workchain_withdrawal_input(input).is_error());
}
TEST(WithdrawalCodec, SpecialRootsAndDescendantsReject) {
  ASSERT_TRUE(decode_workchain_withdrawal_record({}).is_error());
  ASSERT_TRUE(decode_workchain_withdrawal_record(special()).is_error());
  ASSERT_TRUE(decode_workchain_withdrawal_input(special()).is_error());
  ASSERT_TRUE(decode_workchain_withdrawal_data(special()).is_error());
  ASSERT_TRUE(decode_workchain_withdrawal_record(vm::CellBuilder().store_long(0, 8).finalize()).is_error());
  auto root = encode_workchain_withdrawal_record(record()).move_as_ok();
  gen::UnoV2WithdrawalRecordV1::Record wire;
  ASSERT_TRUE(resource_policy_detail::unpack_exact(root, wire));
  wire.costs = special();
  auto changed = confidential_state_detail::pack(wire).move_as_ok();
  ASSERT_TRUE(decode_workchain_withdrawal_record(changed).is_error());
  auto extra = vm::CellBuilder().append_cellslice(vm::load_cell_slice(root)).store_long(0, 1).finalize();
  ASSERT_TRUE(decode_workchain_withdrawal_record(extra).is_error());
}
TEST(WithdrawalCodec, CanonicalContextBindsAllComponents) {
  WorkchainWithdrawalContext value{
      {{2, 2, 1, 1, -99, 2, word(10), word(11)}, {word(12), word(13), word(14)},
       {word(15), word(16), word(17)}, word(18), 19, owner(), 7, 8, 9},
      {word(7), word(20), word(21)}, word(8), 30, 4};
  auto encoded = encode_workchain_withdrawal_context(value); ASSERT_TRUE(encoded.is_ok());
  ASSERT_EQ(encoded.ok().size(), 566u);
  value.settlement_blocks = 31;
  ASSERT_TRUE(encode_workchain_withdrawal_context(value).move_as_ok() != encoded.ok());
  value.settlement_blocks = 30; value.binding.semantic_hash = word(22);
  ASSERT_TRUE(encode_workchain_withdrawal_context(value).move_as_ok() != encoded.ok());
}
TEST(WithdrawalCodec, ControlCountUniquenessAndClosure) {
  WorkchainWithdrawalControl value{WorkchainAccountActive{}, {record()}};
  auto root = encode_workchain_withdrawal_control(value, 2); ASSERT_TRUE(root.is_ok());
  auto decoded = decode_workchain_withdrawal_control(root.ok(), 2); ASSERT_TRUE(decoded.is_ok());
  ASSERT_EQ(decoded.ok().withdrawals.size(), 1u);
  ASSERT_TRUE(check_workchain_withdrawal_closure(decoded.ok()).is_error());
  ASSERT_TRUE(encode_workchain_withdrawal_control(value, 0).is_error());
  ASSERT_TRUE(decode_workchain_withdrawal_control(root.ok(), 0).is_error());
  auto other = record(); other.timing.payout_created_lt++;
  value.withdrawals.push_back(other);
  auto duplicate = encode_workchain_withdrawal_control(value, 2);
  ASSERT_TRUE(duplicate.is_error());
  ASSERT_EQ(duplicate.error().message(), "duplicate Withdrawal identity");
  value.withdrawals.back().withdrawal_id = word(25);
  value.withdrawals.back().timing.payout_created_lt = record().timing.payout_created_lt;
  duplicate = encode_workchain_withdrawal_control(value, 2);
  ASSERT_TRUE(duplicate.is_error());
  ASSERT_EQ(duplicate.error().message(), "duplicate Withdrawal payout created_lt");
  value.withdrawals.back().timing.payout_created_lt++;
  ASSERT_TRUE(encode_workchain_withdrawal_control(value, 2).is_ok());
  gen::UnoV2AccountControlWithdrawalsV1::Record wire;
  ASSERT_TRUE(resource_policy_detail::unpack_exact(root.ok(), wire));
  wire.withdrawal_count = 0;
  auto wrong = decode_workchain_withdrawal_control(confidential_state_detail::pack(wire).move_as_ok(), 2);
  ASSERT_TRUE(wrong.is_error());
  ASSERT_EQ(wrong.error().message(), "Withdrawal count differs from enumerated dictionary");
  wire.withdrawals = vm::load_cell_slice_ref(vm::CellBuilder().store_long(1, 1).store_ref(special()).finalize());
  ASSERT_TRUE(decode_workchain_withdrawal_control(confidential_state_detail::pack(wire).move_as_ok(), 2).is_error());
  value.lifecycle = WorkchainAccountClosed{};
  ASSERT_TRUE(encode_workchain_withdrawal_control(value, 2).is_error());
  value.withdrawals.clear();
  ASSERT_TRUE(check_workchain_withdrawal_closure(value).is_ok());
  ASSERT_TRUE(encode_workchain_withdrawal_control(value, 2).is_ok());
}
