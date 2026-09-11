#include "td/utils/tests.h"
#include "uno/crypto/include/uno_crypto.h"
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

#include "block/workchain-system-origin.h"
TEST(SystemOrigin, ThreeMembersRequireSequenceAndRoundtrip) {
  std::vector<WorkchainSystemOrigin> origins{
      WorkchainDepositOrigin{word(31), 1}, WorkchainSettlementOrigin{word(32), 2},
      WorkchainSweepOrigin{3, {2, -1, word(33), word(34), td::make_refint(100), false}}};
  auto point = word(0);
  point.as_slice().copy_from(td::hex_decode("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76").move_as_ok());
  for (auto origin : origins) {
    auto root = encode_workchain_system_origin(origin); ASSERT_TRUE(root.is_ok());
    auto decoded = decode_workchain_system_origin(root.ok()); ASSERT_TRUE(decoded.is_ok());
    ASSERT_TRUE(encode_workchain_system_origin(decoded.ok()).move_as_ok()->get_hash() == root.ok()->get_hash());
    auto bytes = encode_workchain_system_origin_transcript(origin).move_as_ok();
    ASSERT_EQ(bytes.size(), std::holds_alternative<WorkchainSweepOrigin>(origin) ? 115u : 41u);
    auto id = derive_workchain_system_receipt_id(origin).move_as_ok();
    UnoCryptoSystemEncryptionRequestV2 request{};
    request.abi_version = 2; request.amount = 100;
    std::copy(bytes.begin(), bytes.end(), request.origin); request.origin_bytes = static_cast<std::uint32_t>(bytes.size());
    std::copy(id.as_slice().begin(), id.as_slice().end(), request.receipt_id);
    std::copy(point.as_slice().begin(), point.as_slice().end(), request.recipient);
    UnoCryptoSystemCiphertext encrypted{};
    ASSERT_EQ(uno_crypto_system_encrypt_v2(&request, &encrypted), 0u);
    ASSERT_EQ(uno_crypto_system_verify_v2(&request, &encrypted), 0u);
    auto incorrect = encrypted; incorrect.handle[0] ^= 1;
    ASSERT_EQ(uno_crypto_system_verify_v2(&request, &incorrect), 3u);

    WorkchainSystemReceipt receipt{id, 100, {word(2), 1, word(35)}, {point, point}, origin};
    auto packed = encode_workchain_system_receipt(receipt); ASSERT_TRUE(packed.is_ok());
    auto read = decode_workchain_system_receipt(packed.ok()); ASSERT_TRUE(read.is_ok());
    ASSERT_TRUE(encode_workchain_system_receipt(read.ok()).move_as_ok()->get_hash() == packed.ok()->get_hash());
    std::visit([](auto& value) { value.sequence = 0; }, origin);
    auto missing = encode_workchain_system_origin(origin);
    ASSERT_TRUE(missing.is_error());
    ASSERT_EQ(missing.error().message(), "system origin requires issued sequence");
    // A missing (truncated) serialized scalar is rejected independently of zero.
    auto no_sequence = vm::CellBuilder().store_long(bytes[0], 8).finalize();
    ASSERT_TRUE(decode_workchain_system_origin(no_sequence).is_error());
  }
  ASSERT_TRUE(derive_workchain_system_receipt_id(origins[0]).move_as_ok() ==
              derive_workchain_deposit_id(word(31), 1).move_as_ok());
  ASSERT_TRUE(decode_workchain_system_origin(special()).is_error());
}

#include "block/workchain-withdrawal-account.h"
TEST(WithdrawalAccount, AuthenticatedEnvelopeAndCombinedPending) {
  auto point = word(0);
  point.as_slice().copy_from(td::hex_decode("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76").move_as_ok());
  WorkchainConfidentialAccount core{3, 1, 2, -23903, word(1), owner(), {word(4), word(5), word(6)},
      {10000000000ULL, 0, word(7)}, point, 0, {word(0), word(0)}, 0, 0, {}, WorkchainAccountActive{}, {}};
  WorkchainWithdrawalAccount value{core, {WorkchainAccountActive{}, {record()}}, {}};
  auto origin = WorkchainSystemOrigin{WorkchainSettlementOrigin{word(8), 1}};
  value.origin_pending.push_back({derive_workchain_system_receipt_id(origin).move_as_ok(), 100,
      {owner().instance, 0, word(4)}, {point, point}, origin});
  auto root = encode_workchain_withdrawal_account(value, 2); ASSERT_TRUE(root.is_ok());
  ASSERT_EQ(vm::load_cell_slice(root.ok()).size_refs(), 4u);
  auto decoded = decode_workchain_withdrawal_account(root.ok(), 2); ASSERT_TRUE(decoded.is_ok());
  ASSERT_EQ(decoded.ok().control.withdrawals.size(), 1u);
  ASSERT_EQ(decoded.ok().origin_pending.size(), 1u);
  ASSERT_TRUE(check_workchain_withdrawal_closure(decoded.ok().control).is_error());
  ASSERT_TRUE(decode_workchain_confidential_account(root.ok()).is_error());
  auto old = core; old.schema_version = 2;
  auto old_root = encode_workchain_confidential_account(old).move_as_ok();
  ASSERT_TRUE(decode_workchain_withdrawal_account(old_root, 2).is_error());
  value.origin_pending.push_back(value.origin_pending.front());
  auto duplicate = encode_workchain_withdrawal_account(value, 2); ASSERT_TRUE(duplicate.is_error());
  ASSERT_EQ(duplicate.error().message(), "duplicate pending dictionary key");
  value.origin_pending.pop_back();
  value.control.withdrawals[0].source.account = word(99);
  ASSERT_TRUE(encode_workchain_withdrawal_account(value, 2).is_error());
  ASSERT_TRUE(decode_workchain_withdrawal_account(special(), 2).is_error());
  gen::UnoV2AccountStateWithdrawals::Record wire;
  ASSERT_TRUE(resource_policy_detail::unpack_exact(root.ok(), wire));
  wire.control = special();
  ASSERT_TRUE(decode_workchain_withdrawal_account(confidential_state_detail::pack(wire).move_as_ok(), 2).is_error());
}

TEST(SystemOrigin, IdenticalSweepAttributionUsesDistinctIssuedSequences) {
  // Codec/ABI test, not a host counter-installation or custody settlement test.
  auto point = word(0);
  point.as_slice().copy_from(td::hex_decode("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76").move_as_ok());
  WorkchainSweepOrigin first{41, {2, -1, word(33), word(34), td::make_refint(100), false}};
  auto second = first; second.sequence = 42;
  auto id1 = derive_workchain_system_receipt_id(first).move_as_ok();
  auto id2 = derive_workchain_system_receipt_id(second).move_as_ok();
  ASSERT_TRUE(id1 != id2);
  auto bytes1 = encode_workchain_system_origin_transcript(first).move_as_ok();
  auto bytes2 = encode_workchain_system_origin_transcript(second).move_as_ok();
  ASSERT_EQ(bytes1.substr(9), bytes2.substr(9));  // Exact identical attribution.
  UnoCryptoSystemEncryptionRequestV2 request{};
  request.abi_version = 2; request.amount = 100; request.origin_bytes = 115;
  std::copy(point.as_slice().begin(), point.as_slice().end(), request.recipient);
  std::copy(id1.as_slice().begin(), id1.as_slice().end(), request.receipt_id);
  std::copy(bytes1.begin(), bytes1.end(), request.origin);
  UnoCryptoSystemCiphertext one{}, two{};
  ASSERT_EQ(uno_crypto_system_encrypt_v2(&request, &one), 0u);
  std::copy(id2.as_slice().begin(), id2.as_slice().end(), request.receipt_id);
  std::copy(bytes2.begin(), bytes2.end(), request.origin);
  ASSERT_EQ(uno_crypto_system_encrypt_v2(&request, &two), 0u);
  ASSERT_TRUE(std::memcmp(one.commitment, two.commitment, 32) != 0);
  ASSERT_TRUE(std::memcmp(one.handle, two.handle, 32) != 0);
  ASSERT_EQ(uno_crypto_system_verify_v2(&request, &one), 3u);
  second.sequence = 0;
  auto missing = encode_workchain_system_origin(second);
  ASSERT_TRUE(missing.is_error());
  ASSERT_EQ(missing.error().message(), "system origin requires issued sequence");
}
