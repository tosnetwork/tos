#include "td/utils/tests.h"
#include "block/workchain-withdrawal-association.h"
#include "block/native-bounce-body.h"

using namespace block;
namespace {
td::Bits256 word(unsigned n) {
  auto v = td::Bits256::zero(); v.as_slice().back() = static_cast<char>(n); return v;
}
gen::UnoV2OperationNetworkV1::Record network() { return {-99, word(10), word(1)}; }
WorkchainWithdrawalControl control() {
  WorkchainWithdrawalRecord r{{}, {}, 7, 100, {2, word(1), word(2)}, {0, word(3)},
      {4, 20, 0, 20}, {0, 77, 10, 0, 30}};
  r.withdrawal_id = derive_workchain_withdrawal_id(network(), r.source, r.consumed_auth_nonce).move_as_ok();
  r.attempt_id = derive_workchain_attempt_id(r.withdrawal_id).move_as_ok();
  return {WorkchainAccountActive{}, {r}};
}
td::Ref<vm::Cell> message(std::uint64_t original_lt = 77, bool bounced = true,
    bool rich = true, unsigned source = 3, unsigned original_amount = 100,
    std::uint64_t inbound_lt = 900) {
  auto original = vm::CellBuilder().store_bits(word(2).bits(), 256)
      .store_ref(vm::CellBuilder().store_long(123, 32).finalize()).finalize();
  vm::CellBuilder value;
  CHECK(CurrencyCollection(original_amount).store(value));
  auto original_body = vm::load_cell_slice_ref(original);
  auto original_value = vm::load_cell_slice_ref(value.finalize());
  vm::CellBuilder payload;
  store_native_bounce_body(payload, rich, true, 256, *original_body,
      original_body, original_value, original_lt, 10, {0, -1, {}});
  vm::CellBuilder result;
  result.store_long(bounced ? 5 : 4, 4);
  result.store_long(4, 3).store_long(0, 8).store_bits(word(source).bits(), 256);
  result.store_long(4, 3).store_long(2, 8).store_bits(word(99).bits(), 256);
  CHECK(CurrencyCollection(70).store(result));
  CHECK(tlb::t_Tomis.store_integer_ref(result, td::make_refint(0)));
  CHECK(tlb::t_Tomis.store_integer_ref(result, td::make_refint(0)));
  return result.store_long(inbound_lt, 64).store_long(20, 32).store_long(0, 1)
      .store_long(1, 1).store_ref(payload.finalize()).finalize();
}
auto associate(td::Ref<vm::Cell> m, const WorkchainWithdrawalControl& c) {
  return associate_workchain_withdrawal_return(m, 2, word(99), network(), c);
}
void error_is(td::Result<std::optional<WorkchainWithdrawalAssociation>> result, td::Slice reason) {
  ASSERT_TRUE(result.is_error()); ASSERT_EQ(result.error().message(), reason);
}
}

TEST(WithdrawalAssociation, ActualMessageHashAndOriginalLt) {
  auto c = control(); auto m = message();
  auto result = associate(m, c); ASSERT_TRUE(result.is_ok()); ASSERT_TRUE(result.ok().has_value());
  const auto& found = *result.ok();
  ASSERT_TRUE(found.inbound_message == td::Bits256(m->get_hash().bits()));
  ASSERT_TRUE(found.attempt_id == c.withdrawals[0].attempt_id);
  ASSERT_EQ(found.payout_created_lt, 77u);
  ASSERT_TRUE(found.received == CurrencyCollection(70));
  ASSERT_EQ(vm::load_cell_slice(found.original_body).size_refs(), 1u);
  auto changed = message(77, true, true, 3, 100, 901);
  auto second = associate(changed, c).move_as_ok(); ASSERT_TRUE(second.has_value());
  ASSERT_TRUE(second->inbound_message != found.inbound_message);
  ASSERT_TRUE(second->attempt_id == found.attempt_id);
}
TEST(WithdrawalAssociation, NoReleaseForUnmatchedOrLegacy) {
  auto c = control();
  for (auto m : {message(78), message(77, false), message(77, true, false)}) {
    auto result = associate(m, c); ASSERT_TRUE(result.is_ok()); ASSERT_TRUE(!result.ok());
  }
  c.withdrawals.clear();
  ASSERT_TRUE(!associate(message(), c).move_as_ok());
}
TEST(WithdrawalAssociation, IdentityAndOriginalEvidenceChecks) {
  auto c = control(); c.withdrawals[0].attempt_id = word(20);
  error_is(associate(message(), c), "authenticated Withdrawal identity does not recompute");
  c = control(); c.withdrawals[0].withdrawal_id = word(21);
  error_is(associate(message(), c), "authenticated Withdrawal identity does not recompute");
  c = control(); c.withdrawals.push_back(c.withdrawals[0]);
  error_is(associate(message(), c), "ambiguous Withdrawal payout created_lt");
  error_is(associate(message(77, true, true, 4), control()),
      "matched return source differs from payout destination");
  error_is(associate(message(77, true, true, 3, 101), control()),
      "matched return original value differs from payout principal");
}
