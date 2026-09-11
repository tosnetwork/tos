#include "td/utils/tests.h"
#include "block/workchain-withdrawal-association.h"
#include "workchain-m5-failed-input.h"
#include "block/native-bounce-body.h"
#include "block/workchain-failed-funded.h"
#include "block/workchain-unexpected-bucket.h"
#include "workchain-proof-test-access.h"

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
  CHECK(block::tlb::t_Tomis.store_integer_ref(result, td::make_refint(0)));
  CHECK(block::tlb::t_Tomis.store_integer_ref(result, td::make_refint(0)));
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

TEST(WithdrawalAssociation, TestFailedSelectorExactCodec) {
  m3_test::M5TestFailedInput selector{{2, word(1), word(2)}, word(3)};
  auto root = m3_test::encode_m5_test_failed(selector);
  auto decoded = m3_test::decode_m5_test_failed(root).move_as_ok();
  ASSERT_EQ(decoded.owner.workchain_id, 2);
  ASSERT_EQ(decoded.owner.account, word(1));
  ASSERT_EQ(decoded.owner.instance, word(2));
  ASSERT_EQ(decoded.inbound_message, word(3));
  auto extra = vm::CellBuilder().append_cellslice(vm::load_cell_slice(root)).store_long(0, 1).finalize();
  auto rejected = m3_test::decode_m5_test_failed(extra);
  ASSERT_TRUE(rejected.is_error());
  ASSERT_EQ(rejected.error().code(), -7200);
  ASSERT_EQ(rejected.error().message(), "malformed test Failed selector");
}

TEST(WithdrawalAssociation, CodecFailureCategoriesSurviveProtection) {
  // Observe the real codec exception boundary, not a diagnostic string. This
  // preserves mechanisms, NOT arena provenance or a Native DB fault test.
  auto vm_failure = withdrawal_codec_detail::protect([]() -> td::Result<int> {
    throw vm::VmError{vm::Excno::cell_und};
  });
  auto acquisition = withdrawal_codec_detail::protect([]() -> td::Result<int> {
    throw vm::VmVirtError{1};
  });
  ASSERT_TRUE(vm_failure.is_error());
  ASSERT_TRUE(acquisition.is_error());
  ASSERT_EQ(vm_failure.error().code() != acquisition.error().code(), true);
  ASSERT_EQ(vm_failure.error().code(), static_cast<int>(WorkchainCodecFailure::VmBase) -
      static_cast<int>(vm::Excno::cell_und));
  ASSERT_EQ(acquisition.error().code(), static_cast<int>(WorkchainCodecFailure::Virtualization));
  auto nested = withdrawal_codec_detail::protect([&]() -> td::Result<int> {
    TRY_RESULT(value, acquisition.clone());
    return value;
  });
  ASSERT_TRUE(nested.is_error());
  ASSERT_EQ(nested.error().code(), acquisition.error().code());
  ASSERT_EQ(withdrawal_codec_detail::error("content").code(), static_cast<int>(WorkchainCodecFailure::Content));
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

TEST(FailedFunded, RealIssuanceAndEncodedSequencePair) {
  auto pending = control();
  pending.withdrawals[0].costs = {4, 100, 0, 100};
  pending.withdrawals[0].timing = {1, 77, 10, 12, 30};
  td::Bits256 point;
  point.as_slice().copy_from(td::hex_decode(
      "b6ec3baa39a7357ab9ca16c61373385f7cfb04ab10c4bc20c8bd3cc6db9a6100").move_as_ok());
  WorkchainConfidentialAccount core{3, 1, 4, -99, word(1), {2, word(1), word(2)},
      {word(4), word(99), word(6)}, {10000000000ULL, 0, word(7)}, point, 0,
      {word(0), word(0)}, 8, 0, {}, WorkchainAccountActive{}, {}};
  auto owner = encode_workchain_withdrawal_account({core, pending, {}}, 2).move_as_ok();
  auto bucket = encode_workchain_unexpected_bucket({{}, {}, td::make_refint(0), {}, 0}, {256, 256}, 100).move_as_ok();
  auto coordinator = encode_workchain_coordinator_state({3, {1, 0, 1, 4}, 0, 10, bucket}).move_as_ok();
  auto m = message();
  block::tlb::MsgEnvelope::Record_std wire{96, 96, td::make_refint(0), m, {}, {}};
  td::Ref<vm::Cell> envelope;
  ASSERT_TRUE(block::tlb::pack_cell(envelope, wire));
  WorkchainNativeInboxPlan inbox{{envelope}, 900};
  // Explicit synthetic transition inputs, NOT authenticated business config or
  // frozen tariff defaults. This fixture does not claim a real node block.
  WorkchainFailedFundedPolicy policy{2, 4, 2, 3, 4};
  auto run = [&](WorkchainProofVerifier& meter, std::uint32_t height = 20) {
    return prepare_workchain_failed_funded(inbox, owner, coordinator, policy, {}, network(),
        word(99), word(98), height, meter);
  };
  auto a = WorkchainProofTestAccess::create(7);
  auto b = WorkchainProofTestAccess::create(7);
  auto result = run(a), replay = run(b);
  if (result.is_error()) LOG(ERROR) << result.error();
  ASSERT_TRUE(result.is_ok()); ASSERT_TRUE(replay.is_ok());
  ASSERT_EQ(a.consumed(), 7u); ASSERT_EQ(a.consumed(), b.consumed());
  ASSERT_TRUE(result.ok().owner_data->get_hash() == replay.ok().owner_data->get_hash());
  auto next_owner = decode_workchain_withdrawal_account(result.ok().owner_data, 2).move_as_ok();
  auto next_coordinator = decode_workchain_coordinator_state(result.ok().coordinator_data).move_as_ok();
  ASSERT_EQ(next_owner.origin_pending.size(), 1u);
  ASSERT_TRUE(next_owner.control.withdrawals.empty());
  ASSERT_EQ(*next_coordinator.deposit_sequence, 11u);
  ASSERT_EQ(workchain_system_origin_sequence(next_owner.origin_pending[0].origin), 11u);
  ASSERT_EQ(next_owner.origin_pending[0].amount, 156u);
  ASSERT_TRUE(std::get<WorkchainSettlementOrigin>(next_owner.origin_pending[0].origin).attempt_id ==
              pending.withdrawals[0].attempt_id);
  ASSERT_TRUE(result.ok().inbound_message == td::Bits256(m->get_hash().bits()));
  ASSERT_EQ(result.ok().recovered, 70u); ASSERT_EQ(result.ok().released_p, 100u);
  ASSERT_EQ(result.ok().released_w, 200u);
  ASSERT_EQ(td::cmp(result.ok().fees.state_fee, 2), 0);
  ASSERT_EQ(td::cmp(result.ok().fees.compute_fee, 12), 0);
  ASSERT_EQ(*decode_workchain_coordinator_state(coordinator).move_as_ok().deposit_sequence, 10u);
  auto short_budget = WorkchainProofTestAccess::create(6);
  ASSERT_TRUE(run(short_budget).is_error()); ASSERT_EQ(short_budget.consumed(), 0u);
  auto late = WorkchainProofTestAccess::create(7);
  auto unsupported = run(late, 43);
  ASSERT_TRUE(unsupported.is_error());
  ASSERT_EQ(unsupported.error().message(), "funded Failed requires an open height window");
  ASSERT_EQ(late.consumed(), 0u);
}
