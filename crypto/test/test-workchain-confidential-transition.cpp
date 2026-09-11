#include "block/workchain-confidential-transition.h"
#include "block/workchain-transfer-statement.h"
#include "block/workchain-confidential-execution.h"
#include "td/utils/tests.h"
#include "td/utils/misc.h"

TEST(ConfidentialTransition, CheckedCountersAndStaleRetry) {
  block::WorkchainConfidentialAccount account{};
  account.auth_nonce = 7;
  account.available_revision = 9;
  auto next = block::next_workchain_confidential_counters(account, 7, 9);
  ASSERT_TRUE(next.is_ok());
  ASSERT_EQ(next.ok().auth_nonce, 8u);
  ASSERT_EQ(next.ok().available_revision, 10u);
  ASSERT_EQ(account.auth_nonce, 7u);
  ASSERT_EQ(account.available_revision, 9u);
  account.auth_nonce = next.ok().auth_nonce;
  account.available_revision = next.ok().available_revision;
  auto stale = block::next_workchain_confidential_counters(account, 7, 9);
  ASSERT_TRUE(stale.is_error());
  ASSERT_EQ(stale.error().code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
  account.auth_nonce = UINT64_MAX;
  ASSERT_TRUE(block::next_workchain_confidential_counters(account, UINT64_MAX, 10).is_error());
  account.auth_nonce = 8;
  account.available_revision = UINT64_MAX;
  ASSERT_TRUE(block::next_workchain_confidential_counters(account, 8, UINT64_MAX).is_error());
}

TEST(ConfidentialTransition, PendingCapacityIsCandidateProperty) {
  block::WorkchainConfidentialAccount target{};
  target.pending.resize(15);
  ASSERT_TRUE(block::check_workchain_pending_capacity(target, 16).is_ok());
  target.pending.resize(16);
  auto full = block::check_workchain_pending_capacity(target, 16);
  ASSERT_TRUE(full.is_error());
  ASSERT_EQ(full.code(), static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
  ASSERT_EQ(target.pending.size(), 16u);
}

TEST(ConfidentialTransition, OldStatementBindsRevisionAndDestination) {
  auto zero=td::Bits256::zero();
  block::WorkchainTransferOldStatement statement{zero,{zero,zero},0,7,9,zero,0,{}};
  auto original=block::hash_workchain_transfer_old_statement(1,statement);
  ASSERT_TRUE(original.is_ok());
  ++statement.available_revision;
  ASSERT_TRUE(block::hash_workchain_transfer_old_statement(1,statement).move_as_ok()!=original.ok());
  statement.available_revision=9;
  ++statement.destination_key_epoch;
  ASSERT_TRUE(block::hash_workchain_transfer_old_statement(1,statement).move_as_ok()!=original.ok());
}

TEST(ConfidentialTransition, HistoricalFailureNonceAndExpiry) {
  using namespace block;
  auto zero=td::Bits256::zero();
  auto one=zero; one.as_slice()[31]=1;
  auto two=zero; two.as_slice()[31]=2;
  auto key_bytes=td::hex_decode("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76").move_as_ok();
  td::Bits256 key; key.as_slice().copy_from(key_bytes);
  WorkchainConfidentialAccount a{1,1,2,3,zero,{2,one,zero},{zero,zero,zero},
      {10,0,one},key,0,{zero,zero},7,9,{},WorkchainAccountActive{}};
  auto b=a; b.address.account=two;
  WorkchainTransferEnvironment env{{10000,100,16,1024,4096},{},
      {2,1,1,2,1,3,2,zero,zero},{zero,zero,zero},{zero,zero,zero},zero,0,100,3,16,1,1,2};
  WorkchainTransferClaims claims{a.address,7,9,0,100,3};
  WorkchainTransferData data=WorkchainSendData{claims,b.address,0,{zero,zero},{zero,zero,zero},zero};
  auto id=derive_workchain_operation_id({3,zero,zero},a.address,1,7).move_as_ok();
  WorkchainTransferInput input{id,data,{}};
  WorkchainHistoricalConfidentialAccount source{std::optional{a}},target{std::optional{b}};
  auto prepared=prepare_workchain_transfer_statement(env,input,source,target);
  ASSERT_TRUE(prepared.is_ok()); ASSERT_EQ(prepared.ok().context.size(),427u);
  ASSERT_EQ(prepared.ok().points.size(),10u);
  // Equal expiry height is valid, strictly greater is not.
  ++env.height;
  ASSERT_EQ(prepare_workchain_transfer_statement(env,input,source,target).error().code(),-7200);
  --env.height;
  WorkchainHistoricalConfidentialAccount unavailable{td::Status::Error("historical account not loaded")};
  ASSERT_EQ(prepare_workchain_transfer_statement(env,input,unavailable,target).error().code(),-7201);
  auto advanced=a; ++advanced.auth_nonce;
  WorkchainHistoricalConfidentialAccount already_consumed{std::optional{advanced}};
  auto retry=prepare_workchain_transfer_statement(env,input,already_consumed,target);
  ASSERT_TRUE(retry.is_error());
  ASSERT_EQ(retry.error().message(),"confidential nonce or available revision mismatch");
  ASSERT_EQ(retry.error().code(),-7200);
}

TEST(ConfidentialTransition, CollectBindsCompleteSystemOrigin) {
  using namespace block;
  auto zero = td::Bits256::zero();
  auto one = zero; one.as_slice()[31] = 1;
  auto key_bytes = td::hex_decode("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76").move_as_ok();
  td::Bits256 key; key.as_slice().copy_from(key_bytes);
  WorkchainConfidentialAccount a{2, 1, 4, 3, zero, {2, one, zero}, {zero, zero, zero},
      {10, 0, one}, key, 0, {zero, zero}, 7, 9, {}, WorkchainAccountActive{}, {}};
  auto receipt_id = derive_workchain_deposit_id(one, 1).move_as_ok();
  a.system_pending.push_back({receipt_id, one, 1, 1000000000, a.address.instance, 0,
      a.bindings.asset, {key, key}, 0});
  WorkchainTransferEnvironment env{{(std::uint64_t{1} << 62) - 1, (std::uint64_t{1} << 62) - 1, 8, 1024, 4096}, {},
      {2, 1, 1, 2, 2, 3, 2, zero, zero}, {zero, zero, zero}, {zero, zero, zero}, zero, 0, 100, 3, 16, 2, 1, 4};
  WorkchainTransferClaims claims{a.address, 7, 9, 0, 100, 3};
  WorkchainTransferInput input{derive_workchain_operation_id({3, zero, zero}, a.address, 2, 7).move_as_ok(),
      WorkchainCollectData{claims, {key, key}, key, {{receipt_id, key}}}, {}};
  auto prepare = [&] {
    return prepare_workchain_transfer_statement(env, input, std::optional<WorkchainConfidentialAccount>{a},
        std::optional<WorkchainConfidentialAccount>{});
  };
  auto original = prepare();
  ASSERT_TRUE(original.is_ok());
  ASSERT_EQ(original.ok().receipt_ids.size(), 1u);
  ASSERT_EQ(original.ok().points.size(), 9u);
  ASSERT_EQ(a.pending.size(), 0u);  // No fabricated SEND source was needed.
  a.system_pending.front().target_key_epoch = 1;
  auto wrong_epoch = prepare();
  ASSERT_TRUE(wrong_epoch.is_error());
  ASSERT_EQ(wrong_epoch.error().message(), "system pending consumption, ownership or source domain mismatch");
  ASSERT_EQ(wrong_epoch.error().code(), -7200);
  a.system_pending.front().target_key_epoch = 0;
  // Same ID/ciphertext but a different authenticated public amount changes the
  // old-statement commitment. The complete system receipt is bound, not just C,D.
  ++a.system_pending.front().amount;
  ASSERT_TRUE(prepare().move_as_ok().context != original.ok().context);
  a.system_pending.clear();
  auto missing = prepare();
  ASSERT_TRUE(missing.is_error());
  ASSERT_EQ(missing.error().message(), "selected pending receipt does not exist");
  ASSERT_EQ(missing.error().code(), -7200);
}
