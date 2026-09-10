#include "block/workchain-confidential-transition.h"
#include "block/workchain-transfer-statement.h"
#include "td/utils/tests.h"

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
