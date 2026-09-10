#include "workchain-proof-test-access.h"
#include "block/workchain-account-closure.h"
#include "td/utils/tests.h"
#include "td/utils/misc.h"
#include "vm/boc.h"
#include <algorithm>
#include "workchain-possession-test-policy.h"
#include "block/workchain-possession-replay.h"

TEST(AccountClosure, RandomizedZeroRefundAndReplay) {
  auto fill = [](unsigned char byte) { td::Bits256 r;
    std::fill(r.as_slice().begin(), r.as_slice().end(), byte); return r; };
  auto point = [](td::Slice hex) { auto bytes = td::hex_decode(hex); CHECK(bytes.is_ok());
    td::Bits256 r; r.as_slice().copy_from(bytes.ok()); return r; };
  block::WorkchainConfidentialAccount a{};
  a.global_id=-23903; a.genesis_hash=fill(1); a.address={2,fill(2),fill(3)};
  a.bindings={fill(4),fill(5),fill(6)}; a.schema_version=1; a.relation_profile=1; a.proof_profile=2;
  a.key_epoch=0; a.auth_nonce=3; a.available_revision=4; a.funding={10,0,fill(8)};
  a.lifecycle=block::WorkchainAccountActive{};
  a.public_key=point("da6b841f2b72c6d5e15bd974905e1e218b1aa5c4eb4da5ea34bfeebab76dbf25");
  a.available={point("7a3349e9a50cf9a20a3a92994fecbf9b19ac50d4e743de192a162bb053278767"),
               point("9a3085e444e85dc98eebe3373235c06c71793402885014ce760aff7a0691d124")};
  std::array<unsigned char,80> domain; domain.fill(7);
  auto possession = block::test::possession_policy(a);
  // v2 wallet vector, test-only s=71/k=997, with this canonical host context.
  auto bytes=td::hex_decode("b4262c4f436f97163b68860a20fda0f8b34b8baa176bb5e1f44a5c85b1785c6f"
      "ac6aaea780f6c80dd569fae7000ccda4554ee2885bc3e2320a8f1ab1f53a790b"
      "e71bb3630effd6eddf79f4fee9f8df6db78d24c3a94574ccde5a518186b1880d");
  ASSERT_TRUE(bytes.is_ok());
  std::array<unsigned char,96> proof; std::copy(bytes.ok().begin(),bytes.ok().end(),proof.begin());
  block::WorkchainCoordinatorState coordinator{2,{1,1000000,9,0},90};
  auto id=block::derive_workchain_closure_operation_id({a.global_id,a.genesis_hash,possession.protocol.workchain_instance},
      a.address,a.auth_nonce).move_as_ok();
  block::WorkchainClosureReplayInput replay{id,block::rebuild_workchain_possession_context(possession,a),proof};
  auto replay_root=block::encode_workchain_replay_input(replay).move_as_ok();
  ASSERT_EQ(vm::std_boc_serialize(replay_root,0).move_as_ok().size(),589u);
  auto meter = block::WorkchainProofTestAccess::create(441);
  auto result = block::replay_workchain_account_closure(a, coordinator, possession, domain, replay_root, meter);
  ASSERT_EQ(meter.consumed(), 441u);
  auto short_meter = block::WorkchainProofTestAccess::create(440);
  auto short_result = block::replay_workchain_account_closure(a, coordinator, possession, domain, replay_root, short_meter);
  ASSERT_TRUE(short_result.is_error());
  ASSERT_EQ(short_result.error().code(), -7201);
  ASSERT_EQ(short_result.error().message(), "engine underestimated attempted verification work");
  ASSERT_EQ(short_meter.consumed(), 0u);
#if defined(TOS_CONFIDENTIAL_PROOF_BACKEND_LINKED)
  ASSERT_TRUE(result.is_ok());
  ASSERT_TRUE(block::replay_workchain_account_closure(a, coordinator, possession, domain, replay_root, meter).is_error());
  ASSERT_EQ(meter.consumed(), 441u);
  auto invalid_replay = replay;
  invalid_replay.proof[0] ^= 1;
  auto invalid_root = block::encode_workchain_replay_input(invalid_replay).move_as_ok();
  auto failed_meter = block::WorkchainProofTestAccess::create(882);
  auto invalid_result = block::replay_workchain_account_closure(a, coordinator, possession, domain, invalid_root, failed_meter);
  ASSERT_TRUE(invalid_result.is_error());
  ASSERT_EQ(invalid_result.error().code(), -7200);
  ASSERT_EQ(failed_meter.consumed(), 441u);
  auto sticky_result = block::replay_workchain_account_closure(a, coordinator, possession, domain, replay_root, failed_meter);
  ASSERT_TRUE(sticky_result.is_error());
  ASSERT_EQ(sticky_result.error().code(), -7200);
  ASSERT_EQ(failed_meter.consumed(), 441u);
  auto policy_y=possession;
  policy_y.profiles.configuration.as_slice()[0]^=1;
  auto claimed_y=block::rebuild_workchain_possession_context(policy_y,a);
  ASSERT_TRUE(block::check_workchain_possession_replay_context(claimed_y,policy_y,a,
      block::WorkchainReplayOperation::Closure).is_ok());
  auto replay_y=replay; replay_y.context=claimed_y;
  auto substituted=block::WorkchainProofTestAccess::with_budget(100000, [&](auto& verification_budget) { return block::replay_workchain_account_closure(a,coordinator,policy_y,domain,
      block::encode_workchain_replay_input(replay_y).move_as_ok(), verification_budget); });
  ASSERT_TRUE(substituted.is_error());
  ASSERT_EQ(substituted.error().code(),-7200);
  ASSERT_EQ(substituted.error().message(),"invalid closure zero-balance possession proof");
  auto wrong_id=replay; wrong_id.claimed_operation_id.as_slice()[0]^=1;
  auto rejected_id=block::WorkchainProofTestAccess::with_budget(100000, [&](auto& verification_budget) { return block::replay_workchain_account_closure(a,coordinator,possession,domain,
      block::encode_workchain_replay_input(wrong_id).move_as_ok(), verification_budget); });
  ASSERT_TRUE(rejected_id.is_error()); ASSERT_EQ(rejected_id.error().code(),-7200);
  ASSERT_EQ(rejected_id.error().message(),"claimed operationID mismatch");
  auto closed=block::decode_workchain_confidential_account(result.ok().account_data);
  auto after=block::decode_workchain_coordinator_state(result.ok().coordinator_data);
  ASSERT_TRUE(closed.is_ok()); ASSERT_TRUE(after.is_ok());
  ASSERT_TRUE(std::holds_alternative<block::WorkchainAccountClosed>(closed.ok().lifecycle));
  ASSERT_EQ(closed.ok().auth_nonce,4u); ASSERT_EQ(closed.ok().available_revision,4u);
  ASSERT_EQ(after.ok().system.registered_accounts,9u); ASSERT_EQ(after.ok().refundable_deposits,80u);
  ASSERT_EQ(result.ok().refund.amount,10u); ASSERT_EQ(result.ok().refund.account,fill(8));
  ASSERT_EQ(a.auth_nonce,3u); ASSERT_EQ(coordinator.refundable_deposits,90u);
  ASSERT_TRUE(block::WorkchainProofTestAccess::with_budget(100000, [&](auto& verification_budget) { return block::execute_workchain_account_closure(closed.ok(),after.ok(),possession,domain,proof, verification_budget); }).is_error());
  auto pending=a; pending.pending.resize(1);
  ASSERT_TRUE(block::WorkchainProofTestAccess::with_budget(100000, [&](auto& verification_budget) { return block::execute_workchain_account_closure(pending,coordinator,possession,domain,proof, verification_budget); }).is_error());
  auto stale=a; ++stale.available_revision;
  auto denied=block::WorkchainProofTestAccess::with_budget(100000, [&](auto& verification_budget) { return block::execute_workchain_account_closure(stale,coordinator,possession,domain,proof, verification_budget); });
  ASSERT_TRUE(denied.is_error());
  ASSERT_EQ(denied.error().code(),static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
  auto short_bucket=coordinator; short_bucket.refundable_deposits=9;
  denied=block::WorkchainProofTestAccess::with_budget(100000, [&](auto& verification_budget) { return block::execute_workchain_account_closure(a,short_bucket,possession,domain,proof, verification_budget); });
  ASSERT_TRUE(denied.is_error());
  ASSERT_EQ(denied.error().code(),static_cast<int>(block::WorkchainExecutionFailure::AuthenticatedStateCorrupt));
  ASSERT_EQ(short_bucket.refundable_deposits,9u);
  auto exhausted=a; exhausted.auth_nonce=UINT64_MAX;
  ASSERT_TRUE(block::WorkchainProofTestAccess::with_budget(100000, [&](auto& verification_budget) { return block::execute_workchain_account_closure(exhausted,coordinator,possession,domain,proof, verification_budget); }).is_error());
#else
  ASSERT_TRUE(result.is_error());
  ASSERT_EQ(result.error().code(),static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
#endif
}
