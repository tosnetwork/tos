#include "block/workchain-account-closure.h"
#include "td/utils/tests.h"
#include "td/utils/misc.h"
#include <algorithm>

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
  auto bytes=td::hex_decode("a226f594e835391bcb4b5e737dc2e7f797679527a174cc45d28effc268b3b401"
      "bc954825d11340ad13eace250298c57ab77f119a98bea4439dffae0b04d31922"
      "c042f742accc9303f0fb75ae3ba9b2b453f7e78a585b63b424db7a23c0860a00");
  ASSERT_TRUE(bytes.is_ok());
  std::array<unsigned char,96> proof; std::copy(bytes.ok().begin(),bytes.ok().end(),proof.begin());
  block::WorkchainCoordinatorState coordinator{2,{1,1000000,9,0},90};
  auto result=block::execute_workchain_account_closure(a,coordinator,0,domain,proof);
#if defined(TOS_CONFIDENTIAL_PROOF_BACKEND_LINKED)
  ASSERT_TRUE(result.is_ok());
  auto closed=block::decode_workchain_confidential_account(result.ok().account_data);
  auto after=block::decode_workchain_coordinator_state(result.ok().coordinator_data);
  ASSERT_TRUE(closed.is_ok()); ASSERT_TRUE(after.is_ok());
  ASSERT_TRUE(std::holds_alternative<block::WorkchainAccountClosed>(closed.ok().lifecycle));
  ASSERT_EQ(closed.ok().auth_nonce,4u); ASSERT_EQ(closed.ok().available_revision,4u);
  ASSERT_EQ(after.ok().system.registered_accounts,9u); ASSERT_EQ(after.ok().refundable_deposits,80u);
  ASSERT_EQ(result.ok().refund.amount,10u); ASSERT_EQ(result.ok().refund.account,fill(8));
  ASSERT_EQ(a.auth_nonce,3u); ASSERT_EQ(coordinator.refundable_deposits,90u);
  ASSERT_TRUE(block::execute_workchain_account_closure(closed.ok(),after.ok(),0,domain,proof).is_error());
  auto denied=block::execute_workchain_account_closure(a,coordinator,1,domain,proof);
  ASSERT_TRUE(denied.is_error());
  ASSERT_EQ(denied.error().code(),static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
  auto pending=a; pending.pending.resize(1);
  ASSERT_TRUE(block::execute_workchain_account_closure(pending,coordinator,0,domain,proof).is_error());
  auto stale=a; ++stale.available_revision;
  denied=block::execute_workchain_account_closure(stale,coordinator,0,domain,proof);
  ASSERT_TRUE(denied.is_error());
  ASSERT_EQ(denied.error().code(),static_cast<int>(block::WorkchainExecutionFailure::CandidateInvalid));
  auto short_bucket=coordinator; short_bucket.refundable_deposits=9;
  denied=block::execute_workchain_account_closure(a,short_bucket,0,domain,proof);
  ASSERT_TRUE(denied.is_error());
  ASSERT_EQ(denied.error().code(),static_cast<int>(block::WorkchainExecutionFailure::AuthenticatedStateCorrupt));
  ASSERT_EQ(short_bucket.refundable_deposits,9u);
  auto exhausted=a; exhausted.auth_nonce=UINT64_MAX;
  ASSERT_TRUE(block::execute_workchain_account_closure(exhausted,coordinator,0,domain,proof).is_error());
#else
  ASSERT_TRUE(result.is_error());
  ASSERT_EQ(result.error().code(),static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable));
#endif
}
