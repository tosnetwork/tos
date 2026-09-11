// Test against the committed v2 host API (880fc7f7a or later).
#include "workchain-m3-registration-wallet.h"
#include "workchain-possession-test-policy.h"
#include "td/utils/tests.h"
#include "td/utils/misc.h"
#include <type_traits>
#include "block/mc-config.h"

namespace {
template<class P,class=void> struct HasRefundTable : std::false_type {};
template<class P> struct HasRefundTable<P,std::void_t<decltype(std::declval<P>().refund_workchains)>> : std::true_type {};
template<class P> P policy_for(const block::WorkchainConfidentialAccount& a,
    const block::WorkchainPossessionPolicy& possession, const block::WorkchainSet& table,
    const td::Bits256& instance) {
  if constexpr (HasRefundTable<P>::value)
    return {a.global_id,a.genesis_hash,instance,a.bindings,1,1,2,10,possession,table};
  else
    return {a.global_id,a.genesis_hash,instance,a.bindings,1,1,2,10,possession};
}
}
TEST(M3RegistrationWallet, ActualHostPolicyFields) {
  using namespace block;
  auto word=[](unsigned char n) { td::Bits256 r; std::fill(r.as_slice().begin(),r.as_slice().end(),n); return r; };
  WorkchainConfidentialAccount a{};
  a.global_id=-23903; a.genesis_hash=word(1); a.address={2,word(2),word(3)};
  a.bindings={word(4),word(5),word(6)}; a.schema_version=1; a.relation_profile=1; a.proof_profile=2;
  a.public_key.as_slice().copy_from(td::hex_decode("da6b841f2b72c6d5e15bd974905e1e218b1aa5c4eb4da5ea34bfeebab76dbf25").move_as_ok());
  auto possession=block::test::possession_policy(a);
  WorkchainSet table; // Encoding test only: no destination-admission claim.
  auto policy=policy_for<WorkchainRegistrationPolicy>(a,possession,table,word(7));
  auto input=m3_test::make_m3_test_registration_wallet_input(policy,0,word(8),a.public_key,a.address.account).move_as_ok();
  ASSERT_EQ(input.operation_id.to_hex(),"0DB963E03494EF62B42EBF2CDB9A69F109DAE126399C80801DDACF8E98660A12");
  auto decoded=decode_workchain_confidential_account(input.account_data).move_as_ok();
  ASSERT_EQ(decoded.address.instance,input.operation_id); ASSERT_EQ(decoded.funding.paid_deposit,10u);
  ASSERT_EQ(decoded.funding.refund_account,word(8)); ASSERT_EQ(decoded.funding.refund_workchain,0);
  ASSERT_EQ(decoded.auth_nonce,0u); ASSERT_EQ(decoded.available_revision,0u);
  ASSERT_TRUE(decoded.pending.empty()); ASSERT_TRUE(decoded.available.commitment.is_zero());
  ASSERT_TRUE(decoded.available.handle.is_zero()); ASSERT_EQ(decoded.public_key,a.public_key);
  ASSERT_EQ(input.context_bytes.size(),426u); ASSERT_EQ(input.prefix_bytes.size(),210u);
  // Independent fixed-offset reading of the existing wallet prefix.
  const auto& p=input.prefix_bytes;
  ASSERT_EQ(td::hex_encode(td::Slice(p).substr(0,4)),"ffffa2a1");
  ASSERT_EQ(td::Slice(p).substr(4,32),a.genesis_hash.as_slice());
  ASSERT_EQ(td::hex_encode(td::Slice(p).substr(36,4)),"00000002");
  ASSERT_EQ(td::Slice(p).substr(40,32),a.address.account.as_slice());
  ASSERT_EQ(td::Slice(p).substr(72,32),input.operation_id.as_slice());
  ASSERT_EQ(td::Slice(p).substr(104,32),a.bindings.asset.as_slice());
  ASSERT_EQ(td::Slice(p).substr(136,32),a.bindings.custody.as_slice());
  ASSERT_EQ(td::Slice(p).substr(168,32),a.bindings.policy.as_slice());
  ASSERT_EQ(td::hex_encode(td::Slice(p).substr(200)),"00010001000200000000");
  ASSERT_EQ(input.context.subject.instance,input.operation_id);
  ASSERT_EQ(input.context.protocol.workchain_instance,word(7));
}
